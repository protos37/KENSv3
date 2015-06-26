#include <string.h>
#include <stdlib.h>

#include "Session.hpp"

EndPoint::EndPoint()
	: valid(false)
{
}

EndPoint::EndPoint(const EndPoint &endpoint)
	: valid(endpoint.isValid())
	, addr(endpoint.addr)
	, port(endpoint.port)
{
}

EndPoint::EndPoint(uint32_t _addr, uint16_t _port)
	: valid(true)
	, addr(_addr)
	, port(_port)
{
}

bool EndPoint::operator == (const EndPoint other) const
{
	return !valid || !other.valid ||
		(port == other.port && (addr == INADDR_ANY || other.addr == INADDR_ANY || addr == other.addr));
}

bool EndPoint::isValid() const
{
	return valid;
}

Session::Session(SessionHandler *_handler)
	: state(CLOSED)
	, seq(0), ack_seq(0)
	, local(), remote()
	, handler(_handler), parent(NULL)
{
}

Session::Session(SessionHandler *_handler, Session *_parent, EndPoint _local, EndPoint _remote)
	: state(LISTEN)
	, seq(0), ack_seq(0)
	, local(_local), remote(_remote)
	, handler(_handler), parent(_parent)
{
}

void Session::sendPacket(uint8_t flag, void *payload, size_t size)
{
	struct hdr hdr;

	memset(&hdr, 0, sizeof(struct hdr));
	hdr.ip.saddr = htonl(local.addr);
	hdr.ip.daddr = htonl(remote.addr);
	hdr.tcp.source = htons(local.port);
	hdr.tcp.dest = htons(remote.port);
	hdr.tcp.seq = htonl(seq);
	hdr.tcp.ack_seq = (flag & TCP_ACK) ? htonl(ack_seq) : 0;
	hdr.tcp.doff = sizeof(struct tcphdr) >> 2;
	hdr.tcp.fin = (flag & TCP_FIN) ? 1 : 0;
	hdr.tcp.syn = (flag & TCP_SYN) ? 1 : 0;
	hdr.tcp.rst = (flag & TCP_RST) ? 1 : 0;
	hdr.tcp.psh = (flag & TCP_PSH) ? 1 : 0;
	hdr.tcp.ack = (flag & TCP_ACK) ? 1 : 0;
	hdr.tcp.urg = (flag & TCP_URG) ? 1 : 0;
	hdr.tcp.window = htons(51200);

	handler->sendPacket(&hdr, payload, size);
}

int Session::onBind(EndPoint _local)
{
	if(state != CLOSED || local.isValid())
	{
		return -1;
	}

	local = _local;
	handler->bindSession(this);
	return 0;
}

int Session::onListen(int _backlog)
{
	if(state != CLOSED || !local.isValid() || remote.isValid())
	{
		return -1;
	}

	backlog = _backlog;
	state = LISTEN;
	return 0;
}

int Session::onConnect(EndPoint _remote)
{
	if(state != CLOSED || !local.isValid() || remote.isValid())
	{
		return -1;
	}

	remote = _remote;
	seq = rand();
	sendPacket(TCP_SYN, NULL, 0);
	seq++;
	// send syn
	handler->bindSession(this);
	state = SYN_SENT;
	return 0;
}

int Session::onPacket(struct hdr *hdr, void *payload, size_t size)
{
	uint8_t flag = TCP_FLAG(hdr->tcp);
	Session *session;

	ack_seq = ntohl(hdr->tcp.seq);

	/*
	printf("got packet on %p: ", this);
	if(flag & TCP_FIN) printf("FIN ");
	if(flag & TCP_SYN) printf("SYN ");
	if(flag & TCP_RST) printf("RST ");
	if(flag & TCP_PSH) printf("PSH ");
	if(flag & TCP_ACK) printf("ACK ");
	if(flag & TCP_URG) printf("URG ");
	printf("\n");
	*/
	switch(state)
	{
		case LISTEN:
			if(flag == TCP_SYN && remote.isValid())
			{
				seq = rand();
				ack_seq++;
				sendPacket(TCP_SYN | TCP_ACK, NULL, 0);
				seq++;
				// send syn, ack
				state = SYN_RCVD;
				handler->bindSession(this);
				return 0;
			}
			else if(flag == TCP_SYN && (int)waiters.size() < backlog)
			{
				seq = rand();
				session = new Session(handler, this, EndPoint(ntohl(hdr->ip.daddr), ntohs(hdr->tcp.dest)), EndPoint(ntohl(hdr->ip.saddr), ntohs(hdr->tcp.source)));
				waiters.insert(session);
				return session->onPacket(hdr, payload, size);
			}
			break;
		case SYN_RCVD:
			if(flag == TCP_ACK)
			{
				seq = ntohl(hdr->tcp.ack_seq);
				if(parent)
				{
					parent->onReady(this);
					handler->onReady(parent, this);
				}
				else
				{
					handler->onReady(this, this);
				}
				state = ESTABLISHED;
				return 0;
			}
			else if(flag == TCP_RST)
			{
				if(parent)
				{
					parent->onReady(this);
					delete this;
				}
				else
				{
					state = LISTEN;
					onConnect(remote);
				}
				return 0;
			}
			break;
		case SYN_SENT:
			if(flag == TCP_SYN)
			{
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				state = SYN_RCVD;
				return 0;
			}
			else if(flag == (TCP_SYN | TCP_ACK))
			{
				seq = ntohl(hdr->tcp.ack_seq);
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				if(parent)
				{
					parent->onReady(this);
					handler->onReady(parent, this);
				}
				else
				{
					handler->onReady(this, this);
				}
				state = ESTABLISHED;
				return 0;
			}
			break;
		case ESTABLISHED:
			if(flag == TCP_FIN)
			{
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				state = CLOSE_WAIT;
				return 0;
			}
			break;
		case LAST_ACK:
			if(flag == TCP_ACK)
			{
				seq = ntohl(hdr->tcp.ack_seq);
				handler->unbindSession(this);
				state = CLOSED;
				delete this;
				return 0;
			}
			break;
		case FIN_WAIT_1:
			if(flag == TCP_ACK)
			{
				seq = ntohl(hdr->tcp.ack_seq);
				state = FIN_WAIT_2;
				return 0;
			}
			else if(flag == TCP_FIN)
			{
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				state = CLOSING;
				return 0;
			}
			else if(flag == (TCP_FIN | TCP_ACK))
			{
				seq = ntohl(hdr->tcp.ack_seq);
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				state = TIME_WAIT;
				return 0;
			}
			break;
		case FIN_WAIT_2:
			if(flag == TCP_FIN)
			{
				ack_seq++;
				sendPacket(TCP_ACK, NULL, 0);
				// send ack
				state = TIME_WAIT;
				return 0;
			}
			break;
		case CLOSING:
			if(flag == TCP_ACK)
			{
				seq = ntohl(hdr->tcp.ack_seq);
				state = TIME_WAIT;
				return 0;
			}
			break;
		default:
			break;
	}

	return -1;
}

int Session::onClose()
{
	switch(state)
	{
		case CLOSED:
		case LISTEN:
			handler->unbindSession(this);
			state = CLOSED;
			return 0;
		case SYN_RCVD:
		case ESTABLISHED:
			sendPacket(TCP_FIN, NULL, 0);
			seq++;
			// send fin
			state = FIN_WAIT_1;
			return 0;
		case SYN_SENT:
			handler->unbindSession(this);
			state = CLOSED;
			delete this;
			return 0;
		case CLOSE_WAIT:
			sendPacket(TCP_FIN, NULL, 0);
			seq++;
			// send fin
			handler->unbindSession(this);
			state = CLOSED;
			delete this;
			return 0;
		default:
			break;
	}

	return -1;
}

int Session::onReady(Session *session)
{
	auto it = waiters.find(session);
	
	if(it != waiters.end())
	{
		waiters.erase(it);
		return 0;
	}

	return -1;
}

EndPoint Session::getLocal()
{
	return local;
}

EndPoint Session::getRemote()
{
	return remote;
}
