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
	, base(0), ack_base(0), seq(0), ack_seq(0), nwnd(WINDOW_SIZE), cwnd(WINDOW_SIZE), pwnd(1)
	, local(), remote()
	, handler(_handler), parent(NULL)
{
	insend.limit = inrecv.limit = BUFFER_SIZE;
	recv.limit = nwnd;
	send.limit = pwnd;
}

Session::Session(SessionHandler *_handler, Session *_parent, EndPoint _local, EndPoint _remote)
	: state(LISTEN)
	, base(0), ack_base(0), seq(0), ack_seq(0), nwnd(WINDOW_SIZE), cwnd(WINDOW_SIZE), pwnd(1)
	, local(_local), remote(_remote)
	, handler(_handler), parent(_parent)
{
	insend.limit = inrecv.limit = BUFFER_SIZE;
	recv.limit = nwnd;
	send.limit = pwnd;
}

void Session::sendPacket(uint8_t flag, void *payload, size_t size)
{
	struct hdr hdr;

	/*
	printf("send packet %p (%u, %u): ", this, seq - base, ack_seq - ack_base);
	if(flag & TCP_FIN) printf("FIN ");
	if(flag & TCP_SYN) printf("SYN ");
	if(flag & TCP_RST) printf("RST ");
	if(flag & TCP_PSH) printf("PSH ");
	if(flag & TCP_ACK) printf("ACK ");
	if(flag & TCP_URG) printf("URG ");
	printf("\n");
	*/
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
	hdr.tcp.window = htons(nwnd);

	handler->sendPacket(&hdr, payload, size);
}

void Session::sendChunk(std::shared_ptr<Chunk> chunk)
{
	insend.push(chunk);
	for(; insend.size && send.pushable(); )
	{
		chunk = insend.pop(send.pushable());
		if(!chunk)
		{
			break;
		}
		if(chunk->process)
		{
			chunk->process(chunk);
		}
		seq = send.head + send.size + base;
		ack_seq = recv.head + ack_base;
		send.push(chunk);
		if(typeid(*chunk.get()) == typeid(DataChunk))
		{
			sendPacket(TCP_ACK, std::dynamic_pointer_cast<DataChunk>(chunk)->data, std::dynamic_pointer_cast<DataChunk>(chunk)->size);
		}
		if(typeid(*chunk.get()) == typeid(ControlChunk))
		{
			if((std::dynamic_pointer_cast<ControlChunk>(chunk)->flag & TCP_ACK) == 0)
			{
				ack_seq = 0;
			}
			sendPacket(std::dynamic_pointer_cast<ControlChunk>(chunk)->flag, NULL, 0);
		}
	}
}

void Session::recvChunk(std::shared_ptr<Chunk> chunk, size_t offset)
{
	recv.insert(chunk, offset);
	for(; recv.size && inrecv.pushable(); )
	{
		chunk = recv.pop(inrecv.pushable());
		if(!chunk)
		{
			break;
		}
		if(chunk->process)
		{
			chunk->process(chunk);
		}
		else
		{
			seq = send.head + send.size + base;
			ack_seq = recv.head + ack_base;
			sendPacket(TCP_ACK, NULL, 0);
		}
		if(typeid(*chunk.get()) == typeid(DataChunk))
		{
			inrecv.push(chunk);
		}
	}

	handler->onData(this);
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
	base = rand();
	handler->bindSession(this);
	sendChunk(std::make_shared<ControlChunk>(TCP_SYN,
		[this](std::shared_ptr<Chunk> chunk)
		{
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
		},
		[this](std::shared_ptr<Chunk> chunk)
		{
			handler->onReady(this, NULL);
		},
		[this](std::shared_ptr<Chunk> chunk)
		{
			state = SYN_SENT;
		}));
	return 0;
}

int Session::onRead(void *payload, size_t size)
{
	std::shared_ptr<DataChunk> dataChunk;
	std::shared_ptr<Chunk> chunk;
	if(inrecv.size)
	{
		dataChunk = std::dynamic_pointer_cast<DataChunk>(inrecv.pop(size));
		size = std::min(size, dataChunk->size);
		memcpy(payload, dataChunk->data, size);

		for(; recv.size && inrecv.pushable(); )
		{
			chunk = recv.pop(inrecv.pushable());
			if(!chunk)
			{
				break;
			}
			chunk->process(chunk);
			if(typeid(*chunk.get()) == typeid(DataChunk))
			{
				inrecv.push(chunk);
			}
		}

		return size;
	}

	switch(state)
	{
		case CLOSED:
		case LISTEN:
		case SYN_RCVD:
		case SYN_SENT:
			break;
		case CLOSE_WAIT:
		case LAST_ACK:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSING:
		case TIME_WAIT:
			return -1;
		default:
			break;
	}

	return -1;
}

int Session::onWrite(void *payload, size_t size)
{
	switch(state)
	{
		case CLOSED:
		case LISTEN:
		case SYN_RCVD:
		case SYN_SENT:
			return -1;
		case ESTABLISHED:
			break;
		case CLOSE_WAIT:
		case LAST_ACK:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSING:
		case TIME_WAIT:
			return 0;
		default:
			return -1;
	}

	size = std::min(size, insend.pushable());
	insend.push(std::make_shared<DataChunk>(payload, size));

	return size;
}

int Session::onPacket(struct hdr *hdr, void *payload, size_t size)
{
	uint8_t flag = TCP_FLAG(hdr->tcp);
	Session *session;
	std::shared_ptr<Chunk> chunk;

	send.limit = pwnd = ntohs(hdr->tcp.window);

	/*
	printf(" got packet %p (%u, %u): ", this, ntohl(hdr->tcp.seq) - ack_base, ntohl(hdr->tcp.ack_seq) - base);
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
				base = rand();
				ack_base = ntohl(hdr->tcp.seq);
				handler->bindSession(this);
				recvChunk(std::make_shared<ControlChunk>(TCP_SYN,
					Chunk::callback(),
					Chunk::callback(),
					[this](std::shared_ptr<Chunk> chunk)
					{
						sendChunk(std::make_shared<ControlChunk>(TCP_SYN | TCP_ACK, 
							[this](std::shared_ptr<Chunk> chunk)
							{
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
							},
							[this](std::shared_ptr<Chunk> chunk)
							{
								handler->unbindSession(this);
								state = CLOSED;
								delete this;
							},
							[this](std::shared_ptr<Chunk> chunk)
							{
									state = SYN_RCVD;
							}));
					}), ntohl(hdr->tcp.seq) - ack_base);
				return 0;
			}
			else if(flag == TCP_SYN && (int)waiters.size() < backlog)
			{
				seq = rand();
				ack_seq = ntohl(hdr->tcp.seq);
				session = new Session(handler, this, EndPoint(ntohl(hdr->ip.daddr), ntohs(hdr->tcp.dest)), EndPoint(ntohl(hdr->ip.saddr), ntohs(hdr->tcp.source)));
				waiters.insert(session);
				return session->onPacket(hdr, payload, size);
			}
		case SYN_RCVD:
			break;
		case SYN_SENT:
			if(flag & TCP_SYN)
			{
				ack_base = ntohl(hdr->tcp.seq);
			}
			break;
		case ESTABLISHED:
			if(flag & TCP_FIN)
			{
				recvChunk(std::make_shared<ControlChunk>(TCP_FIN,
					[](std::shared_ptr<Chunk> chunk){},
					[](std::shared_ptr<Chunk> chunk){},
					[this](std::shared_ptr<Chunk> chunk)
					{
						state = CLOSE_WAIT;
						seq = send.head + send.size + base;
						ack_seq = recv.head + ack_base;
						sendPacket(TCP_ACK, NULL, 0);
					}), ntohl(hdr->tcp.seq) - ack_base);
				flag ^= TCP_FIN;
			}
			break;
		case LAST_ACK:
			break;
		case FIN_WAIT_1:
		case FIN_WAIT_2:
			if(flag & TCP_FIN)
			{
				recvChunk(std::make_shared<ControlChunk>(TCP_FIN,
					Chunk::callback(),
					Chunk::callback(),
					[this](std::shared_ptr<Chunk> chunk)
					{
						state = TIME_WAIT;
						seq = send.head + send.size + base;
						ack_seq = recv.head + ack_base;
						sendPacket(TCP_ACK, NULL, 0);
					}), ntohl(hdr->tcp.seq) - ack_base);
				return 0;
			}
		case CLOSING:
		default:
			break;
	}

	if(flag & TCP_ACK)
	{
		for(; send.head < ntohl(hdr->tcp.ack_seq) - base; )
		{
			chunk = send.pop(ntohl(hdr->tcp.ack_seq) - base - send.head);
			if(!chunk)
			{
				break;
			}
			if(chunk->acked)
			{
				chunk->acked(chunk);
			}
		}
		for(; insend.size && send.pushable(); )
		{
			chunk = insend.pop(send.pushable());
			if(!chunk)
			{
				break;
			}
			seq = send.head + send.size + base;
			ack_seq = recv.head + ack_base;
			send.push(chunk);
			if(chunk->process)
			{
				chunk->process(chunk);
			}
			if(typeid(*chunk.get()) == typeid(DataChunk))
			{
				sendPacket(TCP_ACK, std::dynamic_pointer_cast<DataChunk>(chunk)->data, std::dynamic_pointer_cast<DataChunk>(chunk)->size);
			}
			if(typeid(*chunk.get()) == typeid(ControlChunk))
			{
				if((std::dynamic_pointer_cast<ControlChunk>(chunk)->flag & TCP_ACK) == 0)
				{
					ack_seq = 0;
				}
				sendPacket(std::dynamic_pointer_cast<ControlChunk>(chunk)->flag, NULL, 0);
			}
		}
	}

	if((flag & (TCP_SYN | TCP_FIN)))
	{
		recvChunk(std::make_shared<ControlChunk>(flag), ntohl(hdr->tcp.seq) - ack_base);
	}
	if(size)
	{
		recvChunk(std::make_shared<DataChunk>(payload, size), ntohl(hdr->tcp.seq) - ack_base);
	}

	handler->onData(this);

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
			delete this;
			return 0;
		case SYN_RCVD:
		case ESTABLISHED:
			sendChunk(std::make_shared<ControlChunk>(TCP_FIN,
				[this](std::shared_ptr<Chunk> chunk)
				{
					state = FIN_WAIT_2;
				},
				Chunk::callback(),
				[this](std::shared_ptr<Chunk> chunk)
				{
					state = FIN_WAIT_1;
				}));
			return 0;
		case CLOSE_WAIT:
			sendChunk(std::make_shared<ControlChunk>(TCP_FIN,
				[this](std::shared_ptr<Chunk> chunk)
				{
					handler->unbindSession(this);
					state = CLOSED;
				}));
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

bool Session::isReadable()
{
	return state != ESTABLISHED || inrecv.size;
}

bool Session::isWritable()
{
	return state != ESTABLISHED || insend.size < insend.limit;
}

EndPoint Session::getLocal()
{
	return local;
}

EndPoint Session::getRemote()
{
	return remote;
}
