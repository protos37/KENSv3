/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>

#include <cerrno>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <stdlib.h>

#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host)
	: SessionHandler()
	, HostModule("TCP", host)
	, NetworkModule(this->getHostModuleName(), host->getNetworkSystem())
	, SystemCallInterface(AF_INET, IPPROTO_TCP, host)
	, NetworkLog(host->getNetworkSystem())
	, TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	srand((unsigned int)time(NULL));
}

void TCPAssignment::finalize()
{
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
//		printf("socket()\n");
		syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		break;
	case CLOSE:
//		printf("close()\n");
		syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
//		printf("read()\n");
		syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, (size_t)param.param3_int);
		break;
	case WRITE:
//		printf("write()\n");
		syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, (size_t)param.param3_int);
		break;
	case CONNECT:
//		printf("connect()\n");
		syscall_connect(syscallUUID, pid, param.param1_int, (const struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case LISTEN:
//		printf("liste()\n");
		syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
//		printf("accept()\n");
		syscall_accept(syscallUUID, pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case BIND:
//		printf("bind()\n");
		syscall_bind(syscallUUID, pid, param.param1_int, (const struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case GETSOCKNAME:
		syscall_getsockname(syscallUUID, pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case GETPEERNAME:
		syscall_getpeername(syscallUUID, pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	void *payload;
	size_t size;
	struct hdr hdr;
	Session *session = NULL;

	if(fromModule.compare("IPv4") || packet->getSize() < sizeof(struct hdr))
	{
		freePacket(packet);
		return;
	}

	size = packet->getSize() - sizeof(struct hdr);
	if(size)
	{
		payload = malloc(size);
	}
	packet->readData(0, &hdr, sizeof(struct hdr));
	packet->readData(sizeof(struct hdr), payload, size);

	session = lookupSession(EndPoint(ntohl(hdr.ip.daddr), ntohs(hdr.tcp.dest)), EndPoint(ntohl(hdr.ip.saddr), ntohs(hdr.tcp.source)));
	if(session)
	{
		session->onPacket(&hdr, payload, size);
	}

	freePacket(packet);
	if(size)
	{
		free(payload);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
}

void TCPAssignment::sendPacket(struct hdr *hdr, void *payload, size_t size)
{
	Packet *packet = allocatePacket(sizeof(struct hdr) + size);
	void *dummy;
	
	dummy = malloc(sizeof(struct tcphdr) + size);
	memcpy(dummy, &hdr->tcp, sizeof(struct tcphdr));
	memcpy((void*)((uint8_t *)dummy + sizeof(struct tcphdr)), payload, size);
	hdr->tcp.check = htons(~NetworkUtil::tcp_sum(hdr->ip.saddr, hdr->ip.daddr, (uint8_t *)dummy, sizeof(struct tcphdr) + size));
	free(dummy);

	packet->writeData(0, hdr, sizeof(struct hdr));
	packet->writeData(sizeof(struct hdr), payload, size);
	HostModule::sendPacket(std::string("IPv4"), packet);
}

void TCPAssignment::onReady(Session *request, Session *response)
{
	std::multimap<Session *, std::tuple<UUID, int, int, struct sockaddr *, socklen_t> > ::iterator it;
	std::map<Session *, std::tuple<UUID, int, int> > ::iterator jt;

	it = acceptCall.find(request);
	jt = connectCall.find(request);
	if(it != acceptCall.end())
	{
		syscall_accept_return(std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second), std::get<3>(it->second), std::get<4>(it->second), response);
		acceptCall.erase(it);
	}
	else if(jt != connectCall.end())
	{
		if(response)
		{
			syscall_connect_return(std::get<0>(jt->second), std::get<1>(it->second), std::get<2>(it->second), 0);
		}
		else
		{
			syscall_connect_return(std::get<0>(jt->second), std::get<1>(it->second), std::get<2>(it->second), -1);
		}
		connectCall.erase(jt);
	}
	else
	{
		acceptSession.insert(std::make_pair(request, response));
	}
}

void TCPAssignment::onData(Session *request)
{
	std::map<Session *, std::tuple<UUID, void *, size_t> > ::iterator it;
	std::map<Session *, UUID> ::iterator jt;
	it = readCall.find(request);
	if(it != readCall.end() && request->isReadable())
	{
		returnSystemCall(std::get<0>(it->second), request->onRead(std::get<1>(it->second), std::get<2>(it->second)));
		readCall.erase(it);
	}
	it = writeCall.find(request);
	if(it != writeCall.end() && request->isWritable())
	{
		returnSystemCall(std::get<0>(it->second), request->onWrite(std::get<1>(it->second), std::get<2>(it->second)));
		writeCall.erase(it);
	}
	jt = closeCall.find(request);
	if(jt != closeCall.end() && request->isWritable())
	{
		returnSystemCall(jt->second, request->onClose());
		closeCall.erase(jt);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	int socket;

	if(domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	socket = createFileDescriptor(pid);
	sessions[std::make_pair(pid, socket)] = new Session(this);
	returnSystemCall(syscallUUID, socket);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket)
{
	Session *session = lookupSession(pid, socket);

	if(session == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(session->isWritable())
	{
		sessions.erase(std::make_pair(pid, socket));
		removeFileDescriptor(pid, socket);
		returnSystemCall(syscallUUID, session->onClose());
		return;
	}

	closeCall[session] = syscallUUID;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int socket, void *payload, size_t size)
{
	Session *session = lookupSession(pid, socket);

	if(session == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(session->isReadable())
	{
		returnSystemCall(syscallUUID, session->onRead(payload, size));
		return;
	}

	readCall[session] = std::make_tuple(syscallUUID, payload, size);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int socket, void *payload, size_t size)
{
	Session *session = lookupSession(pid, socket);

	if(session == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	
	if(session->isWritable())
	{
		returnSystemCall(syscallUUID, session->onWrite(payload, size));
		return;
	}

	writeCall[session] = std::make_tuple(syscallUUID, payload, size);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len)
{
	uint32_t addr;
	uint16_t port;
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	Session *session = lookupSession(pid, socket);
	std::set<Session *> ::iterator it;

	if(session == NULL || session->getRemote().isValid())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(!session->getLocal().isValid())
	{
		getHost()->getIPAddr((uint8_t *)&addr, 0);
		addr = ntohl(addr);
		while(true)
		{
			port = (uint16_t)(rand() % (0x10000 - 0x400) + 0x400);
			for(it = binds.begin(); it != binds.end(); it++)
			{
				if((*it)->getLocal() == EndPoint(addr, port))
				{
					break;
				}
			}
			if(it == binds.end())
			{
				break;
			}
		}
		if(session->onBind(EndPoint(addr, port)) < 0)
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	if(session->onConnect(EndPoint(htonl(address_in->sin_addr.s_addr), htons(address_in->sin_port))) < 0)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	connectCall.insert(std::make_pair(session, std::make_tuple(syscallUUID, pid, socket)));
}

void TCPAssignment::syscall_connect_return(UUID syscallUUID, int pid, int socket, int result)
{
	returnSystemCall(syscallUUID, result);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int socket, int backlog)
{
	Session *session = lookupSession(pid, socket);

	if(session == NULL || binds.find(session) == binds.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	returnSystemCall(syscallUUID, session->onListen(backlog));
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len)
{
	Session *session = lookupSession(pid, socket);
	std::multimap<Session *, Session *> ::iterator it;

	if(session == NULL || address_len < sizeof(struct sockaddr_in))
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	it = acceptSession.find(session);
	if(it == acceptSession.end())
	{
		acceptCall.insert(std::make_pair(session, std::make_tuple(syscallUUID, pid, socket, address, address_len)));
	}
	else
	{
		syscall_accept_return(syscallUUID, pid, socket, address, address_len, it->second);
		acceptSession.erase(it);
	}
}

void TCPAssignment::syscall_accept_return(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len, Session *session)
{
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	memset(address_in, 0, sizeof(struct sockaddr_in));
	address_in->sin_family = AF_INET;
	address_in->sin_addr.s_addr = htonl(session->getLocal().addr);
	address_in->sin_port = htons(session->getLocal().port);

	socket = createFileDescriptor(pid);
	sessions[std::make_pair(pid, socket)] = session;

	returnSystemCall(syscallUUID, socket);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	Session *session = lookupSession(pid, socket);
	EndPoint local(ntohl(address_in->sin_addr.s_addr), ntohs(address_in->sin_port));

	if(session == NULL || address_len < sizeof(struct sockaddr_in) || address_in->sin_family != AF_INET || binds.find(session) != binds.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	for(auto it = binds.begin(); it != binds.end(); it++)
	{
		if(local == (*it)->getLocal())
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	returnSystemCall(syscallUUID, session->onBind(local));
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	Session *session = lookupSession(pid, socket);
	std::multimap<Session *, Session *> ::iterator it;

	if(session == NULL || address_len < sizeof(struct sockaddr_in) || binds.find(session) == binds.end() || !session->getLocal().isValid())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memset(address_in, 0, sizeof(struct sockaddr_in));
	address_in->sin_family = AF_INET;
	address_in->sin_addr.s_addr = htonl(session->getLocal().addr);
	address_in->sin_port = htons(session->getLocal().port);

	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	Session *session = lookupSession(pid, socket);
	std::multimap<Session *, Session *> ::iterator it;

	if(session == NULL || address_len < sizeof(struct sockaddr_in) || binds.find(session) == binds.end() || !session->getRemote().isValid())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memset(address_in, 0, sizeof(struct sockaddr_in));
	address_in->sin_family = AF_INET;
	address_in->sin_addr.s_addr = htonl(session->getRemote().addr);
	address_in->sin_port = htons(session->getRemote().port);

	returnSystemCall(syscallUUID, 0);
}


}
