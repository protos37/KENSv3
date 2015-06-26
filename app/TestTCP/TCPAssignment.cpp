/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <string.h>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		break;
	case CLOSE:
		syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		syscall_bind(syscallUUID, pid, param.param1_int, (const struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case GETSOCKNAME:
		syscall_getsockname(syscallUUID, pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t)param.param3_int);
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol)
{
	int fd;

	if(domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	fd = createFileDescriptor(pid);
	sockets.insert(std::make_tuple(pid, fd));
	returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket)
{
	std::tuple<int, int> owner(pid, socket);
	auto it = sockets.find(owner);
	auto jt = binds.find(owner);

	if(it == sockets.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(jt != binds.end())
	{
		ports.erase(jt->second);
		binds.erase(jt);
	}
	removeFileDescriptor(pid, socket);
	sockets.erase(it);
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len)
{
	const struct sockaddr_in *address_in = (const struct sockaddr_in *)address;
	uint32_t addr = ntohl(address_in->sin_addr.s_addr);
	uint16_t port = ntohs(address_in->sin_port);
	std::tuple<int, int> owner(pid, socket);
	std::tuple<uint32_t, uint16_t> endpt(addr, port);

	if(sockets.find(owner) == sockets.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(address_len < sizeof(struct sockaddr_in) || address_in->sin_family != AF_INET || binds.find(owner) != binds.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	for(auto it = ports.begin(); it != ports.end(); it++)
	{
		if(std::get<1>(it->first) == port && (std::get<0>(it->first) == INADDR_ANY || addr == INADDR_ANY || std::get<0>(it->first) == addr))
		{
			returnSystemCall(syscallUUID, -1);
			return;
		}
	}

	binds[owner] = endpt;
	ports[endpt] = owner;
	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len)
{
	struct sockaddr_in *address_in = (struct sockaddr_in *)address;
	std::tuple<int, int> owner(pid, socket);
	auto it = binds.find(owner);

	if(sockets.find(owner) == sockets.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if(address_len < sizeof(struct sockaddr_in) || it == binds.end())
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	memset(address_in, 0, sizeof(struct sockaddr_in));
	address_in->sin_family = AF_INET;
	address_in->sin_addr.s_addr = htonl(std::get<0>(it->second));
	address_in->sin_port = htons(std::get<1>(it->second));
	returnSystemCall(syscallUUID, 0);
}


}
