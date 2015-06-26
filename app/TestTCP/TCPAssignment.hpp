/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <map>

#include "SessionHandler.hpp"

namespace E
{

class TCPAssignment
	: public SessionHandler, public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
protected:
	std::multimap<Session *, std::tuple<UUID, int, int, struct sockaddr *, socklen_t> > acceptCall;
	std::multimap<Session *, Session *> acceptSession;
	std::map<Session *, std::tuple<UUID, int, int> > connectCall;

	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual void timerCallback(void* payload) final;
	virtual void sendPacket(struct hdr *hdr, void *payload, size_t size);
	virtual void onReady(Session *request, Session *response);
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int socket);
	virtual void syscall_connect(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len);
	virtual void syscall_connect_return(UUID syscallUUID, int pid, int socket, int result);
	virtual void syscall_listen(UUID syscallUUID, int pid, int socket, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len);
	virtual void syscall_accept_return(UUID syscalUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len, Session *session);
	virtual void syscall_bind(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
