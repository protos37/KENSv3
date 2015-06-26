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
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>


#include <tuple>
#include <map>
#include <set>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::set<std::tuple<int, int> > sockets;
	std::map<std::tuple<int, int>, std::tuple<uint32_t, uint16_t> > binds;
	std::map<std::tuple<uint32_t, uint16_t>, std::tuple<int, int> > ports;

private:
	virtual void timerCallback(void* payload) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
	virtual void syscall_close(UUID syscallUUID, int pid, int socket);
	virtual void syscall_bind(UUID syscallUUID, int pid, int socket, const struct sockaddr *address, socklen_t address_len);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int socket, struct sockaddr *address, socklen_t address_len);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
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
