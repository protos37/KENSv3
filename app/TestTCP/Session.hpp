#ifndef _SESSION_HPP_
#define _SESSION_HPP_

#include <stdint.h>

#include <set>

class EndPoint;
class Session;

#include "common.hpp"
#include "Chunk.hpp"
#include "SessionHandler.hpp"

class EndPoint
{
protected:
	bool valid;

public:
	uint32_t addr;
	uint16_t port;

	EndPoint();
	EndPoint(const EndPoint &endpoint);
	EndPoint(uint32_t _addr, uint16_t _port);
	bool operator == (const EndPoint other) const;
	bool isValid() const;
};

class Session
{
protected:
	enum State {
		CLOSED,
		LISTEN,
		SYN_RCVD,
		SYN_SENT,
		ESTABLISHED,
		CLOSE_WAIT,
		LAST_ACK,
		FIN_WAIT_1,
		FIN_WAIT_2,
		TIME_WAIT,
		CLOSING
	};

	State state;
	int backlog;
	uint32_t base, ack_base, seq, ack_seq, nwnd, cwnd, pwnd;
	EndPoint local, remote;
	SessionHandler *handler;
	Session *parent;
	std::set<Session *> waiters;
	QueuedBuffer send, insend, inrecv;
	IndexedBuffer recv;

	void recvChunk(std::shared_ptr<Chunk> chunk, size_t offset);
	void sendChunk(std::shared_ptr<Chunk> chunk);

public:
	Session(SessionHandler *_handler);
	Session(SessionHandler *_handler, Session *_parent, EndPoint _local, EndPoint _remote);
	int onBind(EndPoint _local);
	int onListen(int _backlog);
	int onConnect(EndPoint _remote);
	int onPacket(struct hdr *hdr, void *payload, size_t size);
	int onRead(void *payload, size_t size);
	int onWrite(void *payload, size_t size);
	int onClose();
	int onReady(Session *session);
	void sendPacket(uint8_t flag, void *payload, size_t size);
	bool isReadable();
	bool isWritable();
	EndPoint getLocal();
	EndPoint getRemote();
};

#endif
