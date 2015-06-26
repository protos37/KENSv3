#ifndef _SESSIONHANDLER_HPP_
#define _SESSIONHANDLER_HPP_

#include <map>
#include <set>

class SessionHandler;

#include "common.hpp"
#include "Session.hpp"

class SessionHandler
{
protected:
	std::map<std::pair<int, int>, Session *> sessions;
	std::set<Session *> binds;

	Session *lookupSession(int pid, int socket);
	Session *lookupSession(EndPoint local, EndPoint remote);

public:
	SessionHandler();
	virtual void bindSession(Session *session);
	virtual void unbindSession(Session *session);
	virtual void sendPacket(struct hdr *hdr, void *payload, size_t size);
	virtual void onReady(Session *request, Session *response);
	virtual void onData(Session *request);
};

#endif
