#include "SessionHandler.hpp"

SessionHandler::SessionHandler()
{
}

void SessionHandler::bindSession(Session *session)
{
	binds.insert(session);
}

void SessionHandler::unbindSession(Session *session)
{
	binds.erase(session);
}

void SessionHandler::sendPacket(struct hdr *hdr, void *payload, size_t size)
{
}

void SessionHandler::onReady(Session *request, Session *response)
{
}

Session *SessionHandler::lookupSession(int pid, int socket)
{
	std::map<std::pair<int, int>, Session *> ::iterator it;

	it = sessions.find(std::make_pair(pid, socket));
	if(it == sessions.end())
	{
		return NULL;
	}

	return it->second;
}

Session *SessionHandler::lookupSession(EndPoint local, EndPoint remote)
{
	Session *session = NULL;

	for(auto it = binds.begin(); it != binds.end(); it++)
	{
		if((*it)->getLocal() == local && (*it)->getRemote() == remote && (session == NULL || (*it)->getRemote().isValid()))
		{
			session = *it;
		}
	}
	return session;
}
