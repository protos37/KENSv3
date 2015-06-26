#ifndef _CHUNK_HPP_
#define _CHUNK_HPP_

#include <map>
#include <deque>
#include <memory>
#include <functional>

class Chunk
{
public:
	typedef std::function<void(std::shared_ptr<Chunk>)> callback;
	size_t size;
	callback acked, timeout, process;

	Chunk(size_t _size, callback _acked = callback(), callback _timeout = callback(), callback _process = callback());
	virtual ~Chunk();
	virtual std::shared_ptr<Chunk> split(size_t _size);
	virtual void sendPacket(std::function<void(uint8_t, void *, size_t)> func);
};

class DataChunk:
	public Chunk
{
public:
	void *data;

	DataChunk(void *_data, size_t _size, callback _acked = callback(), callback _timeout = callback(), callback _process = callback());
	virtual ~DataChunk();
	virtual std::shared_ptr<Chunk> split(size_t _size);
	virtual void sendPacket(std::function<void(uint8_t, void *, size_t)> func);
};

class ControlChunk:
	public Chunk
{
public:
	uint8_t flag;

	ControlChunk(uint8_t _flag, callback _acked = callback(), callback _timeout = callback(), callback _process = callback());
	virtual void sendPacket(std::function<void(uint8_t, void *, size_t)> func);
};

class Buffer
{
public:
	size_t head, size, limit;

	Buffer();
	virtual size_t pushable();
	virtual void push(std::shared_ptr<Chunk> chunk);
	virtual void insert(std::shared_ptr<Chunk> chunk, size_t at);
	virtual std::shared_ptr<Chunk> pop(size_t _size);
};

class QueuedBuffer:
	public Buffer
{
protected:
	std::deque<std::shared_ptr<Chunk> > deq;

public:
	QueuedBuffer();
	virtual void push(std::shared_ptr<Chunk> chunk);
	virtual std::shared_ptr<Chunk> pop(size_t _size);
};

class IndexedBuffer:
	public Buffer
{
protected:
	std::map<size_t, std::shared_ptr<Chunk> > tab;

public:
	IndexedBuffer();
	virtual void insert(std::shared_ptr<Chunk> chunk, size_t at);
	virtual std::shared_ptr<Chunk> pop(size_t _size);
};

#endif
