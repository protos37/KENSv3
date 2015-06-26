#include "Chunk.hpp"

#include <string.h>

Chunk::Chunk(size_t _size, callback _acked, callback _timeout, callback _process)
	: size(_size), acked(_acked), timeout(_timeout), process(_process)
{
}

Chunk::~Chunk()
{
}

std::shared_ptr<Chunk> Chunk::split(size_t _size)
{
	return NULL;
}

void Chunk::sendPacket(std::function<void(uint8_t, void *, size_t)> func)
{
}

DataChunk::DataChunk(void *_data, size_t _size, callback _acked, callback _timeout, callback _process)
	: Chunk(_size, _acked, _timeout, _process), data(NULL)
{
	data = malloc(size);
	memcpy(data, _data, size);
}

DataChunk::~DataChunk()
{
	free(data);
}

std::shared_ptr<Chunk> DataChunk::split(size_t _size)
{
	size_t temp;

	if(_size < size)
	{
		temp = size - _size;
		size = _size;
		return std::make_shared<DataChunk>((uint8_t *)data + _size, temp, acked, timeout);
	}

	return NULL;
}

void DataChunk::sendPacket(std::function<void(uint8_t, void *, size_t)> func)
{
	func(0, data, size);
}

ControlChunk::ControlChunk(uint8_t _flag, callback _acked, callback _timeout, callback _process)
	: Chunk(1, _acked, _timeout, _process), flag(_flag)
{
}

void ControlChunk::sendPacket(std::function<void(uint8_t, void *, size_t)> func)
{
	func(flag, NULL, 0);
}

Buffer::Buffer()
	: head(0), size(0), limit(0)
{
}

size_t Buffer::pushable()
{
	return size < limit ? limit - size : 0;
}

void Buffer::push(std::shared_ptr<Chunk> chunk)
{
}

void Buffer::insert(std::shared_ptr<Chunk> chunk, size_t at)
{
}

std::shared_ptr<Chunk> Buffer::pop(size_t _size)
{
	return NULL;
}

QueuedBuffer::QueuedBuffer()
	: Buffer()
{
}

void QueuedBuffer::push(std::shared_ptr<Chunk> chunk)
{
	deq.push_back(chunk);
	size += chunk->size;
}

std::shared_ptr<Chunk> QueuedBuffer::pop(size_t _size)
{
	std::shared_ptr<Chunk> chunk, temp;

	if(deq.empty())
	{
		return NULL;
	}

	chunk = deq.front();
	deq.pop_front();
	if(_size < chunk->size)
	{
		temp = chunk->split(_size);
		if(temp)
		{
			deq.push_front(temp);
		}
	}
	else
	{
		_size = chunk->size;
	}
	size -= _size;
	head += _size;

	return chunk;
}

IndexedBuffer::IndexedBuffer()
	: Buffer()
{
}

void IndexedBuffer::insert(std::shared_ptr<Chunk> chunk, size_t at)
{
	tab[at] = chunk;
	size += chunk->size;
}

std::shared_ptr<Chunk> IndexedBuffer::pop(size_t _size)
{
	std::shared_ptr<Chunk> chunk, temp;

	if(tab.empty() || head != tab.begin()->first)
	{
		return NULL;
	}

	chunk = tab.begin()->second;
	tab.erase(tab.begin());
	if(_size < chunk->size)
	{
		temp = chunk->split(_size);
		if(temp)
		{
			tab[head + _size] = temp;
		}
	}
	else
	{
		_size = chunk->size;
	}
	size -= _size;
	head += _size;

	return chunk;
}
