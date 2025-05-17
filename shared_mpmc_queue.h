//
// Lockfree, atomic, multi producer, multi consumer queue - between processes
//
// MIT License
//
// Copyright (c) 2019 Erez Strauss, erez@erezstrauss.com
//  http://github.com/erez-strauss/lockfree_mpmc_queue/
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#pragma once

#include <mpmc_queue.h>
//
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#else
#include <Windows.h>
#include <io.h>
#define open _open
constexpr auto O_CLOEXEC = 0;
#endif

namespace es::lockfree {

constexpr const uint32_t ShareMPMCQueue{0x0BadBadB};

struct shared_file_header
{
    uint32_t             signature{ShareMPMCQueue};
    uint32_t             hdr_size{0};
    uint64_t             q_start;
    uint64_t             q_size_elements;
    uint64_t             q_size_bytes;
    std::atomic<int32_t> producer_count;
    std::atomic<int32_t> consumer_count;
    uint32_t             producers[16];
    uint32_t             consumers[16];
};

template<typename Q>
class shared_mpmc_queue
{
    class producer
    {
    public:
        producer(shared_mpmc_queue& sq) : _shared_q(sq) { _shared_q.producers_inc(); }

        bool push(typename Q::value_type d) { return _shared_q._qp->push(d); }
        bool push(typename Q::value_type d, typename Q::index_type& i) { return _shared_q._qp->push(d, i); }
        bool push_keep_n(typename Q::value_type d) { return _shared_q._qp->push_keep_n(d); }
        bool push_keep_n(typename Q::value_type d, typename Q::index_type& i)
        {
            return _shared_q._qp->push_keep_n(d, i);
        }

        ~producer() { _shared_q.producers_dec(); }

    private:
        shared_mpmc_queue& _shared_q;
    };
    class consumer
    {
    public:
        consumer(shared_mpmc_queue& sq) : _shared_q(sq) { _shared_q.consumers_inc(); }

        bool pop(typename Q::value_type& d) { return _shared_q._qp->pop(d); }
        bool pop(typename Q::value_type& d, typename Q::index_type& i) { return _shared_q._qp->pop(d, i); }

        ~consumer() { _shared_q.consumers_dec(); }

    private:
        shared_mpmc_queue& _shared_q;
    };

public:
    shared_mpmc_queue(const char* fname)
    {
#ifndef _WIN32
        int fd = open(fname, O_CREAT | O_RDWR | O_CLOEXEC, 0666);
        if (fd < 0)
        {
            std::cerr << "Error: failed to open/create '" << fname << "': " << strerror(errno) << '\n';
            exit(1);
        }
        shared_file_header header;

        int r = read(fd, &header, sizeof(header));
        if (sizeof(header) != r)
        {
            // create new queu
            header.signature       = ShareMPMCQueue;
            header.hdr_size        = sizeof(shared_file_header);
            header.q_start         = 4096;
            header.q_size_elements = Q::size_n();
            header.q_size_bytes    = sizeof(Q);
            header.producer_count  = 0;
            header.consumer_count  = 0;
            auto r0                = ftruncate(fd, 4096 + sizeof(Q));
            auto r1                = write(fd, &header, sizeof(header));
            if (r0 || r1 != sizeof(header))
            {
                std::cout << "Failed to access shared q: '" << fname << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            _base   = mmap(nullptr, 4096 + sizeof(Q), PROT_WRITE, MAP_SHARED, fd, 0);
            _header = (shared_file_header*)_base;
            _qp     = new ((void*)((uint64_t)_base + 4096)) Q(Q::size_n());
        }
        else if ((ShareMPMCQueue == header.signature) && (sizeof(shared_file_header) == header.hdr_size) &&
                 (4096 == header.q_start) && Q::size_n() == header.q_size_elements && sizeof(Q) == header.q_size_bytes)
        {
            _base   = mmap(nullptr, 4096 + sizeof(Q), PROT_WRITE, MAP_SHARED, fd, 0);
            _header = (shared_file_header*)_base;
            _qp     = reinterpret_cast<Q*>((void*)((uint64_t)_base + 4096));
            std::cout << "Attached successfully to shared q: '" << fname << "'\nq: " << *_qp << '\n';
        }
        else
        {
            std::cerr << "Error: shared q file exists but not compatible\n";
            exit(1);
        }
#else
        HANDLE fh =
            CreateFile(fname, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fh == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Error: failed to open/create '" << fname << "': " << strerror(errno) << '\n';
            exit(1);
        }
        shared_file_header header;

        DWORD numBytesRead{0};
        BOOL ret = ReadFile(fh, &header, sizeof(header), &numBytesRead, NULL);
        if (ret == FALSE || numBytesRead != sizeof(header))
        {
            // create new queu
            header.signature       = ShareMPMCQueue;
            header.hdr_size        = sizeof(shared_file_header);
            header.q_start         = 4096;
            header.q_size_elements = Q::size_n();
            header.q_size_bytes    = sizeof(Q);
            header.producer_count  = 0;
            header.consumer_count  = 0;
            DWORD r0 = SetFilePointer(fh, 4096 + sizeof(Q), 0, FILE_BEGIN);
            if (r0 == FALSE)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(SetFilePointer: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            r0 = SetEndOfFile(fh);
            if (r0 == FALSE)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(SetEndOfFile: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            r0 = SetFilePointer(fh, 0, 0, FILE_BEGIN);
            if (r0 == FALSE)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(SetFilePointer (begining): " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            DWORD numBytesWritten{0};
            r0 = WriteFile(fh, &header, sizeof(header), &numBytesWritten, NULL);
            if (r0 == FALSE || numBytesWritten != sizeof(header))
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(WriteFile: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            HANDLE memMapFileH = CreateFileMapping(fh, NULL, PAGE_READWRITE, 0, 4096 + sizeof(Q), NULL);
            if (memMapFileH == NULL)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(CreateFileMapping: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            _base = MapViewOfFile(memMapFileH, FILE_MAP_ALL_ACCESS, 0, 0, 4096 + sizeof(Q));
            if (_base == NULL)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(MapViewOfFile: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            _header = (shared_file_header*)_base;
            _qp     = new ((void*)((uint64_t)_base + 4096)) Q(Q::size_n());
        }
        else if ((ShareMPMCQueue == header.signature) && (sizeof(shared_file_header) == header.hdr_size) &&
                 (4096 == header.q_start) && Q::size_n() == header.q_size_elements && sizeof(Q) == header.q_size_bytes)
        {
            HANDLE memMapFileH = CreateFileMapping(fh, NULL, PAGE_READWRITE, 0, 4096 + sizeof(Q), NULL);
            if (memMapFileH == NULL)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(CreateFileMapping: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            _base = MapViewOfFile(memMapFileH, FILE_MAP_ALL_ACCESS, 0, 0, 4096 + sizeof(Q));
            if (_base == NULL)
            {
                DWORD gle = GetLastError();
                std::cout << "Failed to access shared q: '" << fname << "(MapViewOfFile: " << gle << ")" << '\n';
                throw std::runtime_error("Failed to access shared q");
            }
            _header = (shared_file_header*)_base;
            _qp     = reinterpret_cast<Q*>((void*)((uint64_t)_base + 4096));
            std::cout << "Attached successfully to shared q: '" << fname << "'\nq: " << *_qp << '\n';
        }
        else
        {
            std::cerr << "Error: shared q file exists but not compatible\n";
            exit(1);
        }
#endif
    }

    auto get_producer() { return producer(*this); }

    auto get_consumer() { return consumer(*this); }

    size_t get_producers_count() { return _header->producer_count; }

    size_t get_consumers_count() { return _header->consumer_count; }

    void producers_inc() { _header->producer_count++; }
    void producers_dec() { _header->producer_count--; }
    void consumers_inc() { _header->consumer_count++; }
    void consumers_dec() { _header->consumer_count--; }

    Q* _qp{nullptr};

private:
    int                 _fd{-1};
    shared_file_header* _header{nullptr};
    void*               _base{nullptr};
};
}  // namespace es::lockfree
