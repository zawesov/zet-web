/*
Copyright (C) Alexander Zavesov
Copyright (C) ZET-WEB
This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef __zSocket_h
#define __zSocket_h 1

#include "zMutex.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#if defined(_WIN32) || defined(_WIN64)
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <sys/socket.h>
#endif
#endif

namespace ZNSOCKET
{

 const int SELECT_READ=1;
 const int SELECT_WRITE=2;
 const int SELECT_EXCEPT=4;

 void sleep(unsigned timeout);
/*
 Sleeps timeout microseconds.
*/
 std::string host(const std::string &addr);
 size_t host(std::vector<std::string>& ret, const std::string &addr);
 size_t host(std::list<std::string>& ret, const std::string &addr);
 std::string iptoString(unsigned addr);
 unsigned strtoIp(const std::string &addr);
/*
 Get IP address corresponding by hostname, that is string addr.
*/
 int socket(const std::string& adr,unsigned short port, bool blocking=false, unsigned timeout=6000);
/*
 Creates a stream socket and connects its to the specified port number at the specified address.
 If error function returns -1;
*/
 int async_socket(const std::string& adr,unsigned short port);
/*
 Creates a non_blocking stream socket and try to connect its to the specified port number at the specified address.
 Check the result of connect by the function async_select(int s);
 If error function returns -1;
*/
 int async_select(int s, unsigned timeout=0);
/*
 Tests the result of connect.
 Return: -1 - connection fault, 0 - in_progress, 1 - success.
*/
 int server(const std::string& adr,unsigned short port, int backlog=1024, bool blocking=false);
/*
 Creates a server socket with the specified port, listen backlog, and local IP address to bind to.
 If error function returns -1;
*/
 int server(unsigned short port, int backlog=1024, bool blocking=false);
/*
 Creates a server socket and binds it to the specified local port number, with the specified backlog.
*/
 bool alive(int s);
/*
 Tests if this socket is alive.
*/
 void close(int s);// close
/*
 Close socket.
*/
 int accept(int s, unsigned tm, bool blocking);
 int accept(int s, bool blocking=false);
/*
 Listens to s server socket with timeout tm or less to return socket is defined blocking parameter.
*/
 ssize_t read(int s, std::string &ret);// read
 ssize_t read(int s, std::string &ret, char* r, size_t len);// read
 ssize_t read(int s, std::string &ret, char r[65536]);// read
 ssize_t read(int s, char* ret, size_t len);// read
/*
 Reads with timeout=0  from the socket and return the number of read bytes.
 If socket is corrupted the function returns -1. 
*/
 ssize_t write(int s, const std::string &v, size_t pos=0);// write
 ssize_t pass(int s, const char* v, size_t len);// pass
/*
 Writes with timeout=0 string v starting pos to the socket. 
 If the socket is corrupted the function returns -1. 
 Returns the number of written bytes.
*/
 ssize_t send(int s,const std::string &v, size_t pos=0);// send
/*
 Writes string v starting pos to the socket.
 Returns the number of written bytes when string v have been sent wholly. 
 If the socket is corrupted the function returns -1. 
*/
 std::string getAddress(int s);// getAddress
/*
 Returns the local address of the socket.
*/
 unsigned getPort(int s);// getPort
/*
 Returns the port on which this socket is listening.
*/
 std::string getPeerAddress(int s);// getPeerAddress
/*
 Returns the peer address of the socket.
*/
 unsigned getPeerPort(int s);// getPeerPort
/*
 Returns the peer port of the socket.
*/
 unsigned getReceiveBufferSize(int s);// getReceiveBufferSize
/*
 Gets the value of the SO_RCVBUF option for this Socket,
 that is the buffer size used by the platform for input on this Socket.
*/
 unsigned getSendBufferSize(int s);// getSendBufferSize
/*
 Gets value of the SO_SNDBUF option for this Socket,
 that is the buffer size used by the platform for output on this Socket.
*/
 unsigned setReceiveBufferSize(int s, unsigned size);// setReceiveBufferSize
/*
 Sets the SO_RCVBUF option to the specified value for this Socket.
*/
 unsigned setSendBufferSize(int s, unsigned size);// setSendBufferSize
/*
 Sets the SO_SNDBUF option to the specified value for this Socket.
*/
 void block(int s, bool blocking);// block
/*
 Sets the blocking flag for the socket s.
*/
 void select(const std::vector<int>& src, std::vector<int>& rd, std::vector<int>& wr, std::vector<int>& ex, unsigned timeout=0, int rwe=(ZNSOCKET::SELECT_READ | ZNSOCKET::SELECT_EXCEPT));
/*
 Tests read,write and except for sockets.
*/

 SSL_CTX* server_ctx(const std::string& server_cert_file,const std::string& server_key_file, const SSL_METHOD* method= ::SSLv23_server_method());
 SSL_CTX* client_ctx(const SSL_METHOD* method= ::SSLv23_client_method());
/*
 Sets certificate and private key to the ssl server side initializing SSL_CTX* structure.
 Creates SSL_CTX* structure to the ssl client side initializing.
*/

 int handle(SSL* s);
/*
 Returns socket handle which has been coupled with SSL structure.
*/
 SSL* socket(int h,SSL_CTX* client_ctx);
 SSL* server(int h,SSL_CTX* server_ctx);
/*
 Return pointer to a SSL structure which is coupled with h socket handle.
 Socket function creates SSL structure for client side.
 Server function creates SSL structure for server side.
*/
 ssize_t connect(SSL* s, unsigned tm=0);
 ssize_t accept(SSL* s, unsigned tm=0);
/*
 Start ssl handshake on client or server side with timeout tm.
 If function returns -1 the connection failds. If function returns 0 it needs to continue doing attempts later.
 If function returns 1 then the TLS/SSL handshake was successfully completed, a TLS/SSL connection has been established.
*/
 ssize_t read(SSL* s, std::string &ret);// read
 ssize_t read(SSL* s, std::string &ret,char* r, size_t len);// read
 ssize_t read(SSL* s, std::string &ret,char r[65536]);// read
 ssize_t read(SSL* s, char* ret, size_t len);// read
/*
 Read with timeout=0  from the socket and return the number of read bytes.
 If socket is corrupted the function returns -1. 
*/
 ssize_t write(SSL* s, const std::string &v,size_t pos=0);// write
 ssize_t pass(SSL* s, const char* v, size_t len);// pass
/*
 Writes with timeout=0 string v starting pos to the socket. 
 If the socket is corrupted the function returns -1. 
 Returns the number of written bytes.
*/
 ssize_t send(SSL* s,const std::string &v,size_t pos=0);// send
/*
 Writes string v starting pos to the socket.
 Returns the number of written bytes when string v have been sent wholly. 
 If the socket is corrupted the function returns -1. 
*/
 void close(SSL* s);// close
/*
 Close SSL* s structure.
*/
 void free(SSL* s);
 void free(SSL_CTX* s);
/*
 Destroys SSL* or SSL_CTX* structure.
*/
};// namespace ZNSOCKET


namespace ZNUDP
{
 std::string net_to_host(unsigned n);
 unsigned host_to_net(const std::string& src);

 int socket(const std::string& adr,unsigned short port, bool blocking=false);
/*
 Creates a udp socket and connects it to the specified port at the specified address in blocking mode.
*/
 int server(const std::string& adr,unsigned short port, bool blocking=false);
/*
 Creates a server socket with the specified port, local IP address and blocking mode to bind to.
*/
 bool alive(int s);
/*
 Tests if this socket is alive.
*/
 void close(int s);// close
/*
 Close socket.
*/
 ssize_t read(int s, unsigned& adr, unsigned short& port, std::string &value);// read
 ssize_t read(int s, unsigned& adr, unsigned short& port, std::string &ret, char rv[65536]);
 ssize_t read(int s, unsigned& adr, unsigned short& port, char* ret, size_t len);
/*
 Reads with timeout=0  from the socket. If socket is corrupted the function returns -1. 
*/
 ssize_t write(int s, unsigned adr,unsigned short port, const std::string &v, size_t pos=0);// write
 ssize_t pass(int s, unsigned adr,unsigned short port, const char* v, size_t len);
/*
 Writes with timeout=0 string v starting pos to the socket. 
 If the socket is corrupted the function returns -1. 
*/
 ssize_t write(int s, const std::string &v, size_t pos=0);// write
 ssize_t pass(int s, const char* v, size_t len);
/*
 Writes with timeout=0 string v starting pos to the socket. 
 If the socket is corrupted the function returns -1. 
*/
 std::string getAddress(int s);// getAddress
/*
 Returns the local address of the socket.
*/
 unsigned getPort(int s);// getPort
/*
 Returns the port on which this socket is listening.
*/
 std::string getPeerAddress(int s);// getPeerAddress
/*
 Returns the peer address of the socket.
*/
 unsigned getPeerPort(int s);// getPeerPort
/*
 Returns the peer port of the socket.
*/
 void block(int s, bool blocking);// block
/*
 Sets the blocking flag for the socket s.
*/

};// namespace ZNUDP


#endif // __zSocket_h
