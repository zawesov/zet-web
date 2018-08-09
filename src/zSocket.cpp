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

#include <stdio.h>
#include <iostream>
#include <errno.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#include <winsock.h>
#include <windows.h>
#include <stdexcept>
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>   
#include <signal.h>
#endif
#endif // __GNUG__

#include <algorithm>
#include <functional>
#include "zSocket.h"
#include "zThread.h"


class __z_localInit_sock
{

 public:
  __z_localInit_sock();
  ~__z_localInit_sock();
#if defined(_WIN32) || defined(_WIN64)
 int sock;
#endif

};// __z_localInit_sock

__z_localInit_sock::__z_localInit_sock()
{

#if defined(_WIN32) || defined(_WIN64)
 WORD wVersionRequested = MAKEWORD(2, 0);
 
 WSADATA wsaData;
 int err= WSAStartup(wVersionRequested, &wsaData);
 if(err != 0)
 {
//  ZNERROR::Message e("can't init WSA");
  std::runtime_error e(std::string("Can't init WSA"));
  throw e;
 }
 sock=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
    ERR_clear_error();
#else
//    OPENSSL_config(NULL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

// ctxc=::SSL_CTX_new(::SSLv23_client_method());
// if(ctxc != NULL) ::SSL_CTX_set_options(ctxc, SSL_OP_ALL);
// if(::SSL_CTX_use_certificate_file(ctxc,CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)
// { ::SSL_CTX_free(ctxc); ctxc=NULL; }
// else if(::SSL_CTX_use_PrivateKey_file(ctxc,CLIENT_KEY,SSL_FILETYPE_PEM) <= 0)
// { ::SSL_CTX_free(ctxc); ctxc=NULL; }
// else if(::SSL_CTX_load_verify_locations(ctxc,CA_CERT,NULL) <= 0) 
// { ::SSL_CTX_free(ctxc); ctxc=NULL; }
// ctxs=::SSL_CTX_new(::SSLv23_server_method());
// if(ctxs != NULL) ::SSL_CTX_set_options(ctxs, SSL_OP_ALL);
// ::SSL_CTX_set_options(ctxs, SSL_OP_ALL);
// if(::SSL_CTX_use_certificate_file(ctxs,SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
// { ::SSL_CTX_free(ctxs); ctxs=NULL; return; }
// if(::SSL_CTX_use_PrivateKey_file(ctxs,SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
// { ::SSL_CTX_free(ctxs); ctxs=NULL; return; }
// if(! ::SSL_CTX_check_private_key(ctxs)) { ::SSL_CTX_free(ctxs); ctxs=NULL; return; }
// if(::SSL_CTX_load_verify_locations(ctxs,CA_CERT,NULL) <= 0)
// { ::SSL_CTX_free(ctxs); ctxs=NULL; return; }
};// __localInit::__localInit

__z_localInit_sock::~__z_localInit_sock() 
{
#if OPENSSL_VERSION_NUMBER < 0x10100003L
 EVP_cleanup();
#endif
#if defined(_WIN32) || defined(_WIN64)
 ::closesocket(sock);
 WSACleanup(); 
#endif
 return;
};// __z_localInit_sock::~__z_localInit_sock

static __z_localInit_sock z_init_sock;

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 typedef int elmlen;
#else
#if defined(__GNUG__) || defined(__linux__) 
// typedef unsigned elmlen;
 typedef socklen_t elmlen;
#endif // _WIN32
#endif // __GNUG__

void ZNSOCKET::sleep(unsigned timeout)
{
 struct timeval tv;
 tv.tv_sec = timeout/1000000;
 tv.tv_usec = timeout%1000000;
#if defined(_WIN32) || defined(_WIN64)
 fd_set dummy;
 FD_ZERO(&dummy);
 FD_SET(z_init_sock.sock, &dummy);
 ::select(0, (fd_set*) NULL, (fd_set*) NULL, &dummy, &tv);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 ::select(0, (fd_set*) NULL, (fd_set*) NULL, (fd_set*) NULL, &tv);
#endif // _WIN32
#endif // __GNUG__
};

std::string ZNSOCKET::host(const std::string &addr)
{
 std::string adr = ZNSTR::trim(addr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if (entry == NULL) return ""; 
 return inet_ntoa(*((in_addr *)entry->h_addr));
};

size_t ZNSOCKET::host(std::vector<std::string>& ret, const std::string &addr)
{
 std::string adr = ZNSTR::trim(addr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if (entry == NULL) return 0;
 size_t i=0;
 for(; entry->h_addr_list[i] != NULL; i++) { ret.push_back(inet_ntoa(*((in_addr *)entry->h_addr_list[i]))); }
 return i;
};

size_t ZNSOCKET::host(std::list<std::string>& ret, const std::string &addr)
{
 std::string adr = ZNSTR::trim(addr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if (entry == NULL) return 0;
 size_t i=0;
 for(; entry->h_addr_list[i] != NULL; i++) { ret.push_back(inet_ntoa(*((in_addr *)entry->h_addr_list[i]))); }
 return i;
};

std::string ZNSOCKET::iptoString(unsigned addr)
{
 return ZNUDP::net_to_host(addr);
/*
 unsigned char* v=(unsigned char*) &addr;
 std::string ret(ZNSTR::toString(v[3]));
 ret+='.';
 ret+=ZNSTR::toString(v[2]);
 ret+='.';
 ret+=ZNSTR::toString(v[1]);
 ret+='.';
 ret+=ZNSTR::toString(v[0]);
 return ret;
*/
};

unsigned ZNSOCKET::strtoIp(const std::string &addr)
{
 return ZNUDP::host_to_net(addr);
/*
 std::string adr=ZNSOCKET::host(addr);
 if(adr == "") return 0;
 size_t k=adr.find('.');
 if(k == std::string::npos) return 0;
 const char* p=adr.c_str(); 
// unsigned ret=ZNSTR::toUnsignedChar(adr.substr(0,k));
 unsigned ret=ZNSTR::asUnsignedChar(p, k);
 ret <<= 8;
 size_t l=(k+1);
 k=adr.find('.',l);
 if(k == std::string::npos) return 0;
 ret+=ZNSTR::asUnsignedChar(p+l, k-l);
 ret <<= 8;
 l=(k+1); 
 k=adr.find('.',l);
 if(k == std::string::npos) return 0;
 ret+=ZNSTR::asUnsignedChar(p+l, k-l);
 ret <<= 8;
 ++k;
 ret+=ZNSTR::asUnsignedChar(p+k, adr.size()-k);
 return ret;
*/
};

int ZNSOCKET::socket(const std::string& _adr, unsigned short port, bool blocking, unsigned timeout)
{
 int s=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(s < 0) return -1;
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry=NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) { ZNSOCKET::close(s); return -1; }
// adr = inet_ntoa(*((in_addr *)entry->h_addr));
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
// myname.sin_addr.s_addr = inet_addr(adr.c_str());
 myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
 myname.sin_port = htons(port);
 ZNSOCKET::block(s,false);
 if(::connect(s,(struct sockaddr *) &myname, sizeof(myname)) < 0) 
 {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() != WSAEWOULDBLOCK) { ZNSOCKET::close(s); return -1; }
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno != EINPROGRESS) { ZNSOCKET::close(s); return -1; }
#endif
#endif
  fd_set tSet;
  FD_ZERO(&tSet);
  FD_SET(((unsigned)s), &tSet);
  fd_set tExc;
  FD_ZERO(&tExc);
  FD_SET(((unsigned)s), &tExc);
  struct timeval tz; tz.tv_sec=timeout/1000; tz.tv_usec=timeout%1000*1000;
  if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) { ZNSOCKET::close(s); return -1; }
  if(FD_ISSET(s,&tExc)) { ZNSOCKET::close(s); return -1; }
  if(!(FD_ISSET(s,&tSet))) { ZNSOCKET::close(s); return -1; }
#if defined(_WIN32) || defined(_WIN64)
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  int optval;
  elmlen optlen = sizeof(optval);
  if(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &optval, &optlen) < 0) { ZNSOCKET::close(s); return -1; }
  if(optval) { ZNSOCKET::close(s); return -1; }
#endif
#endif
 }
 ZNSOCKET::block(s,blocking);
 return s;
};

int ZNSOCKET::async_socket(const std::string& _adr,unsigned short port)
{
 int s=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(s < 0) return -1;
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry=NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) { ZNSOCKET::close(s); return -1; }
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
 myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
 myname.sin_port = htons(port);
 ZNSOCKET::block(s,false);
 if(::connect(s,(struct sockaddr *) &myname, sizeof(myname)) < 0) 
 {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() != WSAEWOULDBLOCK) { ZNSOCKET::close(s); return -1; }
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno != EINPROGRESS) { ZNSOCKET::close(s); return -1; }
#endif
#endif
 }
 return s;
};

int ZNSOCKET::async_select(int s, unsigned timeout)
{
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 struct timeval tz; tz.tv_sec=timeout/1000; tz.tv_usec=timeout%1000*1000;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
 {
#if defined(_WIN32) || defined(_WIN64)
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  int optval;
  elmlen optlen = sizeof(optval);
  if(getsockopt(s, SOL_SOCKET, SO_ERROR, (char *) &optval, &optlen) < 0) return -1;
  if(optval) return -1;
#endif
#endif
  return 1;
 }
 return 0;
};

int ZNSOCKET::server(const std::string &_adr, unsigned short p, int backlog, bool blocking)
{
 int s=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(s < 0) return -1;
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry=NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) { ZNSOCKET::close(s); return -1; }
// adr = inet_ntoa(*((in_addr *) (entry->h_addr)));
 int flags = 1;
 setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &flags, sizeof(flags));
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
// myname.sin_addr.s_addr = inet_addr(adr.c_str());
 myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
 myname.sin_port = htons(p);
 if(::bind(s,(struct sockaddr *) &myname,sizeof(myname)) < 0) { ZNSOCKET::close(s); return -1; }
 if(::listen(s, backlog) < 0) { ZNSOCKET::close(s); return -1; }
 ZNSOCKET::block(s,blocking);
 return s;
};

int ZNSOCKET::server(unsigned short p, int backlog, bool blocking)
{
 int s=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
 if(s < 0) return -1;
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
 myname.sin_addr.s_addr = INADDR_ANY;
 myname.sin_port = htons(p);
 if(::bind(s,(struct sockaddr *) &myname,sizeof(myname)) < 0) { ZNSOCKET::close(s); return -1; }
 if(::listen(s, backlog) < 0) { ZNSOCKET::close(s); return -1; }
 ZNSOCKET::block(s,blocking);
 return s;
};

bool ZNSOCKET::alive(int s)
{
 if(s < 0) return false;
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,(fd_set *) NULL,&tExc,&tz) < 0) return false;
 if(FD_ISSET(s,&tExc)) return false;
 return true;
};

void ZNSOCKET::close(int s)
{
 if(s < 0) return;
 shutdown(s,2);
#if defined(_WIN32) || defined(_WIN64)
  ::closesocket(s);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  ::close(s);
#endif
#endif
};

int ZNSOCKET::accept(int s, unsigned tm, bool blocking)
{
 if(s < 0) return -1;
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned) s), &tSet);
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned) s), &tExc);
 struct timeval tz; tz.tv_sec=tm/1000; tz.tv_usec=tm%1000*1000;
 if(::select(s+1, &tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
 {
  struct sockaddr_in addr;
  elmlen adrlen = sizeof(addr);
  int n = ::accept(s, (struct sockaddr*) &addr,&adrlen);
  if(n < 0) { return -1; }
  ZNSOCKET::block(n,blocking);
  return n;
 }
 return 0;
};


int ZNSOCKET::accept(int s, bool blocking)
{
 struct sockaddr_in addr;
 elmlen adrlen = sizeof(addr);
 int n = ::accept(s, (struct sockaddr*) &addr,&adrlen);
 if(n < 0) { return -1; }
 ZNSOCKET::block(n,blocking);
 return n;
};

ssize_t ZNSOCKET::read(int s, std::string &ret)
{
 if(s < 0) return -1; 
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
  
 char r[65536];
 int n;
 ssize_t n_r=0;
 while(1)
 {
  n= ::recv(s,r,65536,0);
  if(n == 0) return -1;
  if(n < 0)
  {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() == WSAEWOULDBLOCK) break;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno == EAGAIN || errno == EWOULDBLOCK) break;
#endif
#endif
   return -1;
  }
  if(n) { ret.append(r,(size_t) n); n_r+=n; }
 }
 return n_r;
};

ssize_t ZNSOCKET::read(int s, std::string &ret, char* r, size_t len)
{
 if(s < 0) return -1;
 if(len == 0) return 0;
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 int n;
 ssize_t n_r=0;
 while(1)
 {
  n= ::recv(s,r,len,0);
  if(n == 0) return -1;
  if(n < 0)
  {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() == WSAEWOULDBLOCK) break;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno == EAGAIN || errno == EWOULDBLOCK) break;
#endif
#endif
   return -1;
  }
  if(n) { ret.append(r,(size_t) n); n_r+=n; }
 }
 return n_r;
};

ssize_t ZNSOCKET::read(int s, std::string &ret, char r[65536]) { return ZNSOCKET::read(s, ret, r, 65536); };

ssize_t ZNSOCKET::read(int s, char* ret, size_t len)
{
 if(s < 0) return -1;
 if(len == 0) return 0;
 ssize_t n= ::recv(s,ret,len,0);
 if(n == 0) return -1;
 if(n < 0)
 {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() == WSAEWOULDBLOCK) return 0;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno == EAGAIN || errno == EWOULDBLOCK)  return 0;
#endif
#endif
  return -1;
 }
 return n;
};//ZNSOCKET::read

ssize_t ZNSOCKET::write(int s, const std::string &v, size_t pos)
{
 if(s < 0) return -1; 
/*
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 
 size_t l=v.size();
 if(l == 0 || pos >= l) return 0;
 ssize_t n= ::send(s,v.c_str()+pos,l-pos,0);
 if(n < 0)
 {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() == WSAEWOULDBLOCK) return 0;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno == EAGAIN || errno == EWOULDBLOCK)  return 0;
#endif
#endif
  return -1;
 }
 return n;
};// ZNSOCKET::write

ssize_t ZNSOCKET::pass(int s, const char* v, size_t len)
{
 if(s < 0) return -1; 
 if(len == 0) return 0;
 ssize_t n= ::send(s,v,len,0);
 if(n < 0)
 {
#if defined(_WIN32) || defined(_WIN64)
  if(WSAGetLastError() == WSAEWOULDBLOCK) return 0;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(errno == EAGAIN || errno == EWOULDBLOCK)  return 0;
#endif
#endif
  return -1;
 }
 return n; 
};// ZNSOCKET::pass

ssize_t ZNSOCKET::send(int s,const std::string &v, size_t pos)
{
 ssize_t n=0;
 for(ssize_t i; pos < v.size();)
 {
  i=ZNSOCKET::write(s,v,pos);
  if(i < 0) return -1;
  if(i == 0) { zThread::sleep(1); continue; }
  n+=i; pos+=i;
 }
 return n;
};

std::string ZNSOCKET::getAddress(int s)
{
 if(s < 0) return "";
 struct sockaddr addr;
 elmlen adrlen = sizeof(addr);
 memset(&addr,0,adrlen);
 if(getsockname(s,&addr,&adrlen) < 0) return "";
 return inet_ntoa(((sockaddr_in*) &addr)->sin_addr);
};

unsigned ZNSOCKET::getPort(int s)
{
 if(s < 0) return 0;
 struct sockaddr addr;
 elmlen adrlen = sizeof(addr);
 memset(&addr,0,adrlen);
 if(getsockname(s,&addr,&adrlen) < 0) return 0;
 return ((unsigned) ntohs(((sockaddr_in*) &addr)->sin_port));
};

std::string ZNSOCKET::getPeerAddress(int s)
{
 if(s < 0) return "";
 struct sockaddr addr;
 elmlen adrlen = sizeof(addr);
 memset(&addr,0,adrlen);
 if(getpeername(s,&addr,&adrlen) < 0 ) return "";
 return inet_ntoa(((sockaddr_in*) &addr)->sin_addr);
};

unsigned ZNSOCKET::getPeerPort(int s)
{
 if(s < 0) return 0;
 struct sockaddr addr;
 elmlen adrlen = sizeof(addr);
 memset(&addr,0,adrlen);
 if(getpeername(s,&addr,&adrlen) < 0) return 0;
 return ((unsigned) ntohs(((sockaddr_in*) &addr)->sin_port));
};

unsigned ZNSOCKET::getReceiveBufferSize(int s)
{
 if(s < 0) return 0;
 int optval;
 elmlen optlen = sizeof(optval);
 if(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &optval, &optlen) < 0) return 0;
 return optval;
};

unsigned ZNSOCKET::getSendBufferSize(int s)
{
 if(s < 0) return 0;
 int optval;
 elmlen optlen = sizeof(optval);
 if(getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *) &optval, &optlen) < 0)  return 0;
 return optval;
};

unsigned ZNSOCKET::setReceiveBufferSize(int s, unsigned size)
{
 if(s < 0) return 0;
 int optval = size;
 elmlen optlen = sizeof(optval);
 setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &optval, optlen);
 if(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *) &optval, &optlen) < 0) return 0;
 return optval;
};

unsigned ZNSOCKET::setSendBufferSize(int s, unsigned size)
{
 if(s < 0) return 0;
 int optval = size;
 elmlen optlen = sizeof(optval);
 setsockopt(s, SOL_SOCKET,SO_SNDBUF , (char *) &optval, optlen);
 if(getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *) &optval, &optlen) < 0) return 0;
 return optval;
};

void ZNSOCKET::block(int s, bool blocking)
{
#if defined(_WIN32) || defined(_WIN64)
 unsigned long dontblock = 1;
 if(blocking) dontblock = 0;
 ioctlsocket(s,FIONBIO,&dontblock);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 int dontblock = 1;
 if(blocking) dontblock = 0;
 ioctl(s,FIONBIO,(char *) &dontblock);
// fcntl(s, F_SETFL, fcntl(s, F_GETFD, 0)|O_NONBLOCK)
#endif
#endif
};

void ZNSOCKET::select(const std::vector<int>& src, std::vector<int>& rd, std::vector<int>& wr, std::vector<int>& ex, unsigned timeout, int rwe)
{
 rd.clear(); wr.clear(); ex.clear();
 if(src.size() == 0) return;
 if(((rwe & ZNSOCKET::SELECT_READ) | (rwe & ZNSOCKET::SELECT_WRITE) | (rwe & ZNSOCKET::SELECT_EXCEPT)) == 0) return;
 size_t k=src.size()/FD_SETSIZE;
 if((src.size()%FD_SETSIZE) != 0) ++k;
 timeout/=k;
 fd_set tr; fd_set tw; fd_set te; fd_set* pr=NULL; fd_set* pw=NULL; fd_set* pe=NULL;
 if(rwe & ZNSOCKET::SELECT_READ) pr=&tr;
 if(rwe & ZNSOCKET::SELECT_WRITE) pw=&tw;
 if(rwe & ZNSOCKET::SELECT_EXCEPT) pe=&te;
 for(size_t i=0; i < k; i++)
 {
  int s=0;  
  size_t ns= i*FD_SETSIZE;
  if(pr != NULL)
  {
   FD_ZERO(pr);
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   {
    FD_SET(((unsigned) src[ns+j]), pr);
    if(src[ns+j] > s) s=src[ns+j];
   }
  }
  if(pw != NULL)
  {
   FD_ZERO(pw);
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   {
    FD_SET(((unsigned) src[ns+j]), pw);
    if(src[ns+j] > s) s=src[ns+j];
   }
  }
  if(pe != NULL)
  {
   FD_ZERO(pe);
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   {
    FD_SET(((unsigned) src[ns+j]), pe);
    if(src[ns+j] > s) s=src[ns+j];
   }
  }
  struct timeval tz; tz.tv_sec=timeout/1000; tz.tv_usec=timeout%1000*1000;
  if(::select(s+1,pr,pw,pe,&tz) < 0) continue;
  if(pr != NULL)
  {
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   { if(FD_ISSET(src[ns+j],pr)) rd.push_back(src[ns+j]); }
  }
  if(pw != NULL)
  {
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   { if(FD_ISSET(src[ns+j],pw)) wr.push_back(src[ns+j]); }
  }
  if(pe != NULL)
  {
   for(size_t j=0; (ns+j) < src.size() && j < FD_SETSIZE; j++)
   { if(FD_ISSET(src[ns+j],pe)) ex.push_back(src[ns+j]); }
  }
 }
};


SSL_CTX* ZNSOCKET::server_ctx(const std::string& server_cert_file,const std::string& server_key_file, const SSL_METHOD* method)
{
 SSL_CTX* ctx=::SSL_CTX_new(method);
 if(ctx == NULL) return NULL;
 ::SSL_CTX_set_options(ctx, SSL_OP_ALL);
// if(::SSL_CTX_use_certificate_file(ctx,server_cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) { ::SSL_CTX_free(ctx); return NULL; }
 if(SSL_CTX_use_certificate_chain_file(ctx,server_cert_file.c_str()) <= 0) { ::SSL_CTX_free(ctx); return NULL; }
 if(::SSL_CTX_use_PrivateKey_file(ctx,server_key_file.c_str(), SSL_FILETYPE_PEM) <= 0)
 { ::SSL_CTX_free(ctx); return NULL; }
 if(! ::SSL_CTX_check_private_key(ctx)) { ::SSL_CTX_free(ctx); return NULL; }
// if(::SSL_CTX_load_verify_locations(ctxs,CA_CERT,NULL) <= 0) { ::SSL_CTX_free(ctx); return NULL; }
 return ctx;
};

SSL_CTX* ZNSOCKET::client_ctx(const SSL_METHOD* method)
{
 SSL_CTX* ctx=::SSL_CTX_new(method);
 if(ctx == NULL) return NULL;
 ::SSL_CTX_set_options(ctx, SSL_OP_ALL);
 return ctx;
};

int ZNSOCKET::handle(SSL* s) { if(s == NULL) return -1; return ::SSL_get_fd(s); }

SSL* ZNSOCKET::socket(int s,SSL_CTX* ctx)
{
 if(ctx == NULL) return NULL;
 SSL* c=::SSL_new(ctx);
 if(c == NULL)  return NULL;
 if(::SSL_set_fd(c,s) <= 0) { ::SSL_free(c); return NULL; }
// ::SSL_set_mode(c, SSL_MODE_AUTO_RETRY);
// if(::SSL_connect(c) < 0) { ::SSL_free(c); ZNSOCKET::close(s); return NULL; }
// ZNSOCKET::block(s,blocking);
 return c;
};

SSL* ZNSOCKET::server(int s,SSL_CTX* ctx)
{
 if(ctx == NULL) return NULL;
 SSL* c=::SSL_new(ctx);
 if(c == NULL) return NULL;
 if(::SSL_set_fd(c,s) <= 0) { ::SSL_free(c); return NULL; }
// ::SSL_set_mode(c, SSL_MODE_AUTO_RETRY);
// if(::SSL_connect(c) < 0) { ::SSL_free(c); ZNSOCKET::close(s); return NULL; }
// ZNSOCKET::block(s,blocking);
 return c;
};


ssize_t ZNSOCKET::connect(SSL* s, unsigned tm)
{
 if(s == NULL) return -1;
 int n=::SSL_connect(s);
 if(n > 0) return 1;
 if(n == 0) return -1;
 n=::SSL_get_error(s,n);
 if(n != SSL_ERROR_WANT_CONNECT && n != SSL_ERROR_WANT_READ && n != SSL_ERROR_WANT_WRITE) return -1;
 if(tm == 0) return 0;
 for(zTimer t; t.get() <= tm; zThread::sleep(1))
 {
  n=::SSL_connect(s);
  if(n > 0) return 1;
  if(n == 0) return -1;
  n=::SSL_get_error(s,n);
  if(n != SSL_ERROR_WANT_CONNECT && n != SSL_ERROR_WANT_READ && n != SSL_ERROR_WANT_WRITE) return -1;
 }
 return 0;
};


ssize_t ZNSOCKET::accept(SSL* s, unsigned tm)
{
 if(s == NULL) return -1;
 int n=::SSL_accept(s);
 if(n > 0) return 1;
 if(n == 0) return -1;
 n=::SSL_get_error(s,n);
 if(n != SSL_ERROR_WANT_ACCEPT && n != SSL_ERROR_WANT_READ && n != SSL_ERROR_WANT_WRITE) return -1;
 if(tm == 0) return 0;
 for(zTimer t; t.get() <= tm; zThread::sleep(1))
 {
  n=::SSL_accept(s);
  if(n > 0) return 1;
  if(n == 0) return -1;
  n=::SSL_get_error(s,n);
  if(n != SSL_ERROR_WANT_ACCEPT && n != SSL_ERROR_WANT_READ && n != SSL_ERROR_WANT_WRITE) return -1;
 }
 return 0;
};


ssize_t ZNSOCKET::read(SSL* c, std::string &ret)
{
 if(c == NULL) return -1; 
 int s=::SSL_get_fd(c);
 if(s < 0) return -1; 
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 char r[65536];
 ssize_t n_r=0;
 for(int n;;)
 { 
  n= ::SSL_read(c,r,65536);
  if(n <= 0)
  {
   n=::SSL_get_error(c, n);
   if(n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) return n_r;
   return -1;
  }
  else { ret.append(r,(size_t) n); n_r+=n; }
 }
// return 0;
};

ssize_t ZNSOCKET::read(SSL* c, std::string &ret,char* r, size_t len)
{
 if(c == NULL) return -1; 
 int s=::SSL_get_fd(c);
 if(s < 0) return -1; 
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 ssize_t n_r=0;
 for(int n;;)
 { 
  n= ::SSL_read(c,r,len);
  if(n <= 0)
  {
   n=::SSL_get_error(c, n);
   if(n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) return n_r;
   return -1;
  }
  else { ret.append(r,(size_t) n); n_r+=n; }
 }
};

ssize_t ZNSOCKET::read(SSL* c, std::string &ret, char r[65536]) { return ZNSOCKET::read(c, ret, r, 65536); };

ssize_t ZNSOCKET::read(SSL* c, char* ret, size_t len)
{
 if(c == NULL) return -1; 
 int s=::SSL_get_fd(c);
 if(s < 0) return -1; 
 int n= ::SSL_read(c,ret,len);
 if(n <= 0)
 {
  n=::SSL_get_error(c, n);
  if(n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) return 0;
  return -1;
 }
 return (ssize_t) n;
};

ssize_t ZNSOCKET::write(SSL* c, const std::string &v,size_t pos)
{
 if(c == NULL) return -1; 
 int s=::SSL_get_fd(c);
 if(s < 0) return -1; 
/*
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
// if(FD_ISSET(s,&tSet))
*/
 size_t l=v.size();
 if(l == 0 || pos >= l) return 0;
 int n= ::SSL_write(c,v.c_str()+pos,(int) (l-pos));
 if(n <= 0)
 {
  n=::SSL_get_error(c, n);
  if(n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) return 0;
  return -1;
 }
 return (ssize_t) n;
};

ssize_t ZNSOCKET::pass(SSL* c, const char* v, size_t len)
{
 if(c == NULL) return -1; 
 int s=::SSL_get_fd(c);
 if(s < 0) return -1; 
 if(len == 0) return 0;
 int n= ::SSL_write(c,v,(int) len);
 if(n <= 0)
 {
  n=::SSL_get_error(c, n);
  if(n == SSL_ERROR_WANT_READ || n == SSL_ERROR_WANT_WRITE) return 0;
  return -1;
 }
 return (ssize_t) n;
};

ssize_t ZNSOCKET::send(SSL* s,const std::string &v,size_t pos)
{
 ssize_t n=0;
 for(ssize_t i; pos < v.size();)
 {
  i=ZNSOCKET::write(s,v,pos);
  if(i < 0) return -1;
  if(i == 0) { zThread::sleep(1); continue; }
  n+=i; pos+=i;
 }
 return n;
};

void ZNSOCKET::close(SSL* s)
{
 if(s == NULL) return;
 ::SSL_shutdown(s);
};

void ZNSOCKET::free(SSL* s) { if(s == NULL) return; ::SSL_free(s); };

void ZNSOCKET::free(SSL_CTX* s) { if(s == NULL) return; ::SSL_CTX_free(s); };


std::string ZNUDP::net_to_host(unsigned n) 
{
 struct in_addr adr;
 adr.s_addr=n;
 return inet_ntoa(adr); 
};

unsigned ZNUDP::host_to_net(const std::string& _adr)
{
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) return 0;
 return ((in_addr *)entry->h_addr)->s_addr;
};

int ZNUDP::socket(const std::string& _adr, unsigned short port, bool blocking)
{
 int s=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 if(s < 0) return -1;
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) { ZNUDP::close(s); return -1; }
// adr = inet_ntoa(*((in_addr *)entry->h_addr));
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
// myname.sin_addr.s_addr = inet_addr(adr.c_str());
 myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
 myname.sin_port = htons(port);
 if(::connect(s,(struct sockaddr *) &myname, sizeof(myname)) < 0) 
 { ZNUDP::close(s); return -1; }
 ZNUDP::block(s,blocking);
 return s;
};

int ZNUDP::server(const std::string &_adr, unsigned short p, bool blocking)
{
 int s=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 if(s < 0) return -1;
 std::string adr = ZNSTR::trim(_adr);
 struct hostent *entry = NULL;
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
 entry = ::gethostbyname(adr.c_str());
#else
#if defined(__GNUG__) || defined(__linux__)
 struct hostent hst;
 size_t hstbuflen=1024;
 char tmphstbuf[1024];
 int herr;
 ::gethostbyname_r(adr.c_str(), &hst, tmphstbuf, hstbuflen, &entry, &herr);
#endif
#endif
 if(entry == NULL) { ZNUDP::close(s); return -1; }
// adr = inet_ntoa(*((in_addr *) (entry->h_addr)));
 struct sockaddr_in myname;
 memset(&myname, 0, sizeof(myname));
 myname.sin_family = AF_INET;
// myname.sin_addr.s_addr = inet_addr(adr.c_str());
 myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
 myname.sin_port = htons(p);
 if(::bind(s,(struct sockaddr *) &myname,sizeof(myname)) < 0) { ZNUDP::close(s); return -1; }
 ZNUDP::block(s,blocking);
 return s;
};

bool ZNUDP::alive(int s) { return ZNSOCKET::alive(s); };

void ZNUDP::close(int s) { return ZNSOCKET::close(s); };


ssize_t ZNUDP::read(int s, unsigned& adr, unsigned short& port, std::string &ret)
{
 if(s < 0) return -1;
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=timeout/1000; tz.tv_usec=timeout%1000*1000;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 char rv[65536];
 struct sockaddr_in myname;
 elmlen i=sizeof(myname);
 memset(&myname, 0,i);
 myname.sin_family = AF_INET;
 ssize_t n= ::recvfrom(s,rv,65536,0,(struct sockaddr*) &myname,&i);
 if(n < 1) return -1;
 ret.append(rv,n);
 adr=myname.sin_addr.s_addr;
 port=ntohs(myname.sin_port);
 return n;
};

ssize_t ZNUDP::read(int s, unsigned& adr, unsigned short& port, std::string &ret, char rv[65536])
{
 if(s < 0) return -1;
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=timeout/1000; tz.tv_usec=timeout%1000*1000;
 if(::select(s+1,&tSet,(fd_set *) NULL,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 struct sockaddr_in myname;
 elmlen i=sizeof(myname);
 memset(&myname, 0,i);
 myname.sin_family = AF_INET;
 ssize_t n= ::recvfrom(s,rv,65536,0,(struct sockaddr*) &myname,&i);
 if(n < 1) return -1;
 ret.append(rv,n);
 adr=myname.sin_addr.s_addr;
 port=ntohs(myname.sin_port);
 return n;
};

ssize_t ZNUDP::read(int s, unsigned& adr, unsigned short& port, char* ret, size_t len)
{
 if(s < 0) return -1;
 struct sockaddr_in myname;
 elmlen i=sizeof(myname);
 memset(&myname, 0,i);
 myname.sin_family = AF_INET;
 ssize_t n= ::recvfrom(s,ret,len,0,(struct sockaddr*) &myname,&i);
 if(n < 1) return -1;
 adr=myname.sin_addr.s_addr;
 port=ntohs(myname.sin_port);
 return n;
};

ssize_t ZNUDP::write(int s, unsigned adr, unsigned short port, const std::string &v, size_t pos)
{
 if(s < 0) return -1;
 size_t l=v.size();
 if(l == 0 || pos >= l) return 0;
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 {
//  std::string adr = ZNSTR::trim(_adr);
//  struct hostent *entry = gethostbyname(adr.c_str());
//  if(entry == NULL) return 0;
//  adr = inet_ntoa(*((in_addr *) (entry->h_addr)));
  struct sockaddr_in myname;
  memset(&myname, 0, sizeof(myname));
  myname.sin_family = AF_INET;
//  myname.sin_addr.s_addr = inet_addr(adr.c_str());
//  myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
  myname.sin_addr.s_addr = adr;
  myname.sin_port = htons(port);
  if((l-pos) > 65000) l=(65000+pos);
  int n= ::sendto(s,v.c_str()+pos,l-pos,0,(struct sockaddr*) &myname, sizeof(myname));
  if(n < 1) return 0;
  return n;
 }
// return 0;
};

ssize_t ZNUDP::pass(int s, unsigned adr,unsigned short port, const char* v, size_t len)
{
 if(s < 0) return -1;
 if(len == 0) return 0;
/*
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 {
//  std::string adr = ZNSTR::trim(_adr);
//  struct hostent *entry = gethostbyname(adr.c_str());
//  if(entry == NULL) return 0;
//  adr = inet_ntoa(*((in_addr *) (entry->h_addr)));
  struct sockaddr_in myname;
  memset(&myname, 0, sizeof(myname));
  myname.sin_family = AF_INET;
//  myname.sin_addr.s_addr = inet_addr(adr.c_str());
//  myname.sin_addr.s_addr = ((in_addr *)entry->h_addr)->s_addr;
  myname.sin_addr.s_addr = adr;
  myname.sin_port = htons(port);
  if(len > 65000) len=65000;
  int n= ::sendto(s,v,len,0,(struct sockaddr*) &myname, sizeof(myname));
  if(n < 1) return 0;
  return n;
 }
};

ssize_t ZNUDP::write(int s, const std::string &v, size_t pos)
{
 if(s < 0) return -1;
 size_t l=v.size();
 if(l == 0 || pos >= l) return 0;
/*
 fd_set tSet;
 FD_ZERO(&tSet);
 FD_SET(((unsigned)s), &tSet);
 fd_set tExc;
 FD_ZERO(&tExc);
 FD_SET(((unsigned)s), &tExc);
 struct timeval tz; tz.tv_sec=0; tz.tv_usec=0;
 if(::select(s+1,(fd_set *) NULL,&tSet,&tExc,&tz) < 0) return -1;
 if(FD_ISSET(s,&tExc)) return -1;
 if(FD_ISSET(s,&tSet))
*/
 if((l-pos) > 65000) l=(65000+pos);
 ssize_t n= ::send(s,v.c_str()+pos,l-pos,0);
 if(n < 1) return -1;
 return n;
};//ZNUDP::write

ssize_t ZNUDP::pass(int s, const char* v, size_t len)
{
 if(s < 0) return -1;
 if(len == 0) return 0;
 if(len > 65000) len=65000;
 ssize_t n= ::send(s,v,len,0);
 if(n < 1) return -1;
 return n;
};//ZNUDP::pass

std::string ZNUDP::getAddress(int s) { return ZNSOCKET::getAddress(s); };

unsigned ZNUDP::getPort(int s) { return ZNSOCKET::getPort(s); };

std::string ZNUDP::getPeerAddress(int s) { return ZNSOCKET::getPeerAddress(s); };

unsigned ZNUDP::getPeerPort(int s) { return ZNSOCKET::getPeerPort(s); };

void ZNUDP::block(int s, bool blocking) { ZNSOCKET::block(s, blocking); };




