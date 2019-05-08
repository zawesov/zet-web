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

#ifndef __zPacket_h
#define __zPacket_h 1

#define ZET_WEB_VERSION 3.4

#include <iostream>
#include <map>
#include <set>
#include <event.h>
#include "zThread.h"
#include "zSocket.h"
#include "zPool.h"
#include "zLog.h"
#include "zDNS.h"

#define ZHTTP_PACKET_INVALID -1
#define ZHTTP_PACKET_EMPTY 0
#define ZHTTP_PACKET_HEADER 1
#define ZHTTP_PACKET_COMPLETE 2

#define ZHTTP_CLIENT_INVALID -1
#define ZHTTP_CLIENT_EMPTY 0
#define ZHTTP_CLIENT_CONNECTED 1
#define ZHTTP_CLIENT_SENT 2
#define ZHTTP_CLIENT_HEADER 4
#define ZHTTP_CLIENT_COMPLETE 8

#define ZWS_PACKET_INVALID -1
#define ZWS_PACKET_EMPTY 0
#define ZWS_PACKET_HEADER 1
#define ZWS_PACKET_ACCEPTED 2
#define ZWS_PACKET_CLOSED 4

#define ZWS_CLIENT_INVALID -1
#define ZWS_CLIENT_EMPTY 0
#define ZWS_CLIENT_HEADER 1
#define ZWS_CLIENT_CONNECTED 2
#define ZWS_CLIENT_CLOSED 4

#define ZTCP_PACKET_INVALID -1
#define ZTCP_PACKET_EMPTY 0

#define ZTCP_CLIENT_INVALID -1
#define ZTCP_CLIENT_EMPTY 0
#define ZTCP_CLIENT_CONNECTED 1

#define ZHTTP_METHOD_EMPTY 0
#define ZHTTP_METHOD_GET 1
#define ZHTTP_METHOD_POST 2

#define READ_TIMEOUT_SEC 60
#define READ_TIMEOUT_MSEC 0
#define WRITE_TIMEOUT_SEC 60
#define WRITE_TIMEOUT_MSEC 0

//using std::map;
//using std::set;
//using std::cout;
//using std::endl;

class zPacketThread;
class zParamPacket;

class zPacket
{

template<class T> friend class zPool;

public:

template<class T> static T* getParam(zPacket* p)
{
 if(p == NULL || p->ext == NULL) return NULL;
 return dynamic_cast<T*>(p->ext);
};
/*
 Tries to cast zParamPacket* ext to T*.
*/

virtual ~zPacket();

virtual void execute(int s, short what)=0;

virtual void clear()= 0;

virtual event* create_event(event_base* eb, short what, void *arg) const;
virtual event* create_event(event_base* eb, short what, void *arg, unsigned sec, unsigned short msec) const;
virtual void clear_event() const;
virtual short get_event() const;
virtual void clear_socket() const;
virtual void clear_ext() const;


virtual bool push()
{
 if(pool == NULL) { delete this; return true; }
 clear_ext();
 return pool->push((zPacket*) this);
};
/*
 Moves the used object to the storage.
 If success returns true, false otherwise.
*/

virtual bool drop()
{
 if(pool == NULL) { delete this; return true; }
 return pool->drop((zPacket*) this);
};
/*
 Deletes object.
 If success returns true, false otherwise.
*/

virtual bool check(bool inuse=true)
{
 if(pool == NULL) { return false; }
 return pool->check((zPacket*) this, inuse);
};
/*
  Returns true if object is found in pool, false otherwise.
  If inuse is true, function tries to find in the list of used objects.
  If inuse is false, function tries to find in the list of stored objects.
*/

virtual int family() const { return ZNSOCKET::family(sock); };
/*
 Returns the family of the socket (AF_INET or AF_INET6).
*/

mutable zPool<zPacket>* pool;
/*
  Pool for zPacket objects.
*/

mutable event* ev;
mutable event* ev_stor;
mutable struct timeval tmval;
mutable int sock;
/*
  Socket.
*/
mutable SSL* ssl;
/*
  Pointer to SSL structure. If ssl is not NULL the encrypted connection is established.
*/
mutable zPacketThread* parent;
/*
  Pointer to parent thred.
*/
mutable zParamPacket* ext;
/*
  Sets additional parameters for the object.
  Additional parameters are defined in the class inherited from the class zParamPacket.
*/


protected:

 zPacket();

private:

 ZCED(zPacket)

};

class zParamPacket
{
 public:
 zParamPacket(zPacket* prn=NULL): parent(prn) {};
virtual ~zParamPacket();

virtual void clear()= 0;
/*
  Must be redifined.
  The function is called when the object is returned to the pool.
*/

mutable zPacket* parent;
/*
  The Pointer to parent object.
*/

};

class zPacketHTTP: public zPacket
{

friend class zPoolHTTP;
template<class T> friend class zPool;

public:

static size_t header_max_length;
static size_t packet_max_length;
/*
 Maximum size of http header and body.
*/

static int parse(zPacketHTTP* src);

mutable int status;
/*
 Defines packet's status.
 ZHTTP_PACKET_INVALID -1 - Invalid state;
 ZHTTP_PACKET_EMPTY 0 - Initial state;
 ZHTTP_PACKET_HEADER 1 - Header is read;
 ZHTTP_PACKET_COMPLETE 2 - Request is OK;
*/

 std::string str_header;
 std::string str_in;
 std::string str_out;
/*
 str_header is http header with last \r\n\r\n.
 str_in is http body.
 str_out is output buffer.
*/

 size_t pos;

 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port(proxy or browser).
 std::string host; // host in http request (for example www.example.com)
 unsigned port; // socket port on which the connection was opened.
 std::string version; // HTTP version.
 std::string method; // HTTP method(GET, POST).
 std::string path; // http request path.
 std::string boundary;
 std::string content_type; // Content-Type from head.
 bool keep_alive;
/*
 Request: if Connection: close (by default) then keep_alive is false, if Connection: keep_alive then keep_alive is true.
 Reply: if keep_alive is false then the connection will be closed after the response is sent. The connection will stay open if keep_alive is true.
*/
 bool keep_write;
/*
 After sending the entire message, the connection will not be closed.
 To close the connection it is necessary to write:
 p->keep_write=false;
 p->send();
 You can use this option at your own risk.
*/
 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zPacketHTTP* p) function will be called in case of no read/write events.
*/
 size_t max_header;
 size_t max_body;
/*
 By default:
 max_header = zPacketHTTP::header_max_length;
 max_body = zPacketHTTP::packet_max_length;
*/
 size_t length; // length of the message body
 bool chunked;
/*
 If Transfer-Encoding: chunked then chunked is true, chunked is false in other cases.
*/
 std::vector<std::pair<longlong, longlong> > ranges;
/*
 The list of ranges parsed from Range. If second parameter of a range is undefined it is set to -1.
 Range: bytes=7-10, -555, 0- => std::pair<longlong, longlong>: (7,10), (-555, -1), (0,-1)
*/
 std::map<std::string,std::string> head;
/*
 HEAD of the http message. All names are set to uppercase(CONNECTION: keep_alive).
*/
 std::map<std::string,std::vector<std::string> > cookie;
/*
 The list of cookies: name => value;
*/
 std::map<std::string,std::vector<std::string> > param;
/*
 HTTP query parameters (www.example.com/mypath?q1=0&q2=1 param["q2"][0] is 1).
*/
 std::map<std::string,std::vector<std::pair<std::string,std::string> > > file;
/*
 HTTP query files (std::map<param name,std::vector<std::pair<file name,file body> > >).
*/

virtual void write(const std::string &src) { str_out+=src; };
/*
 Sets body reply: str_out+=src;.
*/
virtual void send_empty(const std::string& connection="close");
/*
 Sends reply with header: "HTTP/1.1 204 No Content\r\nContent-Type:text/html\r\nContent-Length:0\r\nConnection:"+connection+"\r\n\r\n";
*/
virtual void send_location(const std::string& path, const std::string& connection="close");
/*
 Sends reply with header: "HTTP/1.1 302 Moved Temporarily\r\nLocation:"+path+"\r\nContent-Length:0\r\nConnection:"+connection+"\r\n\r\n"
*/

virtual void send_text(const std::string& hdr="text/html; charset=utf-8", const std::string& connection="close");
/*
 Sends reply with header: "HTTP/1.1 200 OK\r\nContent-Type:"+hdr+"\r\nContent-Length:"+ZNSTR::toString(str_out.size())+"\r\nConnection:"+connection+"\r\n\r\n"
*/
virtual void send(const std::string& hdr="");
/*
 Sends reply with http header hdr.
*/
virtual void close() { push(); };
/*
 Closes connection and removes packet.
 The function zPacketThread::onClose(zPacketHTTP* p) will not be called.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zPacketHTTP();
virtual ~zPacketHTTP();

private:

 ZCED(zPacketHTTP)

};

class zPoolHTTP: public zPool<zPacket>
{

//friend class zPacketHTTP;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 public:

 zPoolHTTP(): zPool<zPacket>() {};

 virtual ~zPoolHTTP();

// virtual zPacket* get() { return zPool<zPacket>::get(); };

 virtual zPacketHTTP* get(zPacketThread* prn);

private:

 ZCED(zPoolHTTP)

};

class zPacketWS: public zPacket
{

friend class zPoolWS;
template<class T> friend class zPool;

public:

static size_t header_max_length;
static size_t packet_max_length;
/*
 Maximum size of http header and ws body.
*/

static int parse(zPacketWS* src);

mutable int status;
/*
 Defines packet's status.
 ZWS_PACKET_INVALID -1 - Invalid state;
 ZWS_PACKET_EMPTY 0 - Initial state;
 ZWS_PACKET_HEADER 1 - Tries to read Header;
 ZWS_PACKET_ACCEPTED 2 - WS Connection is established;
 ZWS_PACKET_CLOSED 4 - Connection is closed;
*/

 std::string str_header;
/*
 str_header is http header with last \r\n\r\n.
*/

 std::string str_in;
 std::string str_out;

 std::string message;
/*
 When message is received then function onMessage(zPacketWS* p) is called.
*/
 std::string complete_message;
/*
 Can be used to execute fragmented messages.
*/

 bool fin_flag;
/*
 true for complete message;
 false for fragmented not last message.
*/

 size_t opcode;
/*
0x01 - text message;
0x02 - binary message;
0x00 - fragmented not first message;
*/

 size_t pos;

 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port(proxy or browser).
 std::string host; // host in http request (for example www.example.com)
 unsigned port; // socket port on which the connection was opened.
 std::string method; // HTTP method(GET, POST).
 std::string http_version; // HTTP version.
 std::string ws_version; //WS version.
 std::string ws_key; //WS key.
 std::string path; // http request path.

 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zPacketWS* p) function will be called in case of no read/write events.
*/

 size_t max_header;
 size_t max_body;
/*
 By default:
 max_header = zPacketWS::header_max_length;
 max_body = zPacketWS::packet_max_length;
*/

 std::map<std::string,std::string> head;
/*
 HEAD of the http message. All names are set to uppercase(UPGRADE: websocket).
*/

virtual void accept(const std::map<std::string, std::string>& add_header=std::map<std::string, std::string>());
/*
 Sends reply for client to accept connection.
 add_header is the additional parameters for header in reply.
*/

virtual void send(const std::string& msg, bool fragmented=false);
/*
 Sends message msg to client, bool fragmented defines the fragmented type of message.
 The message will be queued.
*/

virtual void close();
/*
 Sends close message to client and then close connection.
 The function zPacketThread::onClose(zPacketWS* p) will be called.
*/

virtual void ping();
virtual void pong();
/*
 Sends ping/pong message.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zPacketWS();
virtual ~zPacketWS();

mutable size_t last_fragmented_count;

private:

 ZCED(zPacketWS)

};

class zPoolWS: public zPool<zPacket>
{

friend class zPacketWS;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 public:

 zPoolWS(): zPool<zPacket>() {};

 virtual ~zPoolWS();

 virtual zPacketWS* get(zPacketThread* prn);

private:

 ZCED(zPoolWS)

};

class zPacketTCP: public zPacket
{

friend class zPoolTCP;
template<class T> friend class zPool;

public:

mutable int status;
/*
 Defines packet's status.
 ZTCP_PACKET_INVALID -1 - Invalid state;
 ZTCP_PACKET_EMPTY 0 - OK state;
*/

 std::string str_in;
/*
 When message is received in str_in then function onRead(zPacketTCP* p) is called.
*/
 std::string str_out;
 std::string message;
/*
 You can use message to execute messages received in str_in.
*/

 size_t pos;

 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port(proxy or browser).
 unsigned port; // socket port on which the connection was opened.
 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zPacketTCP* p) function will be called in case of no read/write events.
*/

virtual void send(const std::string& msg);
/*
 Sends message msg to client. The message will be queued.
*/

virtual void close() { push(); };
/*
 Closes connection and removes packet.
 The function zPacketThread::onClose(zPacketTCP* p) will not be called.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zPacketTCP();
virtual ~zPacketTCP();

private:

 ZCED(zPacketTCP)

};

class zPoolTCP: public zPool<zPacket>
{

friend class zPacketTCP;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 public:

 zPoolTCP(): zPool<zPacket>() {};

 virtual ~zPoolTCP();

 virtual zPacketTCP* get(zPacketThread* prn);

private:

 ZCED(zPoolTCP)

};

class zClientTCP: public zPacket
{

friend class zPoolClientTCP;
template<class T> friend class zPool;

public:

mutable int status;
/*
 Defines packet's status.
 ZTCP_CLIENT_INVALID -1 - Invalid state;
 ZTCP_CLIENT_EMPTY 0 - Initial state;
 ZTCP_CLIENT_CONNECTED 1 - Connection is established;
*/

 std::string str_in;
/*
 When message is received in str_in then function onRead(zClientTCP* p) is called.
*/

 std::string str_out;
 std::string message;
/*
 You can use message to execute messages received in str_in.
*/

 size_t pos;

 std::string host; // host on which the connection was opened.
 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port.
 unsigned port; // socket port on which the connection was opened.
 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zClientTCP* p) function will be called in case of no read/write events.
*/

virtual void send(const std::string& msg);
/*
 Sends message msg to server. The message will be queued.
*/

virtual void close() { push(); };
/*
 Closes connection and removes client.
 The function zPacketThread::onClose(zClientTCP* p) will not be called.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zClientTCP();
virtual ~zClientTCP();

private:

 ZCED(zClientTCP)

};

class zPoolClientTCP: public zPool<zPacket>
{

friend class zClientTCP;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 public:

 zPoolClientTCP(): zPool<zPacket>() {};

 virtual ~zPoolClientTCP();

 virtual zClientTCP* get(zPacketThread* prn);

private:

 ZCED(zPoolClientTCP)

};

class zClientWS: public zPacket
{

friend class zPoolClientWS;
template<class T> friend class zPool;

public:

static size_t header_max_length;
static size_t packet_max_length;
/*
 Maximum size of http header and ws body.
*/

static int parse(zClientWS* src);

mutable int status;
/*
 Defines packet's status.
 ZWS_CLIENT_INVALID -1 - Invalid state;
 ZWS_CLIENT_EMPTY 0 - Initial state;
 ZWS_CLIENT_HEADER 1 - Tries to read Header;
 ZWS_CLIENT_CONNECTED 2 - WS Connection is established;
 ZWS_CLIENT_CLOSED 4 - Connection is closed;
*/

 std::string str_header;
/*
 str_header is http header with last \r\n\r\n.
*/

 std::string str_in;
 std::string str_out;
 std::string message;
/*
 When message is received then function onMessage(zClientWS* p) is called.
*/
 std::string complete_message;
/*
 Can be used to execute fragmented messages.
*/

 bool fin_flag;
/*
 true for complete message;
 false for fragmented not last message.
*/

 size_t opcode;
/*
0x01 - text message;
0x02 - binary message;
0x00 - fragmented not first message;
*/

 size_t pos;

 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port.
 std::string host; // host in http response (for example www.example.com)
 unsigned port; // socket port on which the connection was opened.
 std::string http_code; // Reply HTTP Status Code.
 std::string http_version; // HTTP version.
 std::string ws_version; //WS version.
 std::string ws_key; //WS key.
 std::string path; // http request path.

 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zClientWS* p) function will be called in case of no read/write events.
*/

 size_t max_header;
 size_t max_body;
/*
 By default:
 max_header = zClientWS::header_max_length;
 max_body = zClientWS::packet_max_length;
*/

 std::map<std::string,std::string> head;
/*
 HEAD of the http message. All names are set to uppercase(UPGRADE: websocket).
*/

virtual void send(const std::string& msg, bool fragmented=false);
/*
 Sends message msg to server, bool fragmented defines the fragmented type of message.
 The message will be queued.
*/

virtual void close();
/*
 Sends close message to server and then close connection.
 The function zPacketThread::onClose(zClientWS* p) will be called.
*/

virtual void ping();
virtual void pong();
/*
 Sends ping/pong message.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zClientWS();
virtual ~zClientWS();

mutable size_t last_fragmented_count;

private:

 ZCED(zClientWS)

};

class zPoolClientWS: public zPool<zPacket>
{

friend class zClientWS;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 public:

 zPoolClientWS(): zPool<zPacket>() {};

 virtual ~zPoolClientWS();

 virtual zClientWS* get(zPacketThread* prn);

private:

 ZCED(zPoolClientWS)

};

class zClientHTTP: public zPacket
{

friend class zPoolClientHTTP;
template<class T> friend class zPool;
friend class zPacketThread;

public:

static size_t header_max_length;
static size_t packet_max_length;
/*
 Maximum size of http header and body.
*/

static int parse(zClientHTTP* src);

mutable int status;
/*
 Defines packet's status.
 ZHTTP_CLIENT_INVALID -1 - Invalid state;
 ZHTTP_CLIENT_EMPTY 0 - Initial state;
 ZHTTP_CLIENT_CONNECTED 1 - Connection is established;
 ZHTTP_CLIENT_SENT 2 - Request is sending or was sent.
 ZHTTP_CLIENT_HEADER 4 - Header is read;
 ZHTTP_CLIENT_COMPLETE 8 - Reply is OK;
*/

 std::string str_header;
 std::string str_in;
 std::string str_out;
/*
 str_header is http header with last \r\n\r\n.
 str_in is http body.
 str_out is output buffer.
*/

 size_t pos;

 std::string address; // ip address on which the connection was opened.
 unsigned peerport; // peer port.
 std::string host; // host in http response (for example www.example.com)
 unsigned port; // socket port on which the connection was opened.
 std::string version; // HTTP version.
 std::string http_code; // Reply HTTP Status Code.
 std::string content_type; // Content-Type from head.

 bool keep_alive;
/*
 Reply: if Connection: close (by default) then keep_alive is false, if Connection: keep_alive then keep_alive is true.
*/

 size_t time_out;
/*
 Defines timeout in milliseconds after which the onTimeout(zClientHTTP* p) function will be called in case of no read/write events.
*/

 size_t max_header;
 size_t max_body;
/*
 By default:
 max_header = zClientHTTP::header_max_length;
 max_body = zClientHTTP::packet_max_length;
*/

 size_t length; // length of the message body
 bool chunked;
/*
 If Transfer-Encoding: chunked then chunked is true, chunked is false in other cases.
*/

 std::map<std::string,std::string> head;
/*
 HEAD of the http message. All names are set to uppercase(CONNECTION: keep_alive).
*/

virtual void write(const std::string &src) { str_out+=src; };
/*
 Sets body reply: str_out+=src;.
*/

virtual void send(const std::string& hdr="");
/*
 Sends request with http header hdr.
*/

virtual void close() { push(); };
/*
 Closes connection and removes client.
 The function zPacketThread::onClose(zClientHTTP* p) will not be called.
*/

virtual void execute(int s, short what);
virtual void clear();

protected:

 zClientHTTP();
virtual ~zClientHTTP();

mutable std::string address_port;

private:

 ZCED(zClientHTTP)

};

class zPoolClientHTTP: public zPool<zPacket>
{

friend class zClientHTTP;
friend class zPacketThread;

 protected:

 virtual zPacket* create();

 virtual bool push(zPacket* p);

 virtual bool drop(zPacket* p);

 public:

 zPoolClientHTTP(): zPool<zPacket>(), keep_value() {};

 virtual ~zPoolClientHTTP();

 virtual zClientHTTP* get(zPacketThread* prn);

 virtual zClientHTTP* get(const std::string& adr_prt);

 virtual zClientHTTP* setKeep(zClientHTTP* p);
 virtual zClientHTTP* eraseKeep(zClientHTTP* p);

 mutable std::map<std::string, zChronoPool<zClientHTTP> > keep_value;

private:

 ZCED(zPoolClientHTTP)

};

class zPacketThread: public zPacket, public zThread
{

public:

enum zProto
{
 PROTO_HTTP=1,
 PROTO_WS=2,
 PROTO_TCP=4
};
/*
 Server Socket types.
*/

class zPTParam
{
 public:

 zPTParam(zPacketThread::zProto prt=zPacketThread::PROTO_HTTP, SSL_CTX* sctx=NULL):
  proto(prt),
  ctx(sctx)
 {};

 zPacketThread::zProto proto;
 SSL_CTX* ctx;
};
/*
 A class for describing of server socket and SSL_CTX structure.
*/

 zPacketThread(int s, const zPacketThread::zPTParam& proto);
 zPacketThread(const std::map<int, zPacketThread::zPTParam>& s);
/*
 Creates zPacketThread.
*/

virtual ~zPacketThread();

virtual event* create_event(event_base* eb, short what, void *arg) const { return NULL; };
virtual event* create_event(event_base* eb, short what, void *arg, unsigned sec, unsigned short msec) const { return NULL; };

virtual void clear();
virtual void execute(int s, short what);

virtual void exec_accept(int sk);

virtual void exec_read(zPacketHTTP* p);
virtual void exec_read(zPacketWS* p);
virtual void exec_read(zPacketTCP* p);
virtual void exec_read(zClientTCP* p);
virtual void exec_read(zClientWS* p);
virtual void exec_read(zClientHTTP* p);

virtual void exec_write(zPacketHTTP* p);
virtual void exec_write(zPacketWS* p);
virtual void exec_write(zPacketTCP* p);
virtual void exec_write(zClientTCP* p);
virtual void exec_write(zClientWS* p);
virtual void exec_write(zClientHTTP* p);

virtual void exec_timeout(zPacketHTTP* p);
virtual void exec_timeout(zPacketWS* p);
virtual void exec_timeout(zPacketTCP* p);
virtual void exec_timeout(zClientTCP* p);
virtual void exec_timeout(zClientWS* p);
virtual void exec_timeout(zClientHTTP* p);

virtual void idle() { return; };
/*
 Executes from time to time.
*/

virtual void onAccept(zPacketHTTP* p) { return; };
/*
 Is called on accept connection.
*/
virtual void onHeader(zPacketHTTP* p) { return; };
/*
 Is called when the header has already been processed.
*/
virtual void onRead(zPacketHTTP* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zPacketHTTP* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onMessage(zPacketHTTP* p) =0;
/*
 Is called when http request has completely been received.
*/
virtual bool onTimeout(zPacketHTTP* p) { return false; };
/*
 Is called when there is no event for specified timeout p->time_out.
 Return false to close connection, return true to save connection.
*/
virtual void onClose(zPacketHTTP* p) { return; };
/*
 Is called before p is removed.
*/


virtual void onAccept(zPacketWS* p) { return; };
/*
 Is called on accept connection.
*/
virtual void onOpen(zPacketWS* p) { p->accept(); };
/*
 Is called when connection and ws-handshake has been established.
 p->accept() accepts connection with additional parameters.
 If accept(const std::map<std::string, std::string>& add_header) is not called the connection will be closed.
*/
virtual void onRead(zPacketWS* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zPacketWS* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onMessage(zPacketWS* p) { return; };
/*
 Is called when message has been received.
*/
virtual void onTimeout(zPacketWS* p) { return; };
/*
 Is called when there is no event for specified timeout p->time_out.
*/
virtual void onClose(zPacketWS* p) { return; };
/*
 Is called before p is removed.
*/

virtual void onAccept(zPacketTCP* p) { return; };
/*
 Is called on accept connection.
*/
virtual void onRead(zPacketTCP* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zPacketTCP* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onTimeout(zPacketTCP* p) { return; };
/*
 Is called when there is no event for specified timeout p->time_out.
*/
virtual void onClose(zPacketTCP* p) { return; };
/*
 Is called before p is removed.
*/

virtual void onOpen(zClientHTTP* p) { return; };
/*
 Is called when connection has been established.
*/
virtual void onHeader(zClientHTTP* p) { return; };
/*
 Is called when the header has already been processed.
*/
virtual void onRead(zClientHTTP* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zClientHTTP* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onMessage(zClientHTTP* p) { return; };
/*
 Is called when message has been received.
*/
virtual bool onTimeout(zClientHTTP* p) { return false; };
/*
 Is called when there is no event for specified timeout p->time_out.
 Return false to close connection, return true to save connection.
*/
virtual void onClose(zClientHTTP* p) { return; };
/*
 Is called before p is removed.
*/

virtual void onOpen(zClientWS* p) { return; };
/*
 Is called when connection and ws-handshake has been established.
*/
virtual void onRead(zClientWS* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zClientWS* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onMessage(zClientWS* p) { return; };
/*
 Is called when message has been received.
*/
virtual void onTimeout(zClientWS* p) { return; };
/*
 Is called when there is no event for specified timeout p->time_out.
*/
virtual void onClose(zClientWS* p) { return; };
/*
 Is called before p is removed.
*/

virtual void onOpen(zClientTCP* p) { return; };
/*
 Is called when connection has been established.
*/
virtual void onRead(zClientTCP* p) { return; };
/*
 Is called after reading any bytes when the header has already been processed.
*/
virtual void onWrite(zClientTCP* p) { return; };
/*
 Is called after p->str_out has completely been sent.
*/
virtual void onTimeout(zClientTCP* p) { return; };
/*
 Is called when there is no event for specified timeout p->time_out.
*/
virtual void onClose(zClientTCP* p) { return; };
/*
 Is called before p is removed.
*/

virtual zClientTCP* connectTCP(const std::string& adr,unsigned short port, SSL_CTX* cctx=NULL);
virtual zClientTCP* connectTCP6(const std::string& adr,unsigned short port, SSL_CTX* cctx=NULL);
/*
 Tries to set connection to adr:port.
 If cctx is not NULL the encrypted connection is established.
 If connection has been established then onOpen(zClientTCP* p) is called.
 If connection has been failed then onClose(zClientTCP* p) is called.
 connectTCP - ipv4, connectTCP6 - ipv6.
*/
virtual zClientWS* connectWS(const std::string& adr,unsigned short port, const std::string& path="/", const std::string& version="13", SSL_CTX* cctx=NULL, const std::map<std::string, std::string>& add_header=std::map<std::string, std::string>());
virtual zClientWS* connectWS6(const std::string& adr,unsigned short port, const std::string& path="/", const std::string& version="13", SSL_CTX* cctx=NULL, const std::map<std::string, std::string>& add_header=std::map<std::string, std::string>());
/*
 Tries to set connection to adr:port.
 If cctx is not NULL the encrypted connection is established.
 path - http path, version - ws version, add_header - additional header lines for request.
 If connection has been established then onOpen(zClientWS* p) is called.
 If connection has been failed then onClose(zClientWS* p) is called.
 connectWS - ipv4, connectWS6 - ipv6.
*/
virtual zClientHTTP* connectHTTP(const std::string& adr,unsigned short port, SSL_CTX* cctx=NULL);
virtual zClientHTTP* connectHTTP6(const std::string& adr,unsigned short port, SSL_CTX* cctx=NULL);
/*
 Tries to set connection to adr:port.
 If cctx is not NULL the encrypted connection is established.
 If connection has been established then onOpen(zClientHTTP* p) is called.
 If connection has been failed then onClose(zClientHTTP* p) is called.
 connectHTTP - ipv4, connectHTTP6 - ipv6.
*/
virtual zClientHTTP* getClientHTTP(const std::string& adr,unsigned short port);
virtual zClientHTTP* getClientHTTP6(const std::string& adr,unsigned short port);
/*
 Returns already established connections that have been stored as keep_alive.
 If such connections were not found then NULL is returned.
 getClientHTTP - ipv4, getClientHTTP6 - ipv6.
*/

mutable event_base* ev_base;
mutable int m_sleep_flag;

mutable zPoolHTTP http_pool;
mutable zPoolWS ws_pool;
mutable zPoolTCP tcp_pool;
mutable zPoolClientTCP tcp_client_pool;
mutable zPoolClientWS ws_client_pool;
mutable zPoolClientHTTP http_client_pool;

protected:

class zSockSerVal
{
 public:

 zSockSerVal():
  ev(NULL),
  proto(zPacketThread::PROTO_HTTP),
  ctx(NULL)
 {};

 event* ev;
 zPacketThread::zProto proto;
 SSL_CTX* ctx;
};

virtual void run();

mutable std::map<int, zPacketThread::zSockSerVal> sock_serv;

//mutable char m_crd[65536];
mutable char* m_crd;
mutable zRandomGenerator m_rnd;

private:

 ZCED(zPacketThread)

};

#endif // __zPacket_h
















