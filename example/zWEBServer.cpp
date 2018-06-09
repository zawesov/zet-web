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

#include <algorithm>
#include <functional>
#include <signal.h>

#include "zWEBThread.h"

#define DNS_PERIOD 60
#define THREAD_NUMBER 3
#define HTTP_HOST "127.0.0.1"
#define HTTPS_HOST "127.0.0.1"
#define WS_HOST "127.0.0.1"
#define WSS_HOST "127.0.0.1"
#define HTTP_PORT 12358
#define HTTPS_PORT 12359
#define WS_PORT 11235
#define WSS_PORT 11236
#define BACK_LOG 128
#define HTTPS_CRT "./localhost.crt"
#define HTTPS_KEY "./localhost.key"
#define WSS_CRT "./localhost.crt"
#define WSS_KEY "./localhost.key"

//#define ROTATE_TIMEOUT 60

static bool exit_flag=false;

static void catch_function(int sgn) 
{
 if(sgn == SIGTERM || sgn == SIGINT) exit_flag=true;
};

int main(/* int argc,const char **argv */)
{

#if defined(_WIN32) || defined(_WIN64)
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
 {
  std::cout << "signal(SIGPIPE, SIG_IGN) == SIG_ERR;" << std::endl;
  return 0;
 }
#endif // __GNUG__
#endif // _WIN32 

 if(signal(SIGTERM, catch_function) == SIG_ERR)
 {
  std::cout << "signal(SIGTERM, catch_function) == SIG_ERR;" << std::endl;
  LOG_PRINT_INFO("main", "signal(SIGTERM, catch_function) == SIG_ERR;");
  return 0;
 }
 if(signal(SIGINT, catch_function) == SIG_ERR)
 {
  std::cout << "signal(SIGINT, catch_function) == SIG_ERR;" << std::endl;
  LOG_PRINT_INFO("main", "signal(SIGINT, catch_function) == SIG_ERR;");
  return 0;
 }

/*
 zLog::Log.m_level= ZLOG_INFO;
 zLog::Log.m_level= ZLOG_WARN;
 zLog::Log.m_level= ZLOG_ERROR;
 zLog::Log.m_level= ZLOG_DEBUG;
*/

// std::cout << "OPENSSL_VERSION_NUMBER=" << OPENSSL_VERSION_NUMBER << std::endl;

/*
 Log mode is DEBUG.
*/
 zLog::Log.m_level= ZLOG_DEBUG;
/*
 Period of updating the list of domain names and ip addresses. 
*/
// zDNS::setPeriod(DNS_PERIOD);

/*
 Maximum size of http/ws header and body.
*/

 zPacketHTTP::header_max_length=65536;
 zPacketHTTP::packet_max_length=1048576;

 zPacketWS::header_max_length=65536;
 zPacketWS::packet_max_length=1048576;

 std::map<int, zPacketThread::zPTParam> servsocks;

/*
 Creating a server socket
*/
 {
  int s= ZNSOCKET::server(HTTP_HOST, HTTP_PORT, BACK_LOG);
  if(s < 0)
  {
   std::cout << "Can't open socket: " << HTTP_HOST << ":" << HTTP_PORT << std::endl;
   LOG_PRINT_INFO("main", "Can't open socket: " HTTP_HOST ":"+ZNSTR::toString(HTTP_PORT));
  }
  else
  {
   servsocks[s]=zPacketThread::zPTParam(zPacketThread::PROTO_HTTP);
   std::cout << "HTTP Server socket: " << HTTP_HOST << ":" << HTTP_PORT << std::endl;
   LOG_PRINT_INFO("main", "HTTP Server socket: " HTTP_HOST ":"+ZNSTR::toString(HTTP_PORT));
  }
 
  s= ZNSOCKET::server(WS_HOST, WS_PORT, BACK_LOG);
  if(s < 0)
  {
   std::cout << "Can't open socket: " << WS_HOST << ":" << WS_PORT << std::endl;
   LOG_PRINT_INFO("main", "Can't open socket: " WS_HOST ":"+ZNSTR::toString(WS_PORT));
  }
  else
  {
   servsocks[s]=zPacketThread::zPTParam(zPacketThread::PROTO_WS);
   std::cout << "WS Server socket: " << WS_HOST << ":" << WS_PORT << std::endl;
   LOG_PRINT_INFO("main", "WS Server socket: " WS_HOST ":"+ZNSTR::toString(WS_PORT));
  }

/*
 Creating a server socket and SSL_CTX structures on server side.
*/ 
  s= ZNSOCKET::server(HTTPS_HOST, HTTPS_PORT, BACK_LOG);
  if(s < 0)
  {
   std::cout << "Can't open socket: " << HTTPS_HOST << ":" << HTTPS_PORT << std::endl;
   LOG_PRINT_INFO("main", "Can't open socket: " HTTPS_HOST ":"+ZNSTR::toString(HTTPS_PORT));
  }
  else
  {
   SSL_CTX* ctx= ZNSOCKET::server_ctx(HTTPS_CRT, HTTPS_KEY);
   if(ctx == NULL)
   {
    std::cout << "Can't create SSL_CTX: " << HTTPS_HOST << ":" << HTTPS_PORT << "; " << HTTPS_CRT << " : " << HTTPS_KEY << std::endl;
    LOG_PRINT_INFO("main", "Can't open socket: " HTTPS_HOST ":"+ZNSTR::toString(HTTPS_PORT)+"; " HTTPS_CRT " : " HTTPS_KEY);
   }
   else
   {
/*
 Choose list of available SSL_CIPHERs.
*/
    SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM");
    servsocks[s]=zPacketThread::zPTParam(zPacketThread::PROTO_HTTP, ctx);
    std::cout << "HTTPS Server socket: " << HTTPS_HOST << ":" << HTTPS_PORT << "; " << HTTPS_CRT << " : " << HTTPS_KEY << std::endl;
    LOG_PRINT_INFO("main", "HTTPS Server socket: " HTTPS_HOST ":"+ZNSTR::toString(HTTPS_PORT)+"; " HTTPS_CRT " : " HTTPS_KEY);
   }
  }
 
  s= ZNSOCKET::server(WSS_HOST, WSS_PORT, BACK_LOG);
  if(s < 0)
  {
   std::cout << "Can't open socket: " << WSS_HOST << ":" << WSS_PORT << std::endl;
   LOG_PRINT_INFO("main", "Can't open socket: " WSS_HOST ":"+ZNSTR::toString(WSS_PORT));
  }
  else
  {
   SSL_CTX* ctx= ZNSOCKET::server_ctx(WSS_CRT, WSS_KEY);
   if(ctx == NULL)
   {
    std::cout << "Can't create SSL_CTX: " << WSS_HOST << ":" << WSS_PORT << "; " << WSS_CRT << " : " << WSS_KEY << std::endl;
    LOG_PRINT_INFO("main", "Can't open socket: " WSS_HOST ":"+ZNSTR::toString(WSS_PORT)+"; " WSS_CRT " : " WSS_KEY);
   }
   else
   {
    SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM");
    servsocks[s]=zPacketThread::zPTParam(zPacketThread::PROTO_WS, ctx);
    std::cout << "WSS Server socket: " << WSS_HOST << ":" << WSS_PORT << "; " << WSS_CRT << " : " << WSS_KEY << std::endl;
    LOG_PRINT_INFO("main", "WSS Server socket: " WSS_HOST ":"+ZNSTR::toString(WSS_PORT)+"; " WSS_CRT " : " HTTPS_KEY);
   }
  }
 }

/*
 Creating a SSL_CTX structures on client side.
*/
 zWEBThread::client_ctx= ZNSOCKET::client_ctx();
 if(zWEBThread::client_ctx)
 {
/*
 Locations for ctx, at which CA certificates for verification purposes are located. The certificates available via CAfile and CApath are trusted.
*/
  int r= SSL_CTX_load_verify_locations(zWEBThread::client_ctx, "localhostCA.crt", NULL);
//  std::cout << "SSL_CTX_load_verify_locations= " << r << std::endl;
  LOG_PRINT_DEBUG("main", "SSL_CTX_load_verify_locations="+ZNSTR::toString(r)+";");
 }

 std::set<zWEBThread*> servers;
/*
 Creating THREAD_NUMBER working threads.
*/
 for(int i=0; i < THREAD_NUMBER; i++)
 {
  zWEBThread* p= new zWEBThread(servsocks);
  servers.insert(p);
  p->start();
 }

 std::cout << "Main thread has been started." << std::endl;
 LOG_PRINT_INFO("main", "Main thread has been started.");

 zLog::Log.update();

 for(;;)
 {
/*
 Write log from the buffer to a file.
 Update all hosts stored in database. 
*/
  zLog::Log.update();
  zDNS::update();
/*
  if((zTimer::now()-rt) >= ROTATE_TIMEOUT)
  {
   zLog::Log.rotate();
   rt=zTimer::now();
  }
*/
  if(exit_flag) break;
  zThread::sleep(50);
 }

/*
  Stop, join, delete all working threads.
*/
 for(std::set<zWEBThread*>::iterator k=servers.begin(); k != servers.end(); ++k) { (*k)->stop(); }
 for(std::set<zWEBThread*>::iterator k=servers.begin(); k != servers.end(); ++k) { (*k)->join(); }
 for(std::set<zWEBThread*>::iterator k=servers.begin(); k != servers.end(); ++k) { delete (*k); }
 servers.clear();

/*
 Free SSL_CTX structures on client side.
*/
 if(zWEBThread::client_ctx) { ZNSOCKET::free(zWEBThread::client_ctx); zWEBThread::client_ctx= NULL; }

/*
 Free SSL_CTX structures on server side.
 Close all server sockets.
*/
 for(std::map<int, zPacketThread::zPTParam>::const_iterator k= servsocks.begin(); k != servsocks.end(); ++k)
 {
  ZNSOCKET::free(k->second.ctx);
  ZNSOCKET::close(k->first);
 }
 servsocks.clear();



 std::cout << "Main thread exit." << std::endl;
 LOG_PRINT_INFO("main", "Main thread exit.");

 return 1;
};


