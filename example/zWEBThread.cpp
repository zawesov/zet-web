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
#include "zWEBThread.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 16384
#define KEEP_WRITE_TIMEOUT 10000
#define WS_TIMEOUT 60000

static bool check_name(const std::string& name, const char* p, size_t plen)
{
 const char* s= name.c_str();
 size_t slen= name.size();
 if(slen == 0) return false;
 if(slen == plen)
 {
  bool bret=true;
  for(size_t i=0; i < plen; i++)
  { if(tolower(s[i]) != tolower(p[i])) { bret=false; break; } }
  if(bret) return true;
 }
 if(plen > 2 && p[0] == '*' && p[1] == '.')
 {
  int i= (slen-1); int j= (plen-1);
  for(; (i > -1) && (j > 0); i--, j--)
  { if(tolower(s[i]) != tolower(p[j])) return false; }
  return true;
 }
 return false;
};

/*
 Check hst domain name for X509* cert.
*/
static bool check_host(X509* cert, const std::string& hst)
{
 std::string host=ZNSTR::trim(hst," \t/\\[]");
 if(cert == NULL || host.empty()) return false;

#ifdef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
 LOG_PRINT_DEBUG("System", "X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT");
 if(X509_check_host(cert, host.c_str(), host.size(), 0, NULL) == 1) { return true; }

 return false;

#else
 LOG_PRINT_DEBUG("System", "X509_OLD_VERSION");
 ASN1_STRING* str;
 STACK_OF(GENERAL_NAME)* altnames;
 const char* p;
 size_t plen;
 altnames = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
 if(altnames)
 {
  int n = sk_GENERAL_NAME_num(altnames);
  GENERAL_NAME* altname;
  for(int i = 0; i < n; i++)
  {
   altname = sk_GENERAL_NAME_value(altnames, i);
   if(altname->type == GEN_DNS)
   {
    str = altname->d.dNSName;
    p= (const char*) ASN1_STRING_data(str);
//    p= (const char*) ASN1_STRING_get0_data(str);
    plen= ASN1_STRING_length(str);
    if(check_name(host, p, plen))
    {
     GENERAL_NAMES_free(altnames);
     return true;
    }
   }
   else if(altname->type == GEN_IPADD)
   {
    str = (ASN1_STRING*) altname->d.iPAddress;
    p= (const char*) ASN1_STRING_data(str);
//    p= (const char*) ASN1_STRING_get0_data(str);
    plen= ASN1_STRING_length(str);
    std::string l;
    for(size_t i=0; i < plen; i++) { if(i) { l+='.'; l+=ZNSTR::toString(p[i]); } else l+=ZNSTR::toString(p[i]); }
    if(check_name(host, l.c_str(), l.size()))
    {
     GENERAL_NAMES_free(altnames);
     return true;
    }
   }
  }
  GENERAL_NAMES_free(altnames);
//  return false;
 }

 X509_NAME* sname = X509_get_subject_name(cert);
 if(sname == NULL) { return false; }
 X509_NAME_ENTRY* entry;
 for(int i= -1;;)
 {
  i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);
  if(i < 0) { break; }
  entry = X509_NAME_get_entry(sname, i);
  str = X509_NAME_ENTRY_get_data(entry);
  p= (const char*) ASN1_STRING_data(str);
//  p= (const char*) ASN1_STRING_get0_data(str);
  plen= ASN1_STRING_length(str);
  if(check_name(host, p, plen)) { return true; }
 }
 return false;
#endif
};

/*
 zFileParam class for sending files in parts.
 zFileParam is associated with a zPacketHTTP object.
*/
class zFileParam: public zParamPacket
{
public:
 zFileParam(zPacket* prn, const std::string &path):
  zParamPacket(prn),
  f(path, false),
  pos(0),
  pos_end(-1),
  fin(0)
 {};

virtual void clear() { /*parent->ext=NULL;*/ delete this; };

 zFile f;
 longlong pos;
 longlong pos_end;
 int fin;
};

/*
 zHTTPPacketParam class for binding with zClientHTTP object(REST Api).
 zHTTPPacketParam is associated with a zPacketHTTP object as zParamPacket* ext member.
*/
class zHTTPPacketParam: public zParamPacket
{
public:
 zHTTPPacketParam(zPacket* prn, zClientHTTP* cln):
  zParamPacket(prn),
  client(cln)
 {};

virtual ~zHTTPPacketParam();

virtual void clear() { /*parent->ext=NULL;*/ delete this; };

 zClientHTTP* client;

};

/*
 zHTTPClientParam class for binding with zPacketHTTP object(REST Api).
 zHTTPClientParam is associated with a zClientHTTP object as zParamPacket* ext member.
*/
class zHTTPClientParam: public zParamPacket
{
public:
 zHTTPClientParam(zPacket* prn, zPacketHTTP* pct):
  zParamPacket(prn),
  packet(pct),
  response(0)
 {};

virtual ~zHTTPClientParam();

virtual void clear() { /*parent->ext=NULL;*/ delete this; };

 zPacketHTTP* packet;
 int response;

};

/*
 If zPacketHTTP is bound with zClientHTTP then pointer to itself is set to NULL;
*/
zHTTPPacketParam::~zHTTPPacketParam()
{
 if(client && client->ext)
 {
//  zHTTPClientParam* p= dynamic_cast<zHTTPClientParam*>(client->ext);
  zHTTPClientParam* p= zPacket::getParam<zHTTPClientParam>(client);
  if(p) p->packet=NULL;
 }
};

/*
 If zClientHTTP is bound with zPacketHTTP then pointer to itself is set to NULL;
*/
zHTTPClientParam::~zHTTPClientParam()
{
 if(packet && packet->ext)
 {
//  zHTTPPacketParam* p= dynamic_cast<zHTTPPacketParam*>(packet->ext);
  zHTTPPacketParam* p= zPacket::getParam<zHTTPPacketParam>(packet);
  if(p) p->client=NULL;
 }
};

/*
 zWSPacketParam class for binding with zClientWS object(REST Api).
 zWSPacketParam is associated with a zPacketWS object as zParamPacket* ext member.
*/
class zWSPacketParam: public zParamPacket
{
public:
 zWSPacketParam(zPacket* prn, zClientWS* cln):
  zParamPacket(prn),
  client(cln)
 {};

virtual ~zWSPacketParam();

virtual void clear() { /*parent->ext=NULL;*/ delete this; };

 zClientWS* client;

};

/*
 zWSClientParam class for binding with zPacketWS object(REST Api).
 zWSClientParam is associated with a zClientWS object as zParamPacket* ext member.
*/
class zWSClientParam: public zParamPacket
{
public:
 zWSClientParam(zPacket* prn, zPacketWS* pct):
  zParamPacket(prn),
  packet(pct)
 {};

virtual ~zWSClientParam();

virtual void clear() { /*parent->ext=NULL;*/ delete this; };

 zPacketWS* packet;

};

/*
 If zPacketWS is bound with zClientWS then pointer to itself is set to NULL;
*/
zWSPacketParam::~zWSPacketParam()
{
 if(client && client->ext)
 {
//  zWSClientParam* p= dynamic_cast<zWSClientParam*>(client->ext);
  zWSClientParam* p= zPacket::getParam<zWSClientParam>(client);
  if(p) p->packet=NULL;
 }
};

/*
 If zClientWS is bound with zPacketWS then pointer to itself is set to NULL;
*/
zWSClientParam::~zWSClientParam()
{
 if(packet && packet->ext)
 {
//  zWSPacketParam* p= dynamic_cast<zWSPacketParam*>(packet->ext);
  zWSPacketParam* p= zPacket::getParam<zWSPacketParam>(packet);
  if(p) p->client=NULL;
 }
};

SSL_CTX* zWEBThread::client_ctx=NULL;

/*
 Send proxy reply through zClientHTTP.
*/
static void sendReply(zClientHTTP* p, const std::string& message)
{
// zHTTPClientParam* pc= dynamic_cast<zHTTPClientParam*>(p->ext);
 zHTTPClientParam* pc= zPacket::getParam<zHTTPClientParam>(p);
 if(pc == NULL || pc->packet == NULL)
 {
  LOG_PRINT_DEBUG("zClientHTTP", "sendReply: pc == NULL || pc->packet == NULL???");
  return;
 }
 if(pc->response) return;
 pc->response=1;
 pc->packet->write(message);
 pc->packet->send("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "+ZNSTR::toString(pc->packet->str_out.size())+"\r\nConnection: "+((pc->packet->keep_alive)?"keep-alive":"close")+"\r\n\r\n");
};

/*
 Send proxy reply through zClientWS.
*/
static void sendReply(zClientWS* p, const std::string& message)
{
 zWSClientParam* pc= zPacket::getParam<zWSClientParam>(p);
 if(pc && pc->packet && pc->packet->status == ZWS_PACKET_ACCEPTED)
 { pc->packet->send(message, false); }
 else p->close();
};

/*
 Send proxy request through zClientHTTP.
*/
static void sendRequest(zClientHTTP* p)
{
// zHTTPClientParam* pc= dynamic_cast<zHTTPClientParam*>(p->ext);
 zHTTPClientParam* pc= zPacket::getParam<zHTTPClientParam>(p);
 if(pc == NULL || pc->packet == NULL)
 {
  LOG_PRINT_DEBUG("zWEBThread", "sendRequest: pc == NULL || pc->packet == NULL???");
  p->close();
  return;
 }
 p->write(pc->packet->str_in);
 p->send(pc->packet->str_header);
};

/*
 onMessage is called when http request has completely been received.
*/
void zWEBThread::onMessage(zPacketHTTP* p)
{
 if(p == NULL) return;

 LOG_PRINT_DEBUG("zWEBThread", p->str_header+p->str_in);

/*
 If file is found then send file in parts.
*/
 {
  std::string file_path=ZNSTR::replace(ZNSTR::trim(p->path," \t/\\"),"..","");
  if(!file_path.empty() && ZNFILE::check("./files/"+file_path))
  {
   p->keep_alive=false;
   bool bct=false;
   size_t n=file_path.rfind('.');
   if(n != std::string::npos)
   {
    std::string q=ZNSTR::toLower(file_path.substr(n+1));
    if(q == "html" || q == "htm") bct=true;
   }
   zFileParam* pf= new zFileParam(p, "./files/"+file_path);
   p->ext= pf;
   pf->pos_end=pf->f.size();
   if(p->ranges.size())
   {
    if(p->ranges[0].first < 0 && p->ranges[0].second < 0) { if(pf->pos_end > -p->ranges[0].first) pf->pos= (pf->pos_end-p->ranges[0].first); }
    else if(p->ranges[0].first >= 0 && p->ranges[0].second < 0) { pf->pos= p->ranges[0].first; }
    else if(p->ranges[0].first >= 0)
    {
     pf->pos= p->ranges[0].first;
     if(p->ranges[0].second >= pf->pos && p->ranges[0].second < pf->pos_end) pf->pos_end=(p->ranges[0].second+1);
    }
   }
//   p->send("HTTP/1.1 200 OK\r\nContent-Type: "+(bct?std::string("text/html"):("application/octet-stream\r\nContent-Disposition: attachment; filename=\""+file_path+"\""+(l?("\r\nContent-Range: bytes 0-"+ZNSTR::toString(l-1)+"/"+ZNSTR::toString(l)):"")))+"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
//   p->send("HTTP/1.1 200 OK\r\nContent-Type: "+(bct?std::string("text/html"):("application/octet-stream\r\nContent-Disposition: attachment; filename=\""+file_path+"\""+(l?("\r\nContent-Range: bytes 0-"+ZNSTR::toString(l-1)+"/"+ZNSTR::toString(l)):"")))+"\r\nContent-Length: "+ZNSTR::toString(l)+"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
   p->send("HTTP/1.1 200 OK\r\nContent-Type: "+(bct?std::string("text/html"):("application/octet-stream\r\nContent-Disposition: attachment; filename=\""+file_path+"\""+(pf->pos_end?("\r\nContent-Range: bytes "+ZNSTR::toString(pf->pos)+"-"+ZNSTR::toString(pf->pos_end-1)+"/"+ZNSTR::toString(pf->pos_end)):"")))+"\r\nContent-Length: "+ZNSTR::toString(pf->pos_end-pf->pos)+"\r\nConnection: close\r\n\r\n");
   LOG_PRINT_DEBUG("zWEBThread", p->str_out);
   return;
  }
 }

/*
 If path is 'proxy' then send request through proxy.
*/
 if(ZNSTR::trim(p->path," \t/\\") == "proxy")
 {
  size_t n=p->str_header.find("proxy");
  if(n != std::string::npos)
  {
   int fml= p->family();
/*
 Check already established connections that have been stored as keep_alive.
*/
   zClientHTTP* cp= NULL; 
   switch(fml)
   {
    case AF_INET: { cp= getClientHTTP(p->host,p->port); break; }
    case AF_INET6: { cp= getClientHTTP6(p->host,p->port); break; }
   }
/*
  Try to set connection to host:port.
*/
   bool bka=false;
   if(cp == NULL)
   {
    switch(fml)
    {
     case AF_INET:
     {
      LOG_PRINT_DEBUG("zWEBThread", "connectHTTP family is AF_INET.");
      cp= connectHTTP(p->host,p->port, (p->ssl && zWEBThread::client_ctx)?(zWEBThread::client_ctx):(NULL));
      break;
     }
     case AF_INET6:
     {
      LOG_PRINT_DEBUG("zWEBThread", "connectHTTP6 family is AF_INET6.");
      cp= connectHTTP6(p->host,p->port, (p->ssl && zWEBThread::client_ctx)?(zWEBThread::client_ctx):(NULL));
      break;
     }
     default: { LOG_PRINT_DEBUG("zWEBThread", "connectHTTP is not AF_INET/AF_INET6?"); break; }
    }
   }
   else { bka=true; LOG_PRINT_DEBUG("zWEBThread", "zClientHTTP is gotten from keepalive."); }

   if(cp)
   {
    if(p->ext)
    {
     LOG_PRINT_DEBUG("zWEBThread", "zPacketHTTP->ext is not NULL?");
     delete p->ext;
    }
    if(cp->ext)
    {
     LOG_PRINT_DEBUG("zWEBThread", "zClientHTTP->ext is not NULL?");
     delete cp->ext;
    }
/*
  Set binding between zPacketHTTP and zClientHTTP.
*/
    zHTTPPacketParam* p_prm= new zHTTPPacketParam(p, cp);
    p->ext= p_prm;
    zHTTPClientParam* c_prm= new zHTTPClientParam(cp, p);
    cp->ext= c_prm;
    p->str_header[n]='P'; p->str_header[n+1]='R'; p->str_header[n+2]='O'; p->str_header[n+3]='X'; p->str_header[n+4]='Y';
    if(bka) sendRequest(cp);
    return;
   }
   else { LOG_PRINT_DEBUG("zWEBThread", "Can't create zClientHTTP?"); }
  }
 }

/*
 Send input parameters of http(s).
*/
 p->write(head);
 p->write("<FORM ACTION='");
/*
 if(p->ssl) p->write("https://"); else p->write("http://");
 p->write(p->host+":"+ZNSTR::toString(p->port));
 if(p->param.count("path")) p->write(p->param["path"][0]);
 else p->write(p->path);
*/
 p->write("'ENCTYPE='multipart/form-data' METHOD='POST' NAME='form1'  TARGET='_SELF'>\n");
// p->write("' METHOD='POST' NAME='form1'  TARGET='_SELF'>\n");
 p->write(form);
 p->write("<CENTER>\n<TABLE BORDER=1>\n");
 p->write("<TR><TD>address</TD><TD>"+p->address+"</TD></TR>\n");
 p->write("<TR><TD>peerport</TD><TD>"+ZNSTR::toString(p->peerport)+"</TD></TR>\n");
 p->write("<TR><TD>host</TD><TD>"+p->host+"</TD></TR>\n");
 p->write("<TR><TD>port</TD><TD>"+ZNSTR::toString(p->port)+"</TD></TR>\n");
 p->write("<TR><TD>version</TD><TD>"+p->version+"</TD></TR>\n");
 p->write("<TR><TD>method</TD><TD>"+p->method+"</TD></TR>\n");
 p->write("<TR><TD>path</TD><TD>"+p->path+"</TD></TR>\n");
 p->write("<TR><TD>boundary</TD><TD>"+p->boundary+"</TD></TR>\n");
 p->write("<TR><TD>length</TD><TD>"+ZNSTR::toString(p->length)+"</TD></TR>\n");
 p->write("<TR><TD>chunked</TD><TD>"+std::string(p->chunked?"true":"false")+"</TD></TR>\n");
 p->write("<TR><TD>content_type</TD><TD>"+p->content_type+"</TD></TR>\n");
 p->write("<TR><TD>keep_alive</TD><TD>"+std::string(p->keep_alive?"true":"false")+"</TD></TR>\n");
 p->write("<TR><TD>keep_write</TD><TD>"+std::string(p->keep_write?"true":"false")+"</TD></TR>\n");
 p->write("<TR><TD>time_out</TD><TD>"+ZNSTR::toString(p->time_out)+"</TD></TR>\n");
 p->write("<TR><TD>max_header</TD><TD>"+ZNSTR::toString(p->max_header)+"</TD></TR>\n");
 p->write("<TR><TD>max_body</TD><TD>"+ZNSTR::toString(p->max_body)+"</TD></TR>\n");
 for(size_t i=0; i < p->ranges.size(); i++)
 { p->write("<TR><TD>Ranges["+ZNSTR::toString(i)+"]</TD><TD>"+ZNSTR::toString(p->ranges[i].first)+"-"+ZNSTR::toString(p->ranges[i].second)+"</TD></TR>\n"); }
 for(std::map<std::string,std::string>::const_iterator k= p->head.begin(); k != p->head.end(); ++k)
 { p->write("<TR><TD>head::"+k->first+"</TD><TD>"+k->second+"</TD></TR>\n"); }
 for(std::map<std::string,std::vector<std::string> >::const_iterator k= p->cookie.begin(); k != p->cookie.end(); ++k)
 {
  for(unsigned i=0; i < k->second.size(); i++)
  { p->write("<TR><TD>cookie::"+k->first+"</TD><TD>"+k->second[i]+"</TD></TR>\n"); }
 }
 for(std::map<std::string,std::vector<std::string> >::const_iterator k= p->param.begin(); k != p->param.end(); ++k)
 {
  for(unsigned i=0; i < k->second.size(); i++)
  { p->write("<TR><TD>param::"+k->first+"</TD><TD>"+k->second[i]+"</TD></TR>\n"); }
 }
 for(std::map<std::string,std::vector<std::pair<std::string,std::string> > >::const_iterator k= p->file.begin(); k != p->file.end(); ++k)
 {
  for(unsigned i=0; i < k->second.size(); i++)
  { p->write("<TR><TD>file::"+k->first+"</TD><TD>"+k->second[i].first+"</TD></TR>\n"); }
 }
 p->write("</TABLE>\n</CENTER>\n");
 p->write(bottom);

// p->keep_alive=false;
// p->send_text();
 p->send("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "+ZNSTR::toString(p->str_out.size())+"\r\nConnection: "+((p->keep_alive)?"keep-alive":"close")+"\r\n\r\n");
 LOG_PRINT_DEBUG("zWEBThread", p->str_out);
 return;
};

/*
 Send file in parts.
*/
void zWEBThread::onWrite(zPacketHTTP* p)
{
 if(p->ext == NULL) return;
// zFileParam* pf= dynamic_cast<zFileParam*>(p->ext);
 zFileParam* pf= zPacket::getParam<zFileParam>(p);
 if(pf == NULL)
 {
//  LOG_PRINT_DEBUG("zWEBThread", "onWrite: p->ext is not zFileParam.");
  return;
 }
 if(pf->fin) return;
 longlong l=pf->f.size();
 if(l < (longlong) (pf->pos))
 {
  LOG_PRINT_DEBUG("zWEBThread", "onWrite: pf->f.size()("+ZNSTR::toString(l)+") < pf->f.pos("+ZNSTR::toString((longlong) (pf->pos))+")");
  return;
 }
 size_t c_s=CHUNK_SIZE;
 if((pf->pos_end-pf->pos) < c_s) c_s=(pf->pos_end-pf->pos);
 pf->f.read(p->str_out, pf->pos, c_s);
 if(p->str_out.size() == 0) { pf->pos=pf->pos_end; pf->fin=1; return; }
 size_t n=p->str_out.size();
 pf->pos+=n;
 if(pf->pos >= pf->pos_end) { pf->fin=1; }
};

bool zWEBThread::onTimeout(zPacketHTTP* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "HTTP::onTimeout");
 return false;
};

void zWEBThread::onAccept(zPacketHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "HTTP::onAccept"); };
void zWEBThread::onHeader(zPacketHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "HTTP::onHeader"); };
void zWEBThread::onRead(zPacketHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "HTTP::onRead"); };
void zWEBThread::onClose(zPacketHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "HTTP::onClose"); };

/*
 onOpen is called when connection and ws-handshake has been established.
*/
void zWEBThread::onOpen(zPacketWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "WS::onOpen\n"+p->str_header);
 p->time_out=WS_TIMEOUT;
 p->accept();
 if(ZNSTR::trim(p->path," \t/\\") == "proxy")
 {
/*
  Try to set connection to host:port.
*/
  zClientWS* cp= NULL;
  {
    int fml= p->family();
    switch(fml)
    {
     case AF_INET: { cp= connectWS(p->host, p->port, "/PROXY", "13", (p->ssl && zWEBThread::client_ctx)?(zWEBThread::client_ctx):(NULL)); break; }
     case AF_INET6: { cp= connectWS6(p->host, p->port, "/PROXY", "13", (p->ssl && zWEBThread::client_ctx)?(zWEBThread::client_ctx):(NULL)); break; }
     default: break;
    }
  } 
  if(cp)
  {
   if(p->ext)
   {
    LOG_PRINT_DEBUG("zWEBThread", "zPacketWS->ext is not NULL?");
    delete p->ext;
   }
   if(cp->ext)
   {
    LOG_PRINT_DEBUG("zWEBThread", "zClientWS->ext is not NULL?");
    delete cp->ext;
   }
/*
  Set binding between zPacketWS and zClientWS.
*/
   zWSPacketParam* p_prm= new zWSPacketParam(p, cp);
   p->ext= p_prm;
   zWSClientParam* c_prm= new zWSClientParam(cp, p);
   cp->ext= c_prm;
  }
  else { LOG_PRINT_DEBUG("zWEBThread", "Can't create zClientWS?"); }
 }
};

/*
 onMessage is called when message has been received.
*/
void zWEBThread::onMessage(zPacketWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "WS::onMessage: size="+ZNSTR::toString(p->message.size())+"; fin="+((p->fin_flag)?"1":"0")+"; opcode="+ZNSTR::toString(p->opcode)+";\n"+p->message);
 zWSPacketParam* p_prm= zPacket::getParam<zWSPacketParam>(p);
 if(p_prm)
 {
  if(p_prm->client && p_prm->client->status == ZWS_CLIENT_CONNECTED)
  {
   p_prm->client->send(p->message, (p->fin_flag)?false:true);
  }
  else { p->send("\nProxy connection is not alive.", false); }
  return;
 }
 p->send(p->message, (p->fin_flag)?false:true);
/*
 if(p->fin_flag)
 {
  p->send(p->message, false);
//  if(p->complete_message.empty()) p->send(p->message);
//  else { p->complete_message+=p->message; p->send(p->complete_message); p->complete_message.clear(); }
 }
 else 
 {
  p->send(p->message, true);
//  p->complete_message+=p->message;
//  if(p->complete_message.size() > p->max_body)
//  { LOG_PRINT_DEBUG("zWEBThread", "WS::onMessage: Too long ws packet's body size\n"); p->complete_message.clear(); p->close(); }
 }
*/
};

void zWEBThread::onAccept(zPacketWS* p) { LOG_PRINT_DEBUG("zWEBThread", "WS::onAccept"); };
void zWEBThread::onRead(zPacketWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "WS::onRead:status="+ZNSTR::toString(p->status));
// LOG_PRINT_DEBUG("zWEBThread", "WS::onRead"+ZNSTR::escape(p->str_in));
// LOG_PRINT_DEBUG("zWEBThread", "WS::onRead"+p->str_in);
};
void zWEBThread::onWrite(zPacketWS* p) { LOG_PRINT_DEBUG("zWEBThread", "WS::onWrite"); };
void zWEBThread::onTimeout(zPacketWS* p) { LOG_PRINT_DEBUG("zWEBThread", "WS::onTimeout"); p->ping(); /*p->close();*/ };
void zWEBThread::onClose(zPacketWS* p) { LOG_PRINT_DEBUG("zWEBThread", "WS::onClose"); };

/*
 onOpen is called when connection has been established.
*/
void zWEBThread::onOpen(zClientHTTP* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onOpen");
/*
 Check SSL certificate on client side.
*/
 if(p->ssl)
 {
  X509* cert = ::SSL_get_peer_certificate(p->ssl);
  if(cert)
  {
   if(::SSL_get_verify_result(p->ssl) == X509_V_OK)
   {
    bool bch=check_host(cert, p->host);
    LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::check_host("+p->host+")="+ ZNSTR::toString((int) bch)+";");
   }
   else
   {
    LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::error_verify_result");
    X509_free(cert);
    sendReply(p, "ClientHTTP error verify result");
    p->close();
    return;
   }
   X509_free(cert);
  }
  else
  {
   LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::no_cerificate");
   sendReply(p, "ClientHTTP no cerificate");
   p->close();
   return;
  }
 }
 sendRequest(p);
};

void zWEBThread::onMessage(zClientHTTP* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onMessage");
// zHTTPClientParam* pc= dynamic_cast<zHTTPClientParam*>(p->ext);
 zHTTPClientParam* pc= zPacket::getParam<zHTTPClientParam>(p);
 if(pc == NULL || pc->packet == NULL)
 {
  LOG_PRINT_DEBUG("zWEBThread", "onMessage: pc == NULL || pc->packet == NULL???");
//  p->close();
  return;
 }
 if(pc->response) return;
 pc->response=1;
 pc->packet->write(p->str_in);
 pc->packet->send(p->str_header);
};

void zWEBThread::onHeader(zClientHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onHeader"); };

void zWEBThread::onClose(zClientHTTP* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onClose");
 sendReply(p, "ClientHTTP was closed");
};

void zWEBThread::onRead(zClientHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onRead:status="+ZNSTR::toString(p->status)); };
void zWEBThread::onWrite(zClientHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onWrite"); };
bool zWEBThread::onTimeout(zClientHTTP* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientHTTP::onTimeout"); return false; };

/*
 onOpen is called when connection and ws-handshake has been established.
*/
void zWEBThread::onOpen(zClientWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onOpen");
/*
 Check SSL certificate on client side.
*/
 if(p->ssl)
 {
  X509* cert = ::SSL_get_peer_certificate(p->ssl);
  if(cert)
  {
   if(::SSL_get_verify_result(p->ssl) == X509_V_OK)
   {
    LOG_PRINT_DEBUG("zWEBThread", "ClientWS::check_host("+p->host+")="+ ZNSTR::toString((int) check_host(cert, p->host))+";");
   }
   else
   {
    LOG_PRINT_DEBUG("zWEBThread", "ClientWS::error_verify_result");
    X509_free(cert);
    sendReply(p, "ClientWS error verify result");
    p->close();
    return;
   }
   X509_free(cert);
  }
  else
  {
   LOG_PRINT_DEBUG("zWEBThread", "ClientWS::no_cerificate");
   sendReply(p, "ClientWS no cerificate");
   p->close();
   return;
  }
 }
};

void zWEBThread::onRead(zClientWS* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onRead:status="+ZNSTR::toString(p->status)); };
void zWEBThread::onWrite(zClientWS* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onWrite"); };

void zWEBThread::onMessage(zClientWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onMessaage");
 zWSClientParam* c_prm= zPacket::getParam<zWSClientParam>(p);
 if(c_prm && c_prm->packet && c_prm->packet->status == ZWS_PACKET_ACCEPTED)
 { c_prm->packet->send("PROXY REPLY:\n"+p->message, (p->fin_flag)?false:true); }
 else p->close();
};

void zWEBThread::onTimeout(zClientWS* p) { LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onTimeout"); p->ping(); /*p->close();*/ };

void zWEBThread::onClose(zClientWS* p)
{
 LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onClose");
// zHTTPClientParam* pc= dynamic_cast<zHTTPClientParam*>(p->ext);
 zWSClientParam* pc= zPacket::getParam<zWSClientParam>(p);
 if(pc == NULL || pc->packet == NULL)
 {
  LOG_PRINT_DEBUG("zWEBThread", "ClientWS::onClose: pc == NULL || pc->packet == NULL???");
//  p->close();
 }
};


