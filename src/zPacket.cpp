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
#include <stdio.h>
#include <stdlib.h>
#include "zPacket.h"

#define ZMAX_PACKET_POOL 100000

#define PARSE_BLANK(p, len, pos)\
{\
 for(;pos < len;++pos) { if(p[pos] == ' ' || p[pos] == '\t') continue; break; }\
 if(pos > len) pos=len;\
}\

#define R_PARSE_BLANK(p, len, pos)\
{\
 for(;pos > len;--pos) { if(p[pos] == ' ' || p[pos] == '\t') continue; break; }\
 if(pos < len) pos=len;\
}\

#define FIND_BLANK(p, len, pos)\
{\
 for(;pos < len;++pos) { if(p[pos] == ' ' || p[pos] == '\t' || p[pos] == '\r' || p[pos] == '\n') break; }\
 if(pos > len) pos=len;\
}\

#define R_FIND_BLANK(p, len, pos)\
{\
 for(;pos > len;--pos) { if(p[pos] == ' ' || p[pos] == '\t' || p[pos] == '\r' || p[pos] == '\n') break; }\
 if(pos < len) pos=len;\
}\

#define FIND_CHAR(p, len, pos, c)\
{\
 for(;pos < len;++pos) { if(p[pos] == c) break; }\
 if(pos > len) pos=len;\
}\

#define R_FIND_CHAR(p, len, pos, c)\
{\
 for(;pos > len;--pos) { if(p[pos] == c) break; }\
 if(pos < len) pos=len;\
}\

#define FIND_END(p, len, pos)\
{\
 for(;pos < len;++pos) { if(p[pos] == '\r' || p[pos] == '\n') break; }\
 if(pos > len) pos=len;\
}\

#define R_FIND_END(p, len, pos)\
{\
 for(;pos > len;--pos) { if(p[pos] == '\r' || p[pos] == '\n') break; }\
 if(pos < len) pos=len;\
}\

#define FIND_STRING(p, len, pos, s, l)\
{\
 if(l == 0 || pos+l > len) pos=len;\
 else\
 {\
  size_t __z_m_len__=len-l+1;\
  size_t __z_m_ret__=len;\
  for(size_t __z_m_i__; pos < __z_m_len__; ++pos)\
  {\
   __z_m_ret__=pos;\
   for(__z_m_i__=0; __z_m_i__ < l; ++__z_m_i__) { if(p[pos+__z_m_i__] != s[__z_m_i__]) { __z_m_ret__=len; break; } }\
   if(__z_m_ret__ == pos) break;\
  }\
  pos=__z_m_ret__;\
 }\
}\


struct zWSH
{
 unsigned char opcode3:1;
 unsigned char opcode2:1;
 unsigned char opcode1:1;
 unsigned char opcode0:1;
 unsigned char rsv3:1;
 unsigned char rsv2:1;
 unsigned char rsv1:1;
 unsigned char fin:1;
 unsigned char len6:1;
 unsigned char len5:1;
 unsigned char len4:1;
 unsigned char len3:1;
 unsigned char len2:1;
 unsigned char len1:1;
 unsigned char len0:1;
 unsigned char mask:1;
};

struct zwsl8
{
 unsigned char b7:1;
 unsigned char b6:1;
 unsigned char b5:1;
 unsigned char b4:1;
 unsigned char b3:1;
 unsigned char b2:1;
 unsigned char b1:1;
 unsigned char b0:1;
};

struct zwsl16
{
 zwsl8 c0;
 zwsl8 c1;
};

struct zwsl32
{
 zwsl8 c0;
 zwsl8 c1;
 zwsl8 c2;
 zwsl8 c3;
};

struct zwsl64
{
 zwsl8 c0;
 zwsl8 c1;
 zwsl8 c2;
 zwsl8 c3;
 zwsl8 c4;
 zwsl8 c5;
 zwsl8 c6;
 zwsl8 c7;
};

static std::string ws_str_head_reply="HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

static std::string ws_add_key="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static std::string ws_hash(const std::string& src)
{
 std::string s(src+ws_add_key);
 unsigned char r[SHA_DIGEST_LENGTH];
 SHA1((const unsigned char*) s.c_str(), s.size(), r);
 s.assign((const char*) r,SHA_DIGEST_LENGTH);
 return ZNSTR::encode_base64(s, false);
};

static void parse_content_type(const std::string& src, std::string& type, std::string& boundary)
{
 boundary.clear();
 type.clear();
 size_t n=src.find_first_of(" \t;,");
 if(n == std::string::npos) { type=src; return; }
 type.assign(src, 0, n);
 n=src.find("boundary", n);
 if(n == std::string::npos) return;
 n=src.find_first_not_of(" \t", n+8);
 if(n == std::string::npos || src[n] != '=') return;
 ++n;
 n=src.find_first_not_of(" \t", n);
 if(n == std::string::npos) return;
 size_t l=src.find_first_of(" \t;,", n);
 boundary.assign(src, n, l-n);
};

static int parse_content_disposition(const std::string& src, size_t pos, size_t pos_end, std::string& name, std::string& filename)
{
 for(size_t pos_eln, pos_str, pos_chr; pos < pos_end;)
 {
  pos_eln=src.find("\r\n",pos);
  pos_chr=src.find(':', pos);
  if(pos_chr == std::string::npos || pos_chr > pos_eln) { pos= pos_eln+2; continue; }
  pos_str=src.find_first_not_of(" \t", pos);
  if((pos_chr-pos_str) < 19) { pos= pos_eln+2; continue; }
  if((src[pos_str]    != 'C' && src[pos_str]    != 'c') || (src[pos_str+1]  != 'O' && src[pos_str+1]  != 'o') || (src[pos_str+2] !=  'N' && src[pos_str+2] !=  'n') ||
     (src[pos_str+3]  != 'T' && src[pos_str+3]  != 't') || (src[pos_str+4]  != 'E' && src[pos_str+4]  != 'e') || (src[pos_str+5] !=  'N' && src[pos_str+5] !=  'n') ||
     (src[pos_str+6]  != 'T' && src[pos_str+6]  != 't') ||           src[pos_str+7] != '-'                    || (src[pos_str+8] !=  'D' && src[pos_str+8] !=  'd') ||
     (src[pos_str+9]  != 'I' && src[pos_str+9]  != 'i') || (src[pos_str+10] != 'S' && src[pos_str+10] != 's') || (src[pos_str+11] != 'P' && src[pos_str+11] != 'p') ||
     (src[pos_str+12] != 'O' && src[pos_str+12] != 'o') || (src[pos_str+13] != 'S' && src[pos_str+13] != 's') || (src[pos_str+14] != 'I' && src[pos_str+14] != 'i') ||
     (src[pos_str+15] != 'T' && src[pos_str+15] != 't') || (src[pos_str+16] != 'I' && src[pos_str+16] != 'i') || (src[pos_str+17] != 'O' && src[pos_str+17] != 'o') ||
     (src[pos_str+18] != 'N' && src[pos_str+18] != 'n'))  { pos= pos_eln+2; continue; }
  pos=pos_chr+1;
  pos_str=src.find("name", pos);
  if(pos_str == std::string::npos || pos_str > pos_eln) return 0;
  pos_str=src.find_first_not_of(" \t", pos_str+4);
  if(src[pos_str] != '=') return 0;
  pos_str=src.find_first_not_of(" \t", pos_str+1);
  if(src[pos_str] != '\"') return 0;
  ++pos_str;
  pos_chr=src.find("\"", pos_str);
  if(pos_chr == std::string::npos || pos_chr > pos_eln) return 0;
  name=ZNSTR::unescape(src.c_str()+pos_str, pos_chr-pos_str);
  filename.clear(); 
  ++pos_chr;
  pos_str=src.find("filename", pos_chr);
  if(pos_str != std::string::npos && pos_str < pos_eln)
  {
   pos_str=src.find_first_not_of(' ',pos_str+8);
   if(pos_str != std::string::npos)
   {
    if(src[pos_str] == '=')
    {
     ++pos_str;
     pos_str=src.find_first_not_of(' ',pos_str);
     if(src[pos_str] == '\"')
     {
      ++pos_str;
      pos_chr=src.find("\"", pos_str);
      if(pos_chr != std::string::npos && pos_chr < pos_eln) { filename=ZNSTR::unescape(src.c_str()+pos_str, pos_chr-pos_str); }
     }
    }
   }
   return 2;
  }
  return 1;
 }
 return 0;
};

static void cb_packet(evutil_socket_t s, short what, void *arg)
{
 zPacket* p= (zPacket*) arg;
 if(p == NULL) return;
 p->execute(s, what);
};

static int parse_header(zPacketHTTP* src)
{
 if(src == NULL) return ZHTTP_PACKET_INVALID;
 if(src->status != ZHTTP_PACKET_EMPTY) return src->status;
 size_t n=(src->str_in).find("\r\n\r\n");
 if(n == std::string::npos) return src->status;
 src->str_header.swap(src->str_in);
 src->str_in.assign(src->str_header, n+4, src->str_header.size()-n-4);
 src->str_header.erase(n+4);
 const char* p=src->str_header.c_str();
 size_t len= src->str_header.size();
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 size_t pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
 src->method=ZNSTR::toUpper(p+pos,pos_end-pos);
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
 size_t pos_chr=pos;
 FIND_CHAR(p, pos_end, pos_chr, '?')
 if(pos_chr >= pos_end) { src->path=ZNSTR::unescape(p+pos, pos_end-pos); }
 else
 {
  src->path=ZNSTR::unescape(p+pos, pos_chr-pos);
  pos=pos_chr+1;
  size_t pos_amp;
  size_t pos_eql;
  size_t pos_srp;
  for(;;)
  {
   pos_amp=pos;
   FIND_CHAR(p, pos_end, pos_amp, '&')
   pos_eql=pos;
   FIND_CHAR(p, pos_amp, pos_eql, '=')
   if(pos_eql < pos_amp)
   {
    pos_srp=pos_eql+1;
    FIND_CHAR(p, pos_amp, pos_srp, '#')
    src->param[ZNSTR::unescape(p+pos, pos_eql-pos)].push_back(ZNSTR::unescape(p+pos_eql+1, pos_srp-pos_eql-1));
   }
   pos=pos_amp+1;
   if(pos >= pos_end) break;
  }
 }
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
 src->version.assign(p+pos,pos_end-pos);
 pos=pos_end;
 FIND_END(p, len, pos)
 if(pos < len)
 {
  if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
  else if(p[pos] == '\n') { ++pos; }
  else { src->status=ZHTTP_PACKET_INVALID; return src->status; }
  size_t pos_bln;
  size_t pos_key;
  size_t pos_val;
  for(;;)
  {
   PARSE_BLANK(p, len, pos)
   if(pos >= len) break;
   pos_end=pos;
   FIND_END(p, len, pos_end)
   if(pos_end >= len) break;
   pos_chr=pos;
   FIND_CHAR(p, pos_end, pos_chr, ':')
   if(pos_chr < pos_end)
   {
    pos_key=pos;
    FIND_BLANK(p, pos_chr, pos_key)
    pos_val=pos_chr+1;
    PARSE_BLANK(p, pos_end, pos_val)
    pos_chr=pos_end-1;
    R_PARSE_BLANK(p, pos_val, pos_chr)
    ++pos_chr;
    src->head[ZNSTR::toUpper(p+pos, pos_key-pos)].assign(p+pos_val, pos_chr-pos_val);
   }
   pos=pos_end;
   if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
   else if(p[pos] == '\n') { ++pos; }
   else { src->status=ZHTTP_PACKET_INVALID; return src->status; }
  }
 }
// cookie parsing
 std::map<std::string,std::string>::const_iterator k=src->head.find("COOKIE");
 if(k != src->head.end())
 {
  p=k->second.c_str();
  pos_end= k->second.size();
  pos=0;
  size_t pos_scn;
  size_t pos_eql;
  size_t pos_key;
  size_t pos_val;
  for(;;)
  {
   PARSE_BLANK(p, pos_end, pos)
   pos_scn=pos;
   FIND_CHAR(p, pos_end, pos_scn, ';')
   pos_eql=pos;
   FIND_CHAR(p, pos_scn, pos_eql, '=')
   if(pos_eql < pos_scn)
   {
    pos_key=pos;
    FIND_BLANK(p, pos_eql, pos_key)
    pos_val=pos_eql+1;
    PARSE_BLANK(p, pos_scn, pos_val)
    pos_eql=pos_scn-1;
    R_PARSE_BLANK(p, pos_val, pos_eql)
    ++pos_eql;
    src->cookie[ZNSTR::unescape(p+pos, pos_key-pos)].push_back(ZNSTR::unescape(p+pos_val, pos_eql-pos_val));
   }
   pos=pos_scn+1;
   if(pos >= pos_end) break;
  }
 }

 k=src->head.find("HOST");
 if(k == src->head.end()) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
 else
 {
  size_t s=k->second.find(':');
  if(s == std::string::npos) 
  {
   src->host=ZNSTR::trim(k->second);
//   src->port=prt;
  }
  else
  {
   src->host=ZNSTR::trim(k->second.substr(0,s));
//   src->port=ZNSTR::asUnsigned(k->second.c_str()+s+1,k->second.size()-s-1,prt);
  }
 }

 src->status = ZHTTP_PACKET_HEADER;

 k=src->head.find("CONNECTION");
 if(k != src->head.end()) { if(ZNSTR::toLower(ZNSTR::trim(k->second)) == "keep-alive") src->keep_alive=true; }

 k=src->head.find("TRANSFER-ENCODING");
 if(k != src->head.end() && ZNSTR::toUpper(ZNSTR::trim(k->second)) == "CHUNKED") src->chunked=true;
 k=src->head.find("CONTENT-LENGTH");
 if(k == src->head.end())
 {
  src->head["CONTENT-LENGTH"]="0";
//  return src->status;
 }
 else { src->length=ZNSTR::toUnsigned(k->second); }
 k=src->head.find("RANGE");
 if(k != src->head.end())
 {
  p=k->second.c_str();
  len= k->second.size();
  pos=0;
  PARSE_BLANK(p, len, pos)
  if(p[pos] == 'b' && p[pos+1] == 'y'  && p[pos+2] == 't' && p[pos+3] == 'e' && p[pos+4] == 's')
  {
   pos+=5;
   PARSE_BLANK(p, len, pos)
   if(p[pos] == '=')
   {
    ++pos;
    longlong range1, range2;
    for(;;)
    {
     PARSE_BLANK(p, len, pos)
     pos_end=pos;
     FIND_CHAR(p, len, pos_end, ',')
     if(p[pos] == '-') pos_chr=pos+1;
     else pos_chr=pos;
     FIND_CHAR(p, pos_end, pos_chr, '-')
     range1= ZNSTR::asLongLong(p+pos, pos_chr-pos, 0);
     if(range1 == ZNSTR::asLongLong(p+pos, pos_chr-pos, -1))
     {
      if(pos_chr >= pos_end) range2=-1;
      else { range2=ZNSTR::asLongLong(p+pos_chr+1, pos_end-pos_chr-1, -1); }
      src->ranges.push_back(std::pair<longlong, longlong>(range1, range2));
     }
     pos=pos_end+1;
     if(pos >= len) break;
    }
   }
  }
 }
 return src->status;
};

static int parse_header(zClientHTTP* src)
{
 if(src == NULL) return ZHTTP_CLIENT_INVALID;
 if(src->status != ZHTTP_CLIENT_SENT) return src->status;
 size_t n=(src->str_in).find("\r\n\r\n");
 if(n == std::string::npos) return src->status;
 src->str_header.swap(src->str_in);
 src->str_in.assign(src->str_header, n+4, src->str_header.size()-n-4);
 src->str_header.erase(n+4);
 const char* p=src->str_header.c_str();
 size_t len= src->str_header.size();
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 size_t pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
 src->version.assign(p+pos,pos_end-pos);
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
 src->http_code.assign(p+pos,pos_end-pos);
 pos=pos_end;
 FIND_END(p, len, pos)
 if(pos < len)
 {
  if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
  else if(p[pos] == '\n') { ++pos; }
  else { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
  size_t pos_chr;
  size_t pos_bln;
  size_t pos_key;
  size_t pos_val;
  for(;;)
  {
   PARSE_BLANK(p, len, pos)
   if(pos >= len) break;
   pos_end=pos;
   FIND_END(p, len, pos_end)
   if(pos_end >= len) break;
   pos_chr=pos;
   FIND_CHAR(p, pos_end, pos_chr, ':')
   if(pos_chr < pos_end)
   {
    pos_key=pos;
    FIND_BLANK(p, pos_chr, pos_key)
    pos_val=pos_chr+1;
    PARSE_BLANK(p, pos_end, pos_val)
    pos_chr=pos_end-1;
    R_PARSE_BLANK(p, pos_val, pos_chr)
    ++pos_chr;
    src->head[ZNSTR::toUpper(p+pos, pos_key-pos)].assign(p+pos_val, pos_chr-pos_val);
   }
   pos=pos_end;
   if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
   else if(p[pos] == '\n') { ++pos; }
   else { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
  }
 }

 src->status = ZHTTP_CLIENT_HEADER;

 std::map<std::string,std::string>::const_iterator k=src->head.find("CONNECTION");
 if(k != src->head.end()) { if(ZNSTR::toLower(ZNSTR::trim(k->second)) == "keep-alive") src->keep_alive=true; }

 k=src->head.find("TRANSFER-ENCODING");
 if(k != src->head.end() && ZNSTR::toUpper(ZNSTR::trim(k->second)) == "CHUNKED") src->chunked=true;
 k=src->head.find("CONTENT-LENGTH");
 if(k == src->head.end()) { src->head["CONTENT-LENGTH"]="0"; }
 else { src->length=ZNSTR::toUnsigned(k->second); }
 k=src->head.find("CONTENT-TYPE");
 if(k != src->head.end()) { src->content_type= ZNSTR::trim(k->second); }

 return src->status;
};

static int parse_body(zPacketHTTP* src)
{
 if(src->status != ZHTTP_PACKET_HEADER) return src->status;
 if(src->chunked)
 {
  size_t l= src->str_in.size();
  if(l > 4 && src->str_in[l-1] == '\n' && src->str_in[l-2] == '\r' && src->str_in[l-3] == '\n' && src->str_in[l-4] == '\r' && src->str_in[l-5] == '0')
  {
   std::string str; str.reserve(src->str_in.size());
   int i;
   for(size_t j=0;;)
   {
    l=src->str_in.find("\r\n", j);
    if(l == std::string::npos) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
//    i= ZNSTR::toInt16(src->str_in.substr(j,l-j),-1);
    i= ZNSTR::asInt16(src->str_in.c_str()+j,l-j,-1);
    if(i < 0) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
    if(i == 0 && (l+4) != (src->str_in.size())) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
    if(i == 0)
    {
     src->str_in=str;
     src->length=src->str_in.size();
     src->head["CONTENT-LENGTH"]=ZNSTR::toString(src->length);
//     src->status = ZHTTP_PACKET_COMPLETE;
//     return src->status;
     break;
    }
    if((l+4+i) > src->str_in.size()) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
    str.append(src->str_in,l+2,i);
    j=(l+4+i);
   }
  }
  else return src->status;
 }
 if(src->length > src->str_in.size()) return src->status;
 if(src->length == 0) { src->status= ZHTTP_PACKET_COMPLETE; return src->status; }
 std::map<std::string,std::string>::const_iterator k=src->head.find("CONTENT-TYPE");
 if(k == src->head.end()) { src->status=ZHTTP_PACKET_COMPLETE; return src->status; }
 parse_content_type(k->second, src->content_type, src->boundary);
 if(src->content_type == "application/x-www-form-urlencoded")
 {
  size_t pos=src->str_in.find_first_not_of(" \t\r\n");
  if(pos != std::string::npos)
  {
   size_t pos_end=src->str_in.find_last_not_of(" \t\r\n");
   size_t pos_amp;
   size_t pos_eql;
   size_t pos_srp;
   const char* p=src->str_in.c_str()+pos;
   pos_end=(pos_end+1-pos);
   pos=0;
   for(;;)
   {
    pos_amp=pos;
    FIND_CHAR(p, pos_end, pos_amp, '&')
    pos_eql=pos;
    FIND_CHAR(p, pos_amp, pos_eql, '=')
    if(pos_eql < pos_amp)
    {
     pos_srp=pos_eql+1;
     FIND_CHAR(p, pos_amp, pos_srp, '#')
     src->param[ZNSTR::unescape(p+pos, pos_eql-pos)].push_back(ZNSTR::unescape(p+pos_eql+1, pos_srp-pos_eql-1));
    }
    pos=pos_amp+1;
    if(pos >= pos_end) break;
   }
  }
  src->status=ZHTTP_PACKET_COMPLETE;
  return src->status;
 }
 if(src->content_type != "multipart/form-data" || src->boundary.empty()) { src->status=ZHTTP_PACKET_COMPLETE; return src->status; }
 std::string boundary=("--"+src->boundary);
 std::string next_boundary=("\r\n--"+src->boundary);
 size_t pos=src->str_in.rfind(boundary+"--");
 if(pos == std::string::npos) { src->status=ZHTTP_PACKET_COMPLETE; return src->status; }
 size_t l=boundary.size();
// src->str_in[n+l]='\r'; src->str_in[n+l+1]='\n';
// boundary+="\r\n"; l+=2;
 std::string name,filename;
 pos=0;
 size_t pcd_ret;
 size_t pos_end;
 for(size_t pos_nxt=0;;)
 {
  pos= src->str_in.find(boundary, pos);
  if(pos == std::string::npos || src->str_in[pos+l] != '\r' || src->str_in[pos+l+1] != '\n') { src->status=ZHTTP_PACKET_COMPLETE; return src->status; }
  pos+=(l+2);
  pos_nxt=src->str_in.find(next_boundary, pos);
  if(pos_nxt == std::string::npos) { src->status=ZHTTP_PACKET_COMPLETE; return src->status; }
  pos_end=src->str_in.find("\r\n\r\n", pos);
  if(pos_end == std::string::npos || pos_end > pos_nxt) { pos=pos_nxt; continue; }
  pcd_ret=parse_content_disposition(src->str_in, pos, pos_end, name, filename);
  if(pcd_ret == 0) { pos=pos_nxt; continue; }
  if(pcd_ret == 2) { src->file[name].push_back(std::pair<std::string,std::string>(filename,src->str_in.substr(pos_end+4, pos_nxt-pos_end-4))); }
  else { src->param[name].push_back(src->str_in.substr(pos_end+4, pos_nxt-pos_end-4)); }
  pos=pos_nxt;
 }
};

static int parse_body(zClientHTTP* src)
{
 if(src->status != ZHTTP_CLIENT_HEADER) return src->status;
 if(src->chunked)
 {
  size_t l= src->str_in.size();
  if(l > 4 && src->str_in[l-1] == '\n' && src->str_in[l-2] == '\r' && src->str_in[l-3] == '\n' && src->str_in[l-4] == '\r' && src->str_in[l-5] == '0')
  {
   std::string str; str.reserve(src->str_in.size());
   int i;
   for(size_t j=0;;)
   {
    l=src->str_in.find("\r\n", j);
    if(l == std::string::npos) { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
//    i= ZNSTR::toInt16(src->str_in.substr(j,l-j),-1);
    i= ZNSTR::asInt16(src->str_in.c_str()+j,l-j,-1);
    if(i < 0) { src->status=ZHTTP_PACKET_INVALID; return src->status; }
    if(i == 0 && (l+4) != (src->str_in.size())) { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
    if(i == 0)
    {
     src->str_in=str;
     src->length=src->str_in.size();
     src->head["CONTENT-LENGTH"]=ZNSTR::toString(src->length);
//     src->status = ZHTTP_CLIENT_COMPLETE;
//     return src->status;
     break;
    }
    if((l+4+i) > src->str_in.size()) { src->status=ZHTTP_CLIENT_INVALID; return src->status; }
    str.append(src->str_in,l+2,i);
    j=(l+4+i);
   }
  }
  else return src->status;
 }
 if(src->length > src->str_in.size()) return src->status;
 src->status= ZHTTP_CLIENT_COMPLETE;
 return src->status;
};

static int parse_ws_header(zPacketWS* src)
{
 if(src == NULL) return ZWS_PACKET_INVALID;
 if(src->status != ZWS_PACKET_EMPTY) return src->status;
 size_t n=(src->str_in).find("\r\n\r\n");
 if(n == std::string::npos) return src->status;
 src->str_header.swap(src->str_in);
 src->str_in.assign(src->str_header, n+4, src->str_header.size()-n-4);
 src->str_header.erase(n+4);
 const char* p=src->str_header.c_str();
 size_t len= src->str_header.size();
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 size_t pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZWS_PACKET_INVALID; return src->status; }
 src->method=ZNSTR::toUpper(p+pos,pos_end-pos);
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZWS_PACKET_INVALID; return src->status; }
 src->path=ZNSTR::unescape(p+pos, pos_end-pos);
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZWS_PACKET_INVALID; return src->status; }
 src->http_version.assign(p+pos,pos_end-pos);
 pos=pos_end;
 FIND_END(p, len, pos)
 if(pos < len)
 {
  if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
  else if(p[pos] == '\n') { ++pos; }
  else { src->status=ZWS_PACKET_INVALID; return src->status; }
  size_t pos_chr;
  size_t pos_bln;
  size_t pos_key;
  size_t pos_val;
  for(;;)
  {
   PARSE_BLANK(p, len, pos)
   if(pos >= len) break;
   pos_end=pos;
   FIND_END(p, len, pos_end)
   if(pos_end >= len) break;
   pos_chr=pos;
   FIND_CHAR(p, pos_end, pos_chr, ':')
   if(pos_chr < pos_end)
   {
    pos_key=pos;
    FIND_BLANK(p, pos_chr, pos_key)
    pos_val=pos_chr+1;
    PARSE_BLANK(p, pos_end, pos_val)
    pos_chr=pos_end-1;
    R_PARSE_BLANK(p, pos_val, pos_chr)
    ++pos_chr;
    src->head[ZNSTR::toUpper(p+pos, pos_key-pos)].assign(p+pos_val, pos_chr-pos_val);
   }
   pos=pos_end;
   if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
   else if(p[pos] == '\n') { ++pos; }
   else { src->status=ZWS_PACKET_INVALID; return src->status; }
  }
 }

 std::map<std::string,std::string>::const_iterator k=src->head.find("HOST");
 if(k == src->head.end()) { src->status=ZWS_PACKET_INVALID; return src->status; }
 else
 {
  size_t s=k->second.find(':');
  if(s == std::string::npos) 
  {
   src->host=ZNSTR::trim(k->second);
//   src->port=prt;
  }
  else
  {
   src->host=ZNSTR::trim(k->second.substr(0,s));
//   src->port=ZNSTR::asUnsigned(k->second.c_str()+s+1,k->second.size()-s-1,prt);
  }
 }
/*
 k=src->head.find("CONNECTION");
 if(k == src->head.end() || ZNSTR::toLower(ZNSTR::trim(k->second)) != "upgrade") { src->status=ZWS_PACKET_INVALID; return src->status; }
*/
 k=src->head.find("UPGRADE");
 if(k == src->head.end() || ZNSTR::toLower(ZNSTR::trim(k->second)) != "websocket") { src->status=ZWS_PACKET_INVALID; return src->status; }
 k=src->head.find("SEC-WEBSOCKET-KEY");
 if(k == src->head.end()) { src->status=ZWS_PACKET_INVALID; return src->status; }
 src->ws_key=ZNSTR::trim(k->second);
 k=src->head.find("SEC-WEBSOCKET-VERSION");
 if(k != src->head.end()) { src->ws_version=ZNSTR::trim(k->second); }

 src->status = ZWS_PACKET_HEADER;
 return src->status;
};

static int parse_ws_body(zPacketWS* src)
{
 if(src == NULL) return ZWS_PACKET_INVALID;
 if(src->status == ZWS_PACKET_CLOSED || src->status == ZWS_PACKET_INVALID) { src->str_in.clear(); return src->status; }
 if(src->status != ZWS_PACKET_ACCEPTED) return src->status;
 const char* p=src->str_in.c_str();
 size_t len=src->str_in.size();
 for(size_t pos=0;;)
 {
  if(src->status != ZWS_PACKET_ACCEPTED) break;
  if(len < sizeof(struct zWSH)) { if(pos) { src->str_in.erase(0, pos); } break; }
  const struct zWSH* h=reinterpret_cast<const struct zWSH*>(p);
  unsigned char opcode=0; opcode+=h->opcode0; opcode <<= 1; opcode+=h->opcode1; opcode <<= 1; opcode+=h->opcode2; opcode <<= 1; opcode+=h->opcode3;
  if(opcode == 8) { src->status = ZWS_PACKET_INVALID; src->str_in.clear(); break; }
  unsigned char mask=h->mask;
  if(mask) mask=4;
  unsigned char l=0; l+=h->len0; l <<= 1; l+=h->len1; l <<= 1; l+=h->len2; l <<= 1; l+=h->len3; l <<= 1; l+=h->len4; l <<= 1; l+=h->len5; l <<= 1; l+=h->len6;
  if(l > ((unsigned char) 127)) { src->status=ZWS_PACKET_INVALID; break; }
  if(l == ((unsigned char) 127))
  {
   if(len < (sizeof(struct zWSH)+8+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   ulonglong n=0;
   {
    const struct zwsl64* r=reinterpret_cast<const struct zwsl64*>(p+sizeof(struct zWSH));
             n+=r->c0.b0; n <<= 1; n+=r->c0.b1; n <<= 1; n+=r->c0.b2; n <<= 1; n+=r->c0.b3; n <<= 1; n+=r->c0.b4; n <<= 1; n+=r->c0.b5; n <<= 1; n+=r->c0.b6; n <<= 1; n+=r->c0.b7;
    n <<= 1; n+=r->c1.b0; n <<= 1; n+=r->c1.b1; n <<= 1; n+=r->c1.b2; n <<= 1; n+=r->c1.b3; n <<= 1; n+=r->c1.b4; n <<= 1; n+=r->c1.b5; n <<= 1; n+=r->c1.b6; n <<= 1; n+=r->c1.b7;
    n <<= 1; n+=r->c2.b0; n <<= 1; n+=r->c2.b1; n <<= 1; n+=r->c2.b2; n <<= 1; n+=r->c2.b3; n <<= 1; n+=r->c2.b4; n <<= 1; n+=r->c2.b5; n <<= 1; n+=r->c2.b6; n <<= 1; n+=r->c2.b7;
    n <<= 1; n+=r->c3.b0; n <<= 1; n+=r->c3.b1; n <<= 1; n+=r->c3.b2; n <<= 1; n+=r->c3.b3; n <<= 1; n+=r->c3.b4; n <<= 1; n+=r->c3.b5; n <<= 1; n+=r->c3.b6; n <<= 1; n+=r->c3.b7;
    n <<= 1; n+=r->c4.b0; n <<= 1; n+=r->c4.b1; n <<= 1; n+=r->c4.b2; n <<= 1; n+=r->c4.b3; n <<= 1; n+=r->c4.b4; n <<= 1; n+=r->c4.b5; n <<= 1; n+=r->c4.b6; n <<= 1; n+=r->c4.b7;
    n <<= 1; n+=r->c5.b0; n <<= 1; n+=r->c5.b1; n <<= 1; n+=r->c5.b2; n <<= 1; n+=r->c5.b3; n <<= 1; n+=r->c5.b4; n <<= 1; n+=r->c5.b5; n <<= 1; n+=r->c5.b6; n <<= 1; n+=r->c5.b7;
    n <<= 1; n+=r->c6.b0; n <<= 1; n+=r->c6.b1; n <<= 1; n+=r->c6.b2; n <<= 1; n+=r->c6.b3; n <<= 1; n+=r->c6.b4; n <<= 1; n+=r->c6.b5; n <<= 1; n+=r->c6.b6; n <<= 1; n+=r->c6.b7;
    n <<= 1; n+=r->c7.b0; n <<= 1; n+=r->c7.b1; n <<= 1; n+=r->c7.b2; n <<= 1; n+=r->c7.b3; n <<= 1; n+=r->c7.b4; n <<= 1; n+=r->c7.b5; n <<= 1; n+=r->c7.b6; n <<= 1; n+=r->c7.b7;
   }
//   if(n > src->max_body) { src->status=ZWS_PACKET_INVALID; break; }
   if(len < (sizeof(struct zWSH)+8+n+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+8+n+mask);
   p+=(sizeof(struct zWSH)+8+mask);
   len-=(sizeof(struct zWSH)+8+n+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     char* m=(q-mask);
     for(size_t i=0; i < n; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, n);
    src->parent->onMessage(src);
   }
   p+=n;
  }
  else if(l == ((unsigned char) 126))
  {
   if(len < (sizeof(struct zWSH)+2+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   unsigned short n=0;
   {
    const struct zwsl16* r=reinterpret_cast<const struct zwsl16*>(p+sizeof(struct zWSH));
             n+=r->c0.b0; n <<= 1; n+=r->c0.b1; n <<= 1; n+=r->c0.b2; n <<= 1; n+=r->c0.b3; n <<= 1; n+=r->c0.b4; n <<= 1; n+=r->c0.b5; n <<= 1; n+=r->c0.b6; n <<= 1; n+=r->c0.b7;
    n <<= 1; n+=r->c1.b0; n <<= 1; n+=r->c1.b1; n <<= 1; n+=r->c1.b2; n <<= 1; n+=r->c1.b3; n <<= 1; n+=r->c1.b4; n <<= 1; n+=r->c1.b5; n <<= 1; n+=r->c1.b6; n <<= 1; n+=r->c1.b7;
   }
//   if(n > src->max_body) { src->status=ZWS_PACKET_INVALID; break; }
   if(len < (sizeof(struct zWSH)+2+n+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+2+n+mask);
   p+=(sizeof(struct zWSH)+2+mask);
   len-=(sizeof(struct zWSH)+2+n+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     char* m=(q-mask);
     for(size_t i=0; i < n; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, n);
    src->parent->onMessage(src);
   }
   p+=n;
  }
  else
  {
   if(len < (sizeof(struct zWSH)+l+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+l+mask);
   p+=(sizeof(struct zWSH)+mask);
   len-=(sizeof(struct zWSH)+l+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     const char* m=(q-mask);
     for(size_t i=0; i < l; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, l);
    src->parent->onMessage(src);
   }
   p+=l;
  }
 }
 return src->status;
};

static int parse_ws_header(zClientWS* src)
{
 if(src == NULL) return ZWS_CLIENT_INVALID;
 if(src->status != ZWS_CLIENT_HEADER) return src->status;
 size_t n=(src->str_in).find("\r\n\r\n");
 if(n == std::string::npos) return src->status;
 src->str_header.swap(src->str_in);
 src->str_in.assign(src->str_header, n+4, src->str_header.size()-n-4);
 src->str_header.erase(n+4);
 const char* p=src->str_header.c_str();
 size_t len= src->str_header.size();
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 size_t pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZWS_CLIENT_INVALID; return src->status; }
 src->http_version.assign(p+pos,pos_end-pos);
 pos=pos_end;
 PARSE_BLANK(p, len, pos)
 pos_end=pos;
 FIND_BLANK(p, len, pos_end)
 if(pos_end >= len) { src->status=ZWS_CLIENT_INVALID; return src->status; }
 src->http_code.assign(p+pos,pos_end-pos);
 if(src->http_code != "101") { src->status=ZWS_CLIENT_INVALID; return src->status; }
 pos=pos_end;
 FIND_END(p, len, pos)
 if(pos < len)
 {
  if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
  else if(p[pos] == '\n') { ++pos; }
  else { src->status=ZWS_CLIENT_INVALID; return src->status; }
  size_t pos_chr;
  size_t pos_bln;
  size_t pos_key;
  size_t pos_val;
  for(;;)
  {
   PARSE_BLANK(p, len, pos)
   if(pos >= len) break;
   pos_end=pos;
   FIND_END(p, len, pos_end)
   if(pos_end >= len) break;
   pos_chr=pos;
   FIND_CHAR(p, pos_end, pos_chr, ':')
   if(pos_chr < pos_end)
   {
    pos_key=pos;
    FIND_BLANK(p, pos_chr, pos_key)
    pos_val=pos_chr+1;
    PARSE_BLANK(p, pos_end, pos_val)
    pos_chr=pos_end-1;
    R_PARSE_BLANK(p, pos_val, pos_chr)
    ++pos_chr;
    src->head[ZNSTR::toUpper(p+pos, pos_key-pos)].assign(p+pos_val, pos_chr-pos_val);
   }
   pos=pos_end;
   if(p[pos] == '\r' && p[pos+1] == '\n') { pos+=2; }
   else if(p[pos] == '\n') { ++pos; }
   else { src->status=ZWS_CLIENT_INVALID; return src->status; }
  }
 }
/*
 k=src->head.find("CONNECTION");
 if(k == src->head.end() || ZNSTR::toLower(ZNSTR::trim(k->second)) != "upgrade") { src->status=ZWS_CLIENT_INVALID; return src->status; }
*/
 std::map<std::string,std::string>::const_iterator k=src->head.find("UPGRADE");
 if(k == src->head.end() || ZNSTR::toLower(ZNSTR::trim(k->second)) != "websocket") { src->status=ZWS_CLIENT_INVALID; return src->status; }
 k=src->head.find("SEC-WEBSOCKET-ACCEPT");
 if(k == src->head.end() || src->ws_key != ZNSTR::trim(k->second)) { src->status=ZWS_CLIENT_INVALID; return src->status; }
 src->status = ZWS_CLIENT_CONNECTED;
 return src->status;
};

static int parse_ws_body(zClientWS* src)
{
 if(src == NULL) return ZWS_CLIENT_INVALID;
 if(src->status == ZWS_CLIENT_CLOSED || src->status == ZWS_CLIENT_INVALID) { src->str_in.clear(); return src->status; }
 if(src->status != ZWS_CLIENT_CONNECTED) return src->status;
 const char* p=src->str_in.c_str();
 size_t len=src->str_in.size();
 for(size_t pos=0;;)
 {
  if(src->status != ZWS_CLIENT_CONNECTED) break;
  if(len < sizeof(struct zWSH)) { if(pos) { src->str_in.erase(0, pos); } break; }
  const struct zWSH* h=reinterpret_cast<const struct zWSH*>(p);
  unsigned char opcode=0; opcode+=h->opcode0; opcode <<= 1; opcode+=h->opcode1; opcode <<= 1; opcode+=h->opcode2; opcode <<= 1; opcode+=h->opcode3;
  if(opcode == 8) { src->status = ZWS_CLIENT_INVALID; src->str_in.clear(); break; }
  unsigned char mask=h->mask;
  if(mask) mask=4;
  unsigned char l=0; l+=h->len0; l <<= 1; l+=h->len1; l <<= 1; l+=h->len2; l <<= 1; l+=h->len3; l <<= 1; l+=h->len4; l <<= 1; l+=h->len5; l <<= 1; l+=h->len6;
  if(l > ((unsigned char) 127)) { src->status=ZWS_CLIENT_INVALID; break; }
  if(l == ((unsigned char) 127))
  {
   if(len < (sizeof(struct zWSH)+8+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   ulonglong n=0;
   {
    const struct zwsl64* r=reinterpret_cast<const struct zwsl64*>(p+sizeof(struct zWSH));
             n+=r->c0.b0; n <<= 1; n+=r->c0.b1; n <<= 1; n+=r->c0.b2; n <<= 1; n+=r->c0.b3; n <<= 1; n+=r->c0.b4; n <<= 1; n+=r->c0.b5; n <<= 1; n+=r->c0.b6; n <<= 1; n+=r->c0.b7;
    n <<= 1; n+=r->c1.b0; n <<= 1; n+=r->c1.b1; n <<= 1; n+=r->c1.b2; n <<= 1; n+=r->c1.b3; n <<= 1; n+=r->c1.b4; n <<= 1; n+=r->c1.b5; n <<= 1; n+=r->c1.b6; n <<= 1; n+=r->c1.b7;
    n <<= 1; n+=r->c2.b0; n <<= 1; n+=r->c2.b1; n <<= 1; n+=r->c2.b2; n <<= 1; n+=r->c2.b3; n <<= 1; n+=r->c2.b4; n <<= 1; n+=r->c2.b5; n <<= 1; n+=r->c2.b6; n <<= 1; n+=r->c2.b7;
    n <<= 1; n+=r->c3.b0; n <<= 1; n+=r->c3.b1; n <<= 1; n+=r->c3.b2; n <<= 1; n+=r->c3.b3; n <<= 1; n+=r->c3.b4; n <<= 1; n+=r->c3.b5; n <<= 1; n+=r->c3.b6; n <<= 1; n+=r->c3.b7;
    n <<= 1; n+=r->c4.b0; n <<= 1; n+=r->c4.b1; n <<= 1; n+=r->c4.b2; n <<= 1; n+=r->c4.b3; n <<= 1; n+=r->c4.b4; n <<= 1; n+=r->c4.b5; n <<= 1; n+=r->c4.b6; n <<= 1; n+=r->c4.b7;
    n <<= 1; n+=r->c5.b0; n <<= 1; n+=r->c5.b1; n <<= 1; n+=r->c5.b2; n <<= 1; n+=r->c5.b3; n <<= 1; n+=r->c5.b4; n <<= 1; n+=r->c5.b5; n <<= 1; n+=r->c5.b6; n <<= 1; n+=r->c5.b7;
    n <<= 1; n+=r->c6.b0; n <<= 1; n+=r->c6.b1; n <<= 1; n+=r->c6.b2; n <<= 1; n+=r->c6.b3; n <<= 1; n+=r->c6.b4; n <<= 1; n+=r->c6.b5; n <<= 1; n+=r->c6.b6; n <<= 1; n+=r->c6.b7;
    n <<= 1; n+=r->c7.b0; n <<= 1; n+=r->c7.b1; n <<= 1; n+=r->c7.b2; n <<= 1; n+=r->c7.b3; n <<= 1; n+=r->c7.b4; n <<= 1; n+=r->c7.b5; n <<= 1; n+=r->c7.b6; n <<= 1; n+=r->c7.b7;
   }
//   if(n > src->max_body) { src->status=ZWS_CLIENT_INVALID; break; }
   if(len < (sizeof(struct zWSH)+8+n+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+8+n+mask);
   p+=(sizeof(struct zWSH)+8+mask);
   len-=(sizeof(struct zWSH)+8+n+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     char* m=(q-mask);
     for(size_t i=0; i < n; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, n);
    src->parent->onMessage(src);
   }
   p+=n;
  }
  else if(l == ((unsigned char) 126))
  {
   if(len < (sizeof(struct zWSH)+2+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   unsigned short n=0;
   {
    const struct zwsl16* r=reinterpret_cast<const struct zwsl16*>(p+sizeof(struct zWSH));
             n+=r->c0.b0; n <<= 1; n+=r->c0.b1; n <<= 1; n+=r->c0.b2; n <<= 1; n+=r->c0.b3; n <<= 1; n+=r->c0.b4; n <<= 1; n+=r->c0.b5; n <<= 1; n+=r->c0.b6; n <<= 1; n+=r->c0.b7;
    n <<= 1; n+=r->c1.b0; n <<= 1; n+=r->c1.b1; n <<= 1; n+=r->c1.b2; n <<= 1; n+=r->c1.b3; n <<= 1; n+=r->c1.b4; n <<= 1; n+=r->c1.b5; n <<= 1; n+=r->c1.b6; n <<= 1; n+=r->c1.b7;
   }
//   if(n > src->max_body) { src->status=ZWS_CLIENT_INVALID; break; }
   if(len < (sizeof(struct zWSH)+2+n+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+2+n+mask);
   p+=(sizeof(struct zWSH)+2+mask);
   len-=(sizeof(struct zWSH)+2+n+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     char* m=(q-mask);
     for(size_t i=0; i < n; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, n);
    src->parent->onMessage(src);
   }
   p+=n;
  }
  else
  {
   if(len < (sizeof(struct zWSH)+l+mask)) { if(pos) { src->str_in.erase(0, pos); } break; }
   src->fin_flag=h->fin;
   src->opcode=opcode;
   pos+=(sizeof(struct zWSH)+l+mask);
   p+=(sizeof(struct zWSH)+mask);
   len-=(sizeof(struct zWSH)+l+mask);
   if(opcode == 9) { src->pong(); }
   else if(opcode != 10)
   {
    if(mask)
    {
     char* q=const_cast<char*>(p);
     const char* m=(q-mask);
     for(size_t i=0; i < l; i++) { q[i]^=m[i%mask]; }
    }
    src->message.assign(p, l);
    src->parent->onMessage(src);
   }
   p+=l;
  }
 }
 return src->status;
};

size_t zPacketHTTP::header_max_length=65536;
size_t zPacketHTTP::packet_max_length=1048576;

size_t zClientHTTP::header_max_length=65536;
size_t zClientHTTP::packet_max_length=1048576;

size_t zPacketWS::header_max_length=65536;
size_t zPacketWS::packet_max_length=1048576;

size_t zClientWS::header_max_length=65536;
size_t zClientWS::packet_max_length=1048576;

zParamPacket::~zParamPacket()
{
 if(parent == NULL) return;
 if(parent->ext == this) parent->ext=NULL;
};

zPacket::zPacket():
 pool(NULL), ev(NULL), ev_stor(NULL), tmval(), sock(-1), ssl(NULL), parent(NULL), ext(NULL)
{
 tmval.tv_sec=0; tmval.tv_usec=0;
};

zPacket::~zPacket() { if(ext) { delete ext; } clear_event(); if(ev_stor) { ::event_free(ev_stor); ev_stor=NULL; } clear_socket(); };

void zPacket::clear_event() const { if(ev != NULL) { ::event_del(ev); ev=NULL; tmval.tv_sec=0; tmval.tv_usec=0; } };

short zPacket::get_event() const { if(ev == NULL) return 0; return ::event_get_events(ev); };

void zPacket::clear_socket() const { if(ssl) { ZNSOCKET::free(ssl); ssl=NULL; } if(sock >= 0) { ZNSOCKET::close(sock); sock=-1; } };

void zPacket::clear_ext() const { if(ext) { ext->clear(); } };

event* zPacket::create_event(event_base* eb, short what, void *arg) const
{
 clear_event();
 if(ev_stor == NULL)
 {
  ev_stor= ::event_new(eb, sock, what, cb_packet, arg);
  if(ev_stor == NULL) return ev;
 }
 else if(::event_assign(ev_stor, eb, sock, what, cb_packet, arg) != 0) return ev;
 ev=ev_stor;
 ::event_add(ev, NULL);
 return ev;
};

event* zPacket::create_event(event_base* eb, short what, void *arg, unsigned sec, unsigned short msec) const
{
 clear_event();
 if(ev_stor == NULL)
 {
  ev_stor= ::event_new(eb, sock, what, cb_packet, arg);
  if(ev_stor == NULL) return ev;
 }
 else if(::event_assign(ev_stor, eb, sock, what, cb_packet, arg) != 0) return ev;
 ev=ev_stor;
 tmval.tv_sec= sec; tmval.tv_usec=msec%1000*1000;
 ::event_add(ev, &tmval);
 return ev;
};

zPacketThread::zPacketThread(int s, const zPacketThread::zPTParam& proto):
 zPacket(),
 zThread(),
 ev_base(::event_base_new()),
 m_sleep_flag(0),
 http_pool(),
 ws_pool(),
 tcp_pool(),
 tcp_client_pool(),
 ws_client_pool(),
 http_client_pool(),
 m_rnd((unsigned)(::time(NULL)+((size_t) this)))
{
 parent=this;
 if(s < 0) { clear(); return; }
 zPacketThread::zSockSerVal v;
 v.ev= ::event_new(ev_base, s, EV_READ | EV_PERSIST, cb_packet, (void*) this);
 if(v.ev == NULL) { clear(); return; }
 ::event_add(v.ev, NULL);
 v.proto=proto.proto;
 v.ctx=proto.ctx;
 sock_serv[s]=v;
};

zPacketThread::zPacketThread(const std::map<int, zPacketThread::zPTParam>& s):
 zPacket(),
 zThread(),
 ev_base(::event_base_new()),
 m_sleep_flag(0),
 http_pool(),
 ws_pool(),
 tcp_pool(),
 tcp_client_pool(),
 ws_client_pool(),
 http_client_pool(),
 m_rnd((unsigned)(::time(NULL)+((size_t) this)))
{
 parent=this;
 if(s.size() == 0) { clear(); return; }
 for(std::map<int, zPacketThread::zPTParam>::const_iterator k=s.begin(); k != s.end(); ++k)
 {
  if(k->first < 0) continue;
  zPacketThread::zSockSerVal v;
  v.ev= ::event_new(ev_base, k->first, EV_READ | EV_PERSIST, cb_packet, (void*) this);
  if(v.ev == NULL) continue;
  ::event_add(v.ev, NULL);
  v.proto=k->second.proto;
  v.ctx=k->second.ctx;
  sock_serv[k->first]=v;
 }
 if(sock_serv.size() == 0) { clear(); return; }
};

zPacketThread::~zPacketThread()
{
 clear_event();
 clear();
 sock=-1;
};

void zPacketThread::execute(int s, short what)
{
 idle();
 m_sleep_flag=0;
 exec_accept(s);
// if(testStop()) ::event_base_loopexit(ev_base, NULL);
};

void zPacketThread::clear()
{
 for(std::map<int, zPacketThread::zSockSerVal>::const_iterator k= sock_serv.begin(); k != sock_serv.end(); ++k)
 { if(k->second.ev) { ::event_del(k->second.ev); ::event_free(k->second.ev); } }
 sock_serv.clear();
 if(ev_base) { ::event_base_free(ev_base); ev_base=NULL; }
};

void zPacketThread::run()
{
 if(ev_base == NULL) return;
// LOG_PRINT_INFO("System", "Start event_base_loop\n");
 struct timeval tmth;
 tmth.tv_sec = 0;
 tmth.tv_usec = 1000;
 for(;;)
 {
  idle();
  ::event_base_loop(ev_base, EVLOOP_NONBLOCK);
  if(m_sleep_flag)
  {
   event_base_loopexit(ev_base, &tmth);
   event_base_dispatch(ev_base);
//   zThread::sleep(10);
  }
  m_sleep_flag=1;
  if(testStop()) { ::event_base_loopexit(ev_base, NULL); break; }
 }
// LOG_PRINT_INFO("System", "End event_base_loop\n");
};

void zPacketThread::exec_accept(int sk)
{
 std::map<int, zPacketThread::zSockSerVal>::const_iterator k=sock_serv.find(sk);
 if(k == sock_serv.end())
 {
  LOG_PRINT_INFO("System", "zPacketThread::exec_accept socket is not found???\n");
  return;
 }
 int s=ZNSOCKET::accept(sk);
 if(s <= 0) return;

 if(k->second.proto == zPacketThread::PROTO_WS)
 {
  zPacketWS* p= (zPacketWS*) ws_pool.get(this);
  if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "WS::error_accept_1\n"); return; }
  p->sock=s; p->parent= this; p->port=ZNSOCKET::getPort(sk); p->address=ZNSOCKET::getAddress(sk); p->peerport=ZNSOCKET::getPeerPort(s);
  if(k->second.ctx)
  {
   p->ssl= ZNSOCKET::server(p->sock, k->second.ctx);
   if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "WS::exec_accept: error_ssl\n"); return; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
   SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
  { p->push(); LOG_PRINT_ERROR("System", "WS::error_accept_2\n"); return; }
  if(p->ssl == NULL) onAccept(p);
  return;
 }
 else if(k->second.proto == zPacketThread::PROTO_TCP)
 {
  zPacketTCP* p= (zPacketTCP*) tcp_pool.get(this);
  if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "TCP::error_accept_1\n"); return; }
  p->sock=s; p->parent= this; p->port=ZNSOCKET::getPort(sk); p->address=ZNSOCKET::getAddress(sk); p->peerport=ZNSOCKET::getPeerPort(s);
  if(k->second.ctx)
  {
   p->ssl= ZNSOCKET::server(p->sock, k->second.ctx);
   if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "TCP::exec_accept: error_ssl\n"); return; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
   SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
  { p->push(); LOG_PRINT_ERROR("System", "TCP::error_accept_2\n"); return; }
  if(p->ssl == NULL) onAccept(p);
  return;
 }
 else
 {
  zPacketHTTP* p= (zPacketHTTP*) http_pool.get(this);
  if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "HTTP::error_accept_1\n"); return; }
  p->sock=s; p->parent= this; p->port=ZNSOCKET::getPort(sk); p->address=ZNSOCKET::getAddress(sk); p->peerport=ZNSOCKET::getPeerPort(s);
  if(k->second.ctx)
  {
   p->ssl= ZNSOCKET::server(p->sock, k->second.ctx);
   if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "HTTP::exec_accept: error_ssl\n"); return; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
   SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
  { p->push(); LOG_PRINT_ERROR("System", "HTTP::error_accept_2\n"); return; }
  if(p->ssl == NULL) onAccept(p);
 }
};

zClientTCP* zPacketThread::connectTCP(const std::string& addr,unsigned short port, SSL_CTX* cctx)
{
 std::string adr=zDNS::host(addr);
 if(adr.empty()) return NULL;
 int s=ZNSOCKET::async_socket(adr, port);
 if(s <= 0) return NULL;
 zClientTCP* p= (zClientTCP*) tcp_client_pool.get(this);
 if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "ClientTCP::error_connectTCP_1\n"); return NULL; }
 p->sock=s; p->parent= this; /*p->address=ZNSOCKET::getPeerAddress(s); p->peerport=ZNSOCKET::getPeerPort(s);*/
 p->host=ZNSTR::trim(addr); p->address=adr; p->port=port;
 if(cctx)
 {
  p->ssl= ZNSOCKET::socket(p->sock, cctx);
  if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "ClientTCP::connectTCP: error_ssl\n"); return NULL; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
  SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
   SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  SSL_set_tlsext_host_name(p->ssl, ZNSTR::trim(adr).c_str());
 }
 if(p->create_event(ev_base, EV_TIMEOUT | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { p->push(); LOG_PRINT_ERROR("System", "ClientTCP::error_connectTCP_2\n"); return NULL; }
 return p;
};

zClientWS* zPacketThread::connectWS(const std::string& addr,unsigned short port, const std::string& path, const std::string& version, SSL_CTX* cctx, const std::map<std::string, std::string>& add_header)
{
 std::string adr=zDNS::host(addr);
 if(adr.empty()) return NULL;
 int s=ZNSOCKET::async_socket(adr, port);
 if(s <= 0) return NULL;
 zClientWS* p= (zClientWS*) ws_client_pool.get(this);
 if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "ClientWS::error_connectWS_1\n"); return NULL; }
 p->sock=s; p->parent= this; /*p->address=ZNSOCKET::getPeerAddress(s); p->peerport=ZNSOCKET::getPeerPort(s);*/
 p->host=ZNSTR::trim(addr); p->address=adr; p->port=port;
 if(cctx)
 {
  p->ssl= ZNSOCKET::socket(p->sock, cctx);
  if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "ClientWS::connectWS: error_ssl\n"); return NULL; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
  SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
   SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  SSL_set_tlsext_host_name(p->ssl, p->host.c_str());
 }
 p->str_out="GET "+path+" HTTP/1.1\r\nHost: "+ZNSTR::trim(adr)+':'+ZNSTR::toString(port)+"\r\n";
 p->str_out+="Sec-WebSocket-Version: "+version+"\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: ";
 ulonglong kw=m_rnd.rnd_64();
 std::string w_key=ZNSTR::str2hex((const char*) &kw, sizeof(ulonglong))+"ZetWeb==";
 p->ws_key=ws_hash(w_key);
 p->str_out+=w_key+"\r\n";
 for(std::map<std::string, std::string>::const_iterator k= add_header.begin(); k != add_header.end(); ++k)
 { p->str_out+=k->first; p->str_out+=": "; p->str_out+=k->second; p->str_out+="\r\n"; }
 p->str_out+="\r\n";
 if(p->create_event(ev_base, EV_TIMEOUT | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { p->push(); LOG_PRINT_ERROR("System", "ClientWS::error_connectWS_2\n"); return NULL; }
 LOG_PRINT_DEBUG("System", p->str_out);
 return p;
};

zClientHTTP* zPacketThread::connectHTTP(const std::string& addr,unsigned short port, SSL_CTX* cctx)
{
 std::string adr=zDNS::host(addr);
 if(adr.empty()) return NULL;
 int s=ZNSOCKET::async_socket(adr, port);
 if(s <= 0) return NULL;
 zClientHTTP* p= (zClientHTTP*) http_client_pool.get(this);
 if(p == NULL) { ZNSOCKET::close(s); LOG_PRINT_ERROR("System", "ClientHTTP::error_connectHTTP_1\n"); return NULL; }
 p->sock=s; p->parent= this; /*p->address=ZNSOCKET::getPeerAddress(s); p->peerport=ZNSOCKET::getPeerPort(s);*/
 p->host=ZNSTR::trim(addr); p->address=adr; p->port=port; p->address_port=(p->address+':'+ZNSTR::toString(p->port));
 if(cctx)
 {
  p->ssl= ZNSOCKET::socket(p->sock, cctx);
  if(p->ssl == NULL) { p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::connectHTTP: error_ssl\n"); return NULL; }
#ifdef SSL_MODE_ENABLE_PARTIAL_WRITE
  SSL_set_mode(p->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
   SSL_set_mode(p->ssl, SSL_MODE_RELEASE_BUFFERS);
#endif
  SSL_set_tlsext_host_name(p->ssl, p->host.c_str());
 }
 if(p->create_event(ev_base, EV_TIMEOUT | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::error_connectHTTP_2\n"); return NULL; }
 return p;
};

zClientHTTP* zPacketThread::getClientHTTP(const std::string& adr,unsigned short port)
{ return http_client_pool.get(zDNS::host(adr)+':'+ZNSTR::toString(port)); };

void zPacketThread::exec_read(zPacketHTTP* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "HTTP::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "HTTP::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "HTTP::error_read_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: HTTP::read 0 bytes?\n");*/ return; }
// onRead(p);
 n= zPacketHTTP::parse(p);
 if(p->parent == NULL) return;
 if(n <= ZHTTP_PACKET_INVALID) { LOG_PRINT_DEBUG("System", "Incorrect packet\n"); onClose(p); p->push(); return; }
 if(n == ZHTTP_PACKET_EMPTY && p->str_in.size() > p->max_header) { LOG_PRINT_DEBUG("System", "Too long header packet size\n"); onClose(p); p->push(); return; }
 if(n >= ZHTTP_PACKET_HEADER && p->str_in.size() > p->max_body) { LOG_PRINT_DEBUG("System", "Too long packet size\n"); onClose(p); p->push(); return; }
 if(n >= ZHTTP_PACKET_COMPLETE)
 {
  short es=p->get_event();
  if(!(es & EV_WRITE)) { p->clear_event(); }
  else if(p->create_event(ev_base, EV_TIMEOUT | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { onClose(p); p->push(); LOG_PRINT_WARN("System", "HTTP::exec_read_3\n"); return; }
  onMessage(p);
 }  
};

void zPacketThread::exec_read(zPacketWS* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "WS::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "WS::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "WS::error_read_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: WS::read 0 bytes?\n");*/ return; }
 n= zPacketWS::parse(p);
 if(p->parent == NULL) return;
 if(n <= ZWS_PACKET_INVALID) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: zPacketWS::parse returns ZWS_PACKET_INVALID\n");*/ onClose(p); p->push(); return; }
 if(n == ZWS_PACKET_EMPTY && p->str_in.size() > p->max_header) { LOG_PRINT_DEBUG("System", "Too long header ws packet size\n"); onClose(p); p->push(); return; }
 if(n >= ZWS_PACKET_HEADER && p->str_in.size() > p->max_body) { LOG_PRINT_DEBUG("System", "Too long ws packet size\n"); p->close(); return; }  
};

void zPacketThread::exec_read(zPacketTCP* p)
{
 if(p == NULL) return;
 ssize_t n;
 p->str_in.clear();
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "TCP::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "TCP::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "TCP::error_read_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: TCP::read 0 bytes?\n");*/ return; }
 onRead(p);
};

void zPacketThread::exec_read(zClientTCP* p)
{
 if(p == NULL || p->status != ZTCP_CLIENT_CONNECTED) return;
 ssize_t n;
 p->str_in.clear();
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientTCP::error_read_2\n"); return; }
   onOpen(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: ClientTCP::read 0 bytes?\n");*/ return; }
 onRead(p);
};

void zPacketThread::exec_read(zClientWS* p)
{
 if(p == NULL) return;
 if(p->status == ZWS_CLIENT_EMPTY) { LOG_PRINT_WARN("System", "ClientWS::exec_read: p->status == ZWS_CLIENT_EMPTY?\n"); return; }
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientWS::error_read_2\n"); return; }
//   onAccept(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: ClientWS::read 0 bytes?\n");*/ return; }
 n= zClientWS::parse(p);
 if(p->parent == NULL) return;
 if(n <= ZWS_CLIENT_EMPTY) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: zClientWS::parse returns ZWS_CLIENT_INVALID\n");*/ onClose(p); p->push(); return; }
 if(n == ZWS_CLIENT_HEADER && p->str_in.size() > p->max_header) { LOG_PRINT_DEBUG("System", "Too long header client_ws packet size\n"); onClose(p); p->push(); return; }
 if(n == ZWS_CLIENT_CONNECTED && p->str_in.size() > p->max_body) { LOG_PRINT_DEBUG("System", "Too long ws packet size\n"); p->close(); return; }  
};

void zPacketThread::exec_read(zClientHTTP* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_read_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_read_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::error_read_2\n"); return; }
   onOpen(p);
   return;
  }
  n= ZNSOCKET::read(p->ssl, p->str_in, m_crd);
 }
 else { n=ZNSOCKET::read(p->sock, p->str_in, m_crd); }
 if(n < 0) { onClose(p); p->push(); return; }
 if(n == 0) { /*LOG_PRINT_DEBUG("System", "zPacketThread::exec_read: HTTP::read 0 bytes?\n");*/ return; }
// onRead(p);
 n= zClientHTTP::parse(p);
 if(p->parent == NULL) return;
 if(n <= ZHTTP_CLIENT_INVALID) { LOG_PRINT_DEBUG("System", "ClientHTTP::Incorrect packet\n"); onClose(p); p->push(); return; }
 if(n == ZHTTP_CLIENT_SENT && p->str_in.size() > p->max_header) { LOG_PRINT_DEBUG("System", "ClientHTTP::Too long header packet size\n"); onClose(p); p->push(); return; }
 if(n >= ZHTTP_CLIENT_HEADER && p->str_in.size() > p->max_body) { LOG_PRINT_DEBUG("System", "ClientHTTP::Too long packet size\n"); onClose(p); p->push(); return; }
 if(n >= ZHTTP_CLIENT_COMPLETE)
 {
  onMessage(p);
  if(p->parent == NULL) return;
  if(p->keep_alive)
  {
   if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_read_3\n"); return; }
   p->clear();
   p->status= ZHTTP_CLIENT_CONNECTED;
   http_client_pool.setKeep(p);
  }
  else { onClose(p); p->push(); }
 }  
};

void zPacketThread::exec_write(zPacketHTTP* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "HTTP::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "HTTP::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "HTTP::error_write_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "Socket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p);
  p->push();
  return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->keep_write)
   {
    short es=p->get_event();
    if(es & EV_READ)
    {
     if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_write_1\n"); return; }
    }
    else if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
    { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_write_2\n"); return; }
   }
   else if(p->keep_alive)
   {
    if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
    { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_write_3\n"); return; }
    p->clear();
   }
   else { onClose(p); p->push(); }
  }
 }
};

void zPacketThread::exec_write(zPacketWS* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "WS::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "WS::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "WS::error_write_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "WSSocket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p); p->push(); return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->status == ZWS_PACKET_CLOSED) { onClose(p); p->push(); return; }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_ws_write_1\n"); return; }
  }
 }
};

void zPacketThread::exec_write(zPacketTCP* p)
{
 if(p == NULL) return;
 ssize_t n;
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::accept(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "TCP::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { p->push(); LOG_PRINT_WARN("System", "TCP::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { p->push(); LOG_PRINT_ERROR("System", "TCP::error_write_2\n"); return; }
   onAccept(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "TCPSocket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p); p->push(); return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_tcp_write_1\n"); return; }
  }
 }
};

void zPacketThread::exec_write(zClientTCP* p)
{
 if(p == NULL || p->status == ZTCP_CLIENT_INVALID) return;
 ssize_t n;
 if(p->status == ZTCP_CLIENT_EMPTY)
 {
  if(!ZNSOCKET::alive(p->sock)) { onClose(p); p->push(); LOG_PRINT_DEBUG("System", "ClientTCP::exec_write: socket is not alive\n"); return; }
  p->status= ZTCP_CLIENT_CONNECTED;
//  p->address=ZNSOCKET::getPeerAddress(p->sock);
  p->peerport=ZNSOCKET::getPeerPort(p->sock);
  if(p->ssl)
  {
   if(SSL_is_init_finished(p->ssl) == 0)
   {
    n= ZNSOCKET::connect(p->ssl);
    if(n < 0) { onClose(p); p->push(); return; }
    if(n == 0)
    {
     int w= ::SSL_want(p->ssl);
     short es=p->get_event();
     if(w == SSL_WRITING)
     {
      if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_connect_write_1W\n"); return; }
     }
     else
     {
      if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_connect_write_1R\n"); return; }
     }
     return;
    }
    if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
    { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientTCP::error_connect_write_2\n"); return; }
    onOpen(p);
    return;
   }
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
  { onClose(p);  p->push(); LOG_PRINT_ERROR("System", "ClientTCP::error_connect_2\n"); return; }
  if(p->ssl == NULL) onOpen(p);
  return;
 }
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientTCP::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientTCP::error_write_2\n"); return; }
   onOpen(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "ClientTCPSocket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p); p->push(); return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_tcp_write_1\n"); return; }
  }
 }
};

void zPacketThread::exec_write(zClientWS* p)
{
 if(p == NULL || p->status == ZWS_CLIENT_INVALID) return;
 ssize_t n;
 if(p->status == ZWS_CLIENT_EMPTY)
 {
  if(!ZNSOCKET::alive(p->sock)) { onClose(p); p->push(); LOG_PRINT_DEBUG("System", "ClientWS::exec_write: socket is not alive\n"); return; }
  p->status= ZWS_CLIENT_HEADER;
//  p->address=ZNSOCKET::getPeerAddress(p->sock);
  p->peerport=ZNSOCKET::getPeerPort(p->sock);
  if(p->ssl)
  {
   if(SSL_is_init_finished(p->ssl) == 0)
   {
    n= ZNSOCKET::connect(p->ssl);
    if(n < 0) { onClose(p); p->push(); return; }
    if(n == 0)
    {
     int w= ::SSL_want(p->ssl);
     short es=p->get_event();
     if(w == SSL_WRITING)
     {
      if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_connect_write_1W\n"); return; }
     }
     else
     {
      if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_connect_write_1R\n"); return; }
     }
     return;
    }
    if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
    { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientWS::error_connect_write_2\n"); return; }
//    onOpen(p);
    return;
   }
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):WRITE_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientWS::error_connect_2\n"); return; }
//  if(p->ssl == NULL) onOpen(p);
  return;
 }
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientWS::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ  | EV_WRITE | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientWS::error_write_2\n"); return; }
//   onAccept(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "ClientWSSocket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p); p->push(); return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  if(p->status >= ZWS_CLIENT_CONNECTED) onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->status == ZWS_PACKET_CLOSED) { onClose(p); p->push(); return; }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "error_zPacketThread::exec_client_ws_write_1\n"); return; }
  }
 }
};

void zPacketThread::exec_write(zClientHTTP* p)
{
 if(p == NULL || p->status == ZHTTP_CLIENT_INVALID) return;
 ssize_t n;
 if(p->status == ZHTTP_CLIENT_EMPTY)
 {
  if(!ZNSOCKET::alive(p->sock)) { onClose(p); p->push(); LOG_PRINT_DEBUG("System", "ClientHTTP::exec_write: socket is not alive\n"); return; }
  p->status= ZHTTP_CLIENT_CONNECTED;
//  p->address=ZNSOCKET::getPeerAddress(p->sock);
  p->peerport=ZNSOCKET::getPeerPort(p->sock);
//  p->address_port=(p->address+':'+ZNSTR::toString(p->port));
  if(p->ssl)
  {
   if(SSL_is_init_finished(p->ssl) == 0)
   {
    n= ZNSOCKET::connect(p->ssl);
    if(n < 0) { onClose(p); p->push(); return; }
    if(n == 0)
    {
     int w= ::SSL_want(p->ssl);
     short es=p->get_event();
     if(w == SSL_WRITING)
     {
      if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_connect_write_1W\n"); return; }
     }
     else
     {
      if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
      { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_connect_write_1R\n"); return; }
     }
     return;
    }
    if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
    { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::error_connect_write_2\n"); return; }
    onOpen(p);
    return;
   }
  }
  if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
  { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::error_connect_2\n"); return; }
  if(p->ssl == NULL) onOpen(p);
  return;
 }
 if(p->ssl)
 {
  if(SSL_is_init_finished(p->ssl) == 0)
  {
   n= ZNSOCKET::connect(p->ssl);
   if(n < 0) { onClose(p); p->push(); return; }
   if(n == 0)
   {
    int w= ::SSL_want(p->ssl);
    short es=p->get_event();
    if(w == SSL_WRITING)
    {
     if(!(es & EV_WRITE) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, p, WRITE_TIMEOUT_SEC, WRITE_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_write_1W\n"); return; }
    }
    else
    {
     if(((es & EV_WRITE) || !(es & EV_READ)) && p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, READ_TIMEOUT_SEC, READ_TIMEOUT_MSEC) == NULL)
     { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_write_1R\n"); return; }
    }
    return;
   }
   if(p->create_event(ev_base, EV_TIMEOUT | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_ERROR("System", "ClientHTTP::error_write_2\n"); return; }
   onOpen(p);
   return;
  }
  n= ZNSOCKET::write(p->ssl, p->str_out, p->pos);
 }
 else { n=ZNSOCKET::write(p->sock, p->str_out, p->pos); }
 if(n < 0)
 {
  LOG_PRINT_DEBUG("System", "ClientHTTP::Socket "+ZNSTR::toString(sock)+" is closed?\n"); 
  onClose(p);
  p->push();
  return;
 }
 p->pos+=n;
 if(p->pos >= p->str_out.size())
 {
  p->str_out.clear();
  p->pos=0;
  onWrite(p);
  if(p->parent == NULL) return;
  if(p->pos >= p->str_out.size())
  {
   if(p->create_event(ev_base, EV_TIMEOUT | EV_READ | EV_PERSIST, p, (p->time_out)?(p->time_out/1000):READ_TIMEOUT_SEC, (p->time_out)?(p->time_out%1000):READ_TIMEOUT_MSEC) == NULL)
   { onClose(p); p->push(); LOG_PRINT_WARN("System", "ClientHTTP::exec_write_3\n"); return; }
  }
 }
};

void zPacketThread::exec_timeout(zPacketHTTP* p)
{
 if(p == NULL || onTimeout(p)) return;
 onClose(p); 
 p->push();
};

void zPacketThread::exec_timeout(zPacketWS* p)
{
 if(p == NULL) return;
 if(p->status != ZWS_PACKET_ACCEPTED)
 { onClose(p); p->push(); return; }
 onTimeout(p);
};

void zPacketThread::exec_timeout(zPacketTCP* p)
{
 if(p == NULL) return;
 onTimeout(p);
};

void zPacketThread::exec_timeout(zClientTCP* p)
{
 if(p == NULL) return;
 if(p->status != ZTCP_CLIENT_CONNECTED)
 { onClose(p); p->push(); return; }
 onTimeout(p);
};

void zPacketThread::exec_timeout(zClientWS* p)
{
 if(p == NULL) return;
 if(p->status != ZWS_CLIENT_CONNECTED)
 { onClose(p); p->push(); return; }
 onTimeout(p);
};

void zPacketThread::exec_timeout(zClientHTTP* p)
{
 if(p == NULL || onTimeout(p)) return;
 onClose(p); 
 p->push();
};

zPacketHTTP::zPacketHTTP():
 zPacket(),
 status(ZHTTP_PACKET_EMPTY),str_header(),str_in(),str_out(),pos(0),
 address(),peerport(0),host(),port(0),version(),method(),path(),boundary(),content_type(),keep_alive(false),keep_write(false),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000)),length(0),max_header(zPacketHTTP::header_max_length),max_body(zPacketHTTP::packet_max_length),
 chunked(false),ranges(),head(),cookie(),param(),file()
{ };

zPacketHTTP::~zPacketHTTP() { clear(); };

void zPacketHTTP::clear()
{
 status=ZHTTP_PACKET_EMPTY;
 str_header.clear();
 str_in.clear();
 str_out.clear();
 pos=0;

// address.clear();
// peerport=0;
 host.clear();
// port=0;
 version.clear();
 method.clear();
 path.clear();
 boundary.clear();
 content_type.clear();
 keep_alive= false;
 keep_write= false;
 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));
 max_header=zPacketHTTP::header_max_length;
 max_body=zPacketHTTP::packet_max_length;
 length=0;
 chunked= false;
 ranges.clear();
 head.clear();
 cookie.clear();
 param.clear();
 file.clear();
 if(ext) ext->clear();
// parent=NULL;
};

void zPacketHTTP::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zPacketHTTP::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

int zPacketHTTP::parse(zPacketHTTP* src)
{
 if(src->status == ZHTTP_PACKET_EMPTY)
 {
  parse_header(src);
  if(src->status >= ZHTTP_PACKET_HEADER) { src->parent->onHeader(src); }
 }
 if(src->status >= ZHTTP_PACKET_HEADER) { src->parent->onRead(src); }
 return parse_body(src);
};

void zPacketHTTP::send_empty(const std::string& connection)
{
 if(parent == NULL) return;
 pos=0;
 str_out="HTTP/1.1 204 No Content\r\nContent-Type:text/html\r\nContent-Length:0\r\nConnection:"+connection+"\r\n\r\n";
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | es | EV_WRITE | EV_PERSIST, (zPacketHTTP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zPacketHTTP*) this); push(); LOG_PRINT_WARN("System", "error_zPacketHTTP::send_empty\n"); }
};

void zPacketHTTP::send_location(const std::string& path, const std::string& connection)
{
 if(parent == NULL) return;
 pos=0;
 str_out="HTTP/1.1 302 Moved Temporarily\r\nLocation:"+path+"\r\nContent-Length:0\r\nConnection:"+connection+"\r\n\r\n";
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | es | EV_WRITE | EV_PERSIST, (zPacketHTTP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zPacketHTTP*) this); push(); LOG_PRINT_WARN("System", "error_zPacketHTTP::send_location\n"); }
};

void zPacketHTTP::send_text(const std::string& hdr, const std::string& connection)
{
 if(parent == NULL) return;
 pos=0;
 str_out.insert(0, "HTTP/1.1 200 OK\r\nContent-Type:"+hdr+"\r\nContent-Length:"+ZNSTR::toString(str_out.size())+"\r\nConnection:"+connection+"\r\n\r\n");
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | es | EV_WRITE | EV_PERSIST, (zPacketHTTP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zPacketHTTP*) this); push(); LOG_PRINT_WARN("System", "error_zPacketHTTP::send_text\n"); }
};

void zPacketHTTP::send(const std::string& hdr)
{
 if(parent == NULL) return;
 pos=0;
 if(hdr.size()) str_out.insert(0, hdr);
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | es | EV_WRITE | EV_PERSIST, (zPacketHTTP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zPacketHTTP*) this); push(); LOG_PRINT_WARN("System", "error_zPacketHTTP::send\n");  }
};

zPacket* zPoolHTTP::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zPacketHTTP* p=new zPacketHTTP();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zPacketHTTP* zPoolHTTP::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zPacketHTTP* pp=dynamic_cast<zPacketHTTP*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zPoolHTTP::~zPoolHTTP()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolHTTP::push(*k); }
};

bool zPoolHTTP::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear(); p->clear_event(); p->clear_socket(); p->parent=NULL;
  zPacketHTTP* pp= dynamic_cast<zPacketHTTP*>(p);
  if(pp) { pp->address.clear(); pp->peerport=0; pp->port=0; }
  return true;
 }
 return false;
};

zPacketWS::zPacketWS():
 zPacket(),
 status(ZWS_PACKET_EMPTY),str_header(),str_in(),str_out(),message(),complete_message(),last_fragmented_count(0),
 fin_flag(true),opcode(0),pos(0),address(),peerport(0),host(),port(0),method(),http_version(),ws_version(),ws_key(),path(),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000)),max_header(zPacketWS::header_max_length),max_body(zPacketWS::packet_max_length),head()
{};

zPacketWS::~zPacketWS() { clear(); };

void zPacketWS::clear()
{
 status=ZWS_PACKET_EMPTY;
 str_header.clear();
 str_in.clear();
 str_out.clear();
 message.clear();
 complete_message.clear();
 last_fragmented_count=0;
 fin_flag=true;
 opcode=0;
 pos=0;

 address.clear();
 peerport=0;
 host.clear();
 port=0;
 method.clear();
 http_version.clear();
 ws_version.clear();
 ws_key.clear();
 path.clear();

 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));
 max_header=zPacketWS::header_max_length;
 max_body=zPacketWS::packet_max_length;
 head.clear();
 if(ext) ext->clear();
// parent=NULL;
};

void zPacketWS::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zPacketWS::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

int zPacketWS::parse(zPacketWS* src)
{
 if(src->status == ZWS_PACKET_EMPTY)
 {
  parse_ws_header(src);
  if(src->status == ZWS_PACKET_HEADER)
  {
   src->parent->onOpen(src);
   if(src->status != ZWS_PACKET_ACCEPTED) { src->status = ZWS_PACKET_INVALID; return src->status; }
  }
 }
 if(src->status < ZWS_PACKET_ACCEPTED) { return src->status; }
 if(src->status == ZWS_PACKET_ACCEPTED && src->str_in.size()) { src->parent->onRead(src); }
 return parse_ws_body(src);
};

void zPacketWS::accept(const std::map<std::string, std::string>& add_header)
{
 if(status != ZWS_PACKET_HEADER) return;
 status=ZWS_PACKET_ACCEPTED;
 str_out=ws_str_head_reply;
 str_out+=ws_hash(ws_key);
 str_out+="\r\n";
 for(std::map<std::string, std::string>::const_iterator k= add_header.begin(); k != add_header.end(); ++k)
 { str_out+=k->first; str_out+=": "; str_out+=k->second; str_out+="\r\n"; }
 str_out+="\r\n";
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zPacketWS*) this); LOG_PRINT_WARN("System", "error_zPacketWS::accept\n"); push(); return; }
 }
 LOG_PRINT_DEBUG("System", str_out);
};

void zPacketWS::send(const std::string& msg, bool fragmented)
{
 if(parent == NULL || status != ZWS_PACKET_ACCEPTED) return;
 size_t len=msg.size();
 struct zWSH h;
 if(last_fragmented_count) h.opcode3=0;
 else h.opcode3=1;
 if(fragmented) { h.fin=0; last_fragmented_count++; }
 else { h.fin=1; last_fragmented_count=0; }
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=0;
 h.opcode1=0;
 h.opcode2=0;
 h.mask=0;
 if(len < 126) { unsigned char l=len; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 else if(len < 65536) { unsigned char l=126; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 else { unsigned char l=127; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 if(len < 126) str_out+=msg;
 else if(len < 65536)
 {
  unsigned short l= len;
  zwsl16 s;
           s.c1.b7=l; l >>= 1; s.c1.b6=l; l >>= 1; s.c1.b5=l; l >>= 1; s.c1.b4=l; l >>= 1; s.c1.b3=l; l >>= 1; s.c1.b2=l; l >>= 1; s.c1.b1=l; l >>= 1; s.c1.b0=l;
  l >>= 1; s.c0.b7=l; l >>= 1; s.c0.b6=l; l >>= 1; s.c0.b5=l; l >>= 1; s.c0.b4=l; l >>= 1; s.c0.b3=l; l >>= 1; s.c0.b2=l; l >>= 1; s.c0.b1=l; l >>= 1; s.c0.b0=l;
  str_out.append(reinterpret_cast<const char*>(&s), sizeof(unsigned short));
  str_out+=msg;
 }
 else
 {
  ulonglong l= len;
  zwsl64 s;
           s.c7.b7=l; l >>= 1; s.c7.b6=l; l >>= 1; s.c7.b5=l; l >>= 1; s.c7.b4=l; l >>= 1; s.c7.b3=l; l >>= 1; s.c7.b2=l; l >>= 1; s.c7.b1=l; l >>= 1; s.c7.b0=l;
  l >>= 1; s.c6.b7=l; l >>= 1; s.c6.b6=l; l >>= 1; s.c6.b5=l; l >>= 1; s.c6.b4=l; l >>= 1; s.c6.b3=l; l >>= 1; s.c6.b2=l; l >>= 1; s.c6.b1=l; l >>= 1; s.c6.b0=l;
  l >>= 1; s.c5.b7=l; l >>= 1; s.c5.b6=l; l >>= 1; s.c5.b5=l; l >>= 1; s.c5.b4=l; l >>= 1; s.c5.b3=l; l >>= 1; s.c5.b2=l; l >>= 1; s.c5.b1=l; l >>= 1; s.c5.b0=l;
  l >>= 1; s.c4.b7=l; l >>= 1; s.c4.b6=l; l >>= 1; s.c4.b5=l; l >>= 1; s.c4.b4=l; l >>= 1; s.c4.b3=l; l >>= 1; s.c4.b2=l; l >>= 1; s.c4.b1=l; l >>= 1; s.c4.b0=l;
  l >>= 1; s.c3.b7=l; l >>= 1; s.c3.b6=l; l >>= 1; s.c3.b5=l; l >>= 1; s.c3.b4=l; l >>= 1; s.c3.b3=l; l >>= 1; s.c3.b2=l; l >>= 1; s.c3.b1=l; l >>= 1; s.c3.b0=l;
  l >>= 1; s.c2.b7=l; l >>= 1; s.c2.b6=l; l >>= 1; s.c2.b5=l; l >>= 1; s.c2.b4=l; l >>= 1; s.c2.b3=l; l >>= 1; s.c2.b2=l; l >>= 1; s.c2.b1=l; l >>= 1; s.c2.b0=l;
  l >>= 1; s.c1.b7=l; l >>= 1; s.c1.b6=l; l >>= 1; s.c1.b5=l; l >>= 1; s.c1.b4=l; l >>= 1; s.c1.b3=l; l >>= 1; s.c1.b2=l; l >>= 1; s.c1.b1=l; l >>= 1; s.c1.b0=l;
  l >>= 1; s.c0.b7=l; l >>= 1; s.c0.b6=l; l >>= 1; s.c0.b5=l; l >>= 1; s.c0.b4=l; l >>= 1; s.c0.b3=l; l >>= 1; s.c0.b2=l; l >>= 1; s.c0.b1=l; l >>= 1; s.c0.b0=l;
  str_out.append(reinterpret_cast<const char*>(&s), sizeof(ulonglong));
  str_out+=msg;
 }
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zPacketWS*) this); LOG_PRINT_WARN("System", "error_zPacketWS::send\n"); push(); return; }
 }
};

void zPacketWS::close()
{
 if(status != ZWS_PACKET_ACCEPTED) return;
 status= ZWS_PACKET_CLOSED;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=0;
 h.opcode3=0;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zPacketWS*) this); LOG_PRINT_WARN("System", "error_zPacketWS::close\n"); push(); return; }
 }
};

void zPacketWS::ping()
{
 if(status != ZWS_PACKET_ACCEPTED) return;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=0;
 h.opcode3=1;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zPacketWS*) this); LOG_PRINT_WARN("System", "error_zPacketWS::ping\n"); push(); return; }
 }
};

void zPacketWS::pong()
{
 if(status != ZWS_PACKET_ACCEPTED) return;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=1;
 h.opcode3=0;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zPacketWS*) this); LOG_PRINT_WARN("System", "error_zPacketWS::pong\n"); push(); return; }
 }
};

zPoolWS::~zPoolWS()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolWS::push(*k); }
};

bool zPoolWS::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear(); p->clear_event(); p->clear_socket(); p->parent=NULL;
  return true;
 }
 return false;
};

zPacket* zPoolWS::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zPacketWS* p=new zPacketWS();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zPacketWS* zPoolWS::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zPacketWS* pp=dynamic_cast<zPacketWS*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zPacketTCP::zPacketTCP():
 zPacket(),
 status(ZTCP_PACKET_EMPTY),str_in(),str_out(),message(),
 pos(0),address(),peerport(0),port(0),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000))
{};

zPacketTCP::~zPacketTCP() { clear(); };

void zPacketTCP::clear()
{
 status=ZTCP_PACKET_EMPTY;
 str_in.clear();
 str_out.clear();
 message.clear();
 pos=0;

 address.clear();
 peerport=0;
 port=0;

 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));

 if(ext) ext->clear();
// parent=NULL;
};

void zPacketTCP::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zPacketTCP::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

void zPacketTCP::send(const std::string& msg)
{
 if(parent == NULL || status != ZTCP_PACKET_EMPTY) return;

 str_out+=msg;
 
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zPacketTCP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zPacketTCP*) this); LOG_PRINT_WARN("System", "error_zPacketTCP::send\n"); push(); return; } 
};

zPoolTCP::~zPoolTCP()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolTCP::push(*k); }
};

bool zPoolTCP::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear(); p->clear_event(); p->clear_socket(); p->parent=NULL;
  return true;
 }
 return false;
};

zPacket* zPoolTCP::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zPacketTCP* p=new zPacketTCP();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zPacketTCP* zPoolTCP::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zPacketTCP* pp=dynamic_cast<zPacketTCP*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zClientTCP::zClientTCP():
 zPacket(),
 status(ZTCP_CLIENT_EMPTY),str_in(),str_out(),message(),
 pos(0),host(),address(),peerport(0),port(0),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000))
{};

zClientTCP::~zClientTCP() { clear(); };

void zClientTCP::clear()
{
 status=ZTCP_CLIENT_EMPTY;
 str_in.clear();
 str_out.clear();
 message.clear();
 pos=0;

 host.clear();
 address.clear();
 peerport=0;
 port=0;

 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));

 if(ext) ext->clear();
// parent=NULL;
};

void zClientTCP::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zClientTCP::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

void zClientTCP::send(const std::string& msg)
{
 if(parent == NULL || status != ZTCP_CLIENT_CONNECTED) return;

 str_out+=msg;
 
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zClientTCP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zClientTCP*) this); LOG_PRINT_WARN("System", "error_zClientTCP::send\n"); push(); return; } 
};

zPoolClientTCP::~zPoolClientTCP()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolClientTCP::push(*k); }
};

bool zPoolClientTCP::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear(); p->clear_event(); p->clear_socket(); p->parent=NULL;
  return true;
 }
 return false;
};

zPacket* zPoolClientTCP::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zClientTCP* p=new zClientTCP();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zClientTCP* zPoolClientTCP::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zClientTCP* pp=dynamic_cast<zClientTCP*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zClientWS::zClientWS():
 zPacket(),
 status(ZWS_PACKET_EMPTY),str_header(),str_in(),str_out(),message(),complete_message(),last_fragmented_count(0),
 fin_flag(true),opcode(0),pos(0),address(),peerport(0),host(),port(0),http_code(),http_version(),ws_version(),ws_key(),path(),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000)),max_header(zClientWS::header_max_length),max_body(zClientWS::packet_max_length),head()
{};

zClientWS::~zClientWS() { clear(); };

void zClientWS::clear()
{
 status=ZWS_PACKET_EMPTY;
 str_header.clear();
 str_in.clear();
 str_out.clear();
 message.clear();
 complete_message.clear();
 last_fragmented_count=0;
 fin_flag=true;
 opcode=0;
 pos=0;

 address.clear();
 peerport=0;
 host.clear();
 port=0;

 http_code.clear();
 http_version.clear();
 ws_version.clear();
 ws_key.clear();
 path.clear();

 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));
 max_header=zClientWS::header_max_length;
 max_body=zClientWS::packet_max_length;
 head.clear();
 if(ext) ext->clear();
// parent=NULL;
};

void zClientWS::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zClientWS::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

int zClientWS::parse(zClientWS* src)
{
 if(src->status == ZWS_CLIENT_HEADER)
 {
  parse_ws_header(src);
  if(src->status == ZWS_CLIENT_CONNECTED) { src->parent->onOpen(src); }
 }
 if(src->status < ZWS_CLIENT_CONNECTED) return src->status;
 if(src->status == ZWS_CLIENT_CONNECTED && src->str_in.size()) { src->parent->onRead(src); }
 return parse_ws_body(src);
};

void zClientWS::send(const std::string& msg, bool fragmented)
{
 if(parent == NULL || status != ZWS_CLIENT_CONNECTED) return;
 size_t len=msg.size();
 struct zWSH h;
 if(last_fragmented_count) h.opcode3=0;
 else h.opcode3=1;
 if(fragmented) { h.fin=0; last_fragmented_count++; }
 else { h.fin=1; last_fragmented_count=0; }
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=0;
 h.opcode1=0;
 h.opcode2=0;
 h.mask=0;
 if(len < 126) { unsigned char l=len; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 else if(len < 65536) { unsigned char l=126; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 else { unsigned char l=127; h.len6=l; l >>= 1; h.len5=l; l >>= 1; h.len4=l; l >>= 1; h.len3=l; l >>= 1; h.len2=l; l >>= 1; h.len1=l; l >>= 1; h.len0=l; }
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 if(len < 126) str_out+=msg;
 else if(len < 65536)
 {
  unsigned short l= len;
  zwsl16 s;
           s.c1.b7=l; l >>= 1; s.c1.b6=l; l >>= 1; s.c1.b5=l; l >>= 1; s.c1.b4=l; l >>= 1; s.c1.b3=l; l >>= 1; s.c1.b2=l; l >>= 1; s.c1.b1=l; l >>= 1; s.c1.b0=l;
  l >>= 1; s.c0.b7=l; l >>= 1; s.c0.b6=l; l >>= 1; s.c0.b5=l; l >>= 1; s.c0.b4=l; l >>= 1; s.c0.b3=l; l >>= 1; s.c0.b2=l; l >>= 1; s.c0.b1=l; l >>= 1; s.c0.b0=l;
  str_out.append(reinterpret_cast<const char*>(&s), sizeof(unsigned short));
  str_out+=msg;
 }
 else
 {
  ulonglong l= len;
  zwsl64 s;
           s.c7.b7=l; l >>= 1; s.c7.b6=l; l >>= 1; s.c7.b5=l; l >>= 1; s.c7.b4=l; l >>= 1; s.c7.b3=l; l >>= 1; s.c7.b2=l; l >>= 1; s.c7.b1=l; l >>= 1; s.c7.b0=l;
  l >>= 1; s.c6.b7=l; l >>= 1; s.c6.b6=l; l >>= 1; s.c6.b5=l; l >>= 1; s.c6.b4=l; l >>= 1; s.c6.b3=l; l >>= 1; s.c6.b2=l; l >>= 1; s.c6.b1=l; l >>= 1; s.c6.b0=l;
  l >>= 1; s.c5.b7=l; l >>= 1; s.c5.b6=l; l >>= 1; s.c5.b5=l; l >>= 1; s.c5.b4=l; l >>= 1; s.c5.b3=l; l >>= 1; s.c5.b2=l; l >>= 1; s.c5.b1=l; l >>= 1; s.c5.b0=l;
  l >>= 1; s.c4.b7=l; l >>= 1; s.c4.b6=l; l >>= 1; s.c4.b5=l; l >>= 1; s.c4.b4=l; l >>= 1; s.c4.b3=l; l >>= 1; s.c4.b2=l; l >>= 1; s.c4.b1=l; l >>= 1; s.c4.b0=l;
  l >>= 1; s.c3.b7=l; l >>= 1; s.c3.b6=l; l >>= 1; s.c3.b5=l; l >>= 1; s.c3.b4=l; l >>= 1; s.c3.b3=l; l >>= 1; s.c3.b2=l; l >>= 1; s.c3.b1=l; l >>= 1; s.c3.b0=l;
  l >>= 1; s.c2.b7=l; l >>= 1; s.c2.b6=l; l >>= 1; s.c2.b5=l; l >>= 1; s.c2.b4=l; l >>= 1; s.c2.b3=l; l >>= 1; s.c2.b2=l; l >>= 1; s.c2.b1=l; l >>= 1; s.c2.b0=l;
  l >>= 1; s.c1.b7=l; l >>= 1; s.c1.b6=l; l >>= 1; s.c1.b5=l; l >>= 1; s.c1.b4=l; l >>= 1; s.c1.b3=l; l >>= 1; s.c1.b2=l; l >>= 1; s.c1.b1=l; l >>= 1; s.c1.b0=l;
  l >>= 1; s.c0.b7=l; l >>= 1; s.c0.b6=l; l >>= 1; s.c0.b5=l; l >>= 1; s.c0.b4=l; l >>= 1; s.c0.b3=l; l >>= 1; s.c0.b2=l; l >>= 1; s.c0.b1=l; l >>= 1; s.c0.b0=l;
  str_out.append(reinterpret_cast<const char*>(&s), sizeof(ulonglong));
  str_out+=msg;
 }
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zClientWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zClientWS*) this); LOG_PRINT_WARN("System", "error_zClientWS::send\n"); push(); return; }
 }
};

void zClientWS::close()
{
 if(status != ZWS_CLIENT_CONNECTED) return;
 status= ZWS_CLIENT_CLOSED;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=0;
 h.opcode3=0;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zClientWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zClientWS*) this); LOG_PRINT_WARN("System", "error_zClientWS::close\n"); push(); return; }
 }
};

void zClientWS::ping()
{
 if(status != ZWS_CLIENT_CONNECTED) return;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=0;
 h.opcode3=1;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zClientWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zClientWS*) this); LOG_PRINT_WARN("System", "error_zClientWS::ping\n"); push(); return; }
 }
};

void zClientWS::pong()
{
 if(status != ZWS_CLIENT_CONNECTED) return;
 struct zWSH h;
 h.fin=1;
 h.rsv1=0;
 h.rsv2=0;
 h.rsv3=0;
 h.opcode0=1;
 h.opcode1=0;
 h.opcode2=1;
 h.opcode3=0;
 h.mask=0;
 h.len0=0;
 h.len1=0;
 h.len2=0;
 h.len3=0;
 h.len4=0;
 h.len5=0;
 h.len6=0;
 str_out.append(reinterpret_cast<const char*>(&h), sizeof(struct zWSH));
 {
  short es=get_event();
  if(es & EV_WRITE) return;
  if(create_event(parent->ev_base, EV_TIMEOUT | EV_READ | EV_WRITE | EV_PERSIST, (zClientWS*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
  { parent->onClose((zClientWS*) this); LOG_PRINT_WARN("System", "error_zClientWS::pong\n"); push(); return; }
 }
};

zPoolClientWS::~zPoolClientWS()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolClientWS::push(*k); }
};

bool zPoolClientWS::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear(); p->clear_event(); p->clear_socket(); p->parent=NULL;
  return true;
 }
 return false;
};

zPacket* zPoolClientWS::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zClientWS* p=new zClientWS();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zClientWS* zPoolClientWS::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zClientWS* pp=dynamic_cast<zClientWS*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zClientHTTP::zClientHTTP():
 zPacket(),
 status(ZHTTP_CLIENT_EMPTY),str_header(),str_in(),str_out(),pos(0),
 address(),peerport(0),host(),port(0),version(),http_code(),content_type(),keep_alive(false),address_port(),
 time_out((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000)),length(0),
 max_header(zClientHTTP::header_max_length),max_body(zClientHTTP::packet_max_length),
 chunked(false),head()
{ };

zClientHTTP::~zClientHTTP() { clear(); };

void zClientHTTP::clear()
{
 status=ZHTTP_CLIENT_EMPTY;
 str_header.clear();
 str_in.clear();
 str_out.clear();
 pos=0;

// address.clear();
// peerport=0;
// host.clear();
// port=0;
// address_port.clear();
 version.clear();
 http_code.clear();
 content_type.clear();
 keep_alive= false;
 time_out=((READ_TIMEOUT_SEC*1000)+(READ_TIMEOUT_MSEC%1000));
 max_header=zClientHTTP::header_max_length;
 max_body=zClientHTTP::packet_max_length;
 length=0;
 chunked= false;
 head.clear();
// cookie.clear();
 if(ext) ext->clear();
// parent=NULL;
};

void zClientHTTP::execute(int s, short what)
{
 if(parent == NULL || s != sock)
 {
  LOG_PRINT_INFO("System", "zClientHTTP::execute: s("+ZNSTR::toString(s)+") != sock("+ZNSTR::toString(sock)+");\n"); 
  return;
 }
 parent->m_sleep_flag=0;
 parent->idle();
 if(parent == NULL || s != sock) return;
 if(what & EV_READ)
 {
  parent->exec_read(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_WRITE)
 {
  parent->exec_write(this);
  if(parent == NULL || s != sock) return;
 }
 if(what & EV_TIMEOUT) parent->exec_timeout(this);
};

int zClientHTTP::parse(zClientHTTP* src)
{
// LOG_PRINT_DEBUG("System", "zClientHTTP::parse: status="+ZNSTR::toString(src->status)+";\n"); 
 if(src->status == ZHTTP_CLIENT_SENT)
 {
  parse_header(src);
  if(src->status >= ZHTTP_CLIENT_HEADER) { src->parent->onHeader(src); }
 }
 if(src->status >= ZHTTP_CLIENT_HEADER) { src->parent->onRead(src); }
 return parse_body(src);
};

void zClientHTTP::send(const std::string& hdr)
{
 if(parent == NULL || status != ZHTTP_CLIENT_CONNECTED) return;
 pos=0;
 if(hdr.size()) str_out.insert(0, hdr);
 short es=get_event();
 if(es & EV_WRITE) return;
 if(create_event(parent->ev_base, EV_TIMEOUT | es | EV_WRITE | EV_PERSIST, (zClientHTTP*) this, time_out?(time_out/1000):WRITE_TIMEOUT_SEC, time_out?(time_out%1000):WRITE_TIMEOUT_MSEC) == NULL)
 { parent->onClose((zClientHTTP*) this); push(); LOG_PRINT_WARN("System", "error_zClientHTTP::send\n");  }
 status= ZHTTP_CLIENT_SENT;
 parent->http_client_pool.eraseKeep((zClientHTTP*) this);
};

zPacket* zPoolClientHTTP::create()
{
 if(mtp_value.size() > ZMAX_PACKET_POOL) return NULL;
 zClientHTTP* p=new zClientHTTP();
 p->pool=(zPool<zPacket>*) this;
 return p;
};

zClientHTTP* zPoolClientHTTP::get(zPacketThread* prn)
{
 zPacket* p=zPool<zPacket>::get();
 zClientHTTP* pp=dynamic_cast<zClientHTTP*>(p);
 if(pp == NULL) { push(p); return NULL; }
 p->parent=prn;
 return pp;
};

zClientHTTP* zPoolClientHTTP::get(const std::string& adr_prt)
{
 std::map<std::string, zChronoPool<zClientHTTP> >::iterator k= keep_value.find(adr_prt);
 if(k == keep_value.end()) return NULL;
 return k->second.get();
};

zClientHTTP* zPoolClientHTTP::setKeep(zClientHTTP* p)
{
 if(p->address_port.empty()) return NULL;
 if(keep_value[p->address_port].set(p)) return p;
 return NULL;
};

zClientHTTP* zPoolClientHTTP::eraseKeep(zClientHTTP* p)
{
 if(p == NULL) return NULL;
 std::map<std::string, zChronoPool<zClientHTTP> >::iterator k= keep_value.find(p->address_port);
 if(k == keep_value.end()) return NULL;
 if(k->second.erase(p)) return p;
 return NULL;
};

zPoolClientHTTP::~zPoolClientHTTP()
{
 std::set<zPacket*> v=mtp_value;
 for(std::set<zPacket*>::iterator k=v.begin(); k != v.end(); ++k)
 { zPoolClientHTTP::push(*k); }
};

bool zPoolClientHTTP::push(zPacket* p)
{
 if(zPool<zPacket>::push(p))
 {
  p->clear_ext(); p->clear();
  zClientHTTP* pc= dynamic_cast<zClientHTTP*>(p);
  if(pc)
  {
   eraseKeep(pc);
   pc->address.clear(); pc->peerport=0; pc->host.clear(); pc->port=0; pc->address_port.clear();
  }
  p->clear_event(); p->clear_socket(); p->parent=NULL;
  return true;
 }
 return false;
};

bool zPoolClientHTTP::drop(zPacket* p)
{
 zClientHTTP* pc= dynamic_cast<zClientHTTP*>(p);
 if(pc) { eraseKeep(pc); }
 return zPool<zPacket>::drop(p);
};

