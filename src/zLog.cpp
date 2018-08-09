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

#include "zLog.h"
#include "zThread.h"
#include <algorithm>
#include <functional>

#if defined(_WIN32) || defined(_WIN64)
#include <direct.h>
//#include <dirent.h>
//#include <dir.h>
#include <io.h>
#include <process.h>
#include <sys\stat.h>
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/resource.h>
#endif // _WIN32
#endif // __GNUG__


#define ZLOG_BUF_SIZE 65536000


zLog zLog::Log(ZLOG_PATH, ZLOG_SYNC);

zLog::zLog():
 zFile(),
 m_mut(),
 m_path(""),
 m_level(ZLOG_DEBUG),
 m_value(new std::list<std::string>()),
 m_storage(new std::list<std::string>()),
 m_sync(false)
{
};

zLog::zLog(const std::string &path, bool sync):
 zFile(path),
 m_mut(),
 m_path(path),
 m_level(ZLOG_DEBUG),
 m_value(new std::list<std::string>()),
 m_storage(new std::list<std::string>()),
 m_sync(sync)
{
 if(!alive() && !ZNFILE::check(path))
 {
  if(!ZNFILE::create(path)) return;
#if defined(_WIN32) || defined(_WIN64)
 f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
  f=::open(ZNSTR::trim(path).c_str(),O_RDWR);
 if(f < 0) { f=0; return; }
#endif
#endif
 }
};

bool zLog::open(const std::string &path) const
{
 zMutexLock m(&m_mut);
 zFile::close();
 m_path=path;
 if(!ZNFILE::check(path) && !ZNFILE::create(path)) return false;
#if defined(_WIN32) || defined(_WIN64)
 f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 return (f != INVALID_HANDLE_VALUE);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 f=::open(ZNSTR::trim(path).c_str(),O_RDWR);
 if(f < 0) { f=0; return false; }
 return true;
#endif
#endif
};

void zLog::update() const
{
 if(!m_sync) return;
 {
  zMutexLock m(&m_mut);
  if(m_value->size() == 0) return;
  m_storage->clear();
  std::list<std::string>* p = m_value;
  m_value = m_storage;
  m_storage = p;
 }
 std::string q;
 for(std::list<std::string>::const_iterator k=m_storage->begin(); k != m_storage->end(); ++k)
 {
  q+=*k;
  if(ZLOG_BUF_SIZE < q.size()) { zFile::write(q); q.clear(); }
 }
 m_storage->clear();
/*
 if(m_level >= ZLOG_DEBUG)
 {
  zTimer t;
  time_t s= t.get();
  size_t n = zFile::write(q);
  if(n) zFile::write("<<<"+ZNSTR::toString(t.get()-s)+">>>\n");
  return;
 }
*/
 zFile::write(q); 
};

void zLog::rotate() const
{
 zMutexLock m(&m_mut);
 if(zFile::alive())
 {
  zFile::close();

  size_t l=m_path.find_last_of("/\\");
  if(l == std::string::npos) l=0;
  else ++l;
  std::string q=m_path.substr(0,l);
  time_t ltime= ::time(NULL);
#if defined(_WIN32) || defined(_WIN64)
  struct tm* tmtime=localtime(&ltime);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
  struct tm tmtm;
  struct tm* tmtime=&tmtm;
  localtime_r(&ltime, tmtime);
#endif
#endif
  if(tmtime != NULL)
  {
   q+=ZNSTR::toString(tmtime->tm_year+1900);
   q+='_';
   if(tmtime->tm_mon < 9) q+='0';
   q+=ZNSTR::toString(tmtime->tm_mon+1);
   q+='_';
   if(tmtime->tm_mday < 10) q+='0';
   q+=ZNSTR::toString(tmtime->tm_mday);
   q+='_';
   if(tmtime->tm_hour < 10) q+='0';
   q+=ZNSTR::toString(tmtime->tm_hour);
   q+='_';
   if(tmtime->tm_min < 10) q+='0';
   q+=ZNSTR::toString(tmtime->tm_min);
   q+='_';
   if(tmtime->tm_sec < 10) q+='0';
   q+=ZNSTR::toString(tmtime->tm_sec);
   q+='_';
  }
  else
  {
   q+=ZNSTR::toString((longlong) ltime);
   q+='_';
  }
  q.append(m_path,l,std::string::npos);
  ZNFILE::rename(m_path, q);
 }

 if(!ZNFILE::check(m_path) && !ZNFILE::create(m_path)) return;
#if defined(_WIN32) || defined(_WIN64)
 f=::CreateFile(ZNSTR::trim(m_path).c_str(),GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
// return (f != INVALID_HANDLE_VALUE);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 f=::open(ZNSTR::trim(m_path).c_str(),O_RDWR);
 if(f < 0) f=0;
#endif
#endif
};

size_t zLog::write(const std::string &buf,ulonglong start) const
{
 if(m_sync)
 {
  zMutexLock m(&m_mut);
  m_value->push_back(buf);
  return buf.size();
 }
/*
 if(m_level >= ZLOG_DEBUG)
 {
  zTimer t;
  time_t s= t.get();
  zMutexLock m(&m_mut);
  size_t n = zFile::write(buf, start);
  zFile::write("<<<"+ZNSTR::toString(t.get()-s)+">>>\n");
  return n;
 }
*/
 zMutexLock m(&m_mut);
 return zFile::write(buf, start);
};

size_t zLog::write(const std::list<std::string> &buf,ulonglong start) const
{
 if(buf.size() == 0) return 0;
 std::string q;
 for(std::list<std::string>::const_iterator k=buf.begin(); k != buf.end(); ++k) { q+=*k; }
 return write(q, start);
};


size_t zLog::print(int status, const std::string& classname, const std::string& buf) const
{
 if(status > m_level || status < 0) return 0;
 std::string q;
 time_t ltime = ::time(NULL);
#if defined(_WIN32) || defined(_WIN64)
 struct tm* tmtime=localtime(&ltime);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 struct tm tmtm;
 struct tm* tmtime=&tmtm;
 localtime_r(&ltime, tmtime);
#endif
#endif
 q+='[';
 if(tmtime != NULL)
 {
  q+=ZNSTR::toString(tmtime->tm_year+1900);
  q+='/';
  if(tmtime->tm_mon < 9) q+='0';
  q+=ZNSTR::toString(tmtime->tm_mon+1);
  q+='/';
  if(tmtime->tm_mday < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_mday);
  q+=' ';
 
  if(tmtime->tm_hour < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_hour);
  q+=':';
  if(tmtime->tm_min < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_min);
  q+=':';
  if(tmtime->tm_sec < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_sec);
 }
 std::string st;
 switch(status)
 {
  case ZLOG_INFO: { st="INFO"; break; }
  case ZLOG_WARN: { st="WARN"; break; }
  case ZLOG_ERROR: { st="ERROR"; break; }
  case ZLOG_DEBUG: { st="DEBUG"; break; }
  default: { return 0; }
 }

 q+="] ("+ZNSTR::toString(zThread::getPid())+") {"+ZNSTR::toString(zThread::getTid())+"} ["+st+"] {"+classname+"} ";
 q+=(ZNSTR::trim(buf)+'\n');
 return write(q);
};

size_t zLog::print(int status, const std::string& classname, const std::list<std::string>& buf) const
{
 if(status > m_level || status < 0 || buf.size() == 0) return 0;
 std::string q;
 time_t ltime = ::time(NULL);
#if defined(_WIN32) || defined(_WIN64)
 struct tm* tmtime=localtime(&ltime);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 struct tm tmtm;
 struct tm* tmtime=&tmtm;
 localtime_r(&ltime, tmtime);
#endif
#endif
 q+='[';
 if(tmtime != NULL)
 {
  q+=ZNSTR::toString(tmtime->tm_year+1900);
  q+='/';
  if(tmtime->tm_mon < 9) q+='0';
  q+=ZNSTR::toString(tmtime->tm_mon+1);
  q+='/';
  if(tmtime->tm_mday < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_mday);
  q+=' ';
 
  if(tmtime->tm_hour < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_hour);
  q+=':';
  if(tmtime->tm_min < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_min);
  q+=':';
  if(tmtime->tm_sec < 10) q+='0';
  q+=ZNSTR::toString(tmtime->tm_sec);
 }
 std::string st;
 switch(status)
 {
  case ZLOG_INFO: { st="INFO"; break; }
  case ZLOG_WARN: { st="WARN"; break; }
  case ZLOG_ERROR: { st="ERROR"; break; }
  case ZLOG_DEBUG: { st="DEBUG"; break; }
  default: { return 0; }
 }

 q+="] ("+ZNSTR::toString(zThread::getPid())+") {"+ZNSTR::toString(zThread::getTid())+"} ["+st+"] {"+classname+"} ";
 std::string s;
 for(std::list<std::string>::const_iterator k=buf.begin(); k != buf.end(); ++k) { s+=(q+ZNSTR::trim(*k)+'\n'); }
 return write(s);
};



