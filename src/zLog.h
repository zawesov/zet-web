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

#ifndef __zLog_h
#define __zLog_h 1

#include "zThread.h"
#include "zFile.h"

#define ZLOG_INFO 0
#define ZLOG_WARN 1
#define ZLOG_ERROR 2
#define ZLOG_DEBUG 3


#define LOG_PRINT_ERROR(log_namespase, message) if(ZLOG_ERROR <= zLog::Log.m_level) { zLog::Log.print(ZLOG_ERROR, log_namespase, message); }
#define LOG_PRINT_INFO(log_namespase, message) if(ZLOG_INFO <= zLog::Log.m_level) { zLog::Log.print(ZLOG_INFO, log_namespase, message); }
#define LOG_PRINT_WARN(log_namespase, message) if(ZLOG_WARN <= zLog::Log.m_level) { zLog::Log.print(ZLOG_WARN, log_namespase, message); }
#define LOG_PRINT_DEBUG(log_namespase, message) if(ZLOG_DEBUG <= zLog::Log.m_level) { zLog::Log.print(ZLOG_DEBUG, log_namespase, message); }

#include "zPaths.h"

class zLog: public zFile
{

 public:

static zLog Log;

 bool alive() const { zMutexLock m(&m_mut); return zFile::alive(); };

 longlong size() const { zMutexLock m(&m_mut); return zFile::size(); };

 std::string path() const { zMutexLock m(&m_mut); return m_path; }

 bool read(std::string& ret,ulonglong start=0, size_t number=std::string::npos) const 
 { zMutexLock m(&m_mut); return zFile::read(ret, start, number); };

 void update() const;
 void rotate() const;

 size_t write(const std::string &buf,ulonglong start=zFile::npos) const;

 size_t write(const std::list<std::string> &buf,ulonglong start=zFile::npos) const;

 size_t print(int status, const std::string& classname, const std::string& buf) const;

 size_t print(int status, const std::string& classname, const std::list<std::string>& buf) const;

 bool open(const std::string &pth) const;

 void close() const { zMutexLock m(&m_mut); return zFile::close(); };

 mutable int m_level;

 protected:

 zLog();

explicit zLog(const std::string &pth, bool sync=false);

virtual ~zLog() { update(); if(m_value) delete m_value; if(m_storage) delete m_storage; };

 mutable zMutex m_mut;

 mutable std::string m_path;

 mutable std::list<std::string>* m_value;
 mutable std::list<std::string>* m_storage;
 mutable bool m_sync;


 private:

 zLog(const zLog &src);

 zLog &operator=(const zLog &src);

}; // class zLog

#endif // __zLog_h


