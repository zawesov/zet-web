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

#ifndef __zFile_h
#define __zFile_h 1

#if defined(_WIN32) || defined(_WIN64)

#ifdef _WIN32_WINNT
#if(_WIN32_WINNT  < 0x0500)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
#else
#define _WIN32_WINNT 0x0500
#endif
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
#define _FILE_OFFSET_BITS 64
#endif
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <typeinfo>

#if defined(_WIN32) || defined(_WIN64)
#ifndef _WINDOWS_
#include <windows.h>
#endif
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
#include <sys/stat.h>
#endif
#endif

#include "zString.h"

namespace ZNDIR
{
 bool create(const std::string &path);
 /*
  Creates path directory.
  If success returns true, false otherwise. 
 */

 bool erase(const std::string &path);
 /*
  Removes path directory.
  Returns true if path directory was removed, false otherwise. 
 */

 bool check(const std::string &path);
 /*
  Returns true if path directory was found, false otherwise.
 */

 std::vector<std::string> roll(const std::string &path);
 bool roll(std::vector<std::string>& ret, const std::string &path);
 /*
  Returns list of subdirectories for path directory.
 */

}; // ZNDIR

class ZFINFO
{
 public:
 ulonglong size; // size of file in bytes
 time_t accessed; // last time of access to file
 time_t modified; // last time of modify
 time_t created; // time of create file
 bool read; // can read
 bool write; // can write
 bool exec; //  can execute
 int user; // user owner
 int group; // user group

 ZFINFO():size(0),accessed(0),modified(0),created(0),read(0),write(0),exec(0),user(0),group(0) {};

 ZFINFO(const ZFINFO &src):
  size(src.size),accessed(src.accessed),modified(src.modified),created(src.created),read(src.read),write(src.write),exec(src.exec),user(src.user),group(src.group) {};
 ZFINFO &operator=(const ZFINFO &src)
 {
  if(&src == this) return *this;
  size=src.size; accessed=src.accessed; modified=src.modified; created=src.created; read=src.read;
  write=src.write; exec=src.exec; user=src.user; group=src.group; 
  return *this;
 };
}; // class ZFINFO

class zFile
{
 public:
static const ulonglong npos;

explicit zFile(const std::string &path="", bool writable=true);
/*
 Opens path file if file is exist.
 If writable is true read and write operations are accessable, if writable is false only read.
*/

virtual ~zFile();
/*
 Close file.
*/

virtual bool open(const std::string &path, bool writable=true);
/*
 Tries to reopen path file.
 If path file is not found the old file stay alive.
 If success returns true, false otherwise. 
*/

virtual  bool alive() const;
/*
 If file is open return true, false otherwise.
*/

 longlong size() const;
/*
 Returns size of file.
 Returns -1 if file is not open. 
*/

virtual bool read(std::string& ret,ulonglong start=0, size_t number=std::string::npos) const;
/*
 Reads starting from start position and number bytes or to the end of file.
 If success returns true, false otherwise.
*/

virtual size_t write(const std::string &buf,ulonglong start=zFile::npos) const;
/*
 Writes buf to file starting from start position.
 If success returns true, false otherwise. 
*/

virtual void close() const;
/*
 Closes file.
*/

 protected:
 zFile(const zFile &src);
 /* Constructor copy. */
 zFile &operator=(const zFile &src);
 /* operator=. */
#if defined(_WIN32) || defined(_WIN64)
mutable HANDLE f;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
mutable int f;
#endif // __GNUG__
#endif // _WIN32 
}; // class zFile

namespace ZNFILE
{
 longlong size(const std::string &path);
 /*
   Returns size of path file.
   Returns -1 if file is not found. 
 */

 bool create(const std::string &path);
/*
 Creates path file.
 If success returns true, false otherwise. 
*/

 bool erase(const std::string &path);
/*
 Removes path file.
 Returns true if path file was removed, false otherwise. 
*/

 bool rename(const std::string &oldpath, const std::string &newpath);
/*
 Renames oldpath file to newpath.
 If success returns true, false otherwise. 
*/

 bool copy(const std::string &oldpath, const std::string &newpath);
/*
 Copies oldpath file to newpath.
 If success returns true, false otherwise. 
*/

 bool move(const std::string &oldpath, const std::string &newpath);
/*
 Moves oldpath file to newpath.
 If success returns true, false otherwise.
*/

 bool check(const std::string &path);
/*
 Returns true if path file was found, false otherwise.
*/

 std::vector<std::string> roll(const std::string &path);
 bool roll(std::vector<std::string>& ret, const std::string &path);
/*
 Returns list of files for path directory.
*/

 ZFINFO info(const std::string &path);
/*
 Returns struct ZFINFO for path file.
*/

 bool read(std::string &ret,const std::string &path,ulonglong start=0,size_t number=std::string::npos);
/*
 Reads from path file starting from start position and number bytes or to the end of file.
 If success returns true, false otherwise. 
*/

 bool rewrite(const std::string &path,const std::string &buf);
/*
 Rewrites path file by string buf.
 If success returns true, false otherwise. 
*/

 size_t write(const std::string &path,const std::string &buf,ulonglong start=zFile::npos);
/*
 Writes buf to path file starting from start position.
 If success returns true, false otherwise. 
*/
}; // ZNFILE

#endif // __zFile_h


