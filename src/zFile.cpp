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

#include "zFile.h"
#include <algorithm>
#include <functional>

#if defined(_WIN32) || defined(_WIN64)
//#include <windows.h>
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

static ulonglong z_npos_set() { ulonglong ret(1); ret <<=63; return ret; };

const ulonglong zFile::npos=z_npos_set();

bool ZNDIR::create(const std::string &path)
{
 if(ZNDIR::check(path)) return true;
#if defined(_WIN32) || defined(_WIN64)
 return (mkdir(path.c_str()) == 0);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 return (mkdir(path.c_str(), 0777) == 0);
#endif // __GNUG__
#endif // _WIN32 
}

bool ZNDIR::erase(const std::string &_path)
{
 std::string path=ZNSTR::trim(_path);
 if(!ZNDIR::check(path)) return false; 
 std::vector<std::string> f=ZNFILE::roll(path);
 for(size_t i=0; i < f.size(); i++)
 { ZNFILE::erase(path+std::string(ZNSTR::path_delimiter)+f[i]); }
 std::vector<std::string> d=ZNDIR::roll(path);
 for(size_t i=0; i < d.size(); i++)
 { ZNDIR::erase(path+std::string(ZNSTR::path_delimiter)+d[i]); }
 return (rmdir(path.c_str()) == 0);
}

bool ZNDIR::check(const std::string &path)
{
#if defined(_WIN32) || defined(_WIN64)
 WIN32_FIND_DATA result;
 HANDLE fd = FindFirstFile(ZNSTR::trim(path).c_str(), &result);
 if(fd != INVALID_HANDLE_VALUE) { FindClose(fd); return true; }
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 DIR *fd = opendir(ZNSTR::trim(path).c_str());
 if(fd) { closedir(fd); return true; }
#endif // __GNUG__
#endif // _WIN32 
 return false;
}

std::vector<std::string> ZNDIR::roll(const std::string &path)
{
 std::vector<std::string> v;
 ZNDIR::roll(v, path);
 return v;
};

bool ZNDIR::roll(std::vector<std::string>& ret, const std::string &path)
{
#if defined(_WIN32) || defined(_WIN64)
 WIN32_FIND_DATA result;
 HANDLE fd = FindFirstFile((ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+'*').c_str(), &result);
 if(fd == INVALID_HANDLE_VALUE) return false;
 std::string name=result.cFileName;
 if((result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !name.empty() && name[0] != '.' ) { ret.push_back(name); }
 for(;FindNextFile(fd, &result) != 0;)
 {
  name=result.cFileName;
  if((result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !name.empty() && name[0] != '.' ) { ret.push_back(name); }
 }
 FindClose(fd);
/*
  for(struct dirent *d = ::readdir(fd); d; d = ::readdir(fd))
  {
   std::string name = d->d_name;
   if(!name.empty() && name[0] == '.') continue;
   std::string fullname = (ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+name);
   struct stat statbuf;
   if(::stat(fullname.c_str(),&statbuf) != 0 ) continue;
   if( statbuf.st_mode & S_IFDIR) v.push_back(name);
  }
*/ 
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 DIR *fd = ::opendir(ZNSTR::trim(path).c_str());
 if(!fd) return false;
 struct dirent entry;
 struct dirent *result;
 std::string name, fullname;
 for(int return_code = readdir_r(fd, &entry, &result); result != NULL && return_code == 0; return_code = readdir_r(fd, &entry, &result))
 {
  name = entry.d_name;
  if(!name.empty() && name[0] == '.') continue;
  fullname = (ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+name);
  struct stat statbuf;
  if(::stat(fullname.c_str(),&statbuf) != 0 ) continue;
  if(statbuf.st_mode & S_IFDIR) ret.push_back(name);
 }
 closedir(fd);
#endif // __GNUG__
#endif // _WIN32
 return true;
};

bool ZNFILE::create(const std::string &path)
{
 if(ZNFILE::check(path)) return false; 
 FILE* f=::fopen(ZNSTR::trim(path).c_str(),"w+b");
 if(f == NULL) return false;
 ::fclose(f);
 return true;
}

bool ZNFILE::erase(const std::string &path)
{ return unlink(ZNSTR::trim(path).c_str()) == 0; }

bool ZNFILE::rename(const std::string &oldpath, const std::string &newpath)
{
 if(ZNFILE::check(ZNSTR::trim(newpath))) return false;
 return (::rename(ZNSTR::trim(oldpath).c_str(), ZNSTR::trim(newpath).c_str()) == 0); 
}

bool ZNFILE::copy(const std::string &oldpath, const std::string &newpath)
{
 if(!ZNFILE::check(oldpath)) return false;
 if(!ZNFILE::check(newpath)) { if(!ZNFILE::create(newpath)) return false; }
 else
 {
  struct stat statbuf1;
  if(::stat(ZNSTR::trim(oldpath).c_str(), &statbuf1) != 0) return false;
  struct stat statbuf2;
  if(::stat(ZNSTR::trim(newpath).c_str(), &statbuf2) != 0) return false;
  if(statbuf1.st_uid == statbuf2.st_uid && statbuf1.st_gid == statbuf2.st_gid) return true;
  ZNFILE::rewrite(newpath,"");
 }
 longlong n=ZNFILE::size(oldpath);
 n/=102400; n++;
 std::string s;
 for(longlong i=0; i < n; i++)
 {
  s=""; ZNFILE::read(s,oldpath,i*102400,102400);
  ZNFILE::write(newpath,s);
 }
 return true;
}

bool ZNFILE::move(const std::string &oldpath, const std::string &newpath)
{
 if(!ZNFILE::check(oldpath)) return false;
 if(ZNFILE::check(newpath)) { ZNFILE::erase(newpath); }
 return (::rename(ZNSTR::trim(oldpath).c_str(), ZNSTR::trim(newpath).c_str()) == 0);
}

bool ZNFILE::check(const std::string &path)
{ return ::access(ZNSTR::trim(path).c_str(), 0) == 0; }

std::vector<std::string> ZNFILE::roll(const std::string &path)
{
 std::vector<std::string> v;
 ZNFILE::roll(v, path);
 return v;
};

bool ZNFILE::roll(std::vector<std::string>& ret, const std::string &path)
{
#if defined(_WIN32) || defined(_WIN64)
 WIN32_FIND_DATA result;
 HANDLE fd = FindFirstFile((ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+'*').c_str(), &result);
 if(fd == INVALID_HANDLE_VALUE) return false;
 std::string name=result.cFileName;
 if(!(result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !name.empty() && name[0] != '.' ) { ret.push_back(result.cFileName); }
 for(;FindNextFile(fd, &result) != 0;)
 {
  name=result.cFileName;
  if(!(result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !name.empty() && name[0] != '.' ) { ret.push_back(result.cFileName); }
 }
 FindClose(fd);
/*
  for(struct dirent *d = ::readdir(fd); d; d = ::readdir(fd))
  {
   std::string name = d->d_name;
   if(!name.empty() && name[0] == '.' ) continue;
   std::string fullname =(ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+name);
   struct stat statbuf;
   if(stat(fullname.c_str(),&statbuf) != 0) continue;
   if(!(statbuf.st_mode & S_IFDIR)) v.push_back(name);
  }
*/ 
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 DIR *fd = ::opendir(ZNSTR::trim(path).c_str());
 if(!fd) return false;
 struct dirent entry;
 struct dirent *result;
 std::string name, fullname;
 for(int return_code = readdir_r(fd, &entry, &result); result != NULL && return_code == 0; return_code = readdir_r(fd, &entry, &result))
 {
  name = entry.d_name;
  if(!name.empty() && name[0] == '.' ) continue;
  fullname =(ZNSTR::trim(path)+std::string(ZNSTR::path_delimiter)+name);
  struct stat statbuf;
  if(stat(fullname.c_str(),&statbuf) != 0) continue;
  if(!(statbuf.st_mode & S_IFDIR)) ret.push_back(name);
 }
 ::closedir(fd);
#endif // __GNUG__
#endif // _WIN32
 return true;
};

longlong ZNFILE::size(const std::string &path)
{
#if defined(_WIN32) || defined(_WIN64)
 HANDLE f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f == NULL) return -1;
 LARGE_INTEGER l;
 if(GetFileSizeEx(f,&l)) { longlong ret=l.HighPart; ret <<= 32; ret+=l.LowPart; ::CloseHandle(f); return ret; }
 ::CloseHandle(f); return -1;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 struct stat statbuf;
 if (::stat(ZNSTR::trim(path).c_str(),&statbuf) != 0 ) return -1;
 return statbuf.st_size;
#endif
#endif
}// size

ZFINFO ZNFILE::info(const std::string &path)
{
 ZFINFO ret;
 struct stat statbuf;
 if (::stat(ZNSTR::trim(path).c_str(), &statbuf) != 0) return ret;
/*
#if defined(_WIN32) || defined(_WIN64)
 ret.size=ZNFILE::size(path);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 ret.size=statbuf.st_size;
#endif
#endif
*/
 ret.size=statbuf.st_size;
 ret.accessed=(time_t) statbuf.st_atime;
 ret.modified=(time_t) statbuf.st_mtime;
 ret.created=(time_t) statbuf.st_ctime;
 if(statbuf.st_mode & S_IREAD) ret.read=true;
 if(statbuf.st_mode & S_IWRITE) ret.write=true;
 if(statbuf.st_mode & S_IEXEC) ret.exec=true;
 ret.user=statbuf.st_uid;
 ret.group=statbuf.st_gid;
 return ret; 
}

bool ZNFILE::read(std::string& ret,const std::string &path,ulonglong start,size_t number)
{
// ret="";
 longlong s=ZNFILE::size(path);
 if(s <= ((longlong) start)) return false;
 size_t n=number;
 if((s-start) < n) n=(s-start);
 size_t l=ret.size();
#if defined(_WIN32) || defined(_WIN64)
 HANDLE f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f == INVALID_HANDLE_VALUE) return false;
 LONG ll=(LONG) start;
 LONG lh=(LONG) (start >> 32);
 if(::SetFilePointer(f,ll,&lh,FILE_BEGIN) == INVALID_SET_FILE_POINTER) { ::CloseHandle(f); return false; }
 ret.resize(l+n); DWORD k;
 if(ReadFile(f,(void*) (ret.c_str()+l),n,&k,NULL) == 0) { ::CloseHandle(f); ret.resize(l); return false; }
 ::CloseHandle(f); ret.resize(l+k);
 return true;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
 int f=::open(ZNSTR::trim(path).c_str(),O_RDONLY);
 if(f < 0) return false;
 if(::lseek(f,start,SEEK_SET) < 0) { ::close(f); return false; }
 ret.resize(l+n);
 ssize_t k=::read(f,(void*) (ret.c_str()+l),n);
 ::close(f);
 if(k < 0) { ret.resize(l); return false; }
 ret.resize(l+k);
 return true;
#else
 return false;
#endif
#endif
}

bool ZNFILE::rewrite(const std::string &path, const std::string &buf)
{
 if(!(ZNFILE::check(path))) return false;
 size_t l=buf.size();
// if(l == 0) return true;
#if defined(_WIN32) || defined(_WIN64)
 HANDLE f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE | GENERIC_READ,0,NULL,TRUNCATE_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f == INVALID_HANDLE_VALUE) return false;
 if(l == 0) { ::CloseHandle(f); return true; }
 if(::SetFilePointer(f,0,NULL,FILE_BEGIN) == INVALID_SET_FILE_POINTER) { ::CloseHandle(f); return 0; }
 DWORD k=0;
 if(WriteFile(f,(void*) buf.c_str(),l,&k,NULL) == 0) { ::CloseHandle(f); return 0; }
 ::FlushFileBuffers(f); ::CloseHandle(f); return k;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 int f=::open(ZNSTR::trim(path).c_str(),O_WRONLY | O_TRUNC);
 if(f < 0) return false;
 if(l == 0) { ::close(f); return true; }
 if(::lseek(f,0,SEEK_SET) < 0) { ::close(f); return false; }
 ssize_t k=::write(f,(void*) buf.c_str(),l);
 ::fsync(f);
 ::close(f);
 if(k < 0) { return false; }
 return true;
#else
 return 0;
#endif
#endif
}

size_t ZNFILE::write(const std::string &path, const std::string &buf, ulonglong start)
{
 if(!(ZNFILE::check(path))) return false;
 size_t l=buf.size();
 if(l == 0) return true;
 longlong n=ZNFILE::size(path);
 if(start < ((ulonglong) n)) n=start;
#if defined(_WIN32) || defined(_WIN64)
 HANDLE f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(f == INVALID_HANDLE_VALUE) return false;
 LONG ll=(LONG) n;
 LONG lh=(LONG) (n >> 32);
 if(::SetFilePointer(f,ll,&lh,FILE_BEGIN) == INVALID_SET_FILE_POINTER) { ::CloseHandle(f); return 0; }
 DWORD k=0;
 if(WriteFile(f,(void*) buf.c_str(),l,&k,NULL) == 0) { ::CloseHandle(f); return 0; }
 ::FlushFileBuffers(f); ::CloseHandle(f); return k;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 int f=::open(ZNSTR::trim(path).c_str(),O_WRONLY);
 if(f < 0) return false;
 if(::lseek(f,n,SEEK_SET) < 0) { ::close(f); return 0; }
 ssize_t k=::write(f,(void*) buf.c_str(),l);
 ::fsync(f);
 ::close(f);
 if(k < 0) return 0;
 return k; 
#else
 return 0;
#endif
#endif
}

zFile::zFile(const std::string &path, bool writable):
#if defined(_WIN32) || defined(_WIN64)
 f(INVALID_HANDLE_VALUE)
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 f(0)
#endif
#endif
{
 if(!(ZNFILE::check(path))) return;
#if defined(_WIN32) || defined(_WIN64)
 if(writable) { f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); }
 else { f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); }
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(writable) f=::open(ZNSTR::trim(path).c_str(),O_RDWR);
 else f=::open(ZNSTR::trim(path).c_str(),O_RDONLY);
 if(f < 0) { f=0; return; }
#endif
#endif
}

zFile::~zFile()
{
#if defined(_WIN32) || defined(_WIN64)
 if(f != INVALID_HANDLE_VALUE) { ::CloseHandle(f); f=INVALID_HANDLE_VALUE; }
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(f != 0) { ::fsync(f); ::close(f); f=0; }
#endif
#endif
}

bool zFile::open(const std::string &path, bool writable)
{
 if(!(ZNFILE::check(path))) return false;
 close();
#if defined(_WIN32) || defined(_WIN64)
 if(writable) { f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); }
 else { f=::CreateFile(ZNSTR::trim(path).c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); }
 return (f != INVALID_HANDLE_VALUE);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(writable) f=::open(ZNSTR::trim(path).c_str(),O_RDWR);
 else f=::open(ZNSTR::trim(path).c_str(),O_RDONLY);
 if(f < 0) { f=0; return false; }
 return true;
#endif
#endif
};

bool zFile::alive() const 
{
#if defined(_WIN32) || defined(_WIN64)
 return (f != INVALID_HANDLE_VALUE);
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 return (f != 0);
#endif
#endif
}

longlong zFile::size() const
{
#if defined(_WIN32) || defined(_WIN64)
 if(f == INVALID_HANDLE_VALUE) return -1;
 LARGE_INTEGER l;
 if(GetFileSizeEx(f,&l)) { longlong ret=l.HighPart; ret <<= 32; ret+=l.LowPart; return ret; }
 return -1;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 struct stat statbuf;
 if(::fstat(f,&statbuf) != 0 ) return -1;
 return statbuf.st_size;
#endif
#endif
}

bool zFile::read(std::string& ret,ulonglong start, size_t number) const
{
// ret="";
#if defined(_WIN32) || defined(_WIN64)
 if(f == INVALID_HANDLE_VALUE) return false;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(f == 0) return false;
#endif
#endif
 longlong s=size();
 if(s <= ((longlong) start)) return false;
 size_t n=number;
 if((s-start) < n) n=(s-start);
 size_t l=ret.size();
#if defined(_WIN32) || defined(_WIN64)
 LONG ll=(LONG) start;
 LONG lh=(LONG) (start >> 32);
 if(::SetFilePointer(f,ll,&lh,FILE_BEGIN) == INVALID_SET_FILE_POINTER) { return false; }
 ret.resize(l+n); DWORD k;
 if(ReadFile(f,(void*) (ret.c_str()+l),n,&k,NULL) == 0) { ret.resize(l); return false; }
 ret.resize(l+k); return true;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(::lseek(f,start,SEEK_SET) < 0) { return false; }
 ret.resize(l+n);
 ssize_t k=::read(f,(void*) (ret.c_str()+l),n);
 if(k < 0) { ret.resize(l); return false; }
 ret.resize(l+k); return true;
#else
 return false;
#endif
#endif 
}

size_t zFile::write(const std::string &buf,ulonglong start) const
{
#if defined(_WIN32) || defined(_WIN64)
 if(f == INVALID_HANDLE_VALUE) return 0;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(f == 0) return 0;
#endif
#endif
 size_t l=buf.size();
 if(l == 0) return l;
 longlong n=size();
 if(start < ((ulonglong) n)) n=start;
#if defined(_WIN32) || defined(_WIN64)
 LONG ll=(LONG) n;
 LONG lh=(LONG) (n >> 32);
 if(::SetFilePointer(f,ll,&lh,FILE_BEGIN) == INVALID_SET_FILE_POINTER) { return 0; }
 DWORD k=0;
 if(WriteFile(f,(void*) buf.c_str(),l,&k,NULL) == 0) { return k; }
 ::FlushFileBuffers(f); return k;
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(::lseek(f,n,SEEK_SET) < 0) { return 0; }
 ssize_t k=::write(f,(void*) buf.c_str(),l);
 ::fsync(f);
 if(k < 0) return 0;
 return k;
#endif
#endif
}

void zFile::close() const
{
#if defined(_WIN32) || defined(_WIN64)
 if(f != NULL) { ::CloseHandle(f); f=INVALID_HANDLE_VALUE; }
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__) 
 if(f != 0) { ::fsync(f); ::close(f); f=0; }
#endif
#endif
}



