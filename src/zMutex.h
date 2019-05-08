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

#ifndef __zMutex_h
#define __zMutex_h 1


#if defined(_WIN32) || defined(_WIN64)
#include <time.h>
#ifndef _WINDOWS_
#include <windows.h>
#endif
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <pthread.h>
#include <sys/resource.h>
#include <sys/time.h>
/*
#ifdef __CYGWIN__
#include <sys/errno.h>
#else
#include <asm/errno.h>
#endif
*/
#endif
#endif

#include "zString.h"
#include <queue>
#include <map>

//using std::queue;
//using std::map;

#define ZSLEEP_CYCLES 150

class zMutex
{

 friend class zMutexLock;

public:

 zMutex();
/*
 Creates a lockable object.
*/

 virtual ~zMutex();
/*
 destructor
*/

 bool lock() const;
/*
 Blocks zMutex object.
 Instead lock and unlock methods use zMutexLock object. 
*/

 bool lock(time_t timeout) const;
/*
 Tries to block zMutex object during timeout msec.
 If blocking operation is success return true, false otherwise.
*/

 void unlock() const;
/*
 Unblocks zMutex object.
*/

protected:

#if defined(_WIN32) || defined(_WIN64)
mutable CRITICAL_SECTION m_cs;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
mutable pthread_mutex_t status;
#endif
#endif
mutable size_t pid;
mutable int pn;
mutable std::queue<size_t> que;

private:

 zMutex(const zMutex &src);
/*
 Prevent constructor copy
*/
 zMutex &operator=(const zMutex &src);
/*
 Prevent operator=
*/

}; // class zMutex

class zMutexLock
{
public:

explicit zMutexLock(zMutex* m);
/*
 Blocks zMutex* m.
*/

explicit zMutexLock(zMutex* m, int timeout);
/*
 Tries to block zMutex* m during timeout msec.
*/

 virtual ~zMutexLock();
/*
 Unblocks zMutex object.
*/

 bool operator!() const;
/*
 Return true if mutex is not blocked, false otherwise.
*/

protected:

 zMutex* ml;
 bool result;

private:

explicit zMutexLock(const zMutexLock &);
/*
 Prevent constructor copy
*/
 zMutexLock &operator=(const zMutexLock &);
/*
 Prevent operator=
*/

};// class zMutexLock

class zRWMutex
{

 friend class zRWMutexLock;

public:

 zRWMutex();
/*
 Creates a lockable object.
*/

 virtual ~zRWMutex();
/*
 destructor
*/

 bool lock(bool writable=false) const;
/*
 Blocks zRWMutex object.
 When writable is true then exclusive access for every thread.
 When writable is false then access for multiple threads.
 Instead lock and unlock methods use zRWMutexLock object.
*/

 void unlock(bool writable=false) const;
/*
 Unblocks zRWMutex object.
 writable is the same as in the lock function.
*/

protected:

class zMutInt
{
 public:

 zMutInt():
 value(0)
 { };

 operator int&() { return value; };
 operator int&() const { return value; };

 mutable int value;
};

#if defined(_WIN32) || defined(_WIN64)
mutable CRITICAL_SECTION m_cs;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
mutable pthread_mutex_t status;
#endif
#endif
mutable size_t pid;
mutable int pn;
mutable std::queue<size_t> que;
mutable std::map<size_t, zMutInt> rpid;

private:

 zRWMutex(const zRWMutex &src);
/*
 Prevent constructor copy
*/
 zRWMutex &operator=(const zRWMutex &src);
/*
 Prevent operator=
*/

}; // class zRWMutex

class zRWMutexLock
{

public:

explicit zRWMutexLock(zRWMutex* m, bool writable=false);
/*
 Blocks zRWMutex* m.
 When writable is true then exclusive access for every thread.
 When writable is false then access for multiple threads.
*/

 virtual ~zRWMutexLock();
/*
 Unblocks zRWMutex object.
*/

protected:

 zRWMutex* ml;
 bool writing;

private:

explicit zRWMutexLock(const zRWMutexLock &);
/*
 Prevent constructor copy
*/
 zRWMutexLock &operator=(const zRWMutexLock &);
/*
 Prevent operator=
*/

};// class zRWMutexLock

#endif // __zMutex_h
