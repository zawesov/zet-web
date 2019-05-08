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
 
#ifndef __zThread_h
#define __zThread_h 1

#if defined(_WIN32) || defined(_WIN64) 
#include <time.h>
//#include <io.h>
#include <process.h>
#ifndef _WINDOWS_
#include <windows.h>
#endif
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <sys/stat.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#endif
#endif

#include "zMutex.h"


class zTimer
{
public:

static time_t now(); // return ::time(NULL);

#if defined(_WIN32) || defined(_WIN64) 
  zTimer() : init(clock()) {};
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  zTimer() { gettimeofday(&init, NULL); };
#endif
#endif

 zTimer(const zTimer &src):init(src.init) { };
 zTimer &operator=(const zTimer &src) { if(&src == this) return *this; init=src.init; return *this; };

 bool check(time_t timeout) const;  // in milliseconds
/*
 If timeout <= (now_time-time_create) return true, false otherwise.
*/
 time_t get() const;                // in milliseconds
/*
  Returns (now_time-time_create);
*/
 void reset();
/*
  Resets init.
*/ 

private:
#if defined(_WIN32) || defined(_WIN64) 
 clock_t init;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 struct timeval init;
#endif
#endif
};// class zTimer

class zThread
{
private:

protected:

 zThread(const std::string &nm="");

 virtual void run() = 0;
/*
 You must redefine this function to define thread execution.
*/
 bool testStop() const;
/*
 You must (or can) use this function in your run() to check the 'stop' notification.
*/

public:

 static zThread* currentThread();
/*
 Returns pointer to zThread object of 'current' thread.
 Can return NULL, if current thread wasn't created through zThread interface.
*/
 static size_t size();

 static std::vector<zThread*> getThreadList();
/*
 Returns list of pointers to zThread object created through zThread interface.
*/
 static void sleep(time_t timeout);// in milliseconds

 static void stopAll();
/*
 Notifies all zThread's threads to end execution.
*/
 static void joinAll();
/*
 Waits, until all zThread's threads end execution.
*/
 static size_t getPid();
/*
 Retrieves the process identifier of the calling process.
*/
 static size_t getTid();
/*
 Returns pid of the thread from witch execute this function.
*/
 virtual ~zThread();
/*
  Destructor.
  1.stop(),2.join(),3.terminate
*/
virtual void destroy();
/*
 Destroy thread.
 1.stop(),2.join(),3.terminate
*/
virtual std::string getName() const;
/*
 Returns current name of zThread
*/
virtual void setName(const std::string &q);
/*
 Sets new name 'Name' for current object.
*/
virtual size_t Pid() const;
/*
 Returns current pid of zThread.
*/
virtual int getPriority() const;
/*
 Returns current priority of thread.
*/
virtual void setPriority(int new_priority);
/*
 Sets new priority of the thread.
*/
virtual bool isAlive() const;
/*
 Checks running the thread or not
*/
virtual bool isDaemon() const;
/*
 Checks running the thread as daemon.
*/
virtual bool isInterrupted() const;
/*
 Checks suspendFlag and alive.
*/
virtual void join();
/*
 Waits, until the thread ends execution.
*/
virtual bool join(time_t timeout);
/*
 Waits 'timeout' milliseconds max. If the thread ends execution, returns true.
*/
virtual void setDaemon(bool on = true);
/*
 If(on == true) thread object will be deleted after stoping.
*/
virtual void start();
/*
 Starts the execution of zThread procedure run().
*/
virtual void stop(); 
/*
 Notifies the thread to end its execution. 
 The thread procedure needs to check function testStop() 
 periodically to know about the notification.
*/
virtual void suspend();
/*
 Suspends the thread execution.
*/
virtual void resume(); 
/*
 Resumes the thread execution after suspend().
*/

protected:

#if defined(_WIN32) || defined(_WIN64)
static DWORD run_thread_item(LPDWORD attr);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
static  void *run_thread_item(void *attr);
#endif
#endif

 static zMutex mst_mut;
 static bool stopAllFlag;
 static std::vector<zThread*> ms_list;
 mutable zMutex mtr_mut;
 std::string name;

#if defined(_WIN32) || defined(_WIN64)
 HANDLE hThread;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 pthread_t thread;
#endif
#endif
 bool alive;
 size_t pid;
 bool stopFlag;
 bool suspendFlag;
 bool detachFlag;

private:
  zThread(const zThread &);
  zThread &operator=(const zThread &);


};// class zThread 

#endif // __zThread_h
