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

#include "zThread.h"

//std::vector<std::string>* zThread::def_param=new std::vector<std::string>();
//std::vector<std::pair<std::string,std::string> >* zThread::def_env=new std::vector<std::pair<std::string,std::string> >();

#include <stdio.h>


#if defined(_WIN32) || defined(_WIN64)
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/wait.h>
#endif
#endif

#include <algorithm>
#include <functional>

//zMutex* zThread::mst_mut=new zMutex();
zMutex zThread::mst_mut;
bool zThread::stopAllFlag=false;
//std::vector<zThread*>* zThread::ms_list=new std::vector<zThread*>();
std::vector<zThread*> zThread::ms_list;

time_t zTimer::now() { return ::time(NULL); };

void zTimer::reset()
{
#if defined(_WIN32) || defined(_WIN64) 
  init= clock();
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  gettimeofday(&init, NULL);
#endif
#endif
};

time_t zTimer::get() const
{
#if defined(_WIN32) || defined(_WIN64)
 return time_t((clock() - init)*1000/CLOCKS_PER_SEC);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 struct timeval tv;
 gettimeofday(&tv, NULL);
 return time_t((tv.tv_sec-init.tv_sec)*1000+(tv.tv_usec-init.tv_usec)/1000);
#endif
#endif
};// zTimer::get


bool zTimer::check(time_t timeout) const { return timeout <= get(); };

#if defined(_WIN32) || defined(_WIN64)
zThread::zThread(const std::string &q):
 hThread(NULL), 
 name(q),
 alive(false),
 pid(0),
 stopFlag(false),
 suspendFlag(false),
 detachFlag(false),
 mtr_mut()
{
 zMutexLock m1(&zThread::mst_mut);
 zThread::ms_list.push_back(this);
}
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
zThread::zThread(const std::string &q):
 mtr_mut(),
 name(q),
 thread(),
 alive(false),
 pid(0),
 stopFlag(false),
 suspendFlag(true),
 detachFlag(false)
{
 zMutexLock m1(&zThread::mst_mut);
 zThread::ms_list.push_back(this);
}
#endif
#endif

zThread::~zThread()
{
 stop();
 join();
 zMutexLock m2(&zThread::mst_mut);
 zMutexLock m1(&mtr_mut);
#if defined(_WIN32) || defined(_WIN64)
 if(hThread != ((HANDLE) NULL))
 {
//  TerminateThread(hThread,0);
  CloseHandle(hThread);
  hThread=(HANDLE) 0;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 if(thread != pthread_t())
 {
//  pthread_cancel(thread);
  thread=pthread_t();
#endif
#endif 
  pid=0;
  stopFlag=false;
  suspendFlag=false;
  detachFlag=false;
  std::vector<zThread*>::iterator k=std::find(zThread::ms_list.begin(),zThread::ms_list.end(),this);
  if(k != zThread::ms_list.end()) { zThread::ms_list.erase(k); } 
 }
}

#if defined(_WIN32) || defined(_WIN64)
DWORD zThread::run_thread_item(LPDWORD attr)
{
 zThread *tr = reinterpret_cast<zThread*>(attr);
 if(tr == NULL) return 0;
 {
  zMutexLock m1(&tr->mtr_mut);
  tr->pid=zThread::getTid();
  tr->suspendFlag = false;
  tr->alive=true;
 }
 tr->run();
 {
  zMutexLock m1(&tr->mtr_mut);
  tr->pid=0;
 }
 if(tr->detachFlag)
 {
  {
   zMutexLock m1(&tr->mtr_mut);
   tr->alive=false;
  }
  delete tr; ExitThread(0); return 0;
 }
 else
 {
  zMutexLock m1(&tr->mtr_mut);
  tr->alive=false;
 }
 ExitThread(0);
 return 0; 
}
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
void* zThread::run_thread_item(void* attr)
{
 zThread* tr = reinterpret_cast<zThread*>(attr);
 if(tr == NULL) return NULL;
 {
  zMutexLock m1(&tr->mtr_mut);
  pthread_detach(tr->thread);
  tr->pid=zThread::getTid();
  tr->suspendFlag = false;
  tr->alive=true;
 }
 tr->run();
 {
  zMutexLock m1(&tr->mtr_mut);
  tr->pid=0;
 }
 if(tr->detachFlag)
 {
  {
   zMutexLock m1(&tr->mtr_mut);
   tr->alive=false;
  }
  delete tr; pthread_exit(NULL); return NULL;
 }
 else
 {
  zMutexLock m1(&tr->mtr_mut);
  tr->alive=false;
 }
 pthread_exit(NULL);
 return NULL;
}
#endif
#endif 

void zThread::destroy()
{
 stop();
 join();
 zMutexLock m2(&zThread::mst_mut);
 zMutexLock m1(&mtr_mut);
#if defined(_WIN32) || defined(_WIN64)
 if(hThread != ((HANDLE) NULL))
 {
  TerminateThread(hThread, 0);
  hThread=(HANDLE) NULL;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 if(thread != pthread_t())
 {
//  pthread_cancel(thread);
  thread=pthread_t();
#endif 
#endif // __GNUG__
  pid=0;
  stopFlag=false;
  suspendFlag=true;
  detachFlag=false;
  std::vector<zThread*>::iterator k=std::find(zThread::ms_list.begin(),zThread::ms_list.end(),this);
  if(k != zThread::ms_list.end()) { zThread::ms_list.erase(k); } 
 }
}

std::string zThread::getName() const
{
 zMutexLock m1(&mtr_mut);
 return name;
}

void zThread::setName(const std::string &q)
{
 zMutexLock m1(&mtr_mut);
 name=q;
}

size_t zThread::Pid() const
{
 zMutexLock m1(&mtr_mut);
 return pid;
}

int zThread::getPriority() const
{
#if defined(_WIN32) || defined(_WIN64)
 zMutexLock m1(&mtr_mut);
 if(pid > 0) return GetThreadPriority(hThread);
 return 0;
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#ifndef __CYGWIN__
 zMutexLock m1(&mtr_mut);
 if(pid > 0) return getpriority(PRIO_PROCESS,pid);
 return 0;
#else
return 1;
#endif
#endif
#endif
}

void zThread::setPriority(int new_priority)
{
#if defined(_WIN32) || defined(_WIN64)
 zMutexLock m1(&mtr_mut);
 if(pid > 0) SetThreadPriority(hThread,new_priority);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#ifndef __CYGWIN__
 zMutexLock m1(&mtr_mut);
 if(pid > 0) setpriority(PRIO_PROCESS, pid, new_priority);
#else
 return;
#endif
#endif
#endif
}

bool zThread::isAlive() const
{
 zMutexLock m1(&mtr_mut);
 return alive;
}

bool zThread::isDaemon() const
{
 zMutexLock m1(&mtr_mut);
 return detachFlag;
}

bool zThread::isInterrupted() const
{
 zMutexLock m1(&mtr_mut);
 return (!alive || suspendFlag);
}

void zThread::join()
{
 for(;;)
 {
  {
   zMutexLock m1(&mtr_mut);
   if(!alive) return;
  }
  zThread::sleep(10);
 }
}

bool zThread::join(time_t timeout)
{
 zTimer tim;
 for(;tim.get() < timeout;)
 {
  {
   zMutexLock m1(&mtr_mut);
   if(!alive) return true;
  }
  zThread::sleep(10);
 }
 return false;
}

void zThread::setDaemon(bool on)
{
 zMutexLock m1(&mtr_mut);
 detachFlag=on;
}

void zThread::start()
{
 zMutexLock m1(&mtr_mut);
 if(alive) return;
 stopFlag=false;
#if defined(_WIN32) || defined(_WIN64)
 DWORD ThreadId;
 hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) run_thread_item,
                         reinterpret_cast<LPVOID>(this),0,&ThreadId);
  alive = ( hThread != NULL );
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  alive = (pthread_create(&thread, NULL, run_thread_item, this) == 0);
#endif
#endif
}

void zThread::stop()
{
 zMutexLock m1(&mtr_mut);  
 stopFlag=true;
}

bool zThread::testStop() const
{
 zMutexLock m1(&mtr_mut);  
 return (stopFlag);
}

void zThread::suspend()
{
 {
  zMutexLock m1(&mtr_mut);  
#if defined(_WIN32) || defined(_WIN64)
  if(!suspendFlag && alive && (hThread != ((HANDLE) NULL)))
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  if(!suspendFlag && alive && (thread != pthread_t()))
#endif
#endif
  suspendFlag=true;
 }
#if defined(_WIN32) || defined(_WIN64)
  SuspendThread(hThread);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  pthread_kill(thread, SIGSTOP);
#endif
#endif
}

void zThread::resume()
{
 zMutexLock m1(&mtr_mut);   
#if defined(_WIN32) || defined(_WIN64)
 if(suspendFlag && !alive && (hThread != ((HANDLE) NULL)))
 {
  suspendFlag=false;
  ResumeThread(hThread);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 if(suspendFlag && !alive && (thread != pthread_t()))
 {
  suspendFlag=false;
  pthread_kill(thread, SIGCONT);
#endif
#endif
 }
} 

zThread* zThread::currentThread()
{
 size_t p=zThread::getTid();
 zMutexLock m2(&zThread::mst_mut);
 for(size_t i=0; i < zThread::ms_list.size(); i++)
 {
  if(p == zThread::ms_list.at(i)->Pid()) return zThread::ms_list.at(i);
 }
 return NULL;
}

size_t zThread::getPid()
{
#if defined(_WIN32) || defined(_WIN64)
 return ((size_t) GetCurrentProcessId());
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 return ((size_t) getpid());
#endif 
#endif 
};

size_t zThread::getTid()
{
#if defined(_WIN32) || defined(_WIN64)
 return ((size_t) GetCurrentThreadId());
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
 return ((size_t) pthread_self());
#endif 
#endif 
}

void zThread::sleep(time_t timeout)
{
 if(timeout > 0)
 {
#if defined(_WIN32) || defined(_WIN64)
  Sleep(timeout);
#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
  struct timespec ts;
  ts.tv_sec = (timeout/1000);
  ts.tv_nsec = ((timeout%1000)*1000000);
  nanosleep(&ts, NULL);
#endif 
#endif 
 }
}

void zThread::stopAll()
{
 zMutexLock m2(&zThread::mst_mut);
 for(size_t i=0; i < zThread::ms_list.size(); i++)
 { if(zThread::ms_list.at(i) != NULL) zThread::ms_list.at(i)->stop(); }
}

void zThread::joinAll()
{
 for(;;)
 {
  {
   zMutexLock m2(&zThread::mst_mut);
   bool b=false;
   for(size_t i=0; i < zThread::ms_list.size(); i++)
   {
    if(zThread::ms_list.at(i)->isAlive()) { b=true; break; }
   }
   if(!b) return;
  }
  zThread::sleep(10);
 }
}

std::vector<zThread*> zThread::getThreadList()
{
 zMutexLock m2(&zThread::mst_mut); 
 return zThread::ms_list;
}

size_t zThread::size()
{
 zMutexLock m2(&zThread::mst_mut); 
 return zThread::ms_list.size();
}





