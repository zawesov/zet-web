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

#include "zMutex.h"
#include "zThread.h"
#include <algorithm>
#include <functional>

static void sleep_cycle(unsigned n) { for(unsigned i=0; i < n; ) { i++; } };

#if defined(_WIN32) || defined(_WIN64)
zMutex::zMutex():
 m_cs(),
 pid(0),
 pn(0),
 que()
{ InitializeCriticalSection(&m_cs); }

zMutex::~zMutex() { DeleteCriticalSection(&m_cs); }

bool zMutex::lock() const
{
 size_t pd=zThread::getTid();
 EnterCriticalSection(&m_cs);
 if(pid == pd) { pn++; LeaveCriticalSection(&m_cs); return true; }
 if(pid == 0)  { pid=pd; pn++; LeaveCriticalSection(&m_cs); return true; }
 que.push(pd);
 LeaveCriticalSection(&m_cs);
 for(;;)
 {
  EnterCriticalSection(&m_cs);
//  if(pid == pd) { pn++; LeaveCriticalSection(&m_cs); return true; }
  if(pid == 0  && pd == que.front())  { pid=pd; pn++; que.pop(); LeaveCriticalSection(&m_cs); return true; }
  LeaveCriticalSection(&m_cs);
  sleep_cycle(ZSLEEP_CYCLES);
//  zThread::sleep(0);
 }
}

bool zMutex::lock(time_t timeout) const
{
 size_t pd=zThread::getTid();
 EnterCriticalSection(&m_cs);
 if(pid == pd) { pn++; LeaveCriticalSection(&m_cs); return true; }
 if(pid == 0)  { pid=pd; pn++; LeaveCriticalSection(&m_cs); return true; }
 LeaveCriticalSection(&m_cs);
 zTimer tim;
 for(;tim.get() < timeout;)
 {
  EnterCriticalSection(&m_cs);
  if(pid == pd) { pn++; LeaveCriticalSection(&m_cs); return true; }
  if(pid == 0)  { pid=pd; pn++; LeaveCriticalSection(&m_cs); return true; }
  LeaveCriticalSection(&m_cs);
  sleep_cycle(ZSLEEP_CYCLES);
//  zThread::sleep(0);
 }
 return false;
}

void zMutex::unlock() const
{
 EnterCriticalSection(&m_cs);
 if(pn > 0) { pn--; if(pn == 0) pid=0; }
 LeaveCriticalSection(&m_cs);
}

zRWMutex::zRWMutex():
 m_cs(),
 pid(0),
 pn(0),
 que(),
 rpid()
{ InitializeCriticalSection(&m_cs); }

zRWMutex::~zRWMutex() { DeleteCriticalSection(&m_cs); }

bool zRWMutex::lock(bool writable) const
{
 size_t pd=zThread::getTid();
 int l=1;
 EnterCriticalSection(&m_cs);
 if(writable)
 {
  if(pid == pd) { pn++; LeaveCriticalSection(&m_cs); return true; }
  if(pid == 0 && ((rpid.size() == 0 && que.size() == 0) || (rpid.size() == 1 && rpid.begin()->first == pd)))
  { pid=pd; pn++; LeaveCriticalSection(&m_cs); return true; }
  if(pid == 0 && rpid.count(pd)) { l+=rpid[pd]; rpid.erase(pd); }
 }
 else
 {
  if(pid == pd)
  {
   rpid[pd]++;
   LeaveCriticalSection(&m_cs); return true;
  }
  if(pid == 0 && (que.size() == 0 || rpid.count(pd)))
  {
   rpid[pd]++;
   LeaveCriticalSection(&m_cs); return true;
  }
 }
 que.push(pd);
 LeaveCriticalSection(&m_cs);
 if(writable)
 {
  for(;;)
  {
   EnterCriticalSection(&m_cs);
//   if(pid == pd) { pn++; que.pop(); LeaveCriticalSection(&m_cs); return true; }
   if(pd == que.front() && pid == 0 && (rpid.size() == 0 || (rpid.size() == 1 && rpid.begin()->first == pd)))
   { pid=pd; pn+=l; que.pop(); LeaveCriticalSection(&m_cs); return true; }
   LeaveCriticalSection(&m_cs);
   sleep_cycle(ZSLEEP_CYCLES);
  }
 }
 else
 {
  for(;;)
  {
   EnterCriticalSection(&m_cs);
   if(pd == que.front() && pid == 0)
   {
    rpid[pd]++;
    que.pop();
    LeaveCriticalSection(&m_cs); return true;
   }
   LeaveCriticalSection(&m_cs);
   sleep_cycle(ZSLEEP_CYCLES);
  }
 }
}

void zRWMutex::unlock(bool writable) const
{
 EnterCriticalSection(&m_cs);
 if(writable) {  if(pn > 0) { pn--; if(pn == 0) pid=0; } }
 else
 {
  size_t pd=zThread::getTid();
  std::map<size_t, zMutInt>::iterator k=rpid.find(pd);
  if(k != rpid.end()) { if(k->second > 0) { k->second--; if(k->second == 0) rpid.erase(k); } }
  else if(pd == pid && pn > 0) { pn--; if(pn == 0) pid=0; }
 }
 LeaveCriticalSection(&m_cs);
}

#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
zMutex::zMutex():
 status(),
 pid(0),
 pn(0),
 que()
{
 pthread_mutexattr_t attrs;
 pthread_mutexattr_init(&attrs);
 pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);        
 pthread_mutex_init(&status, &attrs); 
}

zMutex::~zMutex() { pthread_mutex_destroy(&status); }

bool zMutex::lock() const
{
 size_t pd=zThread::getTid();
 pthread_mutex_lock(&status);
 if(pid == pd) { pn++; pthread_mutex_unlock(&status); return true; }
 if(pid == 0)  { pid=pd; pn++; pthread_mutex_unlock(&status); return true; }
 que.push(pd);
 pthread_mutex_unlock(&status);
 for(;;)
 {
  pthread_mutex_lock(&status);
//  if(pid == pd) { pn++; pthread_mutex_unlock(&status); return true; }
  if(pid == 0 && pd == que.front())  { pid=pd; pn++; que.pop(); pthread_mutex_unlock(&status); return true; }
  pthread_mutex_unlock(&status);
  sleep_cycle(ZSLEEP_CYCLES);
//  zThread::sleep(0);
 }
}

bool zMutex::lock(time_t timeout) const
{
 size_t pd=zThread::getTid();
 pthread_mutex_lock(&status);
 if(pid == pd) { pn++; pthread_mutex_unlock(&status); return true; }
 if(pid == 0)  { pid=pd; pn++; pthread_mutex_unlock(&status); return true; }
 pthread_mutex_unlock(&status);
 zTimer tim;
 for(;tim.get() < timeout;)
 {
  pthread_mutex_lock(&status);
//  if(pid == pd) { pn++; pthread_mutex_unlock(&status); return true; }
  if(pid == 0)  { pid=pd; pn++; pthread_mutex_unlock(&status); return true; }
  pthread_mutex_unlock(&status);
  sleep_cycle(ZSLEEP_CYCLES);
//  zThread::sleep(0);
 }
 return false;
}

void zMutex::unlock() const
{
 pthread_mutex_lock(&status);
 if(pn > 0) { pn--; if(pn == 0) pid=0; }
 pthread_mutex_unlock(&status); 
}

zRWMutex::zRWMutex():
 status(),
 pid(0),
 pn(0),
 que(),
 rpid()
{
 pthread_mutexattr_t attrs;
 pthread_mutexattr_init(&attrs);
 pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);        
 pthread_mutex_init(&status, &attrs); 
}

zRWMutex::~zRWMutex() { pthread_mutex_destroy(&status); }

bool zRWMutex::lock(bool writable) const
{
 size_t pd=zThread::getTid();
 int l=1;
 pthread_mutex_lock(&status);
 if(writable)
 {
  if(pid == pd) { pn++; pthread_mutex_unlock(&status); return true; }
  if(pid == 0 && ((rpid.size() == 0 && que.size() == 0) || (rpid.size() == 1 && rpid.begin()->first == pd)))
  { pid=pd; pn++; pthread_mutex_unlock(&status); return true; }
  if(pid == 0 && rpid.count(pd)) { l+=rpid[pd]; rpid.erase(pd); }
 }
 else
 {
  if(pid == pd)
  {
   rpid[pd]++;
   pthread_mutex_unlock(&status); return true;
  }
  if(pid == 0 && (que.size() == 0 || rpid.count(pd)))
  {
   rpid[pd]++;
   pthread_mutex_unlock(&status); return true;
  }
 }
 que.push(pd);
 pthread_mutex_unlock(&status);
 if(writable)
 {
  for(;;)
  {
   pthread_mutex_lock(&status);
//   if(pid == pd) { pn++; que.pop(); pthread_mutex_unlock(&status); return true; }
   if(pd == que.front() && pid == 0 && (rpid.size() == 0 || (rpid.size() == 1 && rpid.begin()->first == pd)))
   { pid=pd; pn+=l; que.pop(); pthread_mutex_unlock(&status); return true; }
   pthread_mutex_unlock(&status);
   sleep_cycle(ZSLEEP_CYCLES);
  }
 }
 else
 {
  for(;;)
  {
   pthread_mutex_lock(&status);
   if(pd == que.front() && pid == 0)
   {
    rpid[pd]++;
    que.pop();
    pthread_mutex_unlock(&status); return true;
   }
   pthread_mutex_unlock(&status);
   sleep_cycle(ZSLEEP_CYCLES);
  }
 }
}

void zRWMutex::unlock(bool writable) const
{
 pthread_mutex_lock(&status);
 if(writable) { if(pn > 0) { pn--; if(pn == 0) pid=0; } }
 else
 {
  size_t pd=zThread::getTid();
  std::map<size_t, zMutInt>::iterator k=rpid.find(pd);
  if(k != rpid.end()) { if(k->second > 0) { k->second--; if(k->second == 0) rpid.erase(k); } }
  else if(pd == pid && pn > 0) { pn--; if(pn == 0) pid=0; }
 }
 pthread_mutex_unlock(&status);
}

#endif
#endif

zMutexLock::zMutexLock(zMutex* m):
 ml(m),
 result(true)
{
 if(ml == NULL) return;
 ml->lock(); 
}

zMutexLock::zMutexLock(zMutex* m, int timeout):
 ml(m),
 result(false)
{
 if(ml == NULL) return;
 result = ml->lock(timeout);
}

zMutexLock::~zMutexLock() 
{
 if(ml == NULL) return;
 if(result) ml->unlock();
}

bool zMutexLock::operator!() const
{
 return (!result);
}

zRWMutexLock::zRWMutexLock(zRWMutex* m, bool writable):
 ml(m),
 writing(writable)
{
 if(ml == NULL) return;
 ml->lock(writing); 
}

zRWMutexLock::~zRWMutexLock() 
{
 if(ml == NULL) return;
 ml->unlock(writing);
}
