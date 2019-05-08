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

#ifndef __zPool_h
#define __zPool_h 1

#include <algorithm>
#include <functional>
#include <stdio.h>
#include <stdlib.h>

#include <set>
#include <list>
#include <map>
#include "zMutex.h"

#define ZCED(q)\
 q(const q &src);\
 q &operator=(const q &src);\

//using std::set;
//using std::list;

template<class T> class zPool
{

private:

 ZCED(zPool)

protected:

// virtual T* create() const { return new T(); };
 virtual T* create()= 0;
/*
 Creates a new object and returns a pointer to it or NULL. 
 The function is called when all objects in the pool are used.
*/
 virtual void destroy();
/*
 Deletes all objects in the pool.
*/

public:

mutable std::list<T*> mtp_storage;
/*
 The list of stored objects;
*/
mutable std::set<T*> mtp_value;
/*
 The list of used objects;
*/

 zPool(): mtp_storage(), mtp_value() {};
/*
 Creates pool.
*/

 virtual ~zPool() { destroy(); return; };
/*
 Deletes all objects in the pool.
*/

 virtual T* get()
 {
  T* p;
  if(mtp_storage.empty()) { p= create(); }
  else
  {
   p=*(mtp_storage.begin());
   mtp_storage.pop_front();
  }
  if(p) mtp_value.insert(p);
  return p;
 };
/*
 Returns new pointer to new object or NULL.
*/

 virtual bool push(T* p)
 {
  if(mtp_value.count(p) == 0) return false;
  mtp_value.erase(p);
  mtp_storage.push_back(p);
  return true;
 };
/*
 Moves the used object to the storage.
 If success returns true, false otherwise.
*/

 virtual bool drop(T* p)
 {
  if(mtp_value.count(p)) { delete p; mtp_value.erase(p); return true; }
  typename std::list<T*>::iterator k=std::find(mtp_storage.begin(), mtp_storage.end(), p);
  if(k != mtp_storage.end()) { delete p; mtp_storage.erase(k); return true; }
  return false;
 };
/*
 Deletes object p.
 If success returns true, false otherwise.
*/

 virtual bool check(T* p, bool inuse=true) const
 {
  if(inuse) return mtp_value.count(p);
  typename std::list<T*>::const_iterator k=std::find(mtp_storage.begin(), mtp_storage.end(), p);
  return (k != mtp_storage.end());
 };
/*
  Returns true if object p is found in pool, false otherwise.
  If inuse is true, function tries to find in the list of used objects.
  If inuse is false, function tries to find in the list of stored objects.
*/

 virtual void clear();
/*
 Deletes all stored objects.
*/

 virtual size_t count(bool inuse=true) const
 {
  if(inuse) return mtp_value.size();
  return mtp_storage.size();
 };
/*
  If inuse is true, function returns the number of used objects.
  If inuse is false, function returns the number of stored objects.
*/
};

template<class T> void zPool<T>::destroy()
{
 for(typename std::list<T*>::iterator k= mtp_storage.begin(); k != mtp_storage.end(); ++k) { delete *k; }
 mtp_storage.clear();
 for(typename std::set<T*>::iterator k= mtp_value.begin(); k != mtp_value.end(); ++k)
 { delete *k; }
 mtp_value.clear();
};

template<class T> void zPool<T>::clear()
{
 for(typename std::list<T*>::iterator k= mtp_storage.begin(); k != mtp_storage.end(); ++k) { delete *k; }
 mtp_storage.clear();
};

template<class T> class zSynchPool: public zPool<T>
{

private:

 ZCED(zSynchPool)

protected:

// virtual T* create() const { return new T(); };
// virtual T* create()= 0;
/*
 
 The function is called when all objects in the pool are used.
*/
 virtual void destroy() { zMutexLock m(&mtp_mut); return zPool<T>::destroy(); };
/*
 Deletes all objects in the pool.
*/

public:

mutable zMutex mtp_mut;

 zSynchPool(): mtp_mut() {};
/*
 Creates pool.
*/

 virtual ~zSynchPool() { return; };
/*
 Deletes all objects in the pool.
*/

 virtual T* get() { zMutexLock m(&mtp_mut); return zPool<T>::get(); };
/*
 Returns new pointer to new object or NULL.
*/

 virtual bool push(T* p) { zMutexLock m(&mtp_mut); return zPool<T>::push(p); };
/*
 Moves the used object to the storage.
 If success returns true, false otherwise.
*/

 virtual bool drop(T* p) { zMutexLock m(&mtp_mut); return zPool<T>::drop(p); };
/*
 Deletes object p.
 If success returns true, false otherwise.
*/

 virtual bool check(T* p, bool inuse=true) const { zMutexLock m(&mtp_mut); return zPool<T>::check(p, inuse); };
/*
  Returns true if object p is found in pool, false otherwise.
  If inuse is true, function tries to find in the list of used objects.
  If inuse is false, function tries to find in the list of stored objects.
*/

 virtual void clear() { zMutexLock m(&mtp_mut); return zPool<T>::clear(); };
/*
 Deletes all stored objects.
*/

 virtual size_t count(bool inuse=true) const { zMutexLock m(&mtp_mut); return zPool<T>::count(inuse); };
/*
  If inuse is true, function returns the number of used objects.
  If inuse is false, function returns the number of stored objects.
*/
};

template<class T> class zChronoPool
{

public:

mutable uint64_t counter;
mutable std::map<uint64_t, T*> storage;
mutable std::map<T*, uint64_t> value;

 zChronoPool(): counter(0), storage(), value() {};
/*
 Creates ChronoPool.
*/

 virtual ~zChronoPool() { return; };

 virtual T* get()
 {
  if(storage.empty()) { return NULL; }
  typename std::map<uint64_t, T*>::iterator l=storage.begin();
  T* p=l->second;
  storage.erase(l);
  typename std::map<T*, uint64_t>::iterator k= value.find(p);
  if(k != value.end()) value.erase(k);
  return p;
 };
/*
  Returns and removes from container a pointer to the first element. Returns NULL if size of pool is 0.
*/

 virtual T* front() const
 {
  if(storage.empty()) { return NULL; }
  return storage.begin()->second;
 };
/*
  Returns a pointer to the first element. Returns NULL if size of pool is 0.
*/

 virtual bool set(T* p)
 {
  if(p == NULL || value.count(p)) return false;
  ++counter;
  value[p]=counter;
  storage[counter]=p;
  return true;
 };
/*
  Adds pointer to the new object in container.
  If success returns true, false otherwise.
*/

 virtual void clear()
 {
  value.clear();
  storage.clear();
 };
/*
  Removes all pointers to objects from container.
*/

 virtual bool erase(T* p)
 {
  typename std::map<T*, uint64_t>::iterator k= value.find(p);
  if(k == value.end()) return false;
  storage.erase(k->second);
  value.erase(k);
  return true;
 };
/*
  Removes pointer p from container.
  If success returns true, false otherwise.
*/

 virtual bool check(T* p) const { return value.count(p); };
/*
  Returns true if object p is found in container, false otherwise.
*/

 virtual bool empty() const { return value.empty(); };
/*
 Test whether container is empty.
*/

 virtual size_t size() const { return value.size(); };
/*
 Returns the number of elements in the container.
*/

};

template<class T> class zMessagePool
{

private:

 ZCED(zMessagePool)

public:

mutable std::queue<T*> msg_que;
mutable zMutex msg_mut;

 zMessagePool(): msg_que(), msg_mut() {};
/*
 Creates MessagePool.
*/

 virtual ~zMessagePool() { return; };

 virtual T* getMessage()
 {
  zMutexLock m(&msg_mut);
  if(msg_que.empty()) { return NULL; }
  T* p=msg_que.front();
  msg_que.pop();
  return p;
 };
/*
  Returns and removes from container a pointer to the first element. Returns NULL if size of pool is 0.
*/

 virtual T* frontMessage() const
 {
  zMutexLock m(&msg_mut);
  if(msg_que.empty()) { return NULL; }
  return msg_que.front();
 };
/*
  Returns a pointer to the first element. Returns NULL if size of pool is 0.
*/

 virtual bool setMessage(T* p)
 {
  if(p == NULL) return false;
  zMutexLock m(&msg_mut);
  msg_que.push(p);
  return true;
 };
/*
  Adds pointer to the new object in container.
  If success returns true, false otherwise.
*/

 virtual bool emptyMessage() const
 {
  zMutexLock m(&msg_mut);
  return msg_que.empty();
 };
/*
 Test whether container is empty.
*/

 virtual size_t sizeMessage() const
 {
  zMutexLock m(&msg_mut);
  return msg_que.size();
 };
/*
 Returns the number of elements in the container.
*/

};

#endif // __zPool_h










