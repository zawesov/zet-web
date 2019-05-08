
#include "zDNS.h"
#include "zSocket.h"
#include "zLog.h"

zDNS zDNS::dns;

zDNS::zDNS():
 m_period(ZDNS_PERIOD),
 m_last(::time(NULL)),
 m_value(new std::map<std::string, zDNS::zDNSValue>()),
 m_storage(new std::map<std::string, zDNS::zDNSValue>()),
 m_mut(),
 m_im()
{};

zDNS::~zDNS()
{
 if(m_storage) { delete m_storage; m_storage=NULL; }
 if(m_value) { delete m_value; m_value=NULL; }
};

std::string zDNS::Host(const std::string &addr)
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");

 {
  zRWMutexLock m(&m_mut, false);
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(k != m_value->end())
  {
   if(!(k->second.value.empty()))
   {
    zMutexLock mi(&m_im);
    if(k->second.index < k->second.value.size()) return k->second.value[k->second.index++];
    k->second.index=0;
    return k->second.value[k->second.index];
   }
   return "";
  }
 }

 zDNS::zDNSValue v;
 if(ZNSOCKET::resolve(v.value, v.value6,adr) == 0) { ZNSOCKET::resolve(v.value, v.value6,adr); }

 {
  zRWMutexLock m(&m_mut, true);
  (*m_value)[adr]=v;
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(!(k->second.value.empty()))
  {
   if(k->second.index < k->second.value.size()) return k->second.value[k->second.index++];
   k->second.index=0;
   return k->second.value[k->second.index++];
  }
  return "";
 }
};

std::string zDNS::Host6(const std::string &addr)
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");

 {
  zRWMutexLock m(&m_mut, false);
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(k != m_value->end())
  {
   if(!(k->second.value6.empty()))
   {
    zMutexLock mi(&m_im);
    if(k->second.index6 < k->second.value6.size()) return k->second.value6[k->second.index6++];
    k->second.index6=0;
    return k->second.value6[k->second.index6++];
   }
   return "";
  }
 }

 zDNS::zDNSValue v;
 if(ZNSOCKET::resolve(v.value, v.value6,adr) == 0) { ZNSOCKET::resolve(v.value, v.value6,adr); }

 {
  zRWMutexLock m(&m_mut, true);
  (*m_value)[adr]=v;
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(!(k->second.value6.empty()))
  {
   if(k->second.index6 < k->second.value6.size()) return k->second.value6[k->second.index6++];
   k->second.index6=0;
   return k->second.value6[k->second.index6++];
  }
  return "";
 }
};

size_t zDNS::Host(std::vector<std::string>& ret, const std::string &addr)
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");

 {
  zRWMutexLock m(&m_mut, false);
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(k != m_value->end())
  {
   ret= k->second.value;
   return ret.size();
  }
 }

 zDNS::zDNSValue v;
 if(ZNSOCKET::resolve(v.value, v.value6,adr) == 0) { ZNSOCKET::resolve(v.value, v.value6,adr); }

 {
  zRWMutexLock m(&m_mut, true);
  (*m_value)[adr]=v;
  ret= v.value;
  return ret.size();
 }
};

size_t zDNS::Host6(std::vector<std::string>& ret, const std::string &addr)
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");

 {
  zRWMutexLock m(&m_mut, false);
  std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->find(adr);
  if(k != m_value->end())
  {
   ret= k->second.value6;
   return ret.size();
  }
 }

 zDNS::zDNSValue v;
 if(ZNSOCKET::resolve(v.value, v.value6,adr) == 0) { ZNSOCKET::resolve(v.value, v.value6,adr); }

 {
  zRWMutexLock m(&m_mut, true);
  (*m_value)[adr]=v;
  ret= v.value6;
  return ret.size();
 }
};

bool zDNS::Erase(const std::string &addr)
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");
 zRWMutexLock m(&m_mut, true);
 std::map<std::string, zDNS::zDNSValue>::iterator k= m_value->find(adr);
 if(k == m_value->end()) return false;
 m_value->erase(k);
 return true;
};

void zDNS::Clear()
{
 zRWMutexLock m(&m_mut, true);
 m_value->clear();
};

bool zDNS::Check(const std::string &addr) const
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");
 zRWMutexLock m(&m_mut, false);
 std::map<std::string, zDNS::zDNSValue>::iterator k= m_value->find(adr);
 if(k == m_value->end()) return false;
 return !(k->second.value.empty());
};

bool zDNS::Check6(const std::string &addr) const
{
 std::string adr=ZNSTR::trim(addr, " \t\v\r\n[]");
 zRWMutexLock m(&m_mut, false);
 std::map<std::string, zDNS::zDNSValue>::iterator k= m_value->find(adr);
 if(k == m_value->end()) return false;
 return !(k->second.value6.empty());
};

size_t zDNS::Size()
{
 zRWMutexLock m(&m_mut, false);
 return m_value->size();
};

void zDNS::GetValue(std::set<std::string>& ret) const
{
 zRWMutexLock m(&m_mut, false);
 for(std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->begin(); k != m_value->end(); ++k)
 { ret.insert(k->first); }
};

void zDNS::Update()
{
 if((m_last+m_period) > ::time(NULL)) return;
 m_last= ::time(NULL);

 {
  m_storage->clear();
  zRWMutexLock m(&m_mut, false);
  for(std::map<std::string, zDNS::zDNSValue>::const_iterator k= m_value->begin(); k != m_value->end(); ++k) { (*m_storage)[k->first]; }
 }
// std::list<std::string> rl;
 for(std::map<std::string, zDNS::zDNSValue>::iterator k= m_storage->begin(); k != m_storage->end(); ++k)
 { if(ZNSOCKET::resolve(k->second.value,k->second.value6,k->first)== 0) { ZNSOCKET::resolve(k->second.value,k->second.value6,k->first); } }
// for(std::list<std::string>::iterator l=rl.begin(); l != rl.end(); ++l) { m_storage->erase(*l); }

 {
  std::map<std::string, zDNS::zDNSValue>* p= m_storage;
  m_storage= m_value;
  zRWMutexLock m(&m_mut, true);
  m_value=p;
 }
 m_storage->clear();
};














