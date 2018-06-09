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

#ifndef __zDNS_h
#define __zDNS_h 1

#include <set>
#include "zMutex.h"

#define ZDNS_PERIOD 3600
/*
 Class zDNS provides interfaces to operate with resolving of domain names.
 It is possible to operate only with a static member of the class through static functions.
*/
class zDNS
{
 public:

static time_t getPeriod() { return zDNS::dns.m_period; };
/*
 Returns the period (in seconds) of updating the list of domain names and ip addresses.
 ZDNS_PERIOD is default period (in seconds) of updating.
*/
static void setPeriod(time_t period) { zDNS::dns.m_period= period; };
/*
 Sets the period (in seconds) of updating the list of domain names and ip addresses.
 ZDNS_PERIOD is default period (in seconds) of updating.
*/
static std::string host(const std::string &adr) { return zDNS::dns.Host(adr); };
static size_t host(std::vector<std::string>& ret, const std::string &adr) { return zDNS::dns.Host(ret, adr); };
/*
 Retrieves host information corresponding to a host name or ip address from a host database.
*/
static bool erase(const std::string &addr) { return zDNS::dns.Erase(addr); };
/*
 Removes host addr from a host database.
*/
static void clear() { return zDNS::dns.Clear(); };
/*
 Clears host database.
*/
static bool check(const std::string &addr) { return zDNS::dns.Check(addr); };
/*
 Returns true if host addr is found in host database, false otherwise.
*/
static size_t size() { return zDNS::dns.Size(); };
/*
 Returns size of host database.
*/
static void getValue(std::set<std::string>& ret) { return zDNS::dns.GetValue(ret); };
/*
 Returns list of hosts stored in database.
*/
static void update() { return zDNS::dns.Update(); };
/*
 It needs periodically (in the main thread) to call zDNS::update().
 This function updates all hosts stored in database.
*/

 protected:

static zDNS dns;

 class zDNSValue
 {
  public:
  zDNSValue(): index(0), value() { };

  mutable size_t index;
  mutable std::vector<std::string> value;

 };

 zDNS();

virtual ~zDNS();

virtual std::string Host(const std::string &addr);
virtual size_t Host(std::vector<std::string>& ret, const std::string &addr);
virtual bool Erase(const std::string &addr);
virtual void Clear();
virtual bool Check(const std::string &addr) const;
virtual size_t Size();
virtual void GetValue(std::set<std::string>& ret) const;
virtual void Update();


 time_t m_period;
 mutable time_t m_last;
 std::map<std::string, zDNS::zDNSValue>* m_value;
 std::map<std::string, zDNS::zDNSValue>* m_storage;
 mutable zRWMutex m_mut;

private:
  zDNS(const zDNS &);
  zDNS &operator=(const zDNS &);

};


#endif // __zDNS_h







