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

#ifndef __zString_h
#define __zString_h 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <typeinfo>

#include <string>
#include <vector>
#include <list>
//using std::string;
//using std::vector;
//using std::list;
//using std::pair;

#if defined(_WIN32) || defined(_WIN64) 
#include <time.h>
typedef __int64 longlong;
typedef unsigned __int64 ulonglong;
#ifndef __INT64_C
#define __INT64_C(c)    c ## L
#endif
#ifndef __UINT64_C
#define __UINT64_C(c)   c ## UL
#endif

#ifndef ssize_t
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#endif

#else
#if defined(__GNUG__) || defined(__linux__) || defined(__CYGWIN__)
#include <stdint.h>
#include <sys/time.h>
typedef int64_t longlong;
//typedef long long longlong;
typedef uint64_t ulonglong;
//typedef unsigned long long ulonglong;
#ifndef __INT64_C
#define __INT64_C(c)    c ## LL
#endif
#ifndef __UINT64_C
#define __UINT64_C(c)   c ## ULL
#endif

#endif 
#endif

namespace ZNSTR
{

#define MAX_LINE   76         // size of encoded lines 
#define XX        255         // illegal base64 char 
#define EQ        254         // padding 
#define INVALID    XX

#if defined(_WIN32) || defined(_WIN64) 
const char path_delimiter[] = "\\";
#else
#if defined(__GNUG__) || defined(__CYGWIN__) || defined(__linux__)
const char path_delimiter[] = "/";
#else
const char path_delimiter[] = "\\/";
#endif // __GNUG__
#endif // _WIN32

 std::string encode_base64(const std::string &str, bool app_eol = true);
 std::string decode_base64(const std::string &str);
/*
 Functions encode/decode string str.
 If app_eol == true the '\n' is added to the end of return string. 
*/

 std::string toUpper(const char* p, size_t len);
 std::string toUpper(const std::string &s);
 void setUpper(std::string &s, size_t start_pos=0, size_t len=std::string::npos);
 std::string toLower(const char* p, size_t len);
 std::string toLower(const std::string &s);
 void setLower(std::string &s, size_t start_pos=0, size_t len=std::string::npos);
/*
 Functions convert characters to upper/lower case.
 size_t len - length p.
 size_t start_pos - first position in s, size_t num - number of characters for translation. 
*/

 std::string str2hex(const char* p, size_t len);
 std::string str2hex(const std::string &s);
 std::string hex2str(const char* p, size_t len);
 std::string hex2str(const std::string &s);
/*
 Functions encode/decode string from/to hex format.
 size_t len - length p. 
*/

 std::string escape(const char* p, size_t len);
 std::string escape(const std::string &s);
 std::string unescape(const char* p, size_t len, bool replus=false);
 std::string unescape(const std::string &s, bool replus=false);
/*
 URL escape/unescape (or encode/decode) string from/to url format.
 size_t len - length p. 
*/

 std::string trim(const std::string &s, const std::string &q=" \t\v\r\n");
 void shrink(std::string &s, const std::string &q=" \t\v\r\n");
 std::string ltrim(const std::string &s, const std::string &q=" \t\v\r\n");
 void lshrink(std::string &s, const std::string &q=" \t\v\r\n");
 std::string rtrim(const std::string &s, const std::string &q=" \t\v\r\n");
 void rshrink(std::string &s, const std::string &q=" \t\v\r\n");
/*
 Function removes defined in std::string &q characters from both(left/right) sides of a string.
 Functions trim return new string, shrink set result into std::string &s. 
*/

 std::string replace(const std::string &src,const std::string &val,const std::string &dest);
 void substitute(std::string &src,const std::string &val,const std::string &dest);
/*
 Strings val is replaced by dest in strings src.
 Function replace returns new string, substitute sets result into std::string &src. 
*/

 std::vector<std::string> split(const std::string &src,const std::string &r);
 size_t split(std::vector<std::string>& ret, const std::string &src,const std::string &r);
 size_t split(std::list<std::string>& ret, const std::string &src,const std::string &r);
/*
 Functions split string src by string r.
 Functions return result into ret or as vector. 
*/

/*
template <class T> std::string toString(const T& t)
{
// std::stringstream ss;
 std::ostringstream ss;
 ss << t;
 return ss.str();
};
*/

 std::string toString(short value);
 std::string toString(unsigned short value);
 std::string toString(int value);
 std::string toString(unsigned value);
// std::string toString(long value);
// std::string toString(unsigned long value);
 std::string toString(longlong value);
 std::string toString(ulonglong value);
 std::string toString(float value);
 std::string toString(double value);
 std::string toString(long double value);
/*
 Functions return a string with the representation of value. 
*/

 char asChar(const char* p, size_t len, char def='\x00');
 char toChar(const std::string &src, char def='\x00');
 unsigned char asUnsignedChar(const char* p, size_t len,unsigned char def='\x00');
 unsigned char toUnsignedChar(const std::string &src, unsigned char def='\x00');
 short asShort(const char* p, size_t len, short def=0);
 short toShort(const std::string &src, short def=0);
 unsigned short asUnsignedShort(const char* p, size_t len, unsigned short def=0);
 unsigned short toUnsignedShort(const std::string &src, unsigned short def=0);
 int asInt(const char* p, size_t len, int def=0);
 int toInt(const std::string &src, int def=0);
 unsigned asUnsigned(const char* p, size_t len, unsigned def=0);
 unsigned toUnsigned(const std::string &src, unsigned def=0);
 long asLong(const char* p, size_t len, long def=0);
 long toLong(const std::string &src, long def=0);
 unsigned long asUnsignedLong(const char* p, size_t len, unsigned long def=0);
 unsigned long toUnsignedLong(const std::string &src, unsigned long def=0);
 longlong asLongLong(const char* p, size_t len, longlong def=0);
 longlong toLongLong(const std::string &src, longlong def=0);
 ulonglong asULongLong(const char* p, size_t len, ulonglong def=0);
 ulonglong toULongLong(const std::string &src, ulonglong def=0);
 float asFloat(const char* p, size_t len, float def=0);
 float toFloat(const std::string &src, float def=0);
 double asDouble(const char* p, size_t len, double def=0);
 double toDouble(const std::string &src, double def=0);
/*
 Functions try to convert string into a number. Number def is returned if error occurs.
 size_t len - length p. 
*/

 char asChar16(const char* p, size_t len, char def='\x00');
 char toChar16(const std::string &src, char def='\x00');
 unsigned char asUnsignedChar16(const char* p, size_t len,unsigned char def='\x00');
 unsigned char toUnsignedChar16(const std::string &src, unsigned char def='\x00');
 short asShort16(const char* p, size_t len, short def=0);
 short toShort16(const std::string &src, short def=0);
 unsigned short asUnsignedShort16(const char* p, size_t len, unsigned short def=0);
 unsigned short toUnsignedShort16(const std::string &src, unsigned short def=0);
 int asInt16(const char* p, size_t len, int def=0);
 int toInt16(const std::string &src,int def=0);
 unsigned asUnsigned16(const char* p, size_t len, unsigned def=0);
 unsigned toUnsigned16(const std::string &src, unsigned def=0);
 long asLong16(const char* p, size_t len, long def=0);
 long toLong16(const std::string &src, long def=0);
 unsigned long asUnsignedLong16(const char* p, size_t len, unsigned long def=0);
 unsigned long toUnsignedLong16(const std::string &src, unsigned long def=0);
 longlong asLongLong16(const char* p, size_t len, longlong def=0);
 longlong toLongLong16(const std::string &src, longlong def=0);
 ulonglong asULongLong16(const char* p, size_t len, ulonglong def=0);
 ulonglong toULongLong16(const std::string &src, ulonglong def=0);
/*
 Functions try to convert hex string into a number. Number def is returned if error occurs.
 size_t len - length p. 
*/

 std::string toHex(short value);
 std::string toHex(unsigned short value);
 std::string toHex(int value);
 std::string toHex(unsigned value);
// std::string toHex(long value);
// std::string toHex(unsigned long value);
 std::string toHex(longlong value);
 std::string toHex(ulonglong value);
/*
 Functions return a hex string with the representation of value.
*/

 char get(); // read 1 bite from console.
 void put(const std::string &v); // write v to console.

 unsigned CRC32(const std::string &q, unsigned ini = 0xFFFFFFFF);
/*
 Counts CRC32 for string q, ini - initial value.
*/
 bool checkCRC(const std::string &q,const unsigned &crc, unsigned ini = 0xFFFFFFFF);
/*
 Checks CRC32 for string q with unsigned crc, ini - initial value.
*/
 ulonglong CRC64(const std::string &q, ulonglong ini = __UINT64_C(0xFFFFFFFFFFFFFFFF));
/*
 Counts CRC64 for string q, ini - initial value.
*/
 bool checkCRC64(const std::string &q, const ulonglong &crc, ulonglong ini = __UINT64_C(0xFFFFFFFFFFFFFFFF));
/*
 Checks CRC64 for string q with ulonglong crc, ini - initial value. 
*/

};// namespace ZNSTR

template<class T> class zSmart
{

 protected:

 T* value;
 int* count;

 public:

 zSmart(T* src=NULL):value(src), count(new int(1)) { };
 zSmart(const zSmart &src):value(src.value), count(src.count) { (*count)++; };
/*
 The object owns src, setting the use count to one.
 Copy constructor. The object shares ownership of src's assets and increases the use count. 
*/

 zSmart& operator=(const zSmart &src)
 {
  if(count == src.count) return *this;
  (*count)--; if((*count) == 0) { delete count; if(value) delete value; }
  value=src.value; count=src.count;
  (*count)++;
  return *this;
 };
/*
 The copy assignments adds the object as a shared owner of src's assets, increasing their use_count. 
*/

 virtual ~zSmart() { (*count)--; if((*count) == 0) { delete count; if(value) delete value; } };
/*
 If use_count is 1 (i.e., the object is the unique owner of the managed pointer): the object pointed by its owned pointer is deleted.
*/

 T* operator->() { return value; };
 const T* operator->() const { return value; };
/*
 Returns a pointer to the object pointed by the stored pointer in order to access one of its members. 
*/

 T* operator*() { return value; };
 const T* operator*() const { return value; };
/*
 Returns a pointer to the object pointed by the stored pointer.
*/

 int use_count() const { return *count; };
/*
 Returns the number of zSmart objects that share ownership over the same pointer as this object (including it).
*/

 void reset()
 {
  (*count)--;
  if((*count) == 0 && value) { delete value; } 
  (*count)=1; value= NULL;
 };
/*
 The object becomes empty (as if default-constructed).
*/

 void swap(zSmart &src)
 {
  if(count == src.count) return;
  int* c= count; T* v=value;
  count=src.count; value=src.value;
  src.count=c; src.value=v;
 };
/*
  Exchanges the contents of the zSmart object with those of src, transferring ownership of any managed object between them
  without destroying or altering the use count of either.
*/

};

class zRandomGenerator
{

 private:

 unsigned value[624];
 unsigned short state;

public:

 zRandomGenerator();
 zRandomGenerator(unsigned seed);
/*
 Create and initialize random number generator.
 The pseudo-random number generator is initialized using the argument passed as seed. 
*/

 void gen();

 unsigned rnd();
/*
 Returns a pseudo-random integral number in the range between 0 and 256^4-1.
*/

 ulonglong rnd_64();
/*
 Returns a pseudo-random integral number in the range between 0 and 256^8-1.
*/

 double rnd2();
/*
 Returns a pseudo-random double number in the range between 0 and 1.
*/

 double rnd2_64();
/*
 Returns a pseudo-random double number in the range between 0 and 1.
*/
};

#endif // __zString_h











