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

#include <ctype.h>
#include <algorithm>
#include <functional>
#include <string.h>
#include "zString.h"

#define PARSE_BLANK(p, len, pos)\
{\
 for(;pos < len;++pos) { if(p[pos] == ' ' || p[pos] == '\t' || p[pos] == '\r' || p[pos] == '\n' || p[pos] == '\v' || p[pos] == '\f') continue; break; }\
 if(pos > len) pos=len;\
}\

namespace ZNSTR
{

#define Z_UC (unsigned char)


const char __digs__[37] = { "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

const char basis_64[64] = 
 { 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
   'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
   'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
   'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/' };

const unsigned char index_64[256] = 
{
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
	52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,EQ,XX,XX,
	XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
	15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
	XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
	41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,

	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
};// index_64

const unsigned long crc32tab[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};// crc32tab


const ulonglong crc64tab[256] = { 
 __UINT64_C(0x0000000000000000), __UINT64_C(0x42F0E1EBA9EA3693), __UINT64_C(0x85E1C3D753D46D26), __UINT64_C(0xC711223CFA3E5BB5), 
 __UINT64_C(0x493366450E42ECDF), __UINT64_C(0x0BC387AEA7A8DA4C), __UINT64_C(0xCCD2A5925D9681F9), __UINT64_C(0x8E224479F47CB76A),
 __UINT64_C(0x9266CC8A1C85D9BE), __UINT64_C(0xD0962D61B56FEF2D), __UINT64_C(0x17870F5D4F51B498), __UINT64_C(0x5577EEB6E6BB820B),
 __UINT64_C(0xDB55AACF12C73561), __UINT64_C(0x99A54B24BB2D03F2), __UINT64_C(0x5EB4691841135847), __UINT64_C(0x1C4488F3E8F96ED4),
 __UINT64_C(0x663D78FF90E185EF), __UINT64_C(0x24CD9914390BB37C), __UINT64_C(0xE3DCBB28C335E8C9), __UINT64_C(0xA12C5AC36ADFDE5A),
 __UINT64_C(0x2F0E1EBA9EA36930), __UINT64_C(0x6DFEFF5137495FA3), __UINT64_C(0xAAEFDD6DCD770416), __UINT64_C(0xE81F3C86649D3285),
 __UINT64_C(0xF45BB4758C645C51), __UINT64_C(0xB6AB559E258E6AC2), __UINT64_C(0x71BA77A2DFB03177), __UINT64_C(0x334A9649765A07E4),
 __UINT64_C(0xBD68D2308226B08E), __UINT64_C(0xFF9833DB2BCC861D), __UINT64_C(0x388911E7D1F2DDA8), __UINT64_C(0x7A79F00C7818EB3B),
 __UINT64_C(0xCC7AF1FF21C30BDE), __UINT64_C(0x8E8A101488293D4D), __UINT64_C(0x499B3228721766F8), __UINT64_C(0x0B6BD3C3DBFD506B),
 __UINT64_C(0x854997BA2F81E701), __UINT64_C(0xC7B97651866BD192), __UINT64_C(0x00A8546D7C558A27), __UINT64_C(0x4258B586D5BFBCB4),
 __UINT64_C(0x5E1C3D753D46D260), __UINT64_C(0x1CECDC9E94ACE4F3), __UINT64_C(0xDBFDFEA26E92BF46), __UINT64_C(0x990D1F49C77889D5),
 __UINT64_C(0x172F5B3033043EBF), __UINT64_C(0x55DFBADB9AEE082C), __UINT64_C(0x92CE98E760D05399), __UINT64_C(0xD03E790CC93A650A),
 __UINT64_C(0xAA478900B1228E31), __UINT64_C(0xE8B768EB18C8B8A2), __UINT64_C(0x2FA64AD7E2F6E317), __UINT64_C(0x6D56AB3C4B1CD584),
 __UINT64_C(0xE374EF45BF6062EE), __UINT64_C(0xA1840EAE168A547D), __UINT64_C(0x66952C92ECB40FC8), __UINT64_C(0x2465CD79455E395B),
 __UINT64_C(0x3821458AADA7578F), __UINT64_C(0x7AD1A461044D611C), __UINT64_C(0xBDC0865DFE733AA9), __UINT64_C(0xFF3067B657990C3A),
 __UINT64_C(0x711223CFA3E5BB50), __UINT64_C(0x33E2C2240A0F8DC3), __UINT64_C(0xF4F3E018F031D676), __UINT64_C(0xB60301F359DBE0E5),
 __UINT64_C(0xDA050215EA6C212F), __UINT64_C(0x98F5E3FE438617BC), __UINT64_C(0x5FE4C1C2B9B84C09), __UINT64_C(0x1D14202910527A9A),
 __UINT64_C(0x93366450E42ECDF0), __UINT64_C(0xD1C685BB4DC4FB63), __UINT64_C(0x16D7A787B7FAA0D6), __UINT64_C(0x5427466C1E109645),
 __UINT64_C(0x4863CE9FF6E9F891), __UINT64_C(0x0A932F745F03CE02), __UINT64_C(0xCD820D48A53D95B7), __UINT64_C(0x8F72ECA30CD7A324),
 __UINT64_C(0x0150A8DAF8AB144E), __UINT64_C(0x43A04931514122DD), __UINT64_C(0x84B16B0DAB7F7968), __UINT64_C(0xC6418AE602954FFB),
 __UINT64_C(0xBC387AEA7A8DA4C0), __UINT64_C(0xFEC89B01D3679253), __UINT64_C(0x39D9B93D2959C9E6), __UINT64_C(0x7B2958D680B3FF75),
 __UINT64_C(0xF50B1CAF74CF481F), __UINT64_C(0xB7FBFD44DD257E8C), __UINT64_C(0x70EADF78271B2539), __UINT64_C(0x321A3E938EF113AA),
 __UINT64_C(0x2E5EB66066087D7E), __UINT64_C(0x6CAE578BCFE24BED), __UINT64_C(0xABBF75B735DC1058), __UINT64_C(0xE94F945C9C3626CB),
 __UINT64_C(0x676DD025684A91A1), __UINT64_C(0x259D31CEC1A0A732), __UINT64_C(0xE28C13F23B9EFC87), __UINT64_C(0xA07CF2199274CA14),
 __UINT64_C(0x167FF3EACBAF2AF1), __UINT64_C(0x548F120162451C62), __UINT64_C(0x939E303D987B47D7), __UINT64_C(0xD16ED1D631917144),
 __UINT64_C(0x5F4C95AFC5EDC62E), __UINT64_C(0x1DBC74446C07F0BD), __UINT64_C(0xDAAD56789639AB08), __UINT64_C(0x985DB7933FD39D9B),
 __UINT64_C(0x84193F60D72AF34F), __UINT64_C(0xC6E9DE8B7EC0C5DC), __UINT64_C(0x01F8FCB784FE9E69), __UINT64_C(0x43081D5C2D14A8FA),
 __UINT64_C(0xCD2A5925D9681F90), __UINT64_C(0x8FDAB8CE70822903), __UINT64_C(0x48CB9AF28ABC72B6), __UINT64_C(0x0A3B7B1923564425),
 __UINT64_C(0x70428B155B4EAF1E), __UINT64_C(0x32B26AFEF2A4998D), __UINT64_C(0xF5A348C2089AC238), __UINT64_C(0xB753A929A170F4AB),
 __UINT64_C(0x3971ED50550C43C1), __UINT64_C(0x7B810CBBFCE67552), __UINT64_C(0xBC902E8706D82EE7), __UINT64_C(0xFE60CF6CAF321874),
 __UINT64_C(0xE224479F47CB76A0), __UINT64_C(0xA0D4A674EE214033), __UINT64_C(0x67C58448141F1B86), __UINT64_C(0x253565A3BDF52D15),
 __UINT64_C(0xAB1721DA49899A7F), __UINT64_C(0xE9E7C031E063ACEC), __UINT64_C(0x2EF6E20D1A5DF759), __UINT64_C(0x6C0603E6B3B7C1CA),
 __UINT64_C(0xF6FAE5C07D3274CD), __UINT64_C(0xB40A042BD4D8425E), __UINT64_C(0x731B26172EE619EB), __UINT64_C(0x31EBC7FC870C2F78),
 __UINT64_C(0xBFC9838573709812), __UINT64_C(0xFD39626EDA9AAE81), __UINT64_C(0x3A28405220A4F534), __UINT64_C(0x78D8A1B9894EC3A7),
 __UINT64_C(0x649C294A61B7AD73), __UINT64_C(0x266CC8A1C85D9BE0), __UINT64_C(0xE17DEA9D3263C055), __UINT64_C(0xA38D0B769B89F6C6),
 __UINT64_C(0x2DAF4F0F6FF541AC), __UINT64_C(0x6F5FAEE4C61F773F), __UINT64_C(0xA84E8CD83C212C8A), __UINT64_C(0xEABE6D3395CB1A19),
 __UINT64_C(0x90C79D3FEDD3F122), __UINT64_C(0xD2377CD44439C7B1), __UINT64_C(0x15265EE8BE079C04), __UINT64_C(0x57D6BF0317EDAA97),
 __UINT64_C(0xD9F4FB7AE3911DFD), __UINT64_C(0x9B041A914A7B2B6E), __UINT64_C(0x5C1538ADB04570DB), __UINT64_C(0x1EE5D94619AF4648),
 __UINT64_C(0x02A151B5F156289C), __UINT64_C(0x4051B05E58BC1E0F), __UINT64_C(0x87409262A28245BA), __UINT64_C(0xC5B073890B687329),
 __UINT64_C(0x4B9237F0FF14C443), __UINT64_C(0x0962D61B56FEF2D0), __UINT64_C(0xCE73F427ACC0A965), __UINT64_C(0x8C8315CC052A9FF6),
 __UINT64_C(0x3A80143F5CF17F13), __UINT64_C(0x7870F5D4F51B4980), __UINT64_C(0xBF61D7E80F251235), __UINT64_C(0xFD913603A6CF24A6),
 __UINT64_C(0x73B3727A52B393CC), __UINT64_C(0x31439391FB59A55F), __UINT64_C(0xF652B1AD0167FEEA), __UINT64_C(0xB4A25046A88DC879),
 __UINT64_C(0xA8E6D8B54074A6AD), __UINT64_C(0xEA16395EE99E903E), __UINT64_C(0x2D071B6213A0CB8B), __UINT64_C(0x6FF7FA89BA4AFD18),
 __UINT64_C(0xE1D5BEF04E364A72), __UINT64_C(0xA3255F1BE7DC7CE1), __UINT64_C(0x64347D271DE22754), __UINT64_C(0x26C49CCCB40811C7),
 __UINT64_C(0x5CBD6CC0CC10FAFC), __UINT64_C(0x1E4D8D2B65FACC6F), __UINT64_C(0xD95CAF179FC497DA), __UINT64_C(0x9BAC4EFC362EA149),
 __UINT64_C(0x158E0A85C2521623), __UINT64_C(0x577EEB6E6BB820B0), __UINT64_C(0x906FC95291867B05), __UINT64_C(0xD29F28B9386C4D96),
 __UINT64_C(0xCEDBA04AD0952342), __UINT64_C(0x8C2B41A1797F15D1), __UINT64_C(0x4B3A639D83414E64), __UINT64_C(0x09CA82762AAB78F7),
 __UINT64_C(0x87E8C60FDED7CF9D), __UINT64_C(0xC51827E4773DF90E), __UINT64_C(0x020905D88D03A2BB), __UINT64_C(0x40F9E43324E99428),
 __UINT64_C(0x2CFFE7D5975E55E2), __UINT64_C(0x6E0F063E3EB46371), __UINT64_C(0xA91E2402C48A38C4), __UINT64_C(0xEBEEC5E96D600E57),
 __UINT64_C(0x65CC8190991CB93D), __UINT64_C(0x273C607B30F68FAE), __UINT64_C(0xE02D4247CAC8D41B), __UINT64_C(0xA2DDA3AC6322E288),
 __UINT64_C(0xBE992B5F8BDB8C5C), __UINT64_C(0xFC69CAB42231BACF), __UINT64_C(0x3B78E888D80FE17A), __UINT64_C(0x7988096371E5D7E9),
 __UINT64_C(0xF7AA4D1A85996083), __UINT64_C(0xB55AACF12C735610), __UINT64_C(0x724B8ECDD64D0DA5), __UINT64_C(0x30BB6F267FA73B36),
 __UINT64_C(0x4AC29F2A07BFD00D), __UINT64_C(0x08327EC1AE55E69E), __UINT64_C(0xCF235CFD546BBD2B), __UINT64_C(0x8DD3BD16FD818BB8),
 __UINT64_C(0x03F1F96F09FD3CD2), __UINT64_C(0x41011884A0170A41), __UINT64_C(0x86103AB85A2951F4), __UINT64_C(0xC4E0DB53F3C36767),
 __UINT64_C(0xD8A453A01B3A09B3), __UINT64_C(0x9A54B24BB2D03F20), __UINT64_C(0x5D45907748EE6495), __UINT64_C(0x1FB5719CE1045206),
 __UINT64_C(0x919735E51578E56C), __UINT64_C(0xD367D40EBC92D3FF), __UINT64_C(0x1476F63246AC884A), __UINT64_C(0x568617D9EF46BED9),
 __UINT64_C(0xE085162AB69D5E3C), __UINT64_C(0xA275F7C11F7768AF), __UINT64_C(0x6564D5FDE549331A), __UINT64_C(0x279434164CA30589),
 __UINT64_C(0xA9B6706FB8DFB2E3), __UINT64_C(0xEB46918411358470), __UINT64_C(0x2C57B3B8EB0BDFC5), __UINT64_C(0x6EA7525342E1E956),
 __UINT64_C(0x72E3DAA0AA188782), __UINT64_C(0x30133B4B03F2B111), __UINT64_C(0xF7021977F9CCEAA4), __UINT64_C(0xB5F2F89C5026DC37),
 __UINT64_C(0x3BD0BCE5A45A6B5D), __UINT64_C(0x79205D0E0DB05DCE), __UINT64_C(0xBE317F32F78E067B), __UINT64_C(0xFCC19ED95E6430E8),
 __UINT64_C(0x86B86ED5267CDBD3), __UINT64_C(0xC4488F3E8F96ED40), __UINT64_C(0x0359AD0275A8B6F5), __UINT64_C(0x41A94CE9DC428066),
 __UINT64_C(0xCF8B0890283E370C), __UINT64_C(0x8D7BE97B81D4019F), __UINT64_C(0x4A6ACB477BEA5A2A), __UINT64_C(0x089A2AACD2006CB9),
 __UINT64_C(0x14DEA25F3AF9026D), __UINT64_C(0x562E43B4931334FE), __UINT64_C(0x913F6188692D6F4B), __UINT64_C(0xD3CF8063C0C759D8),
 __UINT64_C(0x5DEDC41A34BBEEB2), __UINT64_C(0x1F1D25F19D51D821), __UINT64_C(0xD80C07CD676F8394), __UINT64_C(0x9AFCE626CE85B507) 
}; 

};

std::string ZNSTR::encode_base64(const std::string &Str, bool app_eol)
{
 int len = Str.size();
 int rlen = ((len + 2)/3)*4;
 if(rlen) { rlen+=((rlen - 1)/MAX_LINE + 1); }
 char *res = new char[rlen + 1];
 char *r = res;
 const char *str = Str.c_str();
 for(int chunk = 0; len > 0; len -= 3, chunk++)
 {
  if(chunk == (MAX_LINE/4))
  {
   *r++ = '\n';
   chunk = 0;
  }
  unsigned char c1 = *str++;
  unsigned char c2 = *str++;
  *r++ = basis_64[c1>>2];
  *r++ = basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)];
  if(len > 2) 
  {
   unsigned char c3 = *str++;
   *r++ = basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
   *r++ = basis_64[c3 & 0x3F];
  }
  else if(len == 2)
  {
   *r++ = basis_64[(c2 & 0xF) << 2];
   *r++ = '=';
  }
  else
  {                // len == 1 
   *r++ = '=';
   *r++ = '=';
  }
 }
 if(app_eol && rlen)  *r++ = '\n';    // append eol to the result string 
 *r = '\0';
 std::string ret(res);
 delete [] res;
 return ret;
};// encode_base64

std::string ZNSTR::decode_base64(const std::string &Str)
{
 int len = Str.size();
 const char *str = Str.c_str();
 const char *end = str + len;
 unsigned char c[4];
 int rlen = ((len*3)/4);
 char *res = new char[rlen + 1];
 char *r = res;
 while(str < end)
 {
  int i = 0;
  do 
  {
   unsigned char uc = index_64[(unsigned) *str++];
   if(uc != INVALID) c[i++] = uc;
   if(str == end)
   {
    if(i < 4)
    {
     if(i) { delete [] res; return ""; }
     if ( i < 2 ) goto thats_it;
     if ( i == 2 ) c[2] = EQ;
     c[3] = EQ;
    }
    break;
   }
  }
  while(i < 4);
  if(c[0] == EQ || c[1] == EQ) break;
  *r++ = (c[0] << 2) | ((c[1] & 0x30) >> 4);
  if(c[2] == EQ) break;
  *r++ = ((c[1] & 0x0F) << 4) | ((c[2] & 0x3C) >> 2);
  if(c[3] == EQ) break;
  *r++ = ((c[2] & 0x03) << 6) | c[3];
 }
 thats_it:
 *r = '\0';
 std::string ret(res);
 delete [] res;
 return ret;
};// decode_base64

std::string ZNSTR::toUpper(const char* p, size_t len)
{
 std::string ret(p, len);
 for(size_t i=0; i < len; ++i) 
 { ret[i]=toupper(ret[i]); }
 return ret;
};

std::string ZNSTR::toUpper(const std::string &s) { return ZNSTR::toUpper(s.c_str(), s.size()); };

void ZNSTR::setUpper(std::string &s, size_t start_pos, size_t len)
{
 size_t n=s.size();
 if(start_pos >= n) return;
 if((n-start_pos) < len) len=n;
 else len+=start_pos;
 for(size_t i=start_pos; i < len; ++i) 
 { s[i]=toupper(s[i]); }
};

std::string ZNSTR::toLower(const char* p, size_t len)
{
 std::string ret(p, len);
 for(size_t i=0; i < len; i++) 
 { ret[i]=tolower(ret[i]); }
 return ret;
};

std::string ZNSTR::toLower(const std::string &s) { return ZNSTR::toLower(s.c_str(), s.size()); };

void ZNSTR::setLower(std::string &s, size_t start_pos, size_t len)
{
 size_t n=s.size();
 if(start_pos >= n) return;
 if((n-start_pos) < len) len=n;
 else len+=start_pos;
 for(size_t i=start_pos; i < len; ++i) 
 { s[i]=tolower(s[i]); }
};

std::string ZNSTR::str2hex(const char* p, size_t len)
{
 std::string ret;
 ret.reserve(len*2);
 for(size_t i = 0; i < len; ++i, ++p)
 {
  ret += __digs__[((unsigned char) *p) >> 4];
  ret += __digs__[((unsigned char) *p) & 0xf];
 }
 return ret;
};

std::string ZNSTR::str2hex(const std::string &s) { return ZNSTR::str2hex(s.c_str(), s.size()); };

std::string ZNSTR::hex2str(const char* p, size_t len)
{
 if(len & 1) return "";
 std::string ret;
 ret.reserve(len/2);
 size_t v;
 for(size_t i = 0; i < len; i+=2, p+=2)
 {
  v=0;
  switch(*p)
  {
   case 'a': { v+=((unsigned char) '\x0A'); break; }
   case 'A': { v+=((unsigned char) '\x0A'); break; }
   case 'b': { v+=((unsigned char) '\x0B'); break; }
   case 'B': { v+=((unsigned char) '\x0B'); break; }
   case 'c': { v+=((unsigned char) '\x0C'); break; }
   case 'C': { v+=((unsigned char) '\x0C'); break; }
   case 'd': { v+=((unsigned char) '\x0D'); break; }
   case 'D': { v+=((unsigned char) '\x0D'); break; }
   case 'e': { v+=((unsigned char) '\x0E'); break; }
   case 'E': { v+=((unsigned char) '\x0E'); break; }
   case 'f': { v+=((unsigned char) '\x0F'); break; }
   case 'F': { v+=((unsigned char) '\x0F'); break; }
   case '0': { v+=((unsigned char) '\x00'); break; }
   case '1': { v+=((unsigned char) '\x01'); break; }
   case '2': { v+=((unsigned char) '\x02'); break; }
   case '3': { v+=((unsigned char) '\x03'); break; }
   case '4': { v+=((unsigned char) '\x04'); break; }
   case '5': { v+=((unsigned char) '\x05'); break; }
   case '6': { v+=((unsigned char) '\x06'); break; }
   case '7': { v+=((unsigned char) '\x07'); break; }
   case '8': { v+=((unsigned char) '\x08'); break; }
   case '9': { v+=((unsigned char) '\x09'); break; }
   default: { return ""; }
  }
  v <<= 4;
  switch(*(p+1))
  {
   case 'a': { v+=((unsigned char) '\x0A'); break; }
   case 'A': { v+=((unsigned char) '\x0A'); break; }
   case 'b': { v+=((unsigned char) '\x0B'); break; }
   case 'B': { v+=((unsigned char) '\x0B'); break; }
   case 'c': { v+=((unsigned char) '\x0C'); break; }
   case 'C': { v+=((unsigned char) '\x0C'); break; }
   case 'd': { v+=((unsigned char) '\x0D'); break; }
   case 'D': { v+=((unsigned char) '\x0D'); break; }
   case 'e': { v+=((unsigned char) '\x0E'); break; }
   case 'E': { v+=((unsigned char) '\x0E'); break; }
   case 'f': { v+=((unsigned char) '\x0F'); break; }
   case 'F': { v+=((unsigned char) '\x0F'); break; }
   case '0': { v+=((unsigned char) '\x00'); break; }
   case '1': { v+=((unsigned char) '\x01'); break; }
   case '2': { v+=((unsigned char) '\x02'); break; }
   case '3': { v+=((unsigned char) '\x03'); break; }
   case '4': { v+=((unsigned char) '\x04'); break; }
   case '5': { v+=((unsigned char) '\x05'); break; }
   case '6': { v+=((unsigned char) '\x06'); break; }
   case '7': { v+=((unsigned char) '\x07'); break; }
   case '8': { v+=((unsigned char) '\x08'); break; }
   case '9': { v+=((unsigned char) '\x09'); break; }
   default: { return ""; }
  }
  ret+=(unsigned char) v;
 }
 return ret;
};

std::string ZNSTR::hex2str(const std::string &s) { return ZNSTR::hex2str(s.c_str(), s.size()); };

std::string ZNSTR::escape(const char* p, size_t len)
{
 std::string ret;
 ret.reserve(len*3);
 char c;
 for(size_t i= 0; i < len; ++i)
 {
  c=p[i];
  if(('0' <= c && c <= '9') ||//0-9
     ('a' <= c && c <= 'z') ||//abc...xyz
     ('A' <= c && c <= 'Z') || //ABC...XYZ
     c == '~' || c == '!' || c == '*' || c == '(' || c == ')' || c == '\'') ret+=c;
  else
  {
   ret+='%';
   ret+= __digs__[((unsigned char) c) >> 4];
   ret+= __digs__[((unsigned char) c) & 0xf];
  }
 }
 return ret;
};

std::string ZNSTR::escape(const std::string &s) { return ZNSTR::escape(s.c_str(), s.size()); };

std::string ZNSTR::unescape(const char* p, size_t len)
{
 std::string ret; ret.reserve(len);
 char c;
 size_t v;
 for(size_t i = 0; i < len; i++)
 {
  c=p[i];
//  if(c == '+') { ret+=' '; continue; }
  if(c == '%' && (i+2) < len)
  {
   v=0;
   switch(p[i+1])
   {
    case 'a': { v+=((unsigned char) '\x0A'); break; }
    case 'A': { v+=((unsigned char) '\x0A'); break; }
    case 'b': { v+=((unsigned char) '\x0B'); break; }
    case 'B': { v+=((unsigned char) '\x0B'); break; }
    case 'c': { v+=((unsigned char) '\x0C'); break; }
    case 'C': { v+=((unsigned char) '\x0C'); break; }
    case 'd': { v+=((unsigned char) '\x0D'); break; }
    case 'D': { v+=((unsigned char) '\x0D'); break; }
    case 'e': { v+=((unsigned char) '\x0E'); break; }
    case 'E': { v+=((unsigned char) '\x0E'); break; }
    case 'f': { v+=((unsigned char) '\x0F'); break; }
    case 'F': { v+=((unsigned char) '\x0F'); break; }
    case '0': { v+=((unsigned char) '\x00'); break; }
    case '1': { v+=((unsigned char) '\x01'); break; }
    case '2': { v+=((unsigned char) '\x02'); break; }
    case '3': { v+=((unsigned char) '\x03'); break; }
    case '4': { v+=((unsigned char) '\x04'); break; }
    case '5': { v+=((unsigned char) '\x05'); break; }
    case '6': { v+=((unsigned char) '\x06'); break; }
    case '7': { v+=((unsigned char) '\x07'); break; }
    case '8': { v+=((unsigned char) '\x08'); break; }
    case '9': { v+=((unsigned char) '\x09'); break; }
    default: { ret+=c; continue; }
   }
   v <<= 4;
   switch(p[i+2])
   {
    case 'a': { v+=((unsigned char) '\x0A'); break; }
    case 'A': { v+=((unsigned char) '\x0A'); break; }
    case 'b': { v+=((unsigned char) '\x0B'); break; }
    case 'B': { v+=((unsigned char) '\x0B'); break; }
    case 'c': { v+=((unsigned char) '\x0C'); break; }
    case 'C': { v+=((unsigned char) '\x0C'); break; }
    case 'd': { v+=((unsigned char) '\x0D'); break; }
    case 'D': { v+=((unsigned char) '\x0D'); break; }
    case 'e': { v+=((unsigned char) '\x0E'); break; }
    case 'E': { v+=((unsigned char) '\x0E'); break; }
    case 'f': { v+=((unsigned char) '\x0F'); break; }
    case 'F': { v+=((unsigned char) '\x0F'); break; }
    case '0': { v+=((unsigned char) '\x00'); break; }
    case '1': { v+=((unsigned char) '\x01'); break; }
    case '2': { v+=((unsigned char) '\x02'); break; }
    case '3': { v+=((unsigned char) '\x03'); break; }
    case '4': { v+=((unsigned char) '\x04'); break; }
    case '5': { v+=((unsigned char) '\x05'); break; }
    case '6': { v+=((unsigned char) '\x06'); break; }
    case '7': { v+=((unsigned char) '\x07'); break; }
    case '8': { v+=((unsigned char) '\x08'); break; }
    case '9': { v+=((unsigned char) '\x09'); break; }
    default: { ret+=c; continue; }
   }
   ret+=(unsigned char) v;
   i+=2;
  }
  else ret+=c;
 }
 return ret;
};

std::string ZNSTR::unescape(const std::string &s) { return ZNSTR::unescape(s.c_str(), s.size()); };

std::string ZNSTR::trim(const std::string &s, const std::string &q) 
{
 std::string ret;
 size_t pos1 = s.find_first_not_of(q);
 if(pos1 != std::string::npos )
 {
  size_t pos2 = s.find_last_not_of(q);
  ret.append(s, pos1, pos2-pos1+1);
 }
 return ret;
};// trim

void ZNSTR::shrink(std::string &s, const std::string &q)
{
 size_t pos1 = s.find_first_not_of(q);
 if(pos1 != std::string::npos)
 {
  size_t pos2 = s.find_last_not_of(q);
  s.erase(pos2+1);
  s.erase(0, pos1);
 }
};

std::string ZNSTR::ltrim(const std::string &s, const std::string &q)
{
 std::string ret;
 size_t pos = s.find_first_not_of(q);
 if(pos != std::string::npos) ret.append(s, pos, std::string::npos);
 return ret;
};

void ZNSTR::lshrink(std::string &s, const std::string &q)
{
 size_t pos = s.find_first_not_of(q);
 s.erase(0, pos);
};

std::string ZNSTR::rtrim(const std::string &s, const std::string &q)
{
 std::string ret;
 size_t pos = s.find_last_not_of(q);
 if(pos != std::string::npos) ret.append(s,0,pos+1);
 return ret;
};

void ZNSTR::rshrink(std::string &s, const std::string &q)
{
 size_t pos = s.find_last_not_of(q);
 if(pos == std::string::npos) s.clear();
 else s.erase(pos+1);
};

std::string ZNSTR::replace(const std::string &src,const std::string &str,const std::string &rep)
{
 size_t n=str.size();
 if(src.size() == 0 || n == 0) return src;
 std::string ret; ret.reserve(src.size());
 size_t k=0;
 size_t s;
 for(;;)
 {
  s=src.find(str,k);
  if(s == std::string::npos) { ret.append(src, k, s); return ret; }
  ret.append(src, k, s-k);
  ret+=rep;
  k=(s+n);
 }
};

void ZNSTR::substitute(std::string &src, const std::string &str, const std::string &rep)
{
 size_t n=str.size();
 if(src.size() == 0 || n == 0) return;
 size_t l=rep.size();
 size_t s;
 for(size_t k=0;;)
 {
  s=src.find(str,k);
  if(s == std::string::npos) return;
  src.erase(s, n);
  if(l) src.insert(s, rep);
  k=(s+l);
 }
};

std::vector<std::string> ZNSTR::split(const std::string &q,const std::string &r)
{
 std::vector<std::string> ret;
 if(r.size() == 0) { ret.push_back(q); return ret; }
 size_t i;
 size_t j = 0;
 for(;;)
 {
  i=q.find(r,j);
  if(i == std::string::npos)
  {
   if(j < q.size()) { ret.push_back(q.substr(j,(q.size()-j))); }
   return ret;
  }
  ret.push_back(q.substr(j,(i-j)));
  j=(i+r.size());
 }
};

size_t ZNSTR::split(std::vector<std::string>& ret, const std::string &q,const std::string &r)
{
 size_t n=0;
 if(r.size() == 0) { ret.push_back(q); n++; return n; }
 size_t i;
 size_t j = 0;
 for(;;)
 {
  i=q.find(r,j);
  if(i == std::string::npos)
  {
   if(j < q.size()) { ret.push_back(q.substr(j,(q.size()-j))); n++; }
   return n;
  }
  ret.push_back(q.substr(j,(i-j))); n++;
  j=(i+r.size());
 }
};

size_t ZNSTR::split(std::list<std::string>& ret, const std::string &q, const std::string &r)
{
 size_t n=0;
 if(r.size() == 0) { ret.push_back(q); n++; return n; }
 size_t i;
 size_t j = 0;
 for(;;)
 {
  i=q.find(r,j);
  if(i == std::string::npos)
  {
   if(j < q.size()) { ret.push_back(q.substr(j,(q.size()-j))); n++; }
   return n;
  }
  ret.push_back(q.substr(j,(i-j))); n++;
  j=(i+r.size());
 }
};

std::string ZNSTR::toString(short value) { return toString((longlong) value); };
std::string ZNSTR::toString(unsigned short value) { return toString((ulonglong) value); };
std::string ZNSTR::toString(int value) { return toString((longlong) value); };
std::string ZNSTR::toString(unsigned value) { return toString((ulonglong) value); };
//std::string ZNSTR::toString(long value) { return toString((longlong) value); };
//std::string ZNSTR::toString(unsigned long value) { return toString((ulonglong) value); };

std::string ZNSTR::toString(longlong value)
{
 if(value == 0) return "0";
 std::string ret;
 ret.reserve(24);
 int sign=1;
 if(value < 0) { sign=-1; value*=(-1); }
 for(; value; value/=10)
 {
  switch(value%10)
  {
   case 0:  { ret+='0'; break; }
   case 1:  { ret+='1'; break; }
   case 2:  { ret+='2'; break; }
   case 3:  { ret+='3'; break; }
   case 4:  { ret+='4'; break; }
   case 5:  { ret+='5'; break; }
   case 6:  { ret+='6'; break; }
   case 7:  { ret+='7'; break; }
   case 8:  { ret+='8'; break; }
   case 9:  { ret+='9'; break; }
  }
 }
 if(sign < 0) ret+='-';
 char c;
 size_t n=ret.size();
 size_t l=n/2;
 --n;
 for(size_t i=0; i < l; i++) { c=ret[i]; ret[i]=ret[n-i]; ret[n-i]=c; }
 return ret;
};

std::string ZNSTR::toString(ulonglong value)
{
 if(value == 0) return "0";
 std::string ret;
 ret.reserve(24);
 for(; value; value/=10)
 {
  switch(value%10)
  {
   case 0:  { ret+='0'; break; }
   case 1:  { ret+='1'; break; }
   case 2:  { ret+='2'; break; }
   case 3:  { ret+='3'; break; }
   case 4:  { ret+='4'; break; }
   case 5:  { ret+='5'; break; }
   case 6:  { ret+='6'; break; }
   case 7:  { ret+='7'; break; }
   case 8:  { ret+='8'; break; }
   case 9:  { ret+='9'; break; }
  }
 }
 char c;
 size_t n=ret.size();
 size_t l=n/2;
 --n;
 for(size_t i=0; i < l; i++) { c=ret[i]; ret[i]=ret[n-i]; ret[n-i]=c; }
 return ret;
};

std::string ZNSTR::toString(float value)
{
 std::ostringstream s;
 s << value;
 return s.str();
};

std::string ZNSTR::toString(double value)
{
 std::ostringstream s;
 s << value;
 return s.str();
};

std::string ZNSTR::toString(long double value)
{
 std::ostringstream s;
 s << value;
 return s.str();
};

char ZNSTR::asChar(const char* p, size_t len, char def) { return (char) ZNSTR::asLongLong(p, len, (longlong) def); };
char ZNSTR::toChar(const std::string &q,char def) { return (char) ZNSTR::asLongLong(q.c_str(), q.size(), (longlong) def); };

unsigned char ZNSTR::asUnsignedChar(const char* p, size_t len, unsigned char def) { return (unsigned char) ZNSTR::asULongLong(p, len, (ulonglong) def); };
unsigned char ZNSTR::toUnsignedChar(const std::string &q, unsigned char def) { return (unsigned char) ZNSTR::asULongLong(q.c_str(), q.size(), (ulonglong) def); };

short ZNSTR::asShort(const char* p, size_t len, short def) { return (short) ZNSTR::asLongLong(p, len, (longlong) def); };
short ZNSTR::toShort(const std::string &q, short def) { return (short) ZNSTR::asLongLong(q.c_str(), q.size(), (longlong) def); };

unsigned short ZNSTR::asUnsignedShort(const char* p, size_t len,unsigned short def) { return (unsigned short) ZNSTR::asULongLong(p, len, (ulonglong) def); };
unsigned short ZNSTR::toUnsignedShort(const std::string &q,unsigned short def) { return (unsigned short) ZNSTR::asULongLong(q.c_str(), q.size(), (ulonglong) def); };

int ZNSTR::asInt(const char* p, size_t len, int def) { return (int) ZNSTR::asLongLong(p, len, (longlong) def); };
int ZNSTR::toInt(const std::string &q, int def) { return (int) ZNSTR::asLongLong(q.c_str(), q.size(), (longlong) def); };

unsigned ZNSTR::asUnsigned(const char* p, size_t len, unsigned def) { return (unsigned) ZNSTR::asULongLong(p, len, (ulonglong) def); };
unsigned ZNSTR::toUnsigned(const std::string &q, unsigned def) { return (unsigned) ZNSTR::asULongLong(q.c_str(), q.size(), (ulonglong) def); };

long ZNSTR::asLong(const char* p, size_t len, long def) { return (long) ZNSTR::asLongLong(p, len, (longlong) def); };
long ZNSTR::toLong(const std::string &q, long def) { return (long) ZNSTR::asLongLong(q.c_str(), q.size(), (longlong) def); };

unsigned long ZNSTR::asUnsignedLong(const char* p, size_t len, unsigned long def) { return (unsigned long) ZNSTR::asULongLong(p, len, (ulonglong) def); };
unsigned long ZNSTR::toUnsignedLong(const std::string &q, unsigned long def) { return (unsigned long) ZNSTR::asULongLong(q.c_str(), q.size(), (ulonglong) def); };

longlong ZNSTR::asLongLong(const char* p, size_t len, longlong def)
{
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 int sign=1;
 longlong ret=0;
 switch(p[pos])
 {
  case '-': { sign=-1; }
  case '+': { ++pos; }
 }
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 char c=p[pos];
 if(c < '0' || c > '9') return def;
 for(; pos < len; ++pos)
 {
  c=p[pos];
  if(c < '0' || c > '9') break;
  ret*=10; ret+=((unsigned char) c - '0');
 }
 ret*=sign;
 return ret;
};

longlong ZNSTR::toLongLong(const std::string &q, longlong def) { return ZNSTR::asLongLong(q.c_str(), q.size(), def); };

ulonglong ZNSTR::asULongLong(const char* p, size_t len, ulonglong def)
{
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 ulonglong ret=0;
 if(p[pos] == '+') { ++pos; }
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 char c=p[pos];
 if(c < '0' || c > '9') return def;
 for(; pos < len; ++pos)
 {
  c=p[pos];
  if(c < '0' || c > '9') break;
  ret*=10; ret+=((unsigned char) c - '0');
 }
 return ret;
};

ulonglong ZNSTR::toULongLong(const std::string &q, ulonglong def) { return ZNSTR::asULongLong(q.c_str(), q.size(), def); };

float ZNSTR::asFloat(const char* p, size_t len, float def) { return (float) ZNSTR::asDouble(p, len, (double) def); };

float ZNSTR::toFloat(const std::string &q, float def) { return (float) ZNSTR::asDouble(q.c_str(), q.size(), (double) def); };

double ZNSTR::asDouble(const char* p, size_t len, double def)
{
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 int sign=1;
 int point=0;
 size_t exponenta=0;
 double multiplier=1.;
 double ret=0.;
 switch(p[pos])
 {
  case '-': { sign=-1; }
  case '+': { ++pos; }
 }
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 char c=p[pos];
 if(c < '0' || c > '9') return def;
 for(; pos < len; ++pos)
 {
  c=p[pos];
  if(c == '.') { if(point) { break; } point=1; continue; }
  if(c == 'e' || c == 'E')
  {
   if(point > 1) { break; }
   switch(p[pos+1])
   {
    case '-': { point=4; ++pos; break; }
    case '+': { point=2; ++pos; break; }
    default:  { point=2; }
   }
   continue;
  }
  if(c < '0' || c > '9') break;
  if(point < 2) { ret*=10.; ret+=((unsigned char) c - '0'); if(point) { multiplier*=10.; } }
  else { exponenta*=10; exponenta+=((unsigned char) c - '0'); if(exponenta > 308) return def; }
 }
 if(multiplier != 0.0 && multiplier != 1.) { ret/=multiplier; }
 if(point & 2) { for(size_t j=0; j < exponenta; j++) { ret*=10.; } }
 else if(point & 4) { for(size_t j=0; j < exponenta; j++) { ret/=10.; } }
 ret*=sign;
 return ret;
};

double ZNSTR::toDouble(const std::string &q,double def) { return ZNSTR::asDouble(q.c_str(), q.size(), def); };

char ZNSTR::asChar16(const char* p, size_t len, char def) { return (char) ZNSTR::asLongLong16(p, len, (longlong) def); };
char ZNSTR::toChar16(const std::string &q,char def) { return (char) ZNSTR::asLongLong16(q.c_str(), q.size(), (longlong) def); };

unsigned char ZNSTR::asUnsignedChar16(const char* p, size_t len, unsigned char def) { return (unsigned char) ZNSTR::asULongLong16(p, len, (ulonglong) def); };
unsigned char ZNSTR::toUnsignedChar16(const std::string &q, unsigned char def) { return (unsigned char) ZNSTR::asULongLong16(q.c_str(), q.size(), (ulonglong) def); };

short ZNSTR::asShort16(const char* p, size_t len, short def) { return (short) ZNSTR::asLongLong16(p, len, (longlong) def); };
short ZNSTR::toShort16(const std::string &q, short def) { return (short) ZNSTR::asLongLong16(q.c_str(), q.size(), (longlong) def); };

unsigned short ZNSTR::asUnsignedShort16(const char* p, size_t len,unsigned short def) { return (unsigned short) ZNSTR::asULongLong16(p, len, (ulonglong) def); };
unsigned short ZNSTR::toUnsignedShort16(const std::string &q,unsigned short def) { return (unsigned short) ZNSTR::asULongLong16(q.c_str(), q.size(), (ulonglong) def); };

int ZNSTR::asInt16(const char* p, size_t len, int def) { return (int) ZNSTR::asLongLong16(p, len, (longlong) def); };
int ZNSTR::toInt16(const std::string &q,int def) { return (int) ZNSTR::asLongLong16(q.c_str(), q.size(), (longlong) def); };

unsigned ZNSTR::asUnsigned16(const char* p, size_t len, unsigned def) { return (unsigned) ZNSTR::asULongLong16(p, len, (ulonglong) def); };
unsigned ZNSTR::toUnsigned16(const std::string &q, unsigned def) { return (unsigned) ZNSTR::asULongLong16(q.c_str(), q.size(), (ulonglong) def); };

long ZNSTR::asLong16(const char* p, size_t len, long def) { return (long) ZNSTR::asLongLong16(p, len, (longlong) def); };
long ZNSTR::toLong16(const std::string &q, long def) { return (long) ZNSTR::asLongLong16(q.c_str(), q.size(), (longlong) def); };

unsigned long ZNSTR::asUnsignedLong16(const char* p, size_t len, unsigned long def) { return (unsigned long) ZNSTR::asULongLong16(p, len, (ulonglong) def); };
unsigned long ZNSTR::toUnsignedLong16(const std::string &q, unsigned long def) { return (unsigned long) ZNSTR::asULongLong16(q.c_str(), q.size(), (ulonglong) def); };

longlong ZNSTR::asLongLong16(const char* p, size_t len, longlong def)
{
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 int sign=1;
 longlong ret=0;
 switch(p[pos])
 {
  case '-': { sign=-1; }
  case '+': { ++pos; }
 }
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 switch(p[pos])
 {
  case 'a': { break; }
  case 'A': { break; }
  case 'b': { break; }
  case 'B': { break; }
  case 'c': { break; }
  case 'C': { break; }
  case 'd': { break; }
  case 'D': { break; }
  case 'e': { break; }
  case 'E': { break; }
  case 'f': { break; }
  case 'F': { break; }
  case '0': { break; }
  case '1': { break; }
  case '2': { break; }
  case '3': { break; }
  case '4': { break; }
  case '5': { break; }
  case '6': { break; }
  case '7': { break; }
  case '8': { break; }
  case '9': { break; }
  default: { return def; }
 }
 for(; pos < len; ++pos)
 {
  switch(p[pos])
  {
   case 'a': { ret<<=4; ret+=((unsigned char) '\x0A'); break; }
   case 'A': { ret<<=4; ret+=((unsigned char) '\x0A'); break; }
   case 'b': { ret<<=4; ret+=((unsigned char) '\x0B'); break; }
   case 'B': { ret<<=4; ret+=((unsigned char) '\x0B'); break; }
   case 'c': { ret<<=4; ret+=((unsigned char) '\x0C'); break; }
   case 'C': { ret<<=4; ret+=((unsigned char) '\x0C'); break; }
   case 'd': { ret<<=4; ret+=((unsigned char) '\x0D'); break; }
   case 'D': { ret<<=4; ret+=((unsigned char) '\x0D'); break; }
   case 'e': { ret<<=4; ret+=((unsigned char) '\x0E'); break; }
   case 'E': { ret<<=4; ret+=((unsigned char) '\x0E'); break; }
   case 'f': { ret<<=4; ret+=((unsigned char) '\x0F'); break; }
   case 'F': { ret<<=4; ret+=((unsigned char) '\x0F'); break; }
   case '0': { ret<<=4; ret+=((unsigned char) '\x00'); break; }
   case '1': { ret<<=4; ret+=((unsigned char) '\x01'); break; }
   case '2': { ret<<=4; ret+=((unsigned char) '\x02'); break; }
   case '3': { ret<<=4; ret+=((unsigned char) '\x03'); break; }
   case '4': { ret<<=4; ret+=((unsigned char) '\x04'); break; }
   case '5': { ret<<=4; ret+=((unsigned char) '\x05'); break; }
   case '6': { ret<<=4; ret+=((unsigned char) '\x06'); break; }
   case '7': { ret<<=4; ret+=((unsigned char) '\x07'); break; }
   case '8': { ret<<=4; ret+=((unsigned char) '\x08'); break; }
   case '9': { ret<<=4; ret+=((unsigned char) '\x09'); break; }
   default: { pos=len-1; break; }
  }
 }
 ret*=sign;
 return ret;
};

longlong ZNSTR::toLongLong16(const std::string &q, longlong def) { return ZNSTR::asLongLong16(q.c_str(), q.size(), def); };

ulonglong ZNSTR::asULongLong16(const char* p, size_t len, ulonglong def)
{
 size_t pos=0;
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 ulonglong ret=0;
 if(p[pos] == '+') { ++pos; }
 PARSE_BLANK(p, len, pos)
 if(pos >= len) return def;
 switch(p[pos])
 {
  case 'a': { break; }
  case 'A': { break; }
  case 'b': { break; }
  case 'B': { break; }
  case 'c': { break; }
  case 'C': { break; }
  case 'd': { break; }
  case 'D': { break; }
  case 'e': { break; }
  case 'E': { break; }
  case 'f': { break; }
  case 'F': { break; }
  case '0': { break; }
  case '1': { break; }
  case '2': { break; }
  case '3': { break; }
  case '4': { break; }
  case '5': { break; }
  case '6': { break; }
  case '7': { break; }
  case '8': { break; }
  case '9': { break; }
  default: { return def; }
 }
 for(; pos < len; ++pos)
 {
  switch(p[pos])
  {
   case 'a': { ret<<=4; ret+=((unsigned char) '\x0A'); break; }
   case 'A': { ret<<=4; ret+=((unsigned char) '\x0A'); break; }
   case 'b': { ret<<=4; ret+=((unsigned char) '\x0B'); break; }
   case 'B': { ret<<=4; ret+=((unsigned char) '\x0B'); break; }
   case 'c': { ret<<=4; ret+=((unsigned char) '\x0C'); break; }
   case 'C': { ret<<=4; ret+=((unsigned char) '\x0C'); break; }
   case 'd': { ret<<=4; ret+=((unsigned char) '\x0D'); break; }
   case 'D': { ret<<=4; ret+=((unsigned char) '\x0D'); break; }
   case 'e': { ret<<=4; ret+=((unsigned char) '\x0E'); break; }
   case 'E': { ret<<=4; ret+=((unsigned char) '\x0E'); break; }
   case 'f': { ret<<=4; ret+=((unsigned char) '\x0F'); break; }
   case 'F': { ret<<=4; ret+=((unsigned char) '\x0F'); break; }
   case '0': { ret<<=4; ret+=((unsigned char) '\x00'); break; }
   case '1': { ret<<=4; ret+=((unsigned char) '\x01'); break; }
   case '2': { ret<<=4; ret+=((unsigned char) '\x02'); break; }
   case '3': { ret<<=4; ret+=((unsigned char) '\x03'); break; }
   case '4': { ret<<=4; ret+=((unsigned char) '\x04'); break; }
   case '5': { ret<<=4; ret+=((unsigned char) '\x05'); break; }
   case '6': { ret<<=4; ret+=((unsigned char) '\x06'); break; }
   case '7': { ret<<=4; ret+=((unsigned char) '\x07'); break; }
   case '8': { ret<<=4; ret+=((unsigned char) '\x08'); break; }
   case '9': { ret<<=4; ret+=((unsigned char) '\x09'); break; }
   default: { pos=len-1; break; }
  }
 }
 return ret;
};

ulonglong ZNSTR::toULongLong16(const std::string &q, ulonglong def) { return ZNSTR::asULongLong16(q.c_str(), q.size(), def); };

std::string ZNSTR::toHex(short value) { return ZNSTR::toHex((longlong) value); };
std::string ZNSTR::toHex(unsigned short value) { return ZNSTR::toHex((ulonglong) value); };
std::string ZNSTR::toHex(int value) { return ZNSTR::toHex((longlong) value); };
std::string ZNSTR::toHex(unsigned value) { return ZNSTR::toHex((ulonglong) value); };
//std::string ZNSTR::toHex(long value) { return ZNSTR::toHex((longlong) value); };
//std::string ZNSTR::toHex(unsigned long value) { return ZNSTR::toHex((ulonglong) value); };

std::string ZNSTR::toHex(longlong value)
{
 if(value == 0) return "0";
 std::string ret;
 ret.reserve(24);
 int sign=1;
 if(value < 0) { sign=-1; value*=(-1); }
 for(; value; value/=16)
 {
  switch(value%16)
  {
   case 0:  { ret+='0'; break; }
   case 1:  { ret+='1'; break; }
   case 2:  { ret+='2'; break; }
   case 3:  { ret+='3'; break; }
   case 4:  { ret+='4'; break; }
   case 5:  { ret+='5'; break; }
   case 6:  { ret+='6'; break; }
   case 7:  { ret+='7'; break; }
   case 8:  { ret+='8'; break; }
   case 9:  { ret+='9'; break; }
   case 10: { ret+='A'; break; }
   case 11: { ret+='B'; break; }
   case 12: { ret+='C'; break; }
   case 13: { ret+='D'; break; }
   case 14: { ret+='E'; break; }
   case 15: { ret+='F'; break; }
  }
 }
 if(sign < 0) ret+='-';
 char c;
 size_t n=ret.size();
 size_t l=n/2;
 --n;
 for(size_t i=0; i < l; i++) { c=ret[i]; ret[i]=ret[n-i]; ret[n-i]=c; }
 return ret;
};

std::string ZNSTR::toHex(ulonglong value)
{
 if(value == 0) return "0";
 std::string ret;
 ret.reserve(24);
 for(; value; value/=16)
 {
  switch(value%16)
  {
   case 0:  { ret+='0'; break; }
   case 1:  { ret+='1'; break; }
   case 2:  { ret+='2'; break; }
   case 3:  { ret+='3'; break; }
   case 4:  { ret+='4'; break; }
   case 5:  { ret+='5'; break; }
   case 6:  { ret+='6'; break; }
   case 7:  { ret+='7'; break; }
   case 8:  { ret+='8'; break; }
   case 9:  { ret+='9'; break; }
   case 10: { ret+='A'; break; }
   case 11: { ret+='B'; break; }
   case 12: { ret+='C'; break; }
   case 13: { ret+='D'; break; }
   case 14: { ret+='E'; break; }
   case 15: { ret+='F'; break; }
  }
 }
 char c;
 size_t n=ret.size();
 size_t l=n/2;
 --n;
 for(size_t i=0; i < l; i++) { c=ret[i]; ret[i]=ret[n-i]; ret[n-i]=c; }
 return ret;
};

char ZNSTR::get() { return ((char) getchar()); };

void ZNSTR::put(const std::string &v)
{
 for(size_t i=0; i < v.size(); i++)
 { putchar((int) v[i]); }
};

unsigned ZNSTR::CRC32(const std::string &q,unsigned ini)
{
 const char *cbuf = (const char *) q.c_str();
 size_t len=q.size();
 for(size_t i=0; i < len; i++)
 {
  unsigned char inx32 = (short) (cbuf[i] ^ ini);
  ini >>= 8;
  ini ^= crc32tab[inx32];
 }
 return (ini ^ 0xFFFFFFFF);
};

bool ZNSTR::checkCRC(const std::string &q,const unsigned &crc, unsigned ini) 
{ return (ZNSTR::CRC32(q, ini) == crc); };

ulonglong ZNSTR::CRC64(const std::string &q, ulonglong ini)
{
 const unsigned char* cbuf = (const unsigned char*) q.c_str();
 size_t len=q.size();
 for(size_t i=0; i < len; i++)
 {
  unsigned char inx32 = ((int) (ini >> 56) ^ cbuf[i]) & 0xFF; 
  ini = crc64tab[inx32] ^ (ini << 8); 
 }
 return (ini ^ __UINT64_C(0xFFFFFFFFFFFFFFFF));
};

bool ZNSTR::checkCRC64(const std::string &q, const ulonglong &crc, ulonglong ini)
{ return (ZNSTR::CRC64(q, ini) == crc); };

zRandomGenerator::zRandomGenerator():
 state(0xFFFF)
{
 value[0]=::time(NULL);
 for(unsigned short a=1;a<624;a++) { value[a]=(0x10DCD*value[a-1])&0xFFFFFFFF; }
};

zRandomGenerator::zRandomGenerator(unsigned seed):
 state(0xFFFF)
{
 value[0]=seed;
 for(unsigned short a=1;a<624;a++) { value[a]=(0x10DCD*value[a-1])&0xFFFFFFFF; }
};

void zRandomGenerator::gen()
{
 unsigned y=0;
 for(unsigned short a=0;a<=622;a++)
 {
  y=value[a]&0x7FFFFFFF;
  y+=unsigned(double(value[a+1]&0xFFFFFFFF)/0xFFFFFFFF);
  if(!(y%2)) value[a]=value[(a+367)%624]^(y>>1);
  else value[a]=value[(a+397)%624]^(y>>1)^0x9908B0DF;
 }
 y=value[623]&0x7FFFFFFF;
 y+=(unsigned)(double(value[0]&0xFFFFFFFF)/0xFFFFFFFF);
 if(!(y%2)) value[623]=value[396]^(y>>1);
 else value[623]=value[396]^(y>>1)^0x9908B0DF;
};

unsigned zRandomGenerator::rnd()
{
 unsigned y;
 if(state==0xFFFF)
 {
  state=1;
  gen();
  y=value[0];
 }
 else
 {
  y=value[state];
  state++;
  y=y^(y>>11);
  y=y^((y<<7)&0x9D2C5680);
  y=y^((y<<15)&0xEFC60000);
  y=y^(y>>18);
  if(state==623) { state=0; gen(); }
 }
 return (y-1);
};

ulonglong zRandomGenerator::rnd_64()
{
 ulonglong ret=0;
 unsigned n1=rnd();
 unsigned n2=rnd();
 unsigned char* r=(unsigned char*) &ret;
 unsigned char* c=(unsigned char*) &n1;
 r[0]=c[0]; r[1]=c[1]; r[2]=c[2]; r[3]=c[3];
 c=(unsigned char*) &n2;
 r[4]=c[0]; r[5]=c[1]; r[6]=c[2]; r[7]=c[3];
 return ret;
};

double zRandomGenerator::rnd2()
{
 unsigned y=rnd();
 return y==0xFFFFFFFF?double(y-1)/0xFFFFFFFF:double(y)/0xFFFFFFFF;
};

double zRandomGenerator::rnd2_64()
{
 ulonglong y=rnd_64();
 return y==__UINT64_C(0xFFFFFFFFFFFFFFFF)?double(y-1)/__UINT64_C(0xFFFFFFFFFFFFFFFF):double(y)/__UINT64_C(0xFFFFFFFFFFFFFFFF);
};















