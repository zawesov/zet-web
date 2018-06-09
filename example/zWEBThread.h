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

#ifndef __zWEBThread_h
#define __zWEBThread_h 1

#include "zPacket.h"
#include "zFile.h"

class zWEBThread: public zPacketThread
{
 public:

static SSL_CTX* client_ctx;

 zWEBThread(int servsock, const zPacketThread::zPTParam& proto=zPacketThread::zPTParam()):
  zPacketThread(servsock, proto),
  head("<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML//EN'>\n<HTML>\n<HEAD>\n<TITLE>ZWEB</TITLE>\n<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>\n</HEAD>\n<BODY  bgcolor='#FFFFFF'>\n"),
  form(""),
  bottom("</BODY>\n</HTML>")
 {
  form+="<CENTER>\n<TABLE border=1 cellPadding=3 cellSpacing=0 width='100%'>\n";
  form+="<TR bgColor=#ccccff><TD><FONT size=3><B>Param name</B></FONT></TD><TD><center><FONT size=3><B>Value</B></FONT></center></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'>login </FONT></TD><TD><INPUT TYPE='TEXT' NAME='login' VALUE='login' SIZE='25'></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'> text </FONT></TD><TD><TEXTAREA NAME='TEXT' ROWS='4' COLS='55'>This is the text for value</TEXTAREA></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'> file </FONT></TD><TD><INPUT TYPE='FILE' NAME='file' VALUE='' SIZE='25'></TD></TR>\n";
// form+="<TR><TD><FONT color='purple'> path </FONT></TD><TD><INPUT TYPE='TEXT' NAME='path' VALUE='' SIZE='25'></TD></TR>\n";
  form+="</TABLE><BR>\n<INPUT TYPE='SUBMIT' NAME='SEND' VALUE='SEND'>\n</CENTER>\n</FORM>\n";
 };

 zWEBThread(const std::map<int, zPacketThread::zPTParam>& s):
  zPacketThread(s),
  head("<!DOCTYPE HTML PUBLIC '-//IETF//DTD HTML//EN'>\n<HTML>\n<HEAD>\n<TITLE>ZWEB</TITLE>\n<meta http-equiv='Content-Type' content='text/html; charset=windows-1251'>\n</HEAD>\n<BODY  bgcolor='#FFFFFF'>\n"),
  form(""),
  bottom("</BODY>\n</HTML>")
 {
  form+="<CENTER>\n<TABLE border=1 cellPadding=3 cellSpacing=0 width='100%'>\n";
  form+="<TR bgColor=#ccccff><TD><FONT size=3><B>Param name</B></FONT></TD><TD><center><FONT size=3><B>Value</B></FONT></center></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'>login </FONT></TD><TD><INPUT TYPE='TEXT' NAME='login' VALUE='login' SIZE='25'></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'> text </FONT></TD><TD><TEXTAREA NAME='TEXT' ROWS='4' COLS='55'>This is the text for value</TEXTAREA></TD></TR>\n";
  form+="<TR><TD><FONT color='purple'> file </FONT></TD><TD><INPUT TYPE='FILE' NAME='file' VALUE='' SIZE='25'></TD></TR>\n";
// form+="<TR><TD><FONT color='purple'> path </FONT></TD><TD><INPUT TYPE='TEXT' NAME='path' VALUE='' SIZE='25'></TD></TR>\n";
  form+="</TABLE><BR>\n<INPUT TYPE='SUBMIT' NAME='SEND' VALUE='SEND'>\n</CENTER>\n</FORM>\n";
 };

 virtual ~zWEBThread() { return; };

// virtual void execute_packet(zPacket* p) const;
 virtual void onMessage(zPacketHTTP* p);

 virtual void idle() { return; };
 virtual void onAccept(zPacketHTTP* p);
 virtual void onHeader(zPacketHTTP* p);
 virtual void onRead(zPacketHTTP* p);
 virtual void onWrite(zPacketHTTP* p);
 virtual bool onTimeout(zPacketHTTP* p);
 virtual void onClose(zPacketHTTP* p);

virtual void onAccept(zPacketWS* p);
virtual void onOpen(zPacketWS* p);
virtual void onRead(zPacketWS* p);
virtual void onMessage(zPacketWS* p);
virtual void onWrite(zPacketWS* p);
virtual void onTimeout(zPacketWS* p);
virtual void onClose(zPacketWS* p);

virtual void onHeader(zClientHTTP* p);
virtual void onOpen(zClientHTTP* p);
virtual void onMessage(zClientHTTP* p);
virtual void onRead(zClientHTTP* p);
virtual void onWrite(zClientHTTP* p);
virtual bool onTimeout(zClientHTTP* p);
virtual void onClose(zClientHTTP* p);

virtual void onOpen(zClientWS* p);
virtual void onRead(zClientWS* p);
virtual void onWrite(zClientWS* p);
virtual void onMessage(zClientWS* p);
virtual void onTimeout(zClientWS* p);
virtual void onClose(zClientWS* p);


 protected:


 std::string head;
 std::string form;
 std::string bottom;

};

#endif // __zWEBThread_h


