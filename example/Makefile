PREFIX ?= /usr/local

CC=g++

INC = zetweb_3.4

CFLAGS= -g -static -Werror -Wno-reorder -I $(PREFIX)/include/$(INC)
LDPATH= 
LIBPATH = -L /usr/local/lib
LIBS= -lzetweb_3.4 -lcrypto -lssl -levent -ldl -lpthread
LIBNAME=
#TLOPT=/C /P64

OBJS=\
	zWEBThread.o	\
	zWEBServer.o

all: zWEBServer.exe $(OBJS)

clean:
	rm -rf $(OBJS) zWEBServer.exe



zWEBServer.exe : $(OBJS)
	@rm -f zWEBServer.exe
	$(CC) $(OBJS) $(LDPATH) $(LIBPATH) $(LIBS) -o zWEBServer.exe

zWEBThread.o: zWEBThread.h zWEBThread.cpp
	$(CC) $(CFLAGS) -c zWEBThread.cpp

zWEBServer.o: zWEBServer.cpp zWEBThread.h zWEBThread.cpp
	$(CC) $(CFLAGS) -c zWEBServer.cpp





