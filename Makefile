PREFIX ?= /usr/local

CC=g++

BUILD = ./build
SRC = ./src
EXAMPLE= ./example
RES_LIB=libzetweb_3.6.a
RES_INC=zetweb_3.6

CFLAGS= -g -static -Wno-reorder -I $(SRC)
LDPATH= 
LIBPATH = -L /usr/local/lib
LIBS= -lpthread -ldl -levent -lssl -lcrypto
LIBNAME=
#TLOPT=/C /P64

OBJS=\
        $(BUILD)/zString.o		\
	$(BUILD)/zMutex.o		\
	$(BUILD)/zFile.o		\
	$(BUILD)/zThread.o		\
	$(BUILD)/zSocket.o		\
	$(BUILD)/zLog.o                 \
	$(BUILD)/zDNS.o			\
	$(BUILD)/zPacket.o


all: prebuild $(BUILD)/$(RES_LIB) $(OBJS)

prebuild:
	mkdir -p $(BUILD)

clean:
	rm -rf $(OBJS) $(BUILD)/$(RES_LIB)

install: $(BUILD)/$(RES_LIB)
	mkdir -p $(PREFIX)/include/$(RES_INC)
	cp -v $(SRC)/*.h $(PREFIX)/include/$(RES_INC)/
	cp -v $(BUILD)/$(RES_LIB) $(PREFIX)/lib/



$(BUILD)/$(RES_LIB) : $(BUILD)/zString.o $(BUILD)/zMutex.o $(BUILD)/zFile.o $(BUILD)/zThread.o $(BUILD)/zSocket.o $(BUILD)/zLog.o $(BUILD)/zDNS.o $(BUILD)/zPacket.o
	@rm -f $(BUILD)/$(RES_LIB)
	ar rcs $(BUILD)/$(RES_LIB) $(BUILD)/zString.o $(BUILD)/zMutex.o $(BUILD)/zFile.o $(BUILD)/zThread.o $(BUILD)/zSocket.o $(BUILD)/zLog.o $(BUILD)/zDNS.o $(BUILD)/zPacket.o

$(BUILD)/zString.o: $(SRC)/zString.cpp $(SRC)/zString.h
	$(CC) $(CFLAGS) -c $(SRC)/zString.cpp -o $@

$(BUILD)/zMutex.o: $(SRC)/zMutex.cpp $(SRC)/zMutex.h $(SRC)/zString.h $(SRC)/zThread.h 
	$(CC) $(CFLAGS) -c $(SRC)/zMutex.cpp -o $@

$(BUILD)/zFile.o: $(SRC)/zFile.cpp $(SRC)/zFile.h $(SRC)/zMutex.h
	$(CC) $(CFLAGS) -c $(SRC)/zFile.cpp -o $@

$(BUILD)/zThread.o: $(SRC)/zThread.cpp $(SRC)/zThread.h $(SRC)/zMutex.h
	$(CC) $(CFLAGS) -c $(SRC)/zThread.cpp -o $@

$(BUILD)/zSocket.o: $(SRC)/zSocket.cpp $(SRC)/zSocket.h $(SRC)/zThread.h 
	$(CC) $(CFLAGS) -c $(SRC)/zSocket.cpp -o $@

$(BUILD)/zLog.o: $(SRC)/zLog.cpp $(SRC)/zLog.h $(SRC)/zPaths.h $(SRC)/zFile.cpp $(SRC)/zFile.h $(SRC)/zMutex.cpp $(SRC)/zMutex.h
	$(CC) $(CFLAGS) -c $(SRC)/zLog.cpp -o $@

$(BUILD)/zDNS.o: $(SRC)/zDNS.cpp $(SRC)/zDNS.h $(SRC)/zMutex.cpp $(SRC)/zMutex.h
	$(CC) $(CFLAGS) -c $(SRC)/zDNS.cpp -o $@

$(BUILD)/zPacket.o: $(SRC)/zPacket.cpp $(SRC)/zPacket.h $(SRC)/zPool.h $(SRC)/zThread.cpp $(SRC)/zThread.h $(SRC)/zSocket.cpp $(SRC)/zSocket.h $(SRC)/zLog.cpp $(SRC)/zLog.h  $(SRC)/zDNS.cpp $(SRC)/zDNS.h
	$(CC) $(CFLAGS) -c $(SRC)/zPacket.cpp -o $@

