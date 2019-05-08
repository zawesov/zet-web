cmake_minimum_required(VERSION 2.8)

project(zetweb)


set(SOURCE_LIB		src/zString.cpp
			src/zMutex.cpp
			src/zFile.cpp
			src/zThread.cpp
			src/zSocket.cpp
			src/zLog.cpp
			src/zDNS.cpp
			src/zPacket.cpp)


include_directories("src/")
#target_include_directories(src/)
#add_subdirectory(src/)


add_library(libzetweb_3.4 STATIC ${SOURCE_LIB})


