
Linux:
Use the Makefile to compile, install, clean:
make -f Makefile, sudo make -f Makefile install, make -f Makefile clean
Add libraries libevent, openssl.
By default, header files and lib file will be installed in
/usr/local/include/zetweb_ver/ and /usr/local/lib/libzetweb_ver.a

Windows:
For visualStudio set "Character Set" to "Use Multi-Byte Character Set"
Add include directories for libevent, openssl headers.
Add libraries: libevent, openssl.
*.cpp and *h files are defined in ./src/.

How to use the library see Documentation_ver.html, HowTo_ver.html in ./doc/ and ./example.



