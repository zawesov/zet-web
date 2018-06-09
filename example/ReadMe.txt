Use the Makefile to compile:
make -f Makefile
make -f Makefile.cygwin
mingw32-make -fMakefile.mgw

Add libraries libevent, openssl, libzetweb.

For visualStudio set "Character Set" to "Use Multi-Byte Character Set"

Test of the http and https can be reached at:
http://localhost:12358/your_path - shows all the input parameters of http.
https://localhost:12359/your_path - shows all the input parameters of https.

Test of the websocket(ws and wss) can be reached at:
http://localhost:12358/index.html - ws connection.
https://localhost:12359/indexes.html - wss connection.

Test of the http and websocket proxy (REST Api) can be reached at:
http://localhost:12358/proxy - http proxy.
https://localhost:12359/proxy - https proxy.
http://localhost:12358/proxy - ws proxy.
https://localhost:12359/proxy - wss proxy.

Note: For testing https and wss, add 'localhostCA.crt' certificate to the list of trusted certificates in your browser.



