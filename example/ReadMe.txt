Linux:
Use the Makefile to compile, install, clean:
make -f Makefile, make -f Makefile clean
Add libraries libevent, openssl, libzetweb.

Windows:
For visualStudio set "Character Set" to "Use Multi-Byte Character Set"
Add include directories for libevent, openssl, zetweb headers.
Add libraries: event.lib, event_core.lib, event_extra.lib, event_openssl.lib, libcrypto.lib, libssl.lib, ws2_32.lib, zetweblib.lib
*.cpp and *h files are defined in ./example/.

How to use the library see Documentation_ver.html, HowTo_ver.html in ./doc/ and ./example/.

Test:

localhost - ipv4, [::1] - ipv6.

Test of the http and https can be reached at:
http://localhost:12358/your_path - ipv4, shows all the input parameters of http.
https://localhost:12359/your_path - ipv4, shows all the input parameters of https.
http://[::1]:12358/your_path - ipv6, shows all the input parameters of http.
https://[::1]:12359/your_path - ipv6, shows all the input parameters of https.

Test of the websocket(ws and wss) and proxy can be reached at:
http://localhost:12358/index.html - ipv4 ws connection.
https://localhost:12359/indexes.html - ipv4 wss connection.
http://[::1]:12358/index6.html - ipv6 ws connection.
https://[::1]:12359/indexes6.html - ipv6 wss connection.

Test of the http and websocket proxy (REST Api) can be reached at:
http://localhost:12358/proxy - ipv4 http proxy.
https://localhost:12359/proxy - ipv4 https proxy.
http://[::1]:12358/proxy - ipv6 http proxy.
https://[::1]:12359/proxy - ipv6 https proxy.

Note: For testing https and wss, add 'localhostCA.crt' certificate to the list of trusted certificates in your browser.



