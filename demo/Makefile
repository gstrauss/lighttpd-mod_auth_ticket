CC ?= gcc
CXX ?= g++
STRIP ?= strip

all:
	$(CC) login_cgi.c -o web_root/login.cgi -lfcgi -lcrypto
.PHONY: clean

clean:
	-rm web_root/login.cgi
