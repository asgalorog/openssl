SHELL:=/bin/bash -O extglob
ver = "1.0.2h"
cost= ${PWD}
all: openssl-$(ver) config compile

openssl-$(ver).tar.gz:
	 wget -N "www.openssl.org/source/openssl-$(ver).tar.gz"

openssl-$(ver): openssl-$(ver).tar.gz
	tar xzf openssl-$(ver).tar.gz
	cp patchfile.patch openssl-$(ver)/crypto/objects/patchfile.patch
	cd openssl-$(ver)/crypto/objects/ && patch -p1 <patchfile.patch && rm patchfile.patch
	chmod +x ./openssl-$(ver)/Configure
	cd openssl-$(ver) && ./Configure --prefix=/ linux-x86_64 shared zlib -g -DPURIFY
	make -C openssl-$(ver) depend
	make -C openssl-$(ver)
	if [ ! -d openssl]; then mkdir openssl; fi
	make -C openssl-$(ver) INSTALL_PREFIX=`pwd`/openssl install

config:	
	cd openssl/ssl && mv openssl.cnf openssl.cnf.orig && printf "openssl_conf = openssl_def" > openssl.cnf && cat openssl.cnf.orig>>openssl.cnf && printf "[openssl_def]\nengines = engine_section\n[engine_section]\ngost = gost_section\n[gost_section]\nengine_id = gost\ndynamic_path=$(cost)/openssl/lib64/engines/libgost.so\ndefault_algorithms = ALL\nCRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet">>openssl.cnf
compile:
	gcc -c -O3 -Iopenssl/include cms_mess.c my_asn1_module.c  psec.c rw_cert_and_key.c gencert.c tcppsec.c -g 
	gcc -Wl,--no-as-needed -Lopenssl/lib64  psec.o rw_cert_and_key.o gencert.o my_asn1_module.o cms_mess.o tcppsec.o -lcrypto  -o psec
clean-all:
	rm -rf !(README.txt|my_asn1_module.c|patchfile.patch|Makefile|psec.c|rw_cert_and_key.h|rw_cert_and_key.c|keyparams.h|gencert.c|gencert.h|cms_mess.c|cms_mess.h|tcppsec.c|tcppsec.h|psec.sh|myproject|FULL.txt)
clean:
	rm -fr .o
	rm psec
