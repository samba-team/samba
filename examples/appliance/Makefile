# Samba appliance Makefile
# use at your own risk!

PREFIX=/usr/local/samba
CONFIGOPTS=--with-pam --prefix=$(PREFIX)


all: headb tngb

config:
	(cd head/source; CFLAGS="-Wall -g" ./configure $(CONFIGOPTS))
	(cd tng;  CFLAGS="-Wall -g" ./configure $(CONFIGOPTS) --enable-shared=no)

headb:
	(cd head/source; make)	

tngb:
	(cd tng; make bin/samedit bin/winbindd nsswitch)

clean:
	(cd head/source; make clean)
	(cd tng; make clean)

distclean:
	(cd head/source; make clean; rm -f config.cache; rm -f Makefile)
	(cd tng; make clean; rm -f config.cache; rm -f Makefile)

install: installhead installtng

installbin: installheadbin installtng

installhead:
	(cd head/source; make install)

installheadbin:
	(cd head/source; make installbin)

installtng: tngb
	(cd tng; \
	rm -f $(PREFIX)/bin/samedit $(PREFIX)/bin/winbindd; \
	cp bin/samedit bin/winbindd $(PREFIX)/bin; \
	rm -f /lib/libnss_ntdom.so.2 /lib/security/pam_winbind.so; \
	cp nsswitch/libnss_ntdom.so /lib/libnss_ntdom.so.2; \
	cp nsswitch/pam_winbind.so /lib/security/)

stop:
	-killall winbindd smbd nmbd

start:
	$(PREFIX)/bin/smbd
	$(PREFIX)/bin/nmbd
	$(PREFIX)/bin/winbindd

restart: stop start
