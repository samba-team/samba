PACKAGE=smbldap-tools
RELEASE=0.8.2-1
DESTDIR = $(PACKAGE)-$(RELEASE)

dist:	distclean $(DESTDIR).tgz 

$(DESTDIR).tgz:	.diststamp
	rm -rf $(DESTDIR)
	mkdir $(DESTDIR)
	# copy files
	cp CONTRIBUTORS $(DESTDIR)
	cp COPYING $(DESTDIR)
	cp ChangeLog $(DESTDIR)
	cp FILES $(DESTDIR)
	cp INSTALL $(DESTDIR)
	cp README $(DESTDIR)
	cp TODO $(DESTDIR)
	cp INFRASTRUCTURE $(DESTDIR)
	tar cf mkntpwd.tar mkntpwd
	gzip mkntpwd.tar
	cp mkntpwd.tar.gz $(DESTDIR)
	cp smbldap-*.pl $(DESTDIR)
	cp smbldap_*.pm $(DESTDIR)
	# copy directories
	tar cvzf $(DESTDIR).tgz $(DESTDIR)
	rm -rf $(DESTDIR)
	touch .diststamp

.diststamp:

distclean:
	rm -f *~
	rm -f $(DESTDIR).tgz
	rm -f mkntpwd.tar.gz

