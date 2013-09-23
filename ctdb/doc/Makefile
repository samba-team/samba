DOCS = ctdb.1 ctdb.1.html \
	ctdbd.1 ctdbd.1.html \
	ctdbd_wrapper.1 ctdbd_wrapper.1.html \
	onnode.1 onnode.1.html \
	ltdbtool.1 ltdbtool.1.html \
	ping_pong.1 ping_pong.1.html \
	ctdbd.conf.5 ctdbd.conf.5.html \
	ctdb.7 ctdb.7.html \
	ctdb-tunables.7 ctdb-tunables.7.html

all: $(DOCS)

%: %.xml
	xsltproc -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.html: %.xml
	xsltproc -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

distclean:
	rm -f $(DOCS)
