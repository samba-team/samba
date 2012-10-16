DOCS = ctdb.1 ctdb.1.html \
	ctdbd.1 ctdbd.1.html \
	onnode.1 onnode.1.html \
	ltdbtool.1 ltdbtool.1.html \
	ping_pong.1 ping_pong.1.html

all: $(DOCS)

%.1: %.1.xml
	xsltproc -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

%.1.html: %.1.xml
	xsltproc -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

distclean:
	rm -f $(DOCS)
