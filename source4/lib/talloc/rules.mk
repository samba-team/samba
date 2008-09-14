.SUFFIXES: .c .o .3 .3.xml .xml .html

showflags::
	@echo 'talloc will be compiled with flags:'
	@echo '  CFLAGS = $(CFLAGS)'
	@echo '  LIBS = $(LIBS)'

.c.o:
	$(CC) $(PICFLAG) -o $@ -c $< $(CFLAGS)

.3.xml.3:
	-test -z "$(XSLTPROC)" || $(XSLTPROC) --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

.xml.html:
	-test -z "$(XSLTPROC)" || $(XSLTPROC) --nonet -o $@ http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $<

distclean::
	rm -f *~ */*~
