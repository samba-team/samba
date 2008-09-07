
noinst_PROGRAMS = gen-po.sh

gen-po.sh: gen-po.in
	sed \
	  -e 's,[@]top_srcdir[@],$(top_srcdir),' \
	  -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),' \
	  < $(srcdir)/gen-po.in > gen-po.tmp
	chmod +x gen-po.tmp
	mv gen-po.tmp gen-po.sh

po: gen-po.sh
	./gen-po.sh heimdal_krb5 $(top_srcdir)/lib/krb5/*.[chly]
	find $(top_srcdir) -name *.et | while read x; do \
		y=$$(basename $$x); \
		echo $$y ; \
		z=$$(echo $$y | sed 's/\.et$$//') ; \
		t=$$(find $(top_builddir) -name $$z.c) ; \
		t=$$(echo $$t | sed 's/\.c$$//') ; \
		base=$$(grep 'ERROR_TABLE_BASE_' $${t}.h | cut -f3 -d' ') ; \
		./gen-po.sh com_err$$base $${t}.c ; \
		test -f com_err$$base.pot || { echo "$$t missing" ; exit 1; } \
	done
	cp *.pot $(top_srcdir)/po

EXTRA_DIST = \
	gen-po.in \
	heimdal_krb5.pot \
	com_err-1750206208.pot \
	com_err-1765328384.pot \
	com_err-1980176640.pot \
	com_err-969269760.pot \
	com_err1859794432.pot \
	com_err35224064.pot \
	com_err36150272.pot \
	com_err39525376.pot \
	com_err43787520.pot \
	com_err569856.pot

CLEANFILES = gen-po.tmp


