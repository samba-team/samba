# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

foodir = $(includedir)/kadm5
foo_DATA = admin.h

CLEANFILES = $(foo_DATA)

admin.h:
	$(LN_S) $(top_srcdir)/lib/kadm5/admin.h .
