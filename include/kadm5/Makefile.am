# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

foodir = $(includedir)/kadm5
foo_DATA = admin.h private.h

CLEANFILES = $(foo_DATA) kadm5_err.h

admin.h:
	$(LN_S) $(top_srcdir)/lib/kadm5/admin.h .
private.h:
	$(LN_S) $(top_srcdir)/lib/kadm5/private.h .
