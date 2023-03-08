
include $(top_srcdir)/Makefile.am.common

if do_roken_rename
ES = base64.c
endif

IMPLEMENT_TLS=
if MAINTAINER_MODE
IMPLEMENT_TLS += dll.c
AM_CPPFLAGS += -DHEIM_BASE_MAINTAINER
endif

AM_CPPFLAGS += $(ROKEN_RENAME) -I../com_err -I$(srcdir)/../com_err

lib_LTLIBRARIES = libheimbase.la
check_PROGRAMS = test_base

test_base_CFLAGS = -Wno-string-concatenation

libheimbase_la_LDFLAGS = -version-info 1:0:0

if FRAMEWORK_COREFOUNDATION
libheimbase_la_LDFLAGS += -framework CoreFoundation
endif

TESTS = test_base

if versionscript
libheimbase_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

libheimbase_la_LIBADD = $(PTHREAD_LIBADD) $(LIB_dlopen) $(LIB_com_err)

include_HEADERS	= heimbase.h common_plugin.h heimbase-atomics.h heimbase-svc.h

ERR_FILES = heim_err.c

dist_libheimbase_la_SOURCES =	\
	array.c			\
	baselocl.h		\
	bsearch.c		\
	bool.c			\
	common_plugin.h		\
	config_file.c		\
	context.c		\
	data.c			\
	db.c			\
	dict.c			\
	$(IMPLEMENT_TLS)	\
	error.c			\
	error_string.c		\
	expand_path.c		\
	heimbase.c		\
	heimbasepriv.h		\
	json.c			\
	log.c			\
	null.c			\
	number.c		\
	plugin.c		\
	roken_rename.h		\
	string.c		\
	warn.c

nodist_libheimbase_la_SOURCES = $(ES) $(ERR_FILES)

$(libheimbase_la_OBJECTS): $(srcdir)/heimbase-protos.h heim_err.h

$(srcdir)/heimbase-protos.h: $(dist_libheimbase_la_SOURCES)
	cd $(srcdir) && \
	    perl ../../cf/make-proto.pl -q -P comment -o heimbase-protos.h $(dist_libheimbase_la_SOURCES) || \
	    rm -f heimbase-protos.h

$(srcdir)/heimbase-private.h: $(dist_libheimbase_la_SOURCES)
	cd $(srcdir) && \
	    perl ../../cf/make-proto.pl -q -P comment -p heimbase-private.h $(dist_libheimbase_la_SOURCES) || \
	    rm -f heimbase-private.h

# install these?

libheimbase_la_DEPENDENCIES = version-script.map

test_base_LDADD = libheimbase.la $(LIB_roken)

CLEANFILES = base64.c test_db.json heim_err.c heim_err.h

EXTRA_DIST = NTMakefile version-script.map config_reg.c heim_err.et

dist_include_HEADERS = heimbase-protos.h

nodist_include_HEADERS = heim_err.h

heim_err.h: heim_err.et

base64.c:
	rm -f base64.c
	$(LN_S) $(srcdir)/../roken/base64.c .
