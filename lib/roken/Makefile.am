# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CFLAGS += $(WFLAGS)

ACLOCAL = @ACLOCAL@ -I cf

CLEANFILES = roken.h make-roken.c

lib_LTLIBRARIES = libroken.la
libroken_la_LDFLAGS = -version-info @VERSION@:0:0

noinst_PROGRAMS = make-roken

check_PROGRAMS = parse_bytes-test \
		strpftime-test \
		getaddrinfo-test \
		snprintf-test

TESTS = $(check_PROGRAMS)

LIB_crypt = @LIB_crypt@

common_LDADD = libroken.la $(LIB_crypt)

strpftime_test_SOURCES = strpftime-test.c strftime.c strptime.c snprintf.c
snprintf_test_SOURCES  = snprintf-test.c snprintf.c
snprintf_test_LDADD    = $(common_LDADD) -lm
getaddrinfo_test_LDADD = $(common_LDADD)
parse_bytes_test_LDADD = $(common_LDADD)

libroken_la_SOURCES =		\
	base64.c		\
	concat.c		\
	emalloc.c		\
	environment.c		\
	eread.c			\
	erealloc.c		\
	estrdup.c		\
	ewrite.c		\
	getaddrinfo_hostspec.c	\
	get_default_username.c	\
	get_window_size.c	\
	getarg.c		\
	getnameinfo_verified.c	\
	issuid.c		\
	k_getpwnam.c		\
	k_getpwuid.c		\
	mini_inetd.c		\
	net_read.c		\
	net_write.c		\
	parse_bytes.c		\
	parse_time.c		\
	parse_units.c		\
	resolve.c		\
	roken_gethostby.c	\
	signal.c		\
	simple_exec.c		\
	snprintf.c		\
	socket.c		\
	strcollect.c		\
	timeval.c		\
	tm2time.c		\
	verify.c		\
	warnerr.c		\
	write_pid.c		\
	xdbm.h

EXTRA_libroken_la_SOURCES =	\
	chown.c			\
	copyhostent.c		\
	daemon.c		\
	err.c			\
	err.h			\
	errx.c			\
	fchown.c		\
	flock.c			\
	fnmatch.c		\
	fnmatch.h		\
	freeaddrinfo.c		\
	freehostent.c		\
	gai_strerror.c		\
	getaddrinfo.c		\
	getdtablesize.c		\
	getegid.c		\
	geteuid.c		\
	getgid.c		\
	gethostname.c		\
	getipnodebyaddr.c	\
	getipnodebyname.c	\
	getnameinfo.c		\
	getopt.c		\
	gettimeofday.c		\
	getuid.c		\
	getusershell.c		\
	glob.h			\
	hstrerror.c		\
	inet_aton.c		\
	inet_ntop.c		\
	inet_pton.c		\
	initgroups.c		\
	innetgr.c		\
	iruserok.c		\
	lstat.c			\
	memmove.c		\
	mkstemp.c		\
	putenv.c		\
	rcmd.c			\
	readv.c			\
	recvmsg.c		\
	rtbl.c			\
	rtbl.h			\
	sendmsg.c		\
	setegid.c		\
	setenv.c		\
	seteuid.c		\
	strcasecmp.c		\
	strdup.c		\
	strerror.c		\
	strftime.c		\
	strlcat.c		\
	strlcpy.c		\
	strlwr.c		\
	strncasecmp.c		\
	strndup.c		\
	strnlen.c		\
	strptime.c		\
	strsep.c		\
	strsep_copy.c		\
	strtok_r.c		\
	strupr.c		\
	swab.c			\
	unsetenv.c		\
	verr.c			\
	verrx.c			\
	vsyslog.c		\
	vwarn.c			\
	vwarnx.c		\
	warn.c			\
	warnx.c			\
	writev.c

EXTRA_DIST = roken.awk roken.h.in

libroken_la_LIBADD = @LTLIBOBJS@

$(LTLIBOBJS) $(libroken_la_OBJECTS): roken.h

include_HEADERS = $(err_h) base64.h getarg.h		\
	parse_bytes.h parse_time.h parse_units.h	\
	resolve.h roken.h roken-common.h		\
	$(err_h) $(fnmatch_h) $(glob_h) rtbl.h xdbm.h

if have_err_h
err_h =
else
err_h = err.h
endif

if have_fnmatch_h
fnmatch_h =
else
fnmatch_h = fnmatch.h
endif

if have_glob_h
glob_h =
else
glob_h = glob.h
endif

roken.h: make-roken$(EXEEXT)
	@./make-roken$(EXEEXT) > tmp.h ;\
	if [ -f roken.h ] && cmp -s tmp.h roken.h ; then rm -f tmp.h ; \
	else rm -f roken.h; mv tmp.h roken.h; fi

make-roken.c: roken.h.in roken.awk
	$(AWK) -f $(srcdir)/roken.awk $(srcdir)/roken.h.in > make-roken.c
