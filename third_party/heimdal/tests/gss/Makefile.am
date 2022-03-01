# $Id$

include $(top_srcdir)/Makefile.am.common

noinst_DATA = krb5.conf new_clients_k5.conf mech

SCRIPT_TESTS = check-basic check-gss check-gssmask check-context check-spnego check-ntlm check-negoex

TESTS = $(SCRIPT_TESTS)

check_SCRIPTS = $(SCRIPT_TESTS)

port = 49188

do_subst = srcdirabs=`cd "$(srcdir)"; pwd`; objdirabs=`pwd`; sed \
	-e 's,[@]srcdir[@],$(srcdir),g' \
	-e "s,[@]srcdirabs[@],$${srcdirabs},g" \
	-e 's,[@]env_setup[@],$(top_builddir)/tests/bin/setup-env,g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/gss,g' \
	-e "s,[@]objdirabs[@],$${objdirabs},g"

check-gss: check-gss.in Makefile
	$(do_subst) < $(srcdir)/check-gss.in > check-gss.tmp && \
	chmod +x check-gss.tmp && \
	mv check-gss.tmp check-gss

check-gssmask: check-gssmask.in Makefile
	$(do_subst) < $(srcdir)/check-gssmask.in > check-gssmask.tmp && \
	chmod +x check-gssmask.tmp && \
	mv check-gssmask.tmp check-gssmask

check-context: check-context.in Makefile
	$(do_subst) < $(srcdir)/check-context.in > check-context.tmp && \
	chmod +x check-context.tmp && \
	mv check-context.tmp check-context

check-spnego: check-spnego.in Makefile
	$(do_subst) < $(srcdir)/check-spnego.in > check-spnego.tmp && \
	chmod +x check-spnego.tmp && \
	mv check-spnego.tmp check-spnego

check-basic: check-basic.in Makefile
	$(do_subst) < $(srcdir)/check-basic.in > check-basic.tmp && \
	chmod +x check-basic.tmp && \
	mv check-basic.tmp check-basic

check-ntlm: check-ntlm.in Makefile
	$(do_subst) < $(srcdir)/check-ntlm.in > check-ntlm.tmp && \
	chmod +x check-ntlm.tmp && \
	mv check-ntlm.tmp check-ntlm

check-negoex: check-negoex.in Makefile
	$(do_subst) < $(srcdir)/check-negoex.in > check-negoex.tmp && \
	chmod +x check-negoex.tmp && \
	mv check-negoex.tmp check-negoex

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp && \
	mv krb5.conf.tmp krb5.conf

new_clients_k5.conf: new_clients_k5.conf.in Makefile
	$(do_subst) < $(srcdir)/new_clients_k5.conf.in > new_clients_k5.conf.tmp && \
	mv new_clients_k5.conf.tmp new_clients_k5.conf

mech: mech.in Makefile
	$(do_subst) < $(srcdir)/mech.in > mech.tmp && \
	mv mech.tmp mech

CLEANFILES= \
	$(TESTS) \
	foopassword \
	barpassword \
	krb5ccfile \
	krb5ccfile-ds \
	server.keytab \
	krb5.conf \
	new_clients_k5.conf \
	mech \
	current-db* \
	*.log \
	tempfile \
	check-basic.tmp \
	check-gss.tmp \
	check-gssmask.tmp \
	check-spnego.tmp \
	check-ntlm.tmp \
	check-context.tmp

EXTRA_DIST = \
	NTMakefile \
	check-basic.in \
	check-gss.in \
	check-gssmask.in \
	check-spnego.in \
	check-ntlm.in \
	check-context.in \
	check-negoex.in \
	ntlm-user-file.txt \
	krb5.conf.in \
	include-krb5.conf \
	new_clients_k5.conf.in \
	mech.in
