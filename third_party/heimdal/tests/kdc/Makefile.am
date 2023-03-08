include $(top_srcdir)/Makefile.am.common

noinst_DATA = \
	an2ln-db.txt \
	kdc-tester4.json \
	krb5.conf \
	krb5-kcm.conf \
	krb5-cccol.conf \
	krb5-authz.conf \
	krb5-authz2.conf \
	krb5-canon.conf \
	krb5-canon2.conf \
	krb5-hdb-mitdb.conf \
	krb5-weak.conf \
	krb5-pkinit.conf \
	krb5-bx509.conf \
	krb5-httpkadmind.conf \
	krb5-pkinit-win.conf \
	krb5-master2.conf \
	krb5-slave2.conf \
	krb5-slave.conf

check_SCRIPTS = $(SCRIPT_TESTS) 

SCRIPT_TESTS = \
	check-authz \
	check-canon \
	check-cc \
	check-delegation \
	check-des \
	check-digest \
	check-fast \
	check-kadmin \
	check-hdb-mitdb \
	check-kdc \
	check-kdc-weak \
	check-keys \
	check-kpasswdd \
	check-pkinit \
	check-bx509 \
	check-httpkadmind \
	check-iprop \
	check-referral \
	check-tester \
	check-uu

TESTS = $(SCRIPT_TESTS)

port = 49188
admport = 49189
admport2 = 49190
pwport = 49191
restport = 49192
restport2 = 49193
ipropport = 49194
ipropport2 = 49195
pkinit_ticket_max_life_from_cert = 0

if HAVE_DLOPEN
do_dlopen = -e 's,[@]DLOPEN[@],true,g'
else
do_dlopen = -e 's,[@]DLOPEN[@],false,g'
endif

do_subst = $(heim_verbose)sed $(do_dlopen) \
	-e 's,[@]env_setup[@],$(top_builddir)/tests/bin/setup-env,g' \
	-e 's,[@]top_srcdir[@],$(top_srcdir),g' \
	-e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]admport[@],$(admport),g' \
	-e 's,[@]admport2[@],$(admport2),g' \
	-e 's,[@]bx509port[@],$(restport),g' \
	-e 's,[@]restport[@],$(restport),g' \
	-e 's,[@]restport2[@],$(restport2),g' \
	-e 's,[@]pwport[@],$(pwport),g' \
	-e 's,[@]ipropport[@],$(ipropport),g' \
	-e 's,[@]ipropport2[@],$(ipropport2),g' \
	-e 's,[@]objdir[@],$(top_builddir)/tests/kdc,g' \
	-e 's,[@]top_builddir[@],$(top_builddir),g' \
	-e 's,[@]db_type[@],$(db_type),g' \
	-e 's,[@]max_life_from_cert[@],$(pkinit_ticket_max_life_from_cert),g' \
        -e 's,[@]ENABLE_AFS_STRING_TO_KEY[@],$(ENABLE_AFS_STRING_TO_KEY),' \
        -e 's,[@]ENABLE_AFS_STRING_TO_KEY[@],$(ENABLE_AFS_STRING_TO_KEY),' \
	-e 's,[@]EGREP[@],$(EGREP),g' \
	-e 's,[@]MITKRB5[@],$(MITKRB5),g' 

chmod = chmod

LDADD = ../../lib/krb5/libkrb5.la $(LIB_roken)

check-authz: check-authz.in Makefile krb5-authz.conf krb5-authz2.conf
	$(do_subst) < $(srcdir)/check-authz.in > check-authz.tmp && \
	$(chmod) +x check-authz.tmp && \
	mv check-authz.tmp check-authz

check-canon: check-canon.in Makefile krb5-canon.conf krb5-canon2.conf
	$(do_subst) < $(srcdir)/check-canon.in > check-canon.tmp && \
	$(chmod) +x check-canon.tmp && \
	mv check-canon.tmp check-canon

check-cc: check-cc.in Makefile
	$(do_subst) < $(srcdir)/check-cc.in > check-cc.tmp && \
	$(chmod) +x check-cc.tmp && \
	mv check-cc.tmp check-cc

check-delegation: check-delegation.in Makefile
	$(do_subst) < $(srcdir)/check-delegation.in > check-delegation.tmp && \
	$(chmod) +x check-delegation.tmp && \
	mv check-delegation.tmp check-delegation

check-des: check-des.in Makefile krb5.conf
	$(do_subst) < $(srcdir)/check-des.in > check-des.tmp && \
	$(chmod) +x check-des.tmp && \
	mv check-des.tmp check-des

check-hdb-mitdb: check-hdb-mitdb.in Makefile krb5-hdb-mitdb.conf
	$(do_subst) < $(srcdir)/check-hdb-mitdb.in > check-hdb-mitdb.tmp && \
	$(chmod) +x check-hdb-mitdb.tmp && \
	mv check-hdb-mitdb.tmp check-hdb-mitdb

check-fast: check-fast.in Makefile
	$(do_subst) < $(srcdir)/check-fast.in > check-fast.tmp && \
	$(chmod) +x check-fast.tmp && \
	mv check-fast.tmp check-fast

check-kdc: check-kdc.in Makefile
	$(do_subst) < $(srcdir)/check-kdc.in > check-kdc.tmp && \
	$(chmod) +x check-kdc.tmp && \
	mv check-kdc.tmp check-kdc

check-kdc-weak: check-kdc-weak.in Makefile
	$(do_subst) < $(srcdir)/check-kdc-weak.in > check-kdc-weak.tmp && \
	$(chmod) +x check-kdc-weak.tmp && \
	mv check-kdc-weak.tmp check-kdc-weak

check-tester: check-tester.in kdc-tester4.json Makefile
	$(do_subst) < $(srcdir)/check-tester.in > check-tester.tmp && \
	$(chmod) +x check-tester.tmp && \
	mv check-tester.tmp check-tester

check-keys: check-keys.in Makefile
	$(do_subst) < $(srcdir)/check-keys.in > check-keys.tmp && \
	$(chmod) +x check-keys.tmp && \
	mv check-keys.tmp check-keys

check-kinit: check-kinit.in Makefile
	$(do_subst) < $(srcdir)/check-kinit.in > check-kinit.tmp && \
	$(chmod) +x check-kinit.tmp && \
	mv check-kinit.tmp check-kinit

check-kadmin: check-kadmin.in Makefile
	$(do_subst) < $(srcdir)/check-kadmin.in > check-kadmin.tmp && \
	$(chmod) +x check-kadmin.tmp && \
	mv check-kadmin.tmp check-kadmin

check-uu: check-uu.in Makefile
	$(do_subst) < $(srcdir)/check-uu.in > check-uu.tmp && \
	$(chmod) +x check-uu.tmp && \
	mv check-uu.tmp check-uu

check-pkinit: check-pkinit.in Makefile krb5-pkinit.conf krb5-pkinit2.conf
	$(do_subst) < $(srcdir)/check-pkinit.in > check-pkinit.tmp && \
	$(chmod) +x check-pkinit.tmp && \
	mv check-pkinit.tmp check-pkinit

check-bx509: check-bx509.in Makefile krb5-bx509.conf
	$(do_subst) < $(srcdir)/check-bx509.in > check-bx509.tmp && \
	$(chmod) +x check-bx509.tmp && \
	mv check-bx509.tmp check-bx509

check-httpkadmind: check-httpkadmind.in Makefile krb5-httpkadmind.conf
	$(do_subst) < $(srcdir)/check-httpkadmind.in > check-httpkadmind.tmp && \
	$(chmod) +x check-httpkadmind.tmp && \
	mv check-httpkadmind.tmp check-httpkadmind

check-iprop: check-iprop.in Makefile krb5.conf krb5-master2.conf krb5-slave.conf krb5-slave2.conf
	$(do_subst) < $(srcdir)/check-iprop.in > check-iprop.tmp && \
	$(chmod) +x check-iprop.tmp && \
	mv check-iprop.tmp check-iprop

check-digest: check-digest.in Makefile
	$(do_subst) < $(srcdir)/check-digest.in > check-digest.tmp && \
	$(chmod) +x check-digest.tmp && \
	mv check-digest.tmp check-digest

check-referral: check-referral.in Makefile
	$(do_subst) < $(srcdir)/check-referral.in > check-referral.tmp && \
	$(chmod) +x check-referral.tmp && \
	mv check-referral.tmp check-referral

check-kpasswdd: check-kpasswdd.in Makefile
	$(do_subst) < $(srcdir)/check-kpasswdd.in > check-kpasswdd.tmp && \
	$(chmod) +x check-kpasswdd.tmp && \
	mv check-kpasswdd.tmp check-kpasswdd

kdc-tester4.json: kdc-tester4.json.in Makefile
	$(do_subst) < $(srcdir)/kdc-tester4.json.in > kdc-tester4.json.tmp && \
	mv kdc-tester4.json.tmp kdc-tester4.json

krb5.conf: krb5.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]messages[@],messages,g' \
	   -e 's,[@]ipropstats[@],iprop-stats,g' \
	   -e 's,[@]signalsocket[@],signal,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5.conf.in > krb5.conf.tmp && \
	mv krb5.conf.tmp krb5.conf

krb5-kcm.conf: krb5-kcm.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5-kcm.conf.in > krb5-kcm.conf.tmp && \
	mv krb5-kcm.conf.tmp krb5-kcm.conf

krb5-cccol.conf: krb5-cccol.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5-cccol.conf.in > krb5-cccol.conf.tmp && \
	mv krb5-cccol.conf.tmp krb5-cccol.conf

krb5-authz.conf: krb5-authz.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5-authz.conf.in > krb5-authz.conf.tmp && \
	mv krb5-authz.conf.tmp krb5-authz.conf

krb5-authz2.conf: krb5-authz2.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5-authz2.conf.in > krb5-authz2.conf.tmp && \
	mv krb5-authz2.conf.tmp krb5-authz2.conf

krb5-canon.conf: krb5-canon.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5-canon.conf.in > krb5-canon.conf.tmp && \
	mv krb5-canon.conf.tmp krb5-canon.conf

krb5-canon2.conf: krb5-canon2.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5-canon2.conf.in > krb5-canon2.conf.tmp && \
	mv krb5-canon2.conf.tmp krb5-canon2.conf

krb5-hdb-mitdb.conf: krb5-hdb-mitdb.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],false,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5-hdb-mitdb.conf.in > krb5-hdb-mitdb.conf.tmp && \
	mv krb5-hdb-mitdb.conf.tmp krb5-hdb-mitdb.conf

krb5-weak.conf: krb5.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],true,g' \
	   -e 's,[@]dk[@],default_keys = aes256-cts-hmac-sha1-96:pw-salt arcfour-hmac-md5:pw-salt des3-cbc-sha1:pw-salt des:pw-salt,g' \
	   -e 's,[@]messages[@],messages,g' \
	   -e 's,[@]signalsocket[@],signal,g' \
	   -e 's,[@]ipropstats[@],iprop-stats,g' \
	   -e 's,[@]kdc[@],,g' < $(srcdir)/krb5.conf.in > krb5-weak.conf.tmp && \
	mv krb5-weak.conf.tmp krb5-weak.conf

krb5-slave.conf: krb5.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],true,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]messages[@],messages,g' \
	   -e 's,[@]signalsocket[@],signal2,g' \
	   -e 's,[@]ipropstats[@],iprop-stats,g' \
	   -e 's,[@]kdc[@],.slave,g' < $(srcdir)/krb5.conf.in > krb5-slave.conf.tmp && \
	mv krb5-slave.conf.tmp krb5-slave.conf

krb5-master2.conf: krb5.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],true,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]messages[@],messages2,g' \
	   -e 's,[@]signalsocket[@],signal2,g' \
	   -e 's,[@]ipropstats[@],iprop-stats2,g' \
	   -e 's,[@]kdc[@],.slave,g' < $(srcdir)/krb5.conf.in > krb5-master2.conf.tmp && \
	mv krb5-master2.conf.tmp krb5-master2.conf

krb5-slave2.conf: krb5.conf.in Makefile
	$(do_subst) \
	   -e 's,[@]WEAK[@],true,g' \
	   -e 's,[@]dk[@],,g' \
	   -e 's,[@]messages[@],messages2,g' \
	   -e 's,[@]signalsocket[@],signal3,g' \
	   -e 's,[@]ipropstats[@],iprop-stats2,g' \
	   -e 's,[@]kdc[@],.slave2,g' < $(srcdir)/krb5.conf.in > krb5-slave2.conf.tmp && \
	mv krb5-slave2.conf.tmp krb5-slave2.conf

krb5-pkinit.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],no,g' < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit.conf.tmp && \
	mv krb5-pkinit.conf.tmp krb5-pkinit.conf

krb5-pkinit2.conf : pkinit_ticket_max_life_from_cert = 30d

krb5-pkinit2.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],no,g' < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit2.conf.tmp && \
	mv krb5-pkinit2.conf.tmp krb5-pkinit2.conf

krb5-bx509.conf: krb5-bx509.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],no,g' < $(srcdir)/krb5-bx509.conf.in > krb5-bx509.conf.tmp && \
	mv krb5-bx509.conf.tmp krb5-bx509.conf

krb5-httpkadmind.conf: krb5-httpkadmind.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],no,g' < $(srcdir)/krb5-httpkadmind.conf.in > krb5-httpkadmind.conf.tmp && \
	mv krb5-httpkadmind.conf.tmp krb5-httpkadmind.conf

krb5-pkinit-win.conf: krb5-pkinit.conf.in Makefile
	$(do_subst) -e 's,[@]w2k[@],yes,g' < $(srcdir)/krb5-pkinit.conf.in > krb5-pkinit-win.conf.tmp && \
	mv krb5-pkinit-win.conf.tmp krb5-pkinit-win.conf

clean: clean-am
	rm -rf cc_dir authz_dir

CLEANFILES= \
	$(TESTS) \
	*.crt \
	*.der \
	*.log \
	*.pem \
	*.pid \
	*.tmp \
	acache.krb5 \
	barpassword \
	ca.crt \
	cache.krb5 \
	cache2.krb5 \
	cdigest-reply \
	client-cache \
	curlheaders \
	current-db* \
	current.log* \
	digest-reply \
	extracted_config \
	extracted_keytab* \
	foopassword \
	foopassword.rkpty \
	iprop-stats \
	iprop-stats2 \
	iprop.keytab \
	ipropd.dumpfile \
	kdc-tester4.json \
	krb5-authz.conf \
	krb5-authz2.conf \
	krb5-canon.conf \
	krb5-canon2.conf \
	krb5-cc.conf \
	krb5-cccol.conf \
	krb5-hdb-mitdb.conf \
	krb5-master2.conf \
	krb5-pkinit-win.conf \
	krb5-pkinit.conf \
	krb5-pkinit2.conf \
	krb5-bx509.conf \
	krb5-httpkadmind.conf \
	krb5-slave2.conf \
	krb5-slave.conf \
	krb5-weak.conf \
	krb5.conf \
	krb5.conf.keys \
	kt \
	leaks-log \
	localname \
	malloc-log \
	malloc-log-master \
	malloc-log-slave \
	messages.log2 \
	negotiate-token \
	notfoopassword \
	o2cache.krb5 \
	o2digest-reply \
	ocache.krb5 \
	out-log \
	req \
	response-headers \
	s2digest-reply \
	sdb \
	sdigest-init \
	sdigest-reply \
	server.keytab \
	signal \
	signal2 \
	signal3 \
	tempfile \
	test-rc-file.rc \
	ukt \
	uuserver.log

EXTRA_DIST = \
	NTMakefile \
	an2ln-db.txt \
	check-authz.in \
	check-bx509.in \
	check-canon.in \
	check-cc.in \
	check-delegation.in \
	check-des.in \
	check-digest.in \
	check-fast.in \
	check-hdb-mitdb.in \
	check-httpkadmind.in \
	check-iprop.in \
	check-kadmin.in \
	check-kdc-weak.in \
	check-kdc.in \
	check-keys.in \
	check-kinit.in \
	check-kpasswdd.in \
	check-pkinit.in \
	check-referral.in \
	check-tester.in \
	check-uu.in \
	donotexists.txt \
	hdb-mitdb \
	hdb-mitdb.kadm5 \
	hdb-mitdb.mkey \
	heimdal.acl \
	iprop-acl \
	k5login/foo \
	k5login/mapped_user1 \
	kdc-tester1.json \
	kdc-tester2.json \
	kdc-tester3.json \
	kdc-tester4.json.in \
	krb5-authz.conf.in \
	krb5-authz2.conf.in \
	krb5-bx509.conf.in \
	krb5-canon.conf.in \
	krb5-canon2.conf.in \
	krb5-cccol.conf.in \
	krb5-hdb-mitdb.conf.in \
	krb5-httpkadmind.conf.in \
	krb5-pkinit.conf.in \
	krb5.conf.in \
	krb5.conf.keys.in \
	leaks-kill.sh \
	ntlm-user-file.txt \
	pki-mapping \
	uuserver.txt \
	wait-kdc.sh
