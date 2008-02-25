TEST_FORMAT = plain

SELFTEST = $(LD_LIBPATH_OVERRIDE) $(PERL) $(srcdir)/selftest/selftest.pl --prefix=${selftest_prefix} \
    --builddir=$(builddir) --srcdir=$(srcdir) \
    --expected-failures=$(srcdir)/samba4-knownfail \
	--format=$(TEST_FORMAT) \
    --exclude=$(srcdir)/samba4-skip --testlist="./selftest/samba4_tests.sh|" \
    $(TEST_OPTIONS) 

test:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --immediate $(TESTS)

kvmtest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --immediate --target=kvm --image=$(KVM_IMAGE)

kvmquicktest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --immediate --quick --target=kvm --image=$(KVM_IMAGE)

testone:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --one $(TESTS)

test-swrap:: everything
	$(SELFTEST) --socket-wrapper --immediate $(TESTS)

test-swrap-pcap:: everything
	$(SELFTEST) --socket-wrapper-pcap --immediate $(TESTS)

test-swrap-keep-pcap:: everything
	$(SELFTEST) --socket-wrapper-keep-pcap --immediate $(TESTS)

test-noswrap:: everything
	$(SELFTEST) --immediate $(TESTS)

quicktest:: all
	$(SELFTEST) --quick --socket-wrapper --immediate $(TESTS)

quicktestone:: all
	$(SELFTEST) --quick --socket-wrapper --one $(TESTS)

testenv:: everything
	$(SELFTEST) --socket-wrapper --testenv

valgrindtest:: valgrindtest-all

valgrindtest-quick:: all
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) --quick --immediate --socket-wrapper $(TESTS)

valgrindtest-all:: everything
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) --immediate --socket-wrapper $(TESTS)

valgrindtest-env:: everything
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) --socket-wrapper --testenv

gdbtest:: gdbtest-all

gdbtest-quick:: all
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) --immediate --quick --socket-wrapper $(TESTS)

gdbtest-all:: everything
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) --immediate --socket-wrapper $(TESTS)

gdbtest-env:: everything
	SMBD_VALGRIND="xterm -n smbd -e $(srcdir)/script/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) --socket-wrapper --testenv
