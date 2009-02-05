TEST_FORMAT = plain

SELFTEST = $(LD_LIBPATH_OVERRIDE) PYTHON=$(PYTHON) \
    $(PERL) $(selftestdir)/selftest.pl --prefix=${selftest_prefix} \
    --builddir=$(builddir) --srcdir=$(srcdir) \
    --expected-failures=$(srcdir)/selftest/knownfail \
	--format=$(TEST_FORMAT) \
    --exclude=$(srcdir)/selftest/skip --testlist="./selftest/tests.sh|" \
    $(TEST_OPTIONS) 

SELFTEST_NOSLOW_OPTS = --exclude=$(srcdir)/selftest/slow
SELFTEST_QUICK_OPTS = $(SELFTEST_NOSLOW_OPTS) --quick --include=$(srcdir)/selftest/quick

slowtest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --immediate $(TESTS)

test:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) --immediate \
		$(TESTS)

kvmtest:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) --immediate \
		--target=kvm --image=$(KVM_IMAGE)

kvmquicktest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) --immediate \
		$(SELFTEST_QUICK_OPTS) --target=kvm --image=$(KVM_IMAGE)

testone:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) --one $(TESTS)

test-swrap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --immediate $(TESTS)

test-swrap-pcap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper-pcap --immediate $(TESTS)

test-swrap-keep-pcap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper-keep-pcap --immediate $(TESTS)

test-noswrap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --immediate $(TESTS)

quicktest:: all
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper --immediate $(TESTS)

quicktestone:: all
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper --one $(TESTS)

testenv:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

testenv-%:: everything
	SELFTEST_TESTENV=$* $(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

test-%:: 
	$(MAKE) test TESTS=$*

valgrindtest:: valgrindtest-all

valgrindtest-quick:: all
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --immediate --socket-wrapper $(TESTS)

valgrindtest-all:: everything
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --immediate --socket-wrapper $(TESTS)

valgrindtest-env:: everything
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

gdbtest:: gdbtest-all

gdbtest-quick:: all
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --immediate --socket-wrapper $(TESTS)

gdbtest-all:: everything
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --immediate --socket-wrapper $(TESTS)

gdbtest-env:: everything
	SMBD_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

