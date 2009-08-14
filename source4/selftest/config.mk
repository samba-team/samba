TEST_FORMAT = plain

SELFTEST = $(LD_LIBPATH_OVERRIDE) PYTHON=$(PYTHON) \
    $(PERL) $(selftestdir)/selftest.pl --prefix=${selftest_prefix} \
    --builddir=$(builddir) --srcdir=$(srcdir) \
    --exclude=$(srcdir)/selftest/skip --testlist="./selftest/tests.sh|" \
    $(TEST_OPTIONS) 

SELFTEST_NOSLOW_OPTS = --exclude=$(srcdir)/selftest/slow
SELFTEST_QUICK_OPTS = $(SELFTEST_NOSLOW_OPTS) --quick --include=$(srcdir)/selftest/quick
FILTER_XFAIL = $(PERL) $(selftestdir)/filter-subunit.pl --expected-failures=$(srcdir)/selftest/knownfail
FORMAT_TEST_OUTPUT = $(FILTER_XFAIL) | $(PERL) $(selftestdir)/format-subunit.pl --format=$(TEST_FORMAT)

test-subunit:: everything
	$(SELFTEST) --socket-wrapper $(TESTS)

slowtest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

ifeq ($(RUN_FROM_BUILD_FARM),yes)
test:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) $(TESTS) | $(FILTER_XFAIL) --strip-passed-output
else
test:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 
endif

kvmtest:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) \
		--target=kvm --image=$(KVM_IMAGE) | $(FORMAT_TEST_OUTPUT) --immediate 

kvmquicktest:: everything
	$(SELFTEST) $(DEFAULT_TEST_OPTIONS) \
		$(SELFTEST_QUICK_OPTS) --target=kvm --image=$(KVM_IMAGE) | $(FORMAT_TEST_OUTPUT) | $(FORMAT_TEST_OUTPUT) --immediate 

testone:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(DEFAULT_TEST_OPTIONS) --one $(TESTS) | $(FORMAT_TEST_OUTPUT)

test-swrap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

test-swrap-pcap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper-pcap $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

test-swrap-keep-pcap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper-keep-pcap $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

test-noswrap:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

quicktest:: all
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

quicktest-subunit:: all
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper $(TESTS)

quicktestone:: all
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper --one $(TESTS) | $(FORMAT_TEST_OUTPUT)

testenv:: everything
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

testenv-%:: everything
	SELFTEST_TESTENV=$* $(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

test-%:: 
	$(MAKE) test TESTS=$*

valgrindtest:: valgrindtest-all

valgrindtest-quick:: all
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

valgrindtest-all:: everything
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

valgrindtest-env:: everything
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/valgrind_run $(LD_LIBPATH_OVERRIDE)" \
	VALGRIND="valgrind -q --num-callers=30 --log-file=${selftest_prefix}/valgrind.log" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

gdbtest:: gdbtest-all

gdbtest-quick:: all
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_QUICK_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

gdbtest-all:: everything
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper $(TESTS) | $(FORMAT_TEST_OUTPUT) --immediate 

gdbtest-env:: everything
	SAMBA_VALGRIND="xterm -n server -e $(selftestdir)/gdb_run $(LD_LIBPATH_OVERRIDE)" \
	$(SELFTEST) $(SELFTEST_NOSLOW_OPTS) --socket-wrapper --testenv

