Here is how to use gcov to test code coverage in ldb.

Step 1: enable gcov support

     Edit Makefile.ldb and uncommend the two GCOV_ lines
     
Step 2: build ldb

     make -sf Makefile.ldb clean all

Step 3: run the test suite
     make -sf Makefile.ldb test-tdb

Step 4: produce the gcov report
     make -sf Makefile.ldb gcov

Step 5: read the summary reports
     less *.report.gcov

Step 6: examine the per-file reports
     less ldb_tdb\#ldb_tdb.c.gcov

You can also combine steps 2 to 4 like this:

     make -sf Makefile.ldb clean all test-tdb gcov

Note that you should not expect 100% coverage, as some error paths
(such as memory allocation failures) are verr hard to trigger. There
are ways of working around this, but they are quite tricky (they
involve allocation wrappers that "fork and fail on malloc").

The lines to look for in the per-file reports are the ones starting
with "#####". Those are lines that are never executed. 
