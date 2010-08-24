CFLAGS=-Wall -g -I../../include/ -I../../lib/talloc/ -I../../lib/tdb/include/ -I../../lib/util/
LDLIBS=-lreadline

USAGE_SOURCES := $(shell grep -l 'XML Argument' *.c)
HELP_SOURCES := $(shell grep -l 'XML Help' *.c)

ctdb-test: $(patsubst %.c,%.o,$(wildcard *.c)) generated-usage.o ../../talloc.o ../../common/check.o ../../common/error.o ../../common/freelist.o ../../common/io.o ../../common/lock.o ../../common/open.o ../../common/tdb.o ../../common/transaction.o ../../common/traverse.o

$(patsubst %.c,%.o,$(wildcard *.c)): .help-files

.PHONY: links
links:
	cd tools && ./create-links

generated-usage.o: generated-usage.c links .help-files
generated-usage.c: $(USAGE_SOURCES) tools/gen-usage links
	tools/gen-usage $(USAGE_SOURCES) >$@

.help-files: $(HELP_SOURCES) links
	set -e; for f in $(HELP_SOURCES); do tools/gen-help $$f; done; touch .help-files

clean:
	rm -f ctdb-test .help-files generated-* *.o
