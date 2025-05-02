# Fuzzing Samba

See also https://wiki.samba.org/index.php/Fuzzing

Fuzzing supplies valid, invalid, unexpected or random data as input to a piece
of code. Instrumentation, usually compiler-implemented, is used to monitor for
exceptions such as crashes, assertions or memory corruption.

See [Wikipedia article on fuzzing](https://en.wikipedia.org/wiki/Fuzzing) for
more information.

# Honggfuzz

## Configure with fuzzing

Example command line to build binaries for use with
[honggfuzz](https://github.com/google/honggfuzz/):

```sh
CC=.../honggfuzz/hfuzz_cc/hfuzz-clang \
LINK_CC=.../honggfuzz/hfuzz_cc/hfuzz-clang \
./configure -C --without-gettext --enable-debug --enable-developer \
	--address-sanitizer --enable-libfuzzer --abi-check-disable
```


## Fuzzing tiniparser

Example for fuzzing `tiniparser` using `honggfuzz` (see `--help` for more
options):

```sh
make bin/fuzz_tiniparser && \
.../honggfuzz/honggfuzz --sanitizers --timeout 3 --max_file_size 256 \
  --rlimit_rss 100 -f .../tiniparser-corpus -- bin/fuzz_tiniparser
```

# AFL (american fuzzy lop)

## Configure with fuzzing

Example command line to build binaries for use with
[afl](http://lcamtuf.coredump.cx/afl/)

```sh
CC=afl-gcc ./configure -C --without-gettext --enable-debug --enable-developer \
	--enable-afl-fuzzer --abi-check-disable
```

## Fuzzing tiniparser

Example for fuzzing `tiniparser` using `afl-fuzz` (see `--help` for more
options):

```sh
make bin/fuzz_tiniparser build && \
afl-fuzz -m 200 -i inputdir -o outputdir -- bin/fuzz_tiniparser
```

# oss-fuzz

Samba can be fuzzed by Google's oss-fuzz system.  Assuming you have an
oss-fuzz checkout from https://github.com/google/oss-fuzz with Samba's
metadata in projects/samba, the following guides will help:

## Testing locally

https://google.github.io/oss-fuzz/getting-started/new-project-guide/#testing-locally

## Debugging oss-fuzz

See https://google.github.io/oss-fuzz/advanced-topics/debugging/

## Samba-specific hints

A typical debugging workflow is:

oss-fuzz$ python infra/helper.py shell samba
git fetch $REMOTE $BRANCH
git checkout FETCH_HEAD
lib/fuzzing/oss-fuzz/build_image.sh
compile

This will pull in any new Samba deps and build Samba's fuzzers.

# vim: set sw=8 sts=8 ts=8 tw=79 :
