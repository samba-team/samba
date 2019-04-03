# Fuzzing Samba

Fuzzing supplies valid, invalid, unexpected or random data as input to a piece
of code. Instrumentation, usually compiler-implemented, is used to monitor for
exceptions such as crashes, assertions or memory corruption.

See [Wikipedia article on fuzzing](https://en.wikipedia.org/wiki/Fuzzing) for
more information.


## Configure with fuzzing

Example command line to build binaries for use with
[honggfuzz](https://github.com/google/honggfuzz/):

```sh
buildtools/bin/waf -C --without-gettext --enable-debug --enable-developer \
	--address-sanitizer --enable-libfuzzer \
	CC=.../honggfuzz/hfuzz_cc/hfuzz-clang configure \
	LINK_CC=.../honggfuzz/hfuzz_cc/hfuzz-clang
```


## Fuzzing tiniparser

Example for fuzzing `tiniparser` using `honggfuzz` (see `--help` for more
options):

```sh
buildtools/bin/waf --targets=fuzz_tiniparser build && \
.../honggfuzz/honggfuzz --sanitizers --timeout 3 --max_file_size 256 \
  --rlimit_rss 100 -f .../tiniparser-corpus -- bin/fuzz_tiniparser
```

# vim: set sw=8 sts=8 ts=8 tw=79 :
