[SUBSYSTEM::ZLIB]
CFLAGS = -Ilib/zlib

libzlibsrcdir := lib/zlib
ZLIB_OBJ_FILES = \
		$(libzlibsrcdir)/adler32.o \
		$(libzlibsrcdir)/compress.o \
		$(libzlibsrcdir)/crc32.o \
		$(libzlibsrcdir)/gzio.o \
		$(libzlibsrcdir)/uncompr.o \
		$(libzlibsrcdir)/deflate.o \
		$(libzlibsrcdir)/trees.o \
		$(libzlibsrcdir)/zutil.o \
		$(libzlibsrcdir)/inflate.o \
		$(libzlibsrcdir)/infback.o \
		$(libzlibsrcdir)/inftrees.o \
		$(libzlibsrcdir)/inffast.o
