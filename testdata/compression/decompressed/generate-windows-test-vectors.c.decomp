/*
 * Generate test vectorsa for Windows LZ77 Huffman compression.
 *
 * Copyright (c) 2022 Douglas Bagnall <dbagnall@samba.org>
 *
 * GPLv3+.
 *
 * Can be compiled on Windows 2012r2 under Cygwin
 *
 * gcc -o generate-windows-test-vectors  \
 *       generate-windows-test-vectors.c \
 *	 C:\Windows\SysWOW64\cabinet.dll \
 *	 -lcabinet
 *
 * There might be better ways.
 *
 * See https://learn.microsoft.com/en-us/windows/win32/cmpapi/-compression-portal
 */


#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* compressapi.h is in the Windows API. mingw-w64 has a copy. */
#include <compressapi.h>
#include <errhandlingapi.h>

struct blob {
	uint8_t *data;
	size_t length;
};

/* Windows size_t is different than Cygwin size_t (though still 64 bit) */
typedef unsigned long long wsize_t;


#define compression_flags (COMPRESS_ALGORITHM_XPRESS_HUFF | COMPRESS_RAW)

int32_t compression_level = 0;

static struct blob compress(struct blob input)
{
	COMPRESSOR_HANDLE handle;
	struct blob output;
	bool ok;
	wsize_t used;

	ok = CreateCompressor(compression_flags, NULL, &handle);

	if (! ok) {
		fprintf(stderr, "CreateCompressor failed\n");
		exit(1);
	}

	output.length = input.length * 3 + 256;
	output.data = malloc(output.length);
	if (output.data == NULL) {
		fprintf(stderr, "output allocation failed (estimated %zu)\n",
			output.length);
		exit(1);
	}


	ok = SetCompressorInformation(handle,
				      COMPRESS_INFORMATION_CLASS_LEVEL,
				      &compression_level,
				      sizeof(compression_level));

	if (! ok) {
	  fprintf(stderr, "SetCompressorInformation failed: %d\n",
		  GetLastError());
	  //exit(1);
	}

	ok = Compress(handle,
		      input.data,
		      input.length,
		      output.data,
		      output.length,
		      &used);
	if (! ok) {
		fprintf(stderr, "Compress failed\n");
		exit(1);
	}
	output.data = realloc(output.data, used);
	if (output.data == NULL) {
		fprintf(stderr,
			"failed to shrinkwrap output! (from %zu to %llu)\n",
			output.length, used);
		exit(1);
	}
	output.length = used;
	CloseCompressor(handle);
	return output;
}


struct blob decompress(struct blob input,
		       size_t expected_size)
{
	DECOMPRESSOR_HANDLE handle;
	struct blob output;
	bool ok;
	wsize_t used;

	ok = CreateDecompressor(compression_flags, NULL, &handle);

	if (! ok) {
		fprintf(stderr, "CreateDecompressor failed\n");
		exit(1);
	}

	output.length = expected_size;
	output.data = malloc(output.length);
	if (output.data == NULL) {
		fprintf(stderr, "output allocation failed (%zu)\n",
			output.length);
		exit(1);
	}

	ok = Decompress(handle,
			input.data,
			input.length,
			output.data,
			output.length,
			&used);
	if (! ok) {
		fprintf(stderr, "Decompress failed\n");
		exit(1);
	}
	CloseDecompressor(handle);
	return output;
}


static void __attribute__((noreturn)) usage(int ret)
{
	fprintf(stderr,
		"USAGE: test-win-vectors {c,d} filename [length|level] > DEST\n\n");
	fprintf(stderr, "c for< compression, d for decompression\n");
	fprintf(stderr, "decompressed length is required for decompression\n");
	fprintf(stderr, "compression level flag is optional [default 0]\n");
	exit(ret);
}

int main(int argc, const char *argv[])
{
	FILE *fh;
	const char *filename;
	struct stat s;
	int ret;
	struct blob input = {0};
	struct blob output = {0};

	if (argc < 3 || argc > 4) {
		usage(1);
	}
	filename = argv[2];

	fh = fopen(filename, "rb");
	if (fh == NULL) {
		fprintf(stderr, "Could not open %s\n", filename);
		usage(1);
	}

	ret = fstat(fileno(fh), &s);
	if (ret != 0) {
		fprintf(stderr, "Could not stat %s: %d\n", filename, ret);
		usage(1);
	}
	input.length = s.st_size;
	input.data = malloc(input.length);
	if (input.data == NULL) {
		fprintf(stderr, "input too big for memory?! (%zu)\n",
			s.st_size);
		exit(1);
	}

	fread(input.data, 1, input.length, fh);

	if (strcmp(argv[1], "c") == 0) {
		if (argc == 4 && strcmp(argv[3], "0")) {
			compression_level = 1;
		}	       		
		output = compress(input);
	} else if (strcmp(argv[1], "d") == 0) {
		size_t decomp_size;
		if (argc != 4) {
			fprintf(stderr, "no length given\n");
			usage(1);
		}
		decomp_size = atoi(argv[3]);
		output = decompress(input, decomp_size);
	} else {
		usage(1);
	}
	fwrite(output.data, 1, output.length, stdout);
	free(output.data);
	return 0;
}
