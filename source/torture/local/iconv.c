/* 
   Unix SMB/CIFS implementation.

   local testing of iconv routines. This tests the system iconv code against
   the built-in iconv code

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/*
  generate a UTF-16LE buffer for a given unicode codepoint
*/
static int gen_codepoint(unsigned int codepoint,
			  char *buf, size_t *size)
{
	static iconv_t cd;
	uint8_t in[4];
	char *ptr_in;
	size_t size_in, size_out, ret;
	if (!cd) {
		cd = iconv_open("UTF-16LE", "UCS-4LE");
	}

	in[0] = codepoint & 0xFF;
	in[1] = (codepoint>>8) & 0xFF;
	in[2] = (codepoint>>16) & 0xFF;
	in[3] = (codepoint>>24) & 0xFF;

	ptr_in = in;
	size_in = 4;
	size_out = 8;

	ret = iconv(cd, &ptr_in, &size_in, &buf, &size_out);

	*size = 8 - size_out;

	return ret;
}


/*
  work out the unicode codepoint of the first UTF-8 character in the buffer
*/
static unsigned int get_codepoint(char *buf, size_t size, const char *charset)
{
	iconv_t cd;
	uint8_t out[4];
	char *ptr_out;
	size_t size_out, size_in, ret;

	cd = iconv_open("UCS-4LE", charset);

	size_in = size;
	ptr_out = out;
	size_out = sizeof(out);
	memset(out, 0, sizeof(out));

	ret = iconv(cd, &buf, &size_in, &ptr_out, &size_out);

	iconv_close(cd);

	return out[0] | (out[1]<<8) | (out[2]<<16) | (out[3]<<24);
}

/*
  display a buffer with name prefix
*/
static void show_buf(const char *name, uint8_t *buf, size_t size)
{
	int i;
	printf("%s ", name);
	for (i=0;i<size;i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

/*
  given a UTF-16LE buffer, test the system and built-in iconv code to
  make sure they do exactly the same thing in converting the buffer to
  "charset", then convert it back again and ensure we get the same
  buffer back
*/
static int test_buffer(uint8_t *inbuf, size_t size, const char *charset)
{
	uint8_t buf1[1000], buf2[1000], buf3[1000];
	size_t outsize1, outsize2, outsize3;
	const char *ptr_in;
	char *ptr_out;
	size_t size_in1, size_in2, size_in3;
	size_t ret1, ret2, ret3, len1, len2;
	int ok = 1;
	int errno1, errno2;
	static iconv_t cd;
	static smb_iconv_t cd2, cd3;
	static const char *last_charset;

	if (cd && last_charset) {
		iconv_close(cd);
		smb_iconv_close(cd2);
		smb_iconv_close(cd3);
		cd = NULL;
	}

	if (!cd) {
		cd = iconv_open(charset, "UTF-16LE");
		cd2 = smb_iconv_open(charset, "UTF-16LE");
		cd3 = smb_iconv_open("UTF-16LE", charset);
		last_charset = charset;
	}

#if 0
	int i;
	for (i=0;i<50;i++) {
		ptr_in = inbuf;
		ptr_out = buf1;
		size_in1 = size;
		outsize1 = sizeof(buf1);

		memset(ptr_out, 0, outsize1);
		errno = 0;
		ret1 = smb_iconv(cd2, &ptr_in, &size_in1, &ptr_out, &outsize1);
		errno1 = errno;
	}
#endif

	ptr_in = inbuf;
	ptr_out = buf1;
	size_in1 = size;
	outsize1 = sizeof(buf1);

	memset(ptr_out, 0, outsize1);
	errno = 0;
	ret1 = smb_iconv(cd2, &ptr_in, &size_in1, &ptr_out, &outsize1);
	errno1 = errno;

	ptr_in = inbuf;
	ptr_out = buf2;
	size_in2 = size;
	outsize2 = sizeof(buf2);
	
	memset(ptr_out, 0, outsize2);
	errno = 0;
	ret2 = iconv(cd, &ptr_in, &size_in2, &ptr_out, &outsize2);
	errno2 = errno;

	len1 = sizeof(buf1) - outsize1;
	len2 = sizeof(buf2) - outsize2;

	/* codepoints above 1M are not interesting for now */
	if (len2 > len1 && 
	    memcmp(buf1, buf2, len1) == 0 && 
	    get_codepoint(buf2+len1, len2-len1, charset) >= (1<<20)) {
		return ok;
	}
	if (len1 > len2 && 
	    memcmp(buf1, buf2, len2) == 0 && 
	    get_codepoint(buf1+len2, len1-len2, charset) >= (1<<20)) {
		return ok;
	}

	if (ret1 != ret2) {
		printf("ret1=%d ret2=%d\n", ret1, ret2);
		ok = 0;
	}

	if (errno1 != errno2) {
		printf("e1=%s e2=%s\n", strerror(errno1), strerror(errno2));
		show_buf(" rem1:", inbuf+(size-size_in1), size_in1);
		show_buf(" rem2:", inbuf+(size-size_in2), size_in2);
		ok = 0;
	}
	
	if (outsize1 != outsize2) {
		printf("\noutsize mismatch outsize1=%d outsize2=%d\n",
		       outsize1, outsize2);
		ok = 0;
	}
	
	if (size_in1 != size_in2) {
		printf("\nsize_in mismatch size_in1=%d size_in2=%d\n",
		       size_in1, size_in2);
		ok = 0;
	}

	if (!ok ||
	    len1 != len2 ||
	    memcmp(buf1, buf2, len1) != 0) {
		printf("\nsize=%d ret1=%d ret2=%d\n", size, ret1, ret2);
		show_buf(" IN1:", inbuf, size-size_in1);
		show_buf(" IN2:", inbuf, size-size_in2);
		show_buf("OUT1:", buf1, len1);
		show_buf("OUT2:", buf2, len2);
		if (len2 > len1 && memcmp(buf1, buf2, len1) == 0) {
			printf("next codepoint is %u\n", 
			       get_codepoint(buf2+len1, len2-len1, charset));
		}
		if (len1 > len2 && memcmp(buf1, buf2, len2) == 0) {
			printf("next codepoint is %u\n", 
			       get_codepoint(buf1+len2,len1-len2, charset));
		}

		ok = 0;
	}
	
	size = size - size_in1;
	ptr_in = buf1;
	ptr_out = buf3;
	size_in3 = len1;
	outsize3 = sizeof(buf3);

	memset(ptr_out, 0, outsize3);
	ret3 = smb_iconv(cd3, &ptr_in, &size_in3, &ptr_out, &outsize3);
	
	if (ret3 != 0) {
		printf("pull failed - %s\n", strerror(errno));
		ok = 0;
	}
	
	if (outsize3 != sizeof(buf3) - size) {
		printf("wrong outsize3 - %d should be %d\n", 
		       outsize3, sizeof(buf3) - size);
		ok = 0;
	}
	
	if (memcmp(buf3, inbuf, size) != 0) {
		int i;
		printf("pull bytes mismatch:\n");
		show_buf("inbuf", inbuf, size);
		show_buf(" buf3", buf3, size);
		ok = 0;
	}

	if (!ok) {
		printf("test_buffer failed for charset %s\n", charset);
	}

	return ok;
}

BOOL torture_local_iconv(int dummy) 
{
	size_t size;
	unsigned char inbuf[1000];
	int ok = 1;
	unsigned int codepoint, i, c;

	srandom(time(NULL));

	printf("Testing first 1M codepoints\n");
	for (codepoint=0;ok && codepoint<(1<<20);codepoint++) {
		if (gen_codepoint(codepoint, inbuf, &size) != 0) {
			continue;
		}

		if (codepoint % 100 == 0) {
			printf("codepoint=%u   \r", codepoint);
		}

		ok = test_buffer(inbuf, size, "UTF-8");
	}


	printf("Testing 5M random UTF-16LE sequences\n");
	for (i=0;ok && i<500000;i++) {
		if (i % 100 == 0) {
			printf("i=%u              \r", i);
		}

		size = random() % 100;
		for (c=0;c<size;c++) {
			if (random() % 100 < 80) {
				inbuf[c] = random() % 128;
			} else {
				inbuf[c] = random();
			}
			if (random() % 10 == 0) {
				inbuf[c] |= 0xd8;
			}
			if (random() % 10 == 0) {
				inbuf[c] |= 0xdc;
			}
		}
		ok &= test_buffer(inbuf, size, "UTF-8");
		ok &= test_buffer(inbuf, size, "CP850");
	}

	return ok == 1;
}


