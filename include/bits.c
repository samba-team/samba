/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void strupr(char *s)
{
    char *p = s;
    while(*p){
	if(islower(*p))
	    *p = toupper(*p);
	p++;
    }	
}


#define BITSIZE(TYPE)						\
{								\
    int b = 0; TYPE x = 1, zero = 0; char *pre = "u_";		\
    char tmp[128], tmp2[128];					\
    while(x){ x <<= 1; b++; if(x < zero) pre=""; }		\
    if(b >= len){						\
        int tabs;						\
	sprintf(tmp, "%sint%d_t" , pre, len);			\
	sprintf(tmp2, "typedef %s %s;", #TYPE, tmp);		\
	strupr(tmp);						\
	tabs = 5 - strlen(tmp2) / 8;				\
	fprintf(f, "#ifndef HAVE_%s\n", tmp);			\
	fprintf(f, "#define HAVE_%s\n", tmp);			\
        fprintf(f, "%s", tmp2);					\
	while(tabs-- > 0) fprintf(f, "\t");			\
	fprintf(f, "/* %2d bits */\n", b);			\
	fprintf(f, "#endif /* HAVE_%s */\n", tmp);		\
	continue;						\
    }								\
}

int main(int argc, char **argv)
{
    int i, b, len;
    FILE *f;
    int sizes[] = { 8, 16, 32, 64 };
    
    if(argc < 2)
	f = stdout;
    else
	f = fopen(argv[1], "w");
    fprintf(f, "/*\n");
    fprintf(f, " * bits.h -- this file was generated for %s\n", HOST); 
    fprintf(f, " */\n\n");
    fprintf(f, "#ifndef __BITS_H__\n");
    fprintf(f, "#define __BITS_H__\n");
    fprintf(f, "\n");
    fprintf(f, "/* For compatibility with various type definitions */\n");
    fprintf(f, "#ifndef __BIT_TYPES_DEFINED__\n");
    fprintf(f, "#define __BIT_TYPES_DEFINED__\n");
    fprintf(f, "\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(signed char);
	BITSIZE(short);
	BITSIZE(int);
	BITSIZE(long);
#ifdef HAVE_LONG_LONG
	BITSIZE(long long);
#endif
	fprintf(f, "/* There is no %d bit type */\n", len);
	break;
    }
    fprintf(f, "\n");
    for(i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++){
	len = sizes[i];
	BITSIZE(unsigned char);
	BITSIZE(unsigned short);
	BITSIZE(unsigned int);
	BITSIZE(unsigned long);
#ifdef HAVE_LONG_LONG
	BITSIZE(unsigned long long);
#endif
	fprintf(f, "/* There is no %d bit type */\n", len);
	break;
    }
    fprintf(f, "\n");
    fprintf(f, "#endif /* __BIT_TYPES_DEFINED__ */\n");
    fprintf(f, "\n");
    fprintf(f, "#endif /* __BITS_H__ */\n");
    return 0;
}
