%{
/*
 * Copyright (c) 1998 Kungliga Tekniska Högskolan
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

#include "compile_et.h"
RCSID("$Id$");

void yyerror (char *s);
long name2number(const char *str);
%}

%union {
  char *string;
  int number;
}

%token ET INDEX PREFIX EC ID END
%token <string> STRING
%token <number> NUMBER

%%

file		: /* */ 
		| statements
		;

statements	: statement
		| statements statement
		;

statement	: ET STRING
		{
		    base = name2number($2);
		    strncpy(name, $2, sizeof(name));
		    name[sizeof(name) - 1] = '\0';
		    free($2);
		    prologue();
		}
		| ET STRING STRING
		{
		    base = name2number($2);
		    strncpy(name, $3, sizeof(name));
		    name[sizeof(name) - 1] = '\0';
		    free($2);
		    free($3);
		    prologue();
		}
		| INDEX NUMBER 
		{
		    for(; number < $2; number++) {
			/* 
			fprintf(h_file, "\t%s_ERROR_%d = %d,\n", 
				name, number, base + number);
				*/
			fprintf(c_file, "\t/* %03d */ \"Reserved %s error (%d)\",\n",
				number, name, number);
		    }
		}
		| PREFIX STRING
		{
		    prefix = realloc(prefix, strlen($2) + 2);
		    strcpy(prefix, $2);
		    strcat(prefix, "_");
		    free($2);
		}
		| PREFIX
		{
		    prefix = realloc(prefix, 1);
		    *prefix = '\0';
		}
		| EC STRING ',' STRING
		{
		    fprintf(h_file, "\t%s%s = %d,\n", 
			    prefix ? prefix : "", $2, number + base);
		    fprintf(c_file, "\t/* %03d */ \"%s\",\n", number, $4);
		    free($2);
		    free($4);
		    number++;
		}
		| ID STRING
		{
			id_str = $2;
		}
		| END
		{
			return;
		}
		;

%%

long
name2number(const char *str)
{
    const char *p;
    long base = 0;
    const char *x = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz0123456789_";
    if(strlen(str) > 4) {
	yyerror("table name too long");
	return 0;
    }
    for(p = str; *p; p++){
	char *q = strchr(x, *p);
	if(q == NULL) {
	    yyerror("invalid character in table name");
	    return 0;
	}
	base = (base << 6) + (q - x) + 1;
    }
    base <<= 8;
    if(base > 0x7fffffff)
	base = -(0xffffffff - base + 1);
    return base;
}

void
yyerror (char *s)
{
     error_message ("%s\n", s);
}
