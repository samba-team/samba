/*
 * Copyright (c) 1995, 1996, 1997 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by the Kungliga Tekniska
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
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

int
snprintf (char *str, size_t sz, const char *format, ...)
{
  va_list args;
  int ret;

  va_start(args, format);
  ret = vsnprintf (str, sz, format, args);
  va_end(args);
  return ret;
}

static int
append_char (char **s, char *theend, char c)
{
  if (*s < theend) {
    *(*s)++ = c;
    return 0;
  } else {
    *(*s)++ = '\0';
    return 1;
  }
}

static int
append_number (char **s, char *theend,
	       unsigned long num, unsigned base, char *rep,
	       int width, int zerop, int minusp)
{
  char *beg;
  int i, len;

  if (num == 0)
    return append_char (s, theend, '0');
  beg = *s;
  while (num > 0) {
    if (append_char (s, theend, rep[num % base]))
      return 1;
    num /= base;
  }
  if (minusp)
    if (append_char (s, theend, '-'))
      return 1;

  len = *s - beg;
  for (i = 0; i < len / 2; ++i) {
    char c;

    c = beg[i];
    beg[i] = beg[len-i-1];
    beg[len-i-1] = c;
  }

  if (width > len) {
    if (*s + width - len >= theend) {
      *(*s)++ = '\0';
      return 1;
    }
    *s += width - len;
    memmove (beg + width - len, beg, len);
    for (i = 0; i < width - len; ++i)
      beg[i] = (zerop ? '0' : ' ');
  }
  return 0;
}

static int
append_string (char **s, char *theend, char *arg,
	       int prec)
{
  if (prec) {
    while (*arg && prec--)
      if (append_char(s, theend, *arg++))
	return 1;
  } else {
    while (*arg)
      if (append_char(s, theend, *arg++))
	return 1;
  }
  return 0;
}

int
vsnprintf (char *str, size_t sz, const char *format, va_list ap)
{
  char *theend;
  char *s;
  char c;

  s = str;
  theend = str + sz - 1;
  while((c = *format++)) {
    if (c == '%') {
      int zerop      = 0;
      int width      = 0;
      int prec       = 0;
      int long_flag  = 0;
      int short_flag = 0;

      c = *format++;

      /* flags */
      if (c == '0') {
	zerop = 1;
	c = *format++;
      }

      /* width */
      if (isdigit(c))
	do {
	  width = width * 10 + c - '0';
	  c = *format++;
	} while(isdigit(c));
      else if(c == '*') {
	width = va_arg(ap, int);
	c = *format++;
      }

      /* precision */
      if (c == '.') {
	c = *format++;
	if (isdigit(c))
	  do {
	    prec = prec * 10 + c - '0';
	    c = *format++;
	  } while(isdigit(c));
	else if (c == '*') {
	  prec = va_arg(ap, int);
	  c = *format++;
	}
      }

      /* size */

      if (c == 'h') {
	short_flag = 1;
	c = *format++;
      } else if (c == 'l') {
	long_flag = 1;
	c = *format++;
      }

      switch (c) {
      case 'c' :
	if (append_char(&s, theend, (unsigned char)va_arg(ap, int)))
	  return s - str;
	break;
      case 's' :
	if (append_string(&s, theend, va_arg(ap, char*),
			  prec))
	  return s - str;
	break;
      case 'd' :
      case 'i' : {
	long arg;
	unsigned long num;
	int minusp = 0;

	if (long_flag)
	  arg = va_arg(ap, long);
	else if (short_flag)
	  arg = va_arg(ap, short);
	else
	  arg = va_arg(ap, int);

	if (arg < 0) {
	  minusp = 1;
	  num = -arg;
	} else
	  num = arg;

	if (append_number (&s, theend, num, 10, "0123456789",
			   width, zerop, minusp))
	  return s - str;
	break;
      }
      case 'u' : {
	unsigned long arg;

	if (long_flag)
	  arg = va_arg(ap, unsigned long);
	else if (short_flag)
	  arg = va_arg(ap, unsigned short);
	else
	  arg = va_arg(ap, unsigned);

	if (append_number (&s, theend, arg, 10, "0123456789",
			   width, zerop, 0))
	  return s - str;
	break;
      }
      case 'o' : {
	unsigned long arg;

	if (long_flag)
	  arg = va_arg(ap, unsigned long);
	else if (short_flag)
	  arg = va_arg(ap, unsigned short);
	else
	  arg = va_arg(ap, unsigned);

	if (append_number (&s, theend, arg, 010, "01234567",
			   width, zerop, 0))
	  return s - str;
	break;
      }
      case 'x' : {
	unsigned long arg;

	if (long_flag)
	  arg = va_arg(ap, unsigned long);
	else if (short_flag)
	  arg = va_arg(ap, unsigned short);
	else
	  arg = va_arg(ap, unsigned);

	if (append_number (&s, theend, arg, 0x10, "0123456789abcdef",
			   width, zerop, 0))
	  return s - str;
	break;
      }
      case 'X' :{
	unsigned long arg;

	if (long_flag)
	  arg = va_arg(ap, unsigned long);
	else if (short_flag)
	  arg = va_arg(ap, unsigned short);
	else
	  arg = va_arg(ap, unsigned);

	if (append_number (&s, theend, arg, 0x10, "0123456789ABCDEF",
			   width, zerop, 0))
	  return s - str;
	break;
      }
      case 'p' : {
	unsigned long arg = (unsigned long)va_arg(ap, void*);

	if (append_number (&s, theend, arg, 0x10, "0123456789ABCDEF",
			   width, zerop, 0))
	  return s - str;
	break;
      }
      case '%' :
	if (append_char (&s, theend, c))
	  return s - str;
	break;
      default :
	if (   append_char(&s, theend, '%')
	    || append_char(&s, theend, c))
	  return s - str;
	break;
      }
    } else
      if (append_char (&s, theend, c))
	return s - str;
  }
  *s = '\0';
  return s - str;
}
