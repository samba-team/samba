/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   snprintf replacement
   Copyright (C) Andrew Tridgell 1998
   
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

extern int DEBUGLEVEL;

int vslprintf(char *str, int n, char *format, va_list ap)
{
#ifdef HAVE_VSNPRINTF
	int ret = vsnprintf(str, n, format, ap);
	if (ret >= 0) str[ret] = 0;
	return ret;
#else
	static char *buf;
	static int len;
	static int pagesize;
	int ret;

	if (!len || !buf || (len-pagesize) < n) {
		pagesize = getpagesize();
		len = (2+(n/pagesize))*pagesize;
		/* note: we don't free the old memory (if any) as we don't 
		   want a malloc lib to reuse the memory as it will
		   have the wrong permissions */
#ifdef HAVE_MEMALIGN
		buf = memalign(pagesize, len);
#else /* HAVE_MEMALIGN */
#ifdef HAVE_VALLOC
		buf = valloc(len);
#else /* HAVE_VALLOC */
                buf = malloc(len);
#endif /* HAVE_VALLOC */
#endif /* HAVE_MEMALIGN */
		if (buf) {
			if (mprotect(buf+(len-pagesize), pagesize, PROT_READ) != 0) {
				exit(1);
				return -1;
			}
		}
	}

	if (!buf) {
		exit(1);
	}

	ret = vsprintf(str, format, ap);
	/* we will have got a seg fault here if we overflowed the buffer */
	return ret;
#endif
}

#ifdef __STDC__
int slprintf(char *str, int n, char *format, ...)
{
#else
 int slprintf(va_alist)
va_dcl
{
	char *str, *format;
	int n;
#endif
	va_list ap;  
	int ret;

#ifdef __STDC__
	va_start(ap, format);
#else
	va_start(ap);
	str = va_arg(ap,char *);
	n = va_arg(ap,int);
	format = va_arg(ap,char *);
#endif

	ret = vslprintf(str,n,format,ap);
	va_end(ap);
	return ret;
}
