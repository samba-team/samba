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


/* this is like vsnprintf but the 'n' limit does not include
   the terminating null. So if you have a 1024 byte buffer then
   pass 1023 for n */
int vslprintf(char *str, int n, char *format, va_list ap)
{
#ifdef HAVE_VSNPRINTF
	int ret = vsnprintf(str, n, format, ap);
	if (ret > n || ret < 0) {
		str[n] = 0;
		return -1;
	}
	str[ret] = 0;
	return ret;
#else
	static char *buf;
	static int len=8000;
	int ret;

	/* this code is NOT a proper vsnprintf() implementation. It
	   relies on the fact that all calls to slprintf() in Samba
	   pass strings which have already been through pstrcpy() or
	   fstrcpy() and never more than 2 strings are
	   concatenated. This means the above buffer is absolutely
	   ample and can never be overflowed.

	   In the future we would like to replace this with a proper
	   vsnprintf() implementation but right now we need a solution
	   that is secure and portable. This is it.  */

	if (!buf) {
		buf = malloc(len);
		if (!buf) {
			/* can't call debug or we would recurse */
			exit(1);
		}
	}

	vsprintf(buf, format, ap);
	ret = strlen(buf);

	if (ret < n) {
		n = ret;
	} else if (ret > n) {
		ret = -1;
	}

	buf[n] = 0;
	
	memcpy(str, buf, n+1);

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
