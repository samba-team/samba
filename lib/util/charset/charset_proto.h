/* 
   Unix SMB/CIFS implementation.
   Samba charset modules
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Jelmer Vernooij 2002
   Copyright (C) Benjamin Riefenstahl 2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

size_t weird_push(void *cd, const char **inbuf, size_t *inbytesleft,
		  char **outbuf, size_t *outbytesleft);
size_t weird_pull(void *cd, const char **inbuf, size_t *inbytesleft,
		  char **outbuf, size_t *outbytesleft);

size_t macosxfs_encoding_pull(
	void *cd,				/* Encoder handle */
	const char **inbuf, size_t *inbytesleft, /* Script string */
	char **outbuf, size_t *outbytesleft);	/* UTF-16-LE string */
size_t macosxfs_encoding_push(
	void *cd,				/* Encoder handle */
	const char **inbuf, size_t *inbytesleft, /* UTF-16-LE string */
	char **outbuf, size_t *outbytesleft);	/* Script string */


