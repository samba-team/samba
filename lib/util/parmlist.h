/* 
   Unix SMB/CIFS implementation.
   Generic parameter parsing interface
   Copyright (C) Jelmer Vernooij					  2009
   
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

#ifndef _PARMLIST_H /* _PARMLIST_H */
#define _PARMLIST_H 

struct parmlist_entry {
	struct parmlist_entry *prev, *next;
	char *key;
	char *value;
	int priority;
};

struct parmlist {
	struct parmlist_entry *entries;
};

int parmlist_get_int(struct parmlist *ctx, const char *name, int default_v);
const char *parmlist_get_string(struct parmlist *ctx, const char *name, const char *default_v);
struct parmlist_entry *parmlist_get(struct parmlist *ctx, const char *name);
const char **parmlist_get_string_list(struct parmlist *ctx, const char *name, const char *separator);

#endif /* _PARMLIST_H */
