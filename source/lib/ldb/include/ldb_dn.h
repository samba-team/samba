/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Simo Sorce 2004
   Copyright (C) Derrell Lipman 2005
   
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

struct ldb_dn_attribute {
	char *name;
	char *value;
};

struct ldb_dn_component {
	int attr_num;
	struct ldb_dn_attribute **attributes;
};

struct ldb_dn {
	int comp_num;
	struct ldb_dn_component **components;
};


struct ldb_dn *ldb_dn_explode(void *mem_ctx, const char *dn);
char *ldb_dn_linearize(void *mem_ctx, struct ldb_dn *edn);
int ldb_dn_compare(struct ldb_dn *edn0, struct ldb_dn *edn1);
struct ldb_dn *ldb_dn_casefold(struct ldb_context *ldb, struct ldb_dn *edn);
