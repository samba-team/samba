/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Simo Sorce 2004
   
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

struct dn_attribute {
	char *attribute;
	char *name;
	char *value;
};

struct dn_component {
	char *component;
	int attr_num;
	struct dn_attribute **attributes;
};

struct ldap_dn {
	char *dn;
	int comp_num;
	struct dn_component **components;
};

struct ldap_schema {
	int dummy;
};
