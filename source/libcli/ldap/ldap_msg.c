/* 
   Unix SMB/CIFS mplementation.

   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2005
   Copyright (C) Volker Lendecke 2004
    
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
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"


struct ldap_message *new_ldap_message(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct ldap_message);
}


BOOL add_value_to_attrib(TALLOC_CTX *mem_ctx, struct ldb_val *value,
			 struct ldb_message_element *attrib)
{
	attrib->values = talloc_realloc(mem_ctx, 
					  attrib->values,
					  DATA_BLOB,
					  attrib->num_values+1);
	if (attrib->values == NULL)
		return False;

	attrib->values[attrib->num_values].data = talloc_steal(attrib->values, 
							       value->data);
	attrib->values[attrib->num_values].length = value->length;
	attrib->num_values += 1;
	return True;
}

BOOL add_attrib_to_array_talloc(TALLOC_CTX *mem_ctx,
				       const struct ldb_message_element *attrib,
				       struct ldb_message_element **attribs,
				       int *num_attribs)
{
	*attribs = talloc_realloc(mem_ctx,
				    *attribs,
				    struct ldb_message_element,
				    *num_attribs+1);

	if (*attribs == NULL)
		return False;

	(*attribs)[*num_attribs] = *attrib;
	talloc_steal(*attribs, attrib->values);
	talloc_steal(*attribs, attrib->name);
	*num_attribs += 1;
	return True;
}

BOOL add_mod_to_array_talloc(TALLOC_CTX *mem_ctx,
				    struct ldap_mod *mod,
				    struct ldap_mod **mods,
				    int *num_mods)
{
	*mods = talloc_realloc(mem_ctx, *mods, struct ldap_mod, (*num_mods)+1);

	if (*mods == NULL)
		return False;

	(*mods)[*num_mods] = *mod;
	*num_mods += 1;
	return True;
}

