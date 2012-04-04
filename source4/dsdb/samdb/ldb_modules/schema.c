/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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

#include "includes.h"
#include "ldb.h"
#include "ldb_module.h"
#include "librpc/ndr/libndr.h"
#include "dsdb/samdb/ldb_modules/util.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/ldb_modules/schema.h"

/*
 * This function determines the (last) structural or 88 object class of a passed
 * "objectClass" attribute - per MS-ADTS 3.1.1.1.4 this is the last value.
 * Without schema this does not work and hence NULL is returned.
 */
const struct dsdb_class *get_last_structural_class(const struct dsdb_schema *schema,
						   const struct ldb_message_element *element)
{
	const struct dsdb_class *last_class;

	if (schema == NULL) {
		return NULL;
	}

	if (element->num_values == 0) {
		return NULL;
	}

	last_class = dsdb_class_by_lDAPDisplayName_ldb_val(schema,
							   &element->values[element->num_values-1]);
	if (last_class == NULL) {
		return NULL;
	}
	if (last_class->objectClassCategory > 1) {
		return NULL;
	}

	return last_class;
}

const struct GUID *get_oc_guid_from_message(struct ldb_module *module,
						   const struct dsdb_schema *schema,
						   struct ldb_message *msg)
{
	struct ldb_message_element *oc_el;

	oc_el = ldb_msg_find_element(msg, "objectClass");
	if (!oc_el) {
		return NULL;
	}

	return class_schemaid_guid_by_lDAPDisplayName(schema,
						      (char *)oc_el->values[oc_el->num_values-1].data);
}


