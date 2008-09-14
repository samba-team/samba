/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
	name->size = 2 * strlen_m(s);
	name->length = name->size;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 Inits an lsa_QosInfo structure.
********************************************************************/

void init_lsa_sec_qos(struct lsa_QosInfo *r,
		      uint32_t len,
		      uint16_t impersonation_level,
		      uint8_t context_mode,
		      uint8_t effective_only)
{
	DEBUG(5, ("init_lsa_sec_qos\n"));

	r->len = len;
	r->impersonation_level = impersonation_level;
	r->context_mode = context_mode;
	r->effective_only = effective_only;
}

/*******************************************************************
 Inits an lsa_ObjectAttribute structure.
********************************************************************/

void init_lsa_obj_attr(struct lsa_ObjectAttribute *r,
		       uint32_t len,
		       uint8_t *root_dir,
		       const char *object_name,
		       uint32_t attributes,
		       struct security_descriptor *sec_desc,
		       struct lsa_QosInfo *sec_qos)
{
	DEBUG(5,("init_lsa_obj_attr\n"));

	r->len = len;
	r->root_dir = root_dir;
	r->object_name = object_name;
	r->attributes = attributes;
	r->sec_desc = sec_desc;
	r->sec_qos = sec_qos;
}

/*******************************************************************
 Inits a lsa_TranslatedSid structure.
********************************************************************/

void init_lsa_translated_sid(struct lsa_TranslatedSid *r,
			     enum lsa_SidType sid_type,
			     uint32_t rid,
			     uint32_t sid_index)
{
	r->sid_type = sid_type;
	r->rid = rid;
	r->sid_index = sid_index;
}

/*******************************************************************
 Inits a lsa_TranslatedName2 structure.
********************************************************************/

void init_lsa_translated_name2(struct lsa_TranslatedName2 *r,
			       enum lsa_SidType sid_type,
			       const char *name,
			       uint32_t sid_index,
			       uint32_t unknown)
{
	r->sid_type = sid_type;
	init_lsa_String(&r->name, name);
	r->sid_index = sid_index;
	r->unknown = unknown;
}
