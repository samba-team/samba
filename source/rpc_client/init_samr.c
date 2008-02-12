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

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo1(struct samr_DomInfo1 *r,
			uint16_t min_password_length,
			uint16_t password_history_length,
			uint32_t password_properties,
			int64_t max_password_age,
			int64_t min_password_age)
{
	r->min_password_length = min_password_length;
	r->password_history_length = password_history_length;
	r->password_properties = password_properties;
	r->max_password_age = max_password_age;
	r->min_password_age = min_password_age;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo2(struct samr_DomInfo2 *r,
			NTTIME force_logoff_time,
			const char *comment,
			const char *domain_name,
			const char *primary,
			uint64_t sequence_num,
			uint32_t unknown2,
			enum samr_Role role,
			uint32_t unknown3,
			uint32_t num_users,
			uint32_t num_groups,
			uint32_t num_aliases)
{
	r->force_logoff_time = force_logoff_time;
	init_lsa_String(&r->comment, comment);
	init_lsa_String(&r->domain_name, domain_name);
	init_lsa_String(&r->primary, primary);
	r->sequence_num = sequence_num;
	r->unknown2 = unknown2;
	r->role = role;
	r->unknown3 = unknown3;
	r->num_users = num_users;
	r->num_groups = num_groups;
	r->num_aliases = num_aliases;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo3(struct samr_DomInfo3 *r,
			NTTIME force_logoff_time)
{
	r->force_logoff_time = force_logoff_time;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo4(struct samr_DomInfo4 *r,
			const char *comment)
{
	init_lsa_String(&r->comment, comment);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo5(struct samr_DomInfo5 *r,
			const char *domain_name)
{
	init_lsa_String(&r->domain_name, domain_name);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo6(struct samr_DomInfo6 *r,
			const char *primary)
{
	init_lsa_String(&r->primary, primary);
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo7(struct samr_DomInfo7 *r,
			enum samr_Role role)
{
	r->role = role;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo8(struct samr_DomInfo8 *r,
			uint64_t sequence_num,
			NTTIME domain_create_time)
{
	r->sequence_num = sequence_num;
	r->domain_create_time = domain_create_time;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo9(struct samr_DomInfo9 *r,
			uint32_t unknown)
{
	r->unknown = unknown;
}

/*******************************************************************
 inits a structure.
********************************************************************/

void init_samr_DomInfo12(struct samr_DomInfo12 *r,
			 uint64_t lockout_duration,
			 uint64_t lockout_window,
			 uint16_t lockout_threshold)
{
	r->lockout_duration = lockout_duration;
	r->lockout_window = lockout_window;
	r->lockout_threshold = lockout_threshold;
}

/*******************************************************************
 inits a samr_GroupInfoAll structure.
********************************************************************/

void init_samr_group_info1(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_group_info1\n"));

	init_lsa_String(&r->name, name);
	r->attributes = attributes;
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
 inits a lsa_String structure
********************************************************************/

void init_samr_group_info2(struct lsa_String *r, const char *group_name)
{
	DEBUG(5, ("init_samr_group_info2\n"));

	init_lsa_String(r, group_name);
}

/*******************************************************************
 inits a samr_GroupInfoAttributes structure.
********************************************************************/

void init_samr_group_info3(struct samr_GroupInfoAttributes *r,
			   uint32_t attributes)
{
	DEBUG(5, ("init_samr_group_info3\n"));

	r->attributes = attributes;
}

/*******************************************************************
 inits a lsa_String structure
********************************************************************/

void init_samr_group_info4(struct lsa_String *r, const char *description)
{
	DEBUG(5, ("init_samr_group_info4\n"));

	init_lsa_String(r, description);
}

/*******************************************************************
 inits a samr_GroupInfoAll structure.
********************************************************************/

void init_samr_group_info5(struct samr_GroupInfoAll *r,
			   const char *name,
			   uint32_t attributes,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_group_info5\n"));

	init_lsa_String(&r->name, name);
	r->attributes = attributes;
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
 inits a samr_AliasInfoAll structure.
********************************************************************/

void init_samr_alias_info1(struct samr_AliasInfoAll *r,
			   const char *name,
			   uint32_t num_members,
			   const char *description)
{
	DEBUG(5, ("init_samr_alias_info1\n"));

	init_lsa_String(&r->name, name);
	r->num_members = num_members;
	init_lsa_String(&r->description, description);
}

/*******************************************************************
inits a lsa_String structure.
********************************************************************/

void init_samr_alias_info3(struct lsa_String *r,
			   const char *description)
{
	DEBUG(5, ("init_samr_alias_info3\n"));

	init_lsa_String(r, description);
}

