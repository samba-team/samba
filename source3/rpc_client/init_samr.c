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

/*************************************************************************
 inits a samr_CryptPasswordEx structure
 *************************************************************************/

void init_samr_CryptPasswordEx(const char *pwd,
			       DATA_BLOB *session_key,
			       struct samr_CryptPasswordEx *pwd_buf)
{
	/* samr_CryptPasswordEx */

	uchar pwbuf[532];
	struct MD5Context md5_ctx;
	uint8_t confounder[16];
	DATA_BLOB confounded_session_key = data_blob(NULL, 16);

	encode_pw_buffer(pwbuf, pwd, STR_UNICODE);

	generate_random_buffer((uint8_t *)confounder, 16);

	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, confounder, 16);
	MD5Update(&md5_ctx, session_key->data,
			    session_key->length);
	MD5Final(confounded_session_key.data, &md5_ctx);

	SamOEMhashBlob(pwbuf, 516, &confounded_session_key);
	memcpy(&pwbuf[516], confounder, 16);

	memcpy(pwd_buf->data, pwbuf, sizeof(pwbuf));
	data_blob_free(&confounded_session_key);
}

/*************************************************************************
 inits a samr_CryptPassword structure
 *************************************************************************/

void init_samr_CryptPassword(const char *pwd,
			     DATA_BLOB *session_key,
			     struct samr_CryptPassword *pwd_buf)
{
	/* samr_CryptPassword */

	encode_pw_buffer(pwd_buf->data, pwd, STR_UNICODE);
	SamOEMhashBlob(pwd_buf->data, 516, session_key);
}
