/* 
   Unix SMB/CIFS implementation.
   Transparent registry backend handling
   Copyright (C) Jelmer Vernooij			2003-2004.

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

/* Return string description of registry value type */
const char *str_regtype(int type)
{
	switch(type) {
	case REG_SZ: return "STRING";
	case REG_DWORD: return "DWORD";
	case REG_BINARY: return "BINARY";
	}
	return "Unknown";
}

char *reg_val_data_string(TALLOC_CTX *mem_ctx, struct registry_value *v)
{ 
  char *asciip;
  char *ret = NULL;
  int i;

  if(v->data_len == 0) return talloc_strdup(mem_ctx, "");

  switch (v->data_type) {
  case REG_SZ:
	  return talloc_strndup(mem_ctx, v->data_blk, v->data_len);

  case REG_EXPAND_SZ:
	  return talloc_strndup(mem_ctx, v->data_blk, v->data_len);

  case REG_BINARY:
	  ret = talloc(mem_ctx, v->data_len * 3 + 2);
	  asciip = ret;
	  for (i=0; i<v->data_len; i++) { 
		  int str_rem = v->data_len * 3 - (asciip - ret);
		  asciip += snprintf(asciip, str_rem, "%02x", *(uint8_t *)(v->data_blk+i));
		  if (i < v->data_len && str_rem > 0)
			  *asciip = ' '; asciip++;	
	  }
	  *asciip = '\0';
	  return ret;

  case REG_DWORD:
	  if (*(int *)v->data_blk == 0)
		  return talloc_strdup(mem_ctx, "0");

	  return talloc_asprintf(mem_ctx, "0x%x", *(int *)v->data_blk);

  case REG_MULTI_SZ:
	/* FIXME */
    break;

  default:
    break;
  } 

  return ret;
}

char *reg_val_description(TALLOC_CTX *mem_ctx, struct registry_value *val) 
{
	return talloc_asprintf(mem_ctx, "%s = %s : %s", val->name?val->name:"<No Name>", str_regtype(val->data_type), reg_val_data_string(mem_ctx, val));
}

BOOL reg_val_set_string(struct registry_value *val, char *str)
{
	/* FIXME */
	return False;
}

WERROR reg_key_get_subkey_val(TALLOC_CTX *mem_ctx, struct registry_key *key, const char *subname, const char *valname, struct registry_value **val)
{
	struct registry_key *k;
	WERROR error = reg_key_get_subkey_by_name(mem_ctx, key, subname, &k);
	if(!W_ERROR_IS_OK(error)) return error;
	
	return reg_key_get_value_by_name(mem_ctx, k, valname, val);
}

/***********************************************************************
 Utility function for splitting the base path of a registry path off
 by setting base and new_path to the apprapriate offsets withing the
 path.
 
 WARNING!!  Does modify the original string!
 ***********************************************************************/

BOOL reg_split_path( char *path, char **base, char **new_path )
{
	char *p;
	
	*new_path = *base = NULL;
	
	if ( !path)
		return False;
	
	*base = path;
	
	p = strchr( path, '\\' );
	
	if ( p ) {
		*p = '\0';
		*new_path = p+1;
	}
	
	return True;
}

/**
 * Replace all \'s with /'s
 */
char *reg_path_win2unix(char *path) 
{
	int i;
	for(i = 0; path[i]; i++) {
		if(path[i] == '\\') path[i] = '/';
	}
	return path;
}
/**
 * Replace all /'s with \'s
 */
char *reg_path_unix2win(char *path) 
{
	int i;
	for(i = 0; path[i]; i++) {
		if(path[i] == '/') path[i] = '\\';
	}
	return path;
}
