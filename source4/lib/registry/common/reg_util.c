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

char *reg_val_data_string(REG_VAL *v)
{ 
  char *asciip;
  char *ret = NULL;
  int i;

  if(reg_val_size(v) == 0) return strdup("");

  switch (reg_val_type(v)) {
  case REG_SZ:
	  /* FIXME: Convert to ascii */
	  return strndup(reg_val_data_blk(v), reg_val_size(v));

  case REG_EXPAND_SZ:
	  return strndup(reg_val_data_blk(v), reg_val_size(v));

  case REG_BINARY:
	  ret = malloc(reg_val_size(v) * 3 + 2);
	  asciip = ret;
	  for (i=0; i<reg_val_size(v); i++) { 
		  int str_rem = reg_val_size(v) * 3 - (asciip - ret);
		  asciip += snprintf(asciip, str_rem, "%02x", *(uint8_t *)(reg_val_data_blk(v)+i));
		  if (i < reg_val_size(v) && str_rem > 0)
			  *asciip = ' '; asciip++;	
	  }
	  *asciip = '\0';
	  return ret;
	  break;

  case REG_DWORD:
	  if (*(int *)reg_val_data_blk(v) == 0)
		  ret = strdup("0");
	  else
		  asprintf(&ret, "0x%x", *(int *)reg_val_data_blk(v));
	  break;

  case REG_MULTI_SZ:
	/* FIXME */
    break;

  default:
    return 0;
    break;
  } 

  return ret;
}

char *reg_val_description(REG_VAL *val) 
{
	char *ret, *ds = reg_val_data_string(val);
	asprintf(&ret, "%s = %s : %s", reg_val_name(val)?reg_val_name(val):"<No Name>", str_regtype(reg_val_type(val)), ds);
	free(ds);
	return ret;
}

BOOL reg_val_set_string(REG_VAL *val, char *str)
{
	/* FIXME */
	return False;
}

WERROR reg_key_get_subkey_val(REG_KEY *key, const char *subname, const char *valname, REG_VAL **val)
{
	REG_KEY *k;
	WERROR error = reg_key_get_subkey_by_name(key, subname, &k);
	if(!W_ERROR_IS_OK(error)) return error;
	
	return reg_key_get_value_by_name(k, valname, val);
}

WERROR reg_key_set_subkey_val(REG_KEY *key, const char *subname, const char *valname, uint32_t type, uint8_t *data, int real_len)
{
	REG_KEY *k;
	REG_VAL *v;
	WERROR error;

	error = reg_key_get_subkey_by_name(key, subname, &k);
	if(!W_ERROR_IS_OK(error)) return error;

	error = reg_key_get_value_by_name(k, valname, &v);
	if(!W_ERROR_IS_OK(error)) return error;
	
	return reg_val_update(v, type, data, real_len);
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
