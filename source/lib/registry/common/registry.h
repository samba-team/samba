/* 
   Unix SMB/CIFS implementation.
   Registry interface
   This file contains the _internal_ structs for the registry 
   subsystem. Backends and the subsystem itself are the only
   files that need to include this file.
   Copyright (C) Gerald Carter                        2002.
   Copyright (C) Jelmer Vernooij					  2003-2004.
   
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

#ifndef _REGISTRY_REGISTRY_H /* _REGISTRY_REGISTRY_H */
#define _REGISTRY_REGISTRY_H 

#define REGISTRY_INTERFACE_VERSION 1

/* structure to store the registry handles */
struct reg_key_s {
  char *name;         /* Name of the key                    */
  char *path;		  /* Full path to the key */
  smb_ucs2_t *class_name; /* Name of key class */
  NTTIME last_mod; /* Time last modified                 */
  SEC_DESC *security;
  REG_HANDLE *handle;
  void *backend_data;
  REG_VAL **cache_values; 
  int cache_values_count;
  REG_KEY **cache_subkeys; 
  int cache_subkeys_count;
  int ref;
};

struct reg_val_s {
  char *name;
  int has_name;
  int data_type;
  int data_len;
  void *data_blk;    /* Might want a separate block */
  REG_HANDLE *handle;
  REG_KEY *parent;
  void *backend_data;
  int ref;
};

/* 
 * Container for function pointers to enumeration routines
 * for virtual registry view 
 */ 
 
struct reg_ops_s {
	const char *name;
	BOOL (*open_registry) (REG_HANDLE *, const char *location, BOOL try_complete_load);
	BOOL (*sync)(REG_HANDLE *, const char *location);
	BOOL (*close_registry) (REG_HANDLE *);

	/* Either implement these */
	REG_KEY *(*open_root_key) (REG_HANDLE *);
	int (*num_subkeys) (REG_KEY *);
	int (*num_values) (REG_KEY *);
	REG_KEY *(*get_subkey_by_index) (REG_KEY *, int idx);
	REG_KEY *(*get_subkey_by_name) (REG_KEY *, const char *name);
	REG_VAL *(*get_value_by_index) (REG_KEY *, int idx);
	REG_VAL *(*get_value_by_name) (REG_KEY *, const char *name);

	/* Or these */
	REG_KEY *(*open_key) (REG_HANDLE *, const char *name);
	BOOL (*fetch_subkeys) (REG_KEY *, int *count, REG_KEY ***);
	BOOL (*fetch_values) (REG_KEY *, int *count, REG_VAL ***);

	/* Key management */
	BOOL (*add_key)(REG_KEY *, const char *name);
	BOOL (*del_key)(REG_KEY *);

	/* Value management */
	REG_VAL *(*add_value)(REG_KEY *, const char *name, int type, void *data, int len);
	BOOL (*del_value)(REG_VAL *);
 	
	/* If update is not available, value will first be deleted and then added 
	 * again */
	BOOL (*update_value)(REG_VAL *, int type, void *data, int len); 

	void (*free_key_backend_data) (REG_KEY *);
	void (*free_val_backend_data) (REG_VAL *);
};

typedef struct reg_sub_tree_s {
	char *path;
	REG_HANDLE *handle;
	struct reg_sub_tree_s *prev, *next;
} REG_SUBTREE;

struct reg_handle_s {
	REG_OPS *functions;
	REG_SUBTREE *subtrees;
	char *location;
	void *backend_data;
};

struct reg_init_function_entry {
	/* Function to create a member of the pdb_methods list */
	REG_OPS *functions;
	struct reg_init_function_entry *prev, *next;
};

/* Used internally */
#define SMB_REG_ASSERT(a) { if(!(a)) { DEBUG(0,("%s failed! (%s:%d)", #a, __FILE__, __LINE__)); }}

#endif /* _REGISTRY_H */
