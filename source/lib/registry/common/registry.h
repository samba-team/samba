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
  int hive;
  TALLOC_CTX *mem_ctx;
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
  TALLOC_CTX *mem_ctx;
  int ref;
};

/* FIXME */
typedef void (*key_notification_function) (void);
typedef void (*value_notification_function) (void);

/* 
 * Container for function pointers to enumeration routines
 * for virtual registry view 
 *
 * Backends can provide :
 *  - just one hive (example: nt4, w95)
 *  - several hives (example: rpc)
 * 
 */ 
 
struct registry_ops {
	const char *name;
	WERROR (*open_registry) (REG_HANDLE *, const char *location, const char *credentials);
	WERROR (*sync_key)(REG_KEY *, const char *location);
	WERROR (*close_registry) (REG_HANDLE *);

	/* Implement this one */
	WERROR (*get_hive) (REG_HANDLE *, int , REG_KEY **);

	/* Or this one */
	WERROR (*open_key) (REG_HANDLE *, int hive, const char *name, REG_KEY **);

	/* Either implement these */
	WERROR (*num_subkeys) (REG_KEY *, int *count);
	WERROR (*num_values) (REG_KEY *, int *count);
	WERROR (*get_subkey_by_index) (REG_KEY *, int idx, REG_KEY **);
	/* Can not contain more then one level */
	WERROR (*get_subkey_by_name) (REG_KEY *, const char *name, REG_KEY **);
	WERROR (*get_value_by_index) (REG_KEY *, int idx, REG_VAL **);
	/* Can not contain more then one level */
	WERROR (*get_value_by_name) (REG_KEY *, const char *name, REG_VAL **);

	/* Or these */
	WERROR (*fetch_subkeys) (REG_KEY *, int *count, REG_KEY ***);
	WERROR (*fetch_values) (REG_KEY *, int *count, REG_VAL ***);

	/* Security control */
	WERROR (*key_get_sec_desc) (REG_KEY *, SEC_DESC **);
	WERROR (*key_set_sec_desc) (REG_KEY *, SEC_DESC *);

	/* Notification */
	WERROR (*request_key_change_notify) (REG_KEY *, key_notification_function);
	WERROR (*request_value_change_notify) (REG_VAL *, value_notification_function);

	/* Key management */
	WERROR (*add_key)(REG_KEY *, const char *name, uint32 access_mask, SEC_DESC *, REG_KEY **);
	WERROR (*del_key)(REG_KEY *);

	/* Value management */
	WERROR (*add_value)(REG_KEY *, const char *name, int type, void *data, int len);
	WERROR (*del_value)(REG_VAL *);
 	
	/* If update is not available, value will first be deleted and then added 
	 * again */
	WERROR (*update_value)(REG_VAL *, int type, void *data, int len); 

	void (*free_key_backend_data) (REG_KEY *);
	void (*free_val_backend_data) (REG_VAL *);
};

struct reg_handle_s {
	struct registry_ops *functions;
	char *location;
	char *credentials;
	void *backend_data;
	TALLOC_CTX *mem_ctx;
};

struct reg_init_function_entry {
	/* Function to create a member of the pdb_methods list */
	struct registry_ops *functions;
	struct reg_init_function_entry *prev, *next;
};

/* Used internally */
#define SMB_REG_ASSERT(a) { if(!(a)) { DEBUG(0,("%s failed! (%s:%d)", #a, __FILE__, __LINE__)); }}

#endif /* _REGISTRY_H */
