/* 
   Unix SMB/CIFS implementation.
   Registry interface
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

#ifndef _REGISTRY_H /* _REGISTRY_H */
#define _REGISTRY_H 

/* Handles for the predefined keys */
enum reg_predefined_key {
	HKEY_CLASSES_ROOT		= 0x80000000,
	HKEY_CURRENT_USER		= 0x80000001,
	HKEY_LOCAL_MACHINE		= 0x80000002,
	HKEY_USERS				= 0x80000003,
	HKEY_PERFORMANCE_DATA	= 0x80000004,
	HKEY_CURRENT_CONFIG		= 0x80000005,
	HKEY_DYN_DATA			= 0x80000006,
	HKEY_PERFORMANCE_TEXT	= 0x80000050,
	HKEY_PERFORMANCE_NLSTEXT= 0x80000060
};

/* Registry data types */

#define	REG_DELETE								   -1
#define	REG_NONE									0
#define	REG_SZ										1
#define	REG_EXPAND_SZ								2
#define	REG_BINARY									3
#define	REG_DWORD_LE								4 
#define	REG_DWORD						 REG_DWORD_LE
#define	REG_DWORD_BE								5 
#define	REG_LINK									6
#define	REG_MULTI_SZ								7
#define	REG_RESOURCE_LIST							8
#define	REG_FULL_RESOURCE_DESCRIPTOR				9
#define	REG_RESOURCE_REQUIREMENTS_LIST				10
#define REG_QWORD_LE								11
#define REG_QWORD						 REQ_QWORD_LE

#if 0
/* FIXME */
typedef struct ace_struct_s {
  uint8_t type, flags;
  uint_t perms;   /* Perhaps a better def is in order */
  DOM_SID *trustee;
} ACE;
#endif

/*
 * The general idea here is that every backend provides a 'hive'. Combining
 * various hives gives you a complete registry like windows has
 */

#define REGISTRY_INTERFACE_VERSION 1

/* structure to store the registry handles */
struct registry_key {
  char *name;         /* Name of the key                    */
  const char *path;		  /* Full path to the key */
  char *class_name; /* Name of key class */
  NTTIME last_mod; /* Time last modified                 */
  SEC_DESC *security;
  struct registry_hive *hive;
  void *backend_data;
  int ref;
};

struct registry_value {
  char *name;
  unsigned int data_type;
  int data_len;
  void *data_blk;    /* Might want a separate block */
  struct registry_hive *hive;
  struct registry_key *parent;
  void *backend_data;
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
 *  - several hives (example: rpc).
 * 
 */ 

struct hive_operations {
	const char *name;

	/* Implement this one */
	WERROR (*open_hive) (struct registry_hive *, struct registry_key **);

	/* Or this one */
	WERROR (*open_key) (TALLOC_CTX *, struct registry_key *, const char *name, struct registry_key **);

	/* Either implement these */
	WERROR (*num_subkeys) (struct registry_key *, int *count);
	WERROR (*num_values) (struct registry_key *, int *count);
	WERROR (*get_subkey_by_index) (TALLOC_CTX *, struct registry_key *, int idx, struct registry_key **);

	/* Can not contain more then one level */
	WERROR (*get_subkey_by_name) (TALLOC_CTX *, struct registry_key *, const char *name, struct registry_key **);
	WERROR (*get_value_by_index) (TALLOC_CTX *, struct registry_key *, int idx, struct registry_value **);

	/* Can not contain more then one level */
	WERROR (*get_value_by_name) (TALLOC_CTX *, struct registry_key *, const char *name, struct registry_value **);

	/* Security control */
	WERROR (*key_get_sec_desc) (TALLOC_CTX *, struct registry_key *, SEC_DESC **);
	WERROR (*key_set_sec_desc) (struct registry_key *, SEC_DESC *);

	/* Notification */
	WERROR (*request_key_change_notify) (struct registry_key *, key_notification_function);
	WERROR (*request_value_change_notify) (struct registry_value *, value_notification_function);

	/* Key management */
	WERROR (*add_key)(TALLOC_CTX *, struct registry_key *, const char *name, uint32_t access_mask, SEC_DESC *, struct registry_key **);
	WERROR (*del_key)(struct registry_key *);
	WERROR (*flush_key) (struct registry_key *);

	/* Value management */
	WERROR (*set_value)(struct registry_key *, const char *name, int type, void *data, int len); 
	WERROR (*del_value)(struct registry_value *);
};

struct registry_hive {
	const struct hive_operations *functions;
	struct registry_key *root;
	void *backend_data;
	const char *location;
};

/* Handle to a full registry
 * contains zero or more hives */
struct registry_context {
    void *backend_data;
	WERROR (*get_predefined_key) (struct registry_context *, uint32 hkey, struct registry_key **);
};

struct reg_init_function_entry {
	/* Function to create a member of the pdb_methods list */
	const struct hive_operations *hive_functions;
	struct reg_init_function_entry *prev, *next;
};

/* Used internally */
#define SMB_REG_ASSERT(a) { if(!(a)) { DEBUG(0,("%s failed! (%s:%d)", #a, __FILE__, __LINE__)); }}

#endif /* _REGISTRY_H */
