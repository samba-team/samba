/* 
   Unix SMB/CIFS implementation.
   passdb structures and parameters
   Copyright (C) Gerald Carter 2001
   Copyright (C) Luke Kenneth Casson Leighton 1998 - 2000
   
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

#ifndef _PASSDB_H
#define _PASSDB_H


/*****************************************************************
 Functions to be implemented by the new (v2) passdb API 
****************************************************************/

/*
 * This next constant specifies the version number of the PASSDB interface
 * this SAMBA will load. Increment this if *ANY* changes are made to the interface. 
 */

#define PASSDB_INTERFACE_VERSION 4

/* use this inside a passdb module */
#define PDB_MODULE_VERSIONING_MAGIC \
int pdb_version(void)\
{\
	return PASSDB_INTERFACE_VERSION;\
}

typedef struct pdb_context 
{
	struct pdb_methods *pdb_methods;
	struct pdb_methods *pwent_methods;
	
	/* These functions are wrappers for the functions listed above.
	   They may do extra things like re-reading a SAM_ACCOUNT on update */

	NTSTATUS (*pdb_setsampwent)(struct pdb_context *, BOOL update);
	
	void (*pdb_endsampwent)(struct pdb_context *);
	
	NTSTATUS (*pdb_getsampwent)(struct pdb_context *, SAM_ACCOUNT *user);
	
	NTSTATUS (*pdb_getsampwnam)(struct pdb_context *, SAM_ACCOUNT *sam_acct, const char *username);
	
	NTSTATUS (*pdb_getsampwsid)(struct pdb_context *, SAM_ACCOUNT *sam_acct, const DOM_SID *sid);
	
	NTSTATUS (*pdb_add_sam_account)(struct pdb_context *, SAM_ACCOUNT *sampass);
	
	NTSTATUS (*pdb_update_sam_account)(struct pdb_context *, SAM_ACCOUNT *sampass);
	
	NTSTATUS (*pdb_delete_sam_account)(struct pdb_context *, SAM_ACCOUNT *username);

	NTSTATUS (*pdb_getgrsid)(struct pdb_context *context, GROUP_MAP *map,
				 DOM_SID sid, BOOL with_priv);
	
	NTSTATUS (*pdb_getgrgid)(struct pdb_context *context, GROUP_MAP *map,
				 gid_t gid, BOOL with_priv);
	
	NTSTATUS (*pdb_getgrnam)(struct pdb_context *context, GROUP_MAP *map,
				 char *name, BOOL with_priv);
	
	NTSTATUS (*pdb_add_group_mapping_entry)(struct pdb_context *context,
						GROUP_MAP *map);
	
	NTSTATUS (*pdb_update_group_mapping_entry)(struct pdb_context *context,
						   GROUP_MAP *map);
	
	NTSTATUS (*pdb_delete_group_mapping_entry)(struct pdb_context *context,
						   DOM_SID sid);
	
	NTSTATUS (*pdb_enum_group_mapping)(struct pdb_context *context,
					   enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **rmap, int *num_entries,
					   BOOL unix_only, BOOL with_priv);

	void (*free_fn)(struct pdb_context **);
	
	TALLOC_CTX *mem_ctx;
	
} PDB_CONTEXT;

typedef struct pdb_methods 
{
	const char *name; /* What name got this module */
	struct pdb_context *parent;

	/* Use macros from dlinklist.h on these two */
	struct pdb_methods *next;
	struct pdb_methods *prev;

	NTSTATUS (*setsampwent)(struct pdb_methods *, BOOL update);
	
	void (*endsampwent)(struct pdb_methods *);
	
	NTSTATUS (*getsampwent)(struct pdb_methods *, SAM_ACCOUNT *user);
	
	NTSTATUS (*getsampwnam)(struct pdb_methods *, SAM_ACCOUNT *sam_acct, const char *username);
	
	NTSTATUS (*getsampwsid)(struct pdb_methods *, SAM_ACCOUNT *sam_acct, const DOM_SID *Sid);
	
	NTSTATUS (*add_sam_account)(struct pdb_methods *, SAM_ACCOUNT *sampass);
	
	NTSTATUS (*update_sam_account)(struct pdb_methods *, SAM_ACCOUNT *sampass);
	
	NTSTATUS (*delete_sam_account)(struct pdb_methods *, SAM_ACCOUNT *username);
	
	NTSTATUS (*getgrsid)(struct pdb_methods *methods, GROUP_MAP *map,
			     DOM_SID sid, BOOL with_priv);

	NTSTATUS (*getgrgid)(struct pdb_methods *methods, GROUP_MAP *map,
			     gid_t gid, BOOL with_priv);

	NTSTATUS (*getgrnam)(struct pdb_methods *methods, GROUP_MAP *map,
			     char *name, BOOL with_priv);

	NTSTATUS (*add_group_mapping_entry)(struct pdb_methods *methods,
					    GROUP_MAP *map);

	NTSTATUS (*update_group_mapping_entry)(struct pdb_methods *methods,
					       GROUP_MAP *map);

	NTSTATUS (*delete_group_mapping_entry)(struct pdb_methods *methods,
					       DOM_SID sid);

	NTSTATUS (*enum_group_mapping)(struct pdb_methods *methods,
				       enum SID_NAME_USE sid_name_use,
				       GROUP_MAP **rmap, int *num_entries,
				       BOOL unix_only, BOOL with_priv);

	void *private_data;  /* Private data of some kind */
	
	void (*free_private_data)(void **);

} PDB_METHODS;

typedef NTSTATUS (*pdb_init_function)(struct pdb_context *, 
			 struct pdb_methods **, 
			 const char *);

struct pdb_init_function_entry {
	const char *name;
	/* Function to create a member of the pdb_methods list */
	pdb_init_function init;
};

#endif /* _PASSDB_H */
