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

typedef struct pdb_context 
{
	struct pdb_methods *pdb_selected;
	
	/* These functions are wrappers for the functions listed above.
	   They may do extra things like re-reading a SAM_ACCOUNT on update */

	BOOL (*pdb_setsampwent)(struct pdb_context *, BOOL update);
	
	void (*pdb_endsampwent)(struct pdb_context *);
	
	BOOL (*pdb_getsampwent)(struct pdb_context *, SAM_ACCOUNT *user);
	
	BOOL (*pdb_getsampwnam)(struct pdb_context *, SAM_ACCOUNT *sam_acct, const char *username);
	
	BOOL (*pdb_getsampwrid)(struct pdb_context *, SAM_ACCOUNT *sam_acct, uint32 rid);
	
	BOOL (*pdb_add_sam_account)(struct pdb_context *, SAM_ACCOUNT *sampass);
	
	BOOL (*pdb_update_sam_account)(struct pdb_context *, SAM_ACCOUNT *sampass);
	
	BOOL (*pdb_delete_sam_account)(struct pdb_context *, SAM_ACCOUNT *username);
	
	void (*free_fn)(struct pdb_context **);
	
	TALLOC_CTX *mem_ctx;
	
} PDB_CONTEXT;

typedef struct pdb_methods 
{
	const char *name; /* What name got this module */

	BOOL (*setsampwent)(struct pdb_context *, BOOL update);
	
	void (*endsampwent)(struct pdb_context *);
	
	BOOL (*getsampwent)(struct pdb_context *, SAM_ACCOUNT *user);
	
	BOOL (*getsampwnam)(struct pdb_context *, SAM_ACCOUNT *sam_acct, const char *username);
	
	BOOL (*getsampwrid)(struct pdb_context *, SAM_ACCOUNT *sam_acct, uint32 rid);
	
	BOOL (*add_sam_account)(struct pdb_context *, const SAM_ACCOUNT *sampass);
	
	BOOL (*update_sam_account)(struct pdb_context *, const SAM_ACCOUNT *sampass);
	
	BOOL (*delete_sam_account)(struct pdb_context *, const SAM_ACCOUNT *username);
	
	void *private_data;  /* Private data of some kind */
	
	void (*free_private_data)(void **);

} PDB_METHODS;

typedef NTSTATUS (*pdb_init_function)(struct pdb_context *, 
			 struct pdb_methods **, 
			 const char *);

struct pdb_init_function_entry {
	char *name;
	/* Function to create a member of the authmethods list */
	NTSTATUS (*init)(struct pdb_context *pdb_context, 
			 struct pdb_methods **pdb_method, 
			 const char *location);
};

#endif /* _PASSDB_H */
