/*
 * Test password backend for samba
 * Copyright (C) Jelmer Vernooij 2002
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

static int testsam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS testsam_debug_level

/* define the version of the passdb interface */ 
PDB_MODULE_VERSIONING_MAGIC

/***************************************************************
 Start enumeration of the passwd list.
****************************************************************/

static BOOL testsam_setsampwent(struct pdb_methods *methods, BOOL update)
{
	DEBUG(10, ("testsam_setsampwent called\n"));
	return True;
}

/***************************************************************
 End enumeration of the passwd list.
****************************************************************/

static void testsam_endsampwent(struct pdb_methods *methods)
{
	DEBUG(10, ("testsam_endsampwent called\n"));
}

/*****************************************************************
 Get one SAM_ACCOUNT from the list (next in line)
*****************************************************************/

static BOOL testsam_getsampwent(struct pdb_methods *methods, SAM_ACCOUNT *user)
{
	DEBUG(10, ("testsam_getsampwent called\n"));
	return False;
}

/******************************************************************
 Lookup a name in the SAM database
******************************************************************/

static BOOL testsam_getsampwnam (struct pdb_methods *methods, SAM_ACCOUNT *user, const char *sname)
{
	DEBUG(10, ("testsam_getsampwnam called\n"));
	return False;
}

/***************************************************************************
 Search by sid
 **************************************************************************/

static BOOL testsam_getsampwsid (struct pdb_methods *methods, SAM_ACCOUNT *user, DOM_SID sid)
{
	DEBUG(10, ("testsam_getsampwsid called\n"));
	return False;
}

/***************************************************************************
 Delete a SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_delete_sam_account(struct pdb_methods *methods, const SAM_ACCOUNT *sam_pass)
{
	DEBUG(10, ("testsam_delete_sam_account called\n"));
	return False;
}

/***************************************************************************
 Modifies an existing SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_update_sam_account (struct pdb_methods *methods, const SAM_ACCOUNT *newpwd)
{
	DEBUG(10, ("testsam_update_sam_account called\n"));
	return False;
}

/***************************************************************************
 Adds an existing SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_add_sam_account (struct pdb_methods *methods, const SAM_ACCOUNT *newpwd)
{
	DEBUG(10, ("testsam_add_sam_account called\n"));
	return False;
}

NTSTATUS pdb_init(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "testsam";

	/* Functions your pdb module doesn't provide should be set 
	 * to NULL */

	(*pdb_method)->setsampwent = testsam_setsampwent;
	(*pdb_method)->endsampwent = testsam_endsampwent;
	(*pdb_method)->getsampwent = testsam_getsampwent;
	(*pdb_method)->getsampwnam = testsam_getsampwnam;
	(*pdb_method)->getsampwsid = testsam_getsampwsid;
	(*pdb_method)->add_sam_account = testsam_add_sam_account;
	(*pdb_method)->update_sam_account = testsam_update_sam_account;
	(*pdb_method)->delete_sam_account = testsam_delete_sam_account;

	testsam_debug_level = debug_add_class("testsam");
	if (testsam_debug_level == -1) {
		testsam_debug_level = DBGC_ALL;
		DEBUG(0, ("testsam: Couldn't register custom debugging class!\n"));
	} else DEBUG(0, ("testsam: Debug class number of 'testsam': %d\n", testsam_debug_level));
    
	DEBUG(0, ("Initializing testsam\n"));
	if (location)
		DEBUG(10, ("Location: %s\n", location));

	return NT_STATUS_OK;
}
