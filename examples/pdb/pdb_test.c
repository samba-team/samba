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

static BOOL testsam_setsampwent(struct pdb_context *context, BOOL update)
{
	DEBUG(0, ("testsam_setsampwent called\n"));
	return True;
}

/***************************************************************
 End enumeration of the passwd list.
****************************************************************/

static void testsam_endsampwent(struct pdb_context *context)
{
	DEBUG(0, ("testsam_endsampwent called\n"));
}

/*****************************************************************
 Get one SAM_ACCOUNT from the list (next in line)
*****************************************************************/

static BOOL testsam_getsampwent(struct pdb_context *context, SAM_ACCOUNT *user)
{
	DEBUG(0, ("testsam_getsampwent called\n"));
	return False;
}

/******************************************************************
 Lookup a name in the SAM database
******************************************************************/

static BOOL testsam_getsampwnam (struct pdb_context *context, SAM_ACCOUNT *user, const char *sname)
{
	DEBUG(0, ("testsam_getsampwnam called\n"));
	return False;
}

/***************************************************************************
 Search by rid
 **************************************************************************/

static BOOL testsam_getsampwrid (struct pdb_context *context, SAM_ACCOUNT *user, uint32 rid)
{
	DEBUG(0, ("testsam_getsampwrid called\n"));
	return False;
}

/***************************************************************************
 Delete a SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_delete_sam_account(struct pdb_context *context, const SAM_ACCOUNT *sam_pass)
{
	DEBUG(0, ("testsam_delete_sam_account called\n"));
	return False;
}

/***************************************************************************
 Modifies an existing SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_update_sam_account (struct pdb_context *context, const SAM_ACCOUNT *newpwd)
{
	DEBUG(0, ("testsam_update_sam_account called\n"));
	return False;
}

/***************************************************************************
 Adds an existing SAM_ACCOUNT
****************************************************************************/

static BOOL testsam_add_sam_account (struct pdb_context *context, const SAM_ACCOUNT *newpwd)
{
	DEBUG(0, ("testsam_add_sam_account called\n"));
	return False;
}

NTSTATUS pdb_init(PDB_CONTEXT *pdb_context, PDB_METHODS **pdb_method, const char *location)
{
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_methods(pdb_context->mem_ctx, pdb_method))) {
		return nt_status;
	}

	(*pdb_method)->name = "testsam";

	(*pdb_method)->setsampwent = testsam_setsampwent;
	(*pdb_method)->endsampwent = testsam_endsampwent;
	(*pdb_method)->getsampwent = testsam_getsampwent;
	(*pdb_method)->getsampwnam = testsam_getsampwnam;
	(*pdb_method)->getsampwrid = testsam_getsampwrid;
	(*pdb_method)->add_sam_account = testsam_add_sam_account;
	(*pdb_method)->update_sam_account = testsam_update_sam_account;
	(*pdb_method)->delete_sam_account = testsam_delete_sam_account;
    
	DEBUG(0, ("Initializing testsam\n"));
	if (location)
		DEBUG(0, ("Location: %s\n", location));

	return NT_STATUS_OK;
}
