/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *
 *  Copyright (C) Andrew Tridgell		1992-1997,
 *  Copyright (C) Gerald (Jerry) Carter		2006.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* This is the implementation of the wks interface. */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 Fill in the valiues for the struct wkssvc_NetWkstaInfo100.
 ********************************************************************/

static void create_wks_info_100(struct wkssvc_NetWkstaInfo100 *info100)
{
	pstring my_name;
	pstring domain;

	pstrcpy (my_name, global_myname());
	strupper_m(my_name);

	pstrcpy (domain, lp_workgroup());
	strupper_m(domain);
	
	info100->platform_id     = 0x000001f4; 	/* unknown */
	info100->version_major   = lp_major_announce_version(); 
	info100->version_minor   = lp_minor_announce_version();   

	info100->server_name = talloc_strdup( info100, my_name );
	info100->domain_name = talloc_strdup( info100, domain );

	return;
}

/********************************************************************
 only supports info level 100 at the moment.
 ********************************************************************/

WERROR _wkssvc_NetWkstaGetInfo( pipes_struct *p, const char *server_name, uint32_t level, 
                                 union wkssvc_NetWkstaInfo *info )
{
	struct wkssvc_NetWkstaInfo100 *wks100 = NULL;
	
	/* We only support info level 100 currently */
	
	if ( level != 100 ) {
		return WERR_UNKNOWN_LEVEL;
	}

	if ( (wks100 = TALLOC_ZERO_P(p->mem_ctx, struct wkssvc_NetWkstaInfo100)) == NULL ) {
		return WERR_NOMEM;
	}

	create_wks_info_100( wks100 );
	
	info->info100 = wks100;

	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetWkstaSetInfo( pipes_struct *p, const char *server_name, 
                                uint32_t level, union wkssvc_NetWkstaInfo *info,
                                uint32_t *parm_error )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetWkstaEnumUsers( pipes_struct *p, const char *server_name,
                                  uint32_t level, 
                                  union WKS_USER_ENUM_UNION *users,
                                  uint32_t prefmaxlen, uint32_t *entriesread,
                                  uint32_t *totalentries, 
                                  uint32_t *resumehandle )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRWKSTAUSERGETINFO( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRWKSTAUSERSETINFO( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetWkstaTransportEnum( pipes_struct *p, const char *server_name, uint32_t *level, union wkssvc_NetWkstaTransportCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRWKSTATRANSPORTADD( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRWKSTATRANSPORTDEL( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRUSEADD( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRUSEGETINFO( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRUSEDEL( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRUSEENUM( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRMESSAGEBUFFERSEND( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRWORKSTATIONSTATISTICSGET( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRLOGONDOMAINNAMEADD( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRLOGONDOMAINNAMEDEL( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRJOINDOMAIN( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRUNJOINDOMAIN( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRRENAMEMACHINEINDOMAIN( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRVALIDATENAME( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRGETJOININFORMATION( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRGETJOINABLEOUS( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetrJoinDomain2(pipes_struct *p, const char *server_name, const char *domain_name, const char *account_name, const char *admin_account, struct wkssvc_PasswordBuffer *encrypted_password, uint32_t join_flags)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetrUnjoinDomain2(pipes_struct *p, const char *server_name, const char *account, struct wkssvc_PasswordBuffer *encrypted_password, uint32_t unjoin_flags)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetrRenameMachineInDomain2(pipes_struct *p, const char *server_name, const char *NewMachineName, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t RenameOptions)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRVALIDATENAME2( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRGETJOINABLEOUS2( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetrAddAlternateComputerName(pipes_struct *p, const char *server_name, const char *NewAlternateMachineName, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t Reserved)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _wkssvc_NetrRemoveAlternateComputerName(pipes_struct *p, const char *server_name, const char *AlternateMachineNameToRemove, const char *Account, struct wkssvc_PasswordBuffer *EncryptedPassword, uint32_t Reserved)
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRSETPRIMARYCOMPUTERNAME( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

/********************************************************************
 ********************************************************************/

WERROR _WKSSVC_NETRENUMERATECOMPUTERNAMES( pipes_struct *p )
{
	/* FIXME: Add implementation code here */
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

