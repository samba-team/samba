/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) Gerald (Jerry) Carter          2004

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "utils/net.h"

/********************************************************************
********************************************************************/

static NTSTATUS sid_to_name(struct cli_state *cli, 
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid, fstring name)
{
	POLICY_HND pol;
	uint32 *sid_types;
	NTSTATUS result;
	char **domains, **names;

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
		SEC_RIGHTS_MAXIMUM_ALLOWED, &pol);
		
	if ( !NT_STATUS_IS_OK(result) )
		return result;

	result = cli_lsa_lookup_sids(cli, mem_ctx, &pol, 1, sid, &domains, &names, &sid_types);
	
	if ( NT_STATUS_IS_OK(result) ) {
		if ( *domains[0] )
			fstr_sprintf( name, "%s\\%s", domains[0], names[0] );
		else
			fstrcpy( name, names[0] );
	}

	cli_lsa_close(cli, mem_ctx, &pol);
	return result;
}

/********************************************************************
********************************************************************/

static NTSTATUS name_to_sid(struct cli_state *cli, 
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid, const char *name)
{
	POLICY_HND pol;
	uint32 *sid_types;
	NTSTATUS result;
	DOM_SID *sids;

	/* maybe its a raw SID */
	if ( strncmp(name, "S-", 2) == 0 && string_to_sid(sid, name) ) 
	{
		return NT_STATUS_OK;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True, 
		SEC_RIGHTS_MAXIMUM_ALLOWED, &pol);
		
	if ( !NT_STATUS_IS_OK(result) )
		return result;

	result = cli_lsa_lookup_names(cli, mem_ctx, &pol, 1, &name, &sids, &sid_types);
	
	if ( NT_STATUS_IS_OK(result) )
		sid_copy( sid, &sids[0] );

	cli_lsa_close(cli, mem_ctx, &pol);
	return result;
}

/********************************************************************
********************************************************************/

static NTSTATUS enum_privileges( TALLOC_CTX *ctx, struct cli_state *cli, 
                                 POLICY_HND *pol )
{
	NTSTATUS result;
	uint32 enum_context = 0;
	uint32 pref_max_length=0x1000;
	uint32 count=0;
	char   **privs_name;
	uint32 *privs_high;
	uint32 *privs_low;
	int i;
	uint16 lang_id=0;
	uint16 lang_id_sys=0;
	uint16 lang_id_desc;
	fstring description;

	result = cli_lsa_enum_privilege(cli, ctx, pol, &enum_context, 
		pref_max_length, &count, &privs_name, &privs_high, &privs_low);

	if ( !NT_STATUS_IS_OK(result) )
		return result;

	/* Print results */
	
	for (i = 0; i < count; i++) {
		d_printf("%30s  ", privs_name[i] ? privs_name[i] : "*unknown*" );
		
		/* try to get the description */
		
		if ( !NT_STATUS_IS_OK(cli_lsa_get_dispname(cli, ctx, pol, 
			privs_name[i], lang_id, lang_id_sys, description, &lang_id_desc)) )
		{
			d_printf("??????\n");
			continue;
		}
		
		d_printf("%s\n", description );		
	}

	return NT_STATUS_OK;

}

/********************************************************************
********************************************************************/

static NTSTATUS enum_privileges_for_user( TALLOC_CTX *ctx, struct cli_state *cli,
                                          POLICY_HND *pol, DOM_SID *sid )
{
	NTSTATUS result;
	uint32 count;
	char **rights;
	int i;

	result = cli_lsa_enum_account_rights(cli, ctx, pol, sid, &count, &rights);

	if (!NT_STATUS_IS_OK(result))
		return result;

	if ( count == 0 )
		d_printf("No privileges assigned\n");
		
	for (i = 0; i < count; i++) {
		printf("%s\n", rights[i]);
	}

	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS enum_privileges_for_accounts( TALLOC_CTX *ctx, struct cli_state *cli,
                                              POLICY_HND *pol )
{
	NTSTATUS result;
	uint32 enum_context=0;
	uint32 pref_max_length=0x1000;
	DOM_SID *sids;
	uint32 count=0;
	int i;
	fstring name;

	result = cli_lsa_enum_sids(cli, ctx, pol, &enum_context, 
		pref_max_length, &count, &sids);

	if (!NT_STATUS_IS_OK(result))
		return result;
		
	for ( i=0; i<count; i++ ) {
	
		/* try to convert the SID to a name.  Fall back to 
		   printing the raw SID if necessary */
		   
		result = sid_to_name( cli, ctx, &sids[i], name );
		if ( !NT_STATUS_IS_OK (result) )
			fstrcpy( name, sid_string_static(&sids[i]) );
			
		d_printf("%s\n", name);
		
		result = enum_privileges_for_user( ctx, cli, pol, &sids[i] );
		
		if ( !NT_STATUS_IS_OK(result) )
			return result;

		d_printf("\n");
	}

	return NT_STATUS_OK;
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_rights_list_internal( const DOM_SID *domain_sid, const char *domain_name, 
                            struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            int argc, const char **argv )
{
	POLICY_HND pol;
	NTSTATUS result;
	DOM_SID sid;
	
	result = cli_lsa_open_policy(cli, mem_ctx, True, 
		SEC_RIGHTS_MAXIMUM_ALLOWED, &pol);

	if ( !NT_STATUS_IS_OK(result) )
		return result;
		
	switch (argc) {
	case 0:
		result = enum_privileges( mem_ctx, cli, &pol );
		break;
			
	case 1:
		/* special case to enuemrate all privileged SIDs 
		   with associated rights */
		
		if ( strequal( argv[0], "accounts" ) ) {
			result = enum_privileges_for_accounts( mem_ctx, cli, &pol );
		}
		else {

			result = name_to_sid(cli, mem_ctx, &sid, argv[0]);
			if (!NT_STATUS_IS_OK(result))
				goto done;	
			result = enum_privileges_for_user( mem_ctx, cli, &pol, &sid );
		}
		break;
			
	default:		
		if ( argc > 1 ) {
			d_printf("Usage: net rpc rights list [name|SID]\n");
			result = NT_STATUS_OK;
		}
	}

	


done:
	cli_lsa_close(cli, mem_ctx, &pol);

	return result;
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_rights_grant_internal( const DOM_SID *domain_sid, const char *domain_name, 
                            struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            int argc, const char **argv )
{
	POLICY_HND dom_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DOM_SID sid;

	if (argc < 2 ) {
		d_printf("Usage: net rpc rights grant <name|SID> <rights...>\n");
		return NT_STATUS_OK;
	}

	result = name_to_sid(cli, mem_ctx, &sid, argv[0]);
	if (!NT_STATUS_IS_OK(result))
		return result;	

	result = cli_lsa_open_policy2(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;	

	result = cli_lsa_add_account_rights(cli, mem_ctx, &dom_pol, sid, 
					    argc-1, argv+1);

	if (!NT_STATUS_IS_OK(result))
		goto done;
		
	d_printf("Successfully granted rights.\n");

 done:
	if ( !NT_STATUS_IS_OK(result) ) {
		d_printf("Failed to grant privileges for %s (%s)\n", 
			argv[0], nt_errstr(result));
	}
		
 	cli_lsa_close(cli, mem_ctx, &dom_pol);
	
	return result;
}

/********************************************************************
********************************************************************/

static NTSTATUS rpc_rights_revoke_internal( const DOM_SID *domain_sid, const char *domain_name, 
                              struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                              int argc, const char **argv )
{
	POLICY_HND dom_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DOM_SID sid;

	if (argc < 2 ) {
		d_printf("Usage: net rpc rights revoke <name|SID> <rights...>\n");
		return NT_STATUS_OK;
	}

	result = name_to_sid(cli, mem_ctx, &sid, argv[0]);
	if (!NT_STATUS_IS_OK(result))
		return result;	

	result = cli_lsa_open_policy2(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;	

	result = cli_lsa_remove_account_rights(cli, mem_ctx, &dom_pol, sid, 
					       False, argc-1, argv+1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	d_printf("Successfully revoked rights.\n");

done:
	if ( !NT_STATUS_IS_OK(result) ) {
		d_printf("Failed to revoke privileges for %s (%s)", 
			argv[0], nt_errstr(result));
	}
	
	cli_lsa_close(cli, mem_ctx, &dom_pol);

	return result;
}	


/********************************************************************
********************************************************************/

static int rpc_rights_list( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_list_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_rights_grant( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_grant_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int rpc_rights_revoke( int argc, const char **argv )
{
	return run_rpc_command( NULL, PI_LSARPC, 0, 
		rpc_rights_revoke_internal, argc, argv );
}

/********************************************************************
********************************************************************/

static int net_help_rights( int argc, const char **argv )
{
	d_printf("net rpc rights list [accounts|username]   View available or assigned privileges\n");
	d_printf("net rpc rights grant <name|SID> <right>   Assign privilege[s]\n");
	d_printf("net rpc rights revoke <name|SID> <right>  Revoke privilege[s]\n");
	
	d_printf("\nBoth 'grant' and 'revoke' require a SID and a list of privilege names.\n");
	d_printf("For example\n");
	d_printf("\n  net rpc rights grant 'VALE\\biddle' SePrintOperatorPrivilege SeDiskOperatorPrivilege\n");
	d_printf("\nwould grant the printer admin and disk manager rights to the user 'VALE\\biddle'\n\n");
	
	
	return -1;
}

/********************************************************************
********************************************************************/

int net_rpc_rights(int argc, const char **argv) 
{
	struct functable func[] = {
		{"list", rpc_rights_list},
		{"grant", rpc_rights_grant},
		{"revoke", rpc_rights_revoke},
		{NULL, NULL}
	};
	
	if ( argc )
		return net_run_function( argc, argv, func, net_help_rights );
		
	return net_help_rights( argc, argv );
}


