/* 
   Unix SMB/Netbios implementation.
   Version 3.0.
   Authentication utility functions
   Copyright (C) Andrew Bartlett 2001

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

const struct auth_init_function builtin_auth_init_functions[] = {
	{ "guest", auth_init_guest },
	{ "rhosts", auth_init_rhosts },
	{ "hostsequiv", auth_init_hostsequiv },
	{ "sam", auth_init_sam },
	{ "unix", auth_init_unix },
	{ "local", auth_init_local },
	{ "smbserver", auth_init_smbserver },
	{ "ntdomain", auth_init_ntdomain },
	{ "winbind", auth_init_winbind },
#ifdef DEVELOPER
	{ "name_to_ntstatus", auth_init_name_to_ntstatus },
#endif
	{ NULL, NULL}
};

/***************************************************************************
 Make a auth_info struct
***************************************************************************/

static BOOL make_auth_info(auth_authsupplied_info **auth_info) 
{
	*auth_info = malloc(sizeof(**auth_info));
	if (!*auth_info) {
		DEBUG(0,("make_auth_info: malloc failed!\n"));
		return False;
	}
	ZERO_STRUCTP(*auth_info);
	
	return True;
}

/***************************************************************************
 Make a auth_info struct with a specified list.
***************************************************************************/

BOOL make_auth_info_list(auth_authsupplied_info **auth_info, auth_methods *list) 
{
	if (!make_auth_info(auth_info)) {
		return False;
	}
	
	(*auth_info)->auth_method_list = list;
	
	return True;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
***************************************************************************/

static BOOL make_auth_info_text_list(auth_authsupplied_info **auth_info, char **text_list) 
{
	auth_methods *list = NULL;
	auth_methods *t = NULL;
	auth_methods *tmp;
	int i;

	if (!text_list) {
		DEBUG(2,("No auth method list!?\n"));
		return False;
	}
	
	for (;*text_list; text_list++)
	{ 
		DEBUG(5,("Attempting to find an auth method to match %s\n", *text_list));
		for (i = 0; builtin_auth_init_functions[i].name; i++)
		{
			if (strequal(builtin_auth_init_functions[i].name, *text_list))
			{
				DEBUG(5,("Found auth method %s (at pos %d)\n", *text_list, i));
				/* Malloc entry,  fill it,  link it */
				t = (auth_methods *)malloc(sizeof(*t));
				if (!t) {
					DEBUG(0,("make_pw_chat: malloc failed!\n"));
					return False;
				}
				
				ZERO_STRUCTP(t);
				
				if (builtin_auth_init_functions[i].init(&t)) {
					DEBUG(5,("auth method %s has a valid init\n", *text_list));
					t->name = builtin_auth_init_functions[i].name;
					DLIST_ADD_END(list, t, tmp);
				} else {
					DEBUG(5,("auth method %s DOES NOT have a valid init\n", *text_list));
				}
				break;
			}
		}
	}
	
	make_auth_info_list(auth_info, list);
	
	return True;
}

/***************************************************************************
 Make a auth_info struct for the auth subsystem
***************************************************************************/

BOOL make_auth_info_subsystem(auth_authsupplied_info **auth_info) 
{
	char **auth_method_list = NULL; 
	
	if (!make_auth_info(auth_info)) {
		return False;
	}
	
	if (lp_auth_methods() && !lp_list_copy(&auth_method_list, lp_auth_methods())) {
		return False;
	}

	if (auth_method_list == NULL) {
		switch (lp_security()) 
		{
		case SEC_DOMAIN:
			DEBUG(5,("Making default auth method list for security=domain\n"));
			auth_method_list = lp_list_make("guest ntdomain local");
			break;
		case SEC_SERVER:
			DEBUG(5,("Making default auth method list for security=server\n"));
			auth_method_list = lp_list_make("guest smbserver local");
			break;
		case SEC_USER:
			DEBUG(5,("Making default auth method list for security=user\n"));
			auth_method_list = lp_list_make("guest local");
			break;
		case SEC_SHARE:
			DEBUG(5,("Making default auth method list for security=share\n"));
			auth_method_list = lp_list_make("guest local");
			break;
		case SEC_ADS:
			DEBUG(5,("Making default auth method list for security=ADS\n"));
			auth_method_list = lp_list_make("guest ads ntdomain local");
			break;
		default:
			DEBUG(5,("Unknown auth method!\n"));
			return False;
		}
	} else {
		DEBUG(5,("Using specified auth order\n"));
	}
	
	if (!make_auth_info_text_list(auth_info, auth_method_list)) {
		lp_list_free(&auth_method_list);
		return False;
	}
	
	lp_list_free(&auth_method_list);
	return True;
}

/***************************************************************************
 Make a auth_info struct with a random challenge
***************************************************************************/

BOOL make_auth_info_random(auth_authsupplied_info **auth_info) 
{
	uchar chal[8];
	if (!make_auth_info_subsystem(auth_info)) {
		return False;
	}
	
	generate_random_buffer(chal, sizeof(chal), False);
	(*auth_info)->challenge = data_blob(chal, sizeof(chal));

	(*auth_info)->challenge_set_by = "random";

	return True;
}

/***************************************************************************
 Make a auth_info struct with a fixed challenge
***************************************************************************/

BOOL make_auth_info_fixed(auth_authsupplied_info **auth_info, uchar chal[8]) 
{
	if (!make_auth_info_subsystem(auth_info)) {
		return False;
	}
	
	(*auth_info)->challenge = data_blob(chal, 8);
	return True;
}

/***************************************************************************
 Clear out a auth_info struct that has been allocated
***************************************************************************/

void free_auth_info(auth_authsupplied_info **auth_info)
{
	auth_methods *list;
	if (*auth_info != NULL) {
		list = (*auth_info)->auth_method_list;	
		while (list) {
			auth_methods *old_head = list;
			if (list->free_private_data) {
				list->free_private_data(&(list->private_data));
			}
			DLIST_REMOVE(list, list);			
			SAFE_FREE(old_head);
		}
		
		data_blob_free(&(*auth_info)->challenge);
		ZERO_STRUCT(**auth_info);
	}
	SAFE_FREE(*auth_info);
}

/****************************************************************************
 Try to get a challenge out of the various authenticaion modules.
 It is up to the caller to free it.
****************************************************************************/

DATA_BLOB auth_get_challenge(auth_authsupplied_info *auth_info) 
{
	DATA_BLOB challenge = data_blob(NULL, 0);
	char *challenge_set_by = NULL;
	auth_methods *auth_method;

	if (auth_info->challenge.length) {
		DEBUG(5, ("auth_get_challenge: returning previous challenge (normal)\n"));
		return data_blob(auth_info->challenge.data, auth_info->challenge.length);
	}

	for (auth_method = auth_info->auth_method_list; auth_method; auth_method = auth_method->next)
	{
		if (auth_method->get_chal) {
			DEBUG(5, ("auth_get_challenge: getting challenge from module %s\n", auth_method->name));
			if (challenge_set_by) {
				DEBUG(1, ("auth_get_challenge: CONFIGURATION ERROR: authenticaion method %s has already specified a challenge.  Challenge by %s ignored.\n", 
					  challenge_set_by, auth_method->name));
			} else {
				challenge = auth_method->get_chal(&auth_method->private_data, auth_info);
				if (challenge.length) {
					DEBUG(5, ("auth_get_challenge: sucessfully got challenge from module %s\n", auth_method->name));
					auth_info->challenge = challenge;
					challenge_set_by = auth_method->name;
					auth_info->challenge_set_method = auth_method;
				} else {
					DEBUG(3, ("auth_get_challenge: getting challenge from authenticaion method %s FAILED.\n", 
						  auth_method->name));
				}
			}
		} else {
			DEBUG(5, ("auth_get_challenge: module %s did not want to specify a challenge\n", auth_method->name));
		}
	}
	
	if (!challenge_set_by) {
		uchar chal[8];
		
		generate_random_buffer(chal, sizeof(chal), False);
		auth_info->challenge = data_blob(chal, sizeof(chal));
		
		challenge_set_by = "random";
	} 
	
	DEBUG(5, ("auth_info challenge created by %s\n", challenge_set_by));
	DEBUG(5, ("challenge is: \n"));
	dump_data(5, auth_info->challenge.data, (auth_info)->challenge.length);
	
	SMB_ASSERT(auth_info->challenge.length == 8);

	auth_info->challenge_set_by=challenge_set_by;

	return data_blob(auth_info->challenge.data, auth_info->challenge.length);
}


