
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Sander Striker                    2000.
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


#include "includes.h"
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
 get_policy_svc_name 
****************************************************************************/
static BOOL get_policy_svc_name(struct policy_cache *cache, 
					  const POLICY_HND *hnd,
					  fstring name)
{
	char *dev;
	dev = (char *)get_policy_state_info(cache, hnd);

	if (dev != NULL)
	{
		fstrcpy(name, dev);
		DEBUG(5,("getting policy svc name=%s\n", name));
		return True;
	}

	DEBUG(3,("Error getting policy svc name\n"));
	return False;
}

/****************************************************************************
 set_policy_svc_name 
****************************************************************************/
static BOOL set_policy_svc_name(struct policy_cache *cache, POLICY_HND *hnd,
				fstring name)
{
	char *dev = strdup(name);
	if (dev != NULL)
	{
		if (set_policy_state(cache, hnd, NULL, (void*)dev))
		{
			DEBUG(3,("Service setting policy name=%s\n", name));
			return True;
		}
		free(dev);
		return True;
	}

	DEBUG(3,("Error setting policy name=%s\n", name));
	return False;
}

/*******************************************************************
 _svc_close
 ********************************************************************/
uint32 _svc_close(POLICY_HND *pol)
{

	/* close the policy handle */
	if (!close_policy_hnd(get_global_hnd_cache(), pol))
	{
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	/* strikerXXXX Luke, is this line below needed, or does close_policy_hnd()
       * take care of this? */

	/* set up the REG unknown_1 response */
	bzero(pol->data, POL_HND_SIZE);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _svc_open_service
 ********************************************************************/
uint32 _svc_open_service(const POLICY_HND *scman_pol,
				 const UNISTR2* uni_svc_name,
				 uint32 des_access,
				 POLICY_HND *pol)
{
	fstring name;

	if (find_policy_by_hnd(get_global_hnd_cache(), scman_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!open_policy_hnd(get_global_hnd_cache(), pol, des_access))
	{
		return NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, uni_svc_name, sizeof(name)-1);

	DEBUG(5,("svc_open_service: %s\n", name));
	/* lkcl XXXX do a check on the name, here */

	if (!set_policy_svc_name(get_global_hnd_cache(), pol, name))
	{
		return NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _svc_stop_service
 ********************************************************************/
uint32 _svc_stop_service(const POLICY_HND *pol,
				 uint32 unknown,
				 uint32 *unknown0,
				 uint32 *unknown1,
				 uint32 *unknown2,
				 uint32 *unknown3,
				 uint32 *unknown4,
				 uint32 *unknown5,
				 uint32 *unknown6)
{
	fstring svc_name;
	fstring script;

	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1 ||
		!get_policy_svc_name(get_global_hnd_cache(), pol, svc_name))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	slprintf(script, sizeof(script)-1, "%s/rc.service stop %s/%s.pid %s/%s",
			SBINDIR, LOCKDIR, svc_name, BINDIR, svc_name);
	
	DEBUG(10,("stop_service: %s\n", script));

	/* stop the service here */
	if (smbrun(script, "/tmp/foo", False) == 0)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _svc_start_service
 ********************************************************************/
uint32 _svc_start_service(const POLICY_HND *pol,
				  uint32 argc,
				  uint32 argc2,
				  const UNISTR2 *argv)
{
	fstring svc_name;
	pstring script;

	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1 ||
	    !get_policy_svc_name(get_global_hnd_cache(), pol, svc_name))
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	slprintf(script, sizeof(script)-1, "%s/rc.service start %s/%s.pid %s/%s",
			SBINDIR, LOCKDIR, svc_name, BINDIR, svc_name);
	
	DEBUG(10,("svc_start_service: %s\n", script));

	/* start the service here */
	if (smbrun(script, "/tmp/foo", False) == 0)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _svc_open_sc_man
 ********************************************************************/
uint32 _svc_open_sc_man(const UNISTR2 *uni_srv_name,
				const UNISTR2 *uni_db_name,
				uint32 des_access,
				POLICY_HND *pol)
{
	fstring name;

	if (!open_policy_hnd(get_global_hnd_cache(), pol, des_access))
	{
		return NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	unistr2_to_ascii(name, uni_srv_name, sizeof(name)-1);

	DEBUG(5,("svc_open_sc_man: %s\n", name));
	/* lkcl XXXX do a check on the name, here */

	if (!set_policy_svc_name(get_global_hnd_cache(), pol, name))
	{
		return NT_STATUS_TOO_MANY_SECRETS; /* ha ha very droll */
	}

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
 _svc_enum_svcs_status
 ********************************************************************/
uint32 _svc_enum_svcs_status(const POLICY_HND *pol,
				     uint32 service_type,
				     uint32 service_state,
				     uint32 *buf_size,
				     ENUM_HND *resume_hnd,
				     ENUM_SRVC_STATUS *svcs,
				     uint32 *more_buf_size,
				     uint32 *num_svcs)
{
	uint32 dos_status = 0;
	int i = get_enum_hnd(resume_hnd);
	uint32 local_resume_hnd = 0;
	uint32 local_buf_size = 0;
	uint32 num_entries = 10;
	char *services[] =
	{
		"lsarpcd",
		"srvsvcd",
		"wkssvcd",
		"smbd",
		"nmbd",
		"svcctld",
		"samrd",
		"spoolssd",
		"browserd",
		"winregd"
	};

	*more_buf_size = 0x10000;
	*num_svcs = 0;

	if (find_policy_by_hnd(get_global_hnd_cache(), pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	for (i = 0; i < num_entries; i++)
	{
		ENUM_SRVC_STATUS *svc = NULL;
		fstring svc_name;
		int len;

		fstrcpy(svc_name, services[i]);
		len = strlen(services[i]);

		local_buf_size += (len+1) * 2;
		local_buf_size += 9 * sizeof(uint32);

		DEBUG(10,("r_buf_size: %d q_buf_size: %d\n",
			   local_buf_size, *buf_size));

		if (local_buf_size >= *more_buf_size)
		{
			local_resume_hnd = i;
			break;
		}

		if (local_buf_size > *buf_size)
		{
			dos_status = ERRmoredata;
			break;
		}

		(*num_svcs)++;
		if (*num_svcs > MAX_SERVICES)
		{
			dos_status = ERRnomem;
			*num_svcs = 0;
			break;
		}

		svc = &svcs[(*num_svcs) - 1];
		ZERO_STRUCTP(svc);

		make_unistr(&svc->uni_srvc_name, svc_name);
		make_unistr(&svc->uni_disp_name, svc_name);

		DEBUG(10,("show service: %s\n", svc_name));
	}

	/*
	 * check for finished condition: no resume handle and last buffer fits
	 */

	if (local_resume_hnd == 0 && local_buf_size <= *buf_size)
	{
		/* this indicates, along with resume_hnd of 0, an end. */
		*more_buf_size = 0;
	}

	*buf_size = local_buf_size;
	make_enum_hnd(resume_hnd, local_resume_hnd);

	return dos_status;
}

/*******************************************************************
 _svc_query_disp_name
 ********************************************************************/
uint32 _svc_query_disp_name(const POLICY_HND *scman_pol,
				    const UNISTR2 *uni_svc_name,
				    uint32 buf_size,
				    UNISTR2 *uni_disp_name,
				    uint32 *pbuf_size)
{
	if (find_policy_by_hnd(get_global_hnd_cache(), scman_pol) == -1)
	{
		return NT_STATUS_INVALID_HANDLE;
	}

	/* for now display name = service name */
	copy_unistr2(uni_disp_name, uni_svc_name);
	/* and thus the length of the strings is the same */
	*pbuf_size = buf_size;

	return NT_STATUS_NOPROBLEMO;
}
