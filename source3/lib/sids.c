/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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


extern int DEBUGLEVEL;
extern pstring scope;
extern pstring global_myname;

/*
 * This is set on startup - it defines the SID for this
 * machine, and therefore the SAM database for which it is
 * responsible.
 */

DOM_SID global_sam_sid;

/*
 * This is the name associated with the SAM database for
 * which this machine is responsible.  In the case of a PDC
 * or PDC, this name is the same as the workgroup.  In the
 * case of "security = domain" mode, this is the same as
 * the name of the server (global_myname).
 */

fstring global_sam_name; 

/*
 * This is obtained on startup - it defines the SID for which
 * this machine is a member.  It is therefore only set, and
 * used, in "security = domain" mode.
 */

DOM_SID global_member_sid;

/*
 * note the lack of a "global_member_name" - this is because
 * this is the same as "global_myworkgroup".
 */

extern fstring global_myworkgroup;
/* fstring global_member_dom_name; */

/*
 * some useful sids
 */

DOM_SID global_sid_S_1_5_20; /* local well-known domain */
DOM_SID global_sid_S_1_1;    /* everyone */
DOM_SID global_sid_S_1_3;    /* Creator Owner */
DOM_SID global_sid_S_1_5;    /* NT Authority */

static struct sid_name_map_info
{
	DOM_SID *sid;
	char *name;

}
sid_name_map[] =
{
	{ &global_sid_S_1_5_20, "BUILTIN" },
	{ &global_sid_S_1_1   , "Everyone" },
	{ &global_sid_S_1_3   , "Creator Owner" },
	{ &global_sid_S_1_5   , "NT Authority" },
	{ &global_sam_sid     , global_sam_name },
	{ &global_member_sid  , global_myworkgroup },
	{ NULL                , NULL      }
};

/****************************************************************************
 Read the machine SID from a file.
****************************************************************************/

static BOOL read_sid_from_file(int fd, char *sid_file)
{   
  fstring fline;
	fstring sid_str;
    
  memset(fline, '\0', sizeof(fline));

  if (read(fd, fline, sizeof(fline) -1 ) < 0) {
    DEBUG(0,("unable to read file %s. Error was %s\n",
           sid_file, strerror(errno) ));
    return False;
  }

  /*
   * Convert to the machine SID.
   */

  fline[sizeof(fline)-1] = '\0';
  if (!string_to_sid( &global_sam_sid, fline)) {
    DEBUG(0,("unable to generate machine SID.\n"));
    return False;
  }

	sid_to_string(sid_str, &global_sam_sid);
	DEBUG(5,("read_sid_from_file: sid %s\n", sid_str));

  return True;
}

/****************************************************************************
 sets up the name associated with the SAM database for which we are responsible
****************************************************************************/
void get_sam_domain_name(void)
{
	switch (lp_server_role())
	{
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
		{
			/* we are PDC (or BDC) for a Domain */
			fstrcpy(global_sam_name, lp_workgroup());
			break;
		}
		case ROLE_DOMAIN_MEMBER:
		{
			/* we are a "PDC", but FOR LOCAL SAM DATABASE ONLY */
			fstrcpy(global_sam_name, global_myname);
			break;
		}
		default:
		{
			/* no domain role, probably due to "security = share" */
			memset(global_sam_name, 0, sizeof(global_sam_name));
			break;
		}
	}
}

/****************************************************************************
 obtain the sid from the PDC.
****************************************************************************/
BOOL get_member_domain_sid(void)
{
	switch (lp_server_role())
	{
		case ROLE_DOMAIN_NONE:
		{
			ZERO_STRUCT(global_member_sid);
			return True;
		}
		case ROLE_DOMAIN_PDC:
		{
			sid_copy(&global_member_sid, &global_sam_sid);
			return True;
		}
		default:
		{
			/* member or BDC, we're going for connection to PDC */
			break;
		}
	}

	return get_domain_sids(NULL, &global_member_sid, lp_passwordserver());
}

/****************************************************************************
 obtain the sid from the PDC.  do some verification along the way...
****************************************************************************/
BOOL get_domain_sids(DOM_SID *sid3, DOM_SID *sid5, char *servers)
{
	uint16 nt_pipe_fnum;
	POLICY_HND pol;
	fstring srv_name;
	struct cli_state cli;
	BOOL res = True;
	fstring dom3;
	fstring dom5;

	if (sid3 == NULL && sid5 == NULL)
	{
		/* don't waste my time... */
		return False;
	}

	if (!cli_connect_serverlist(&cli, servers))
	{
		DEBUG(0,("get_domain_sids: unable to initialise client connection.\n"));
		return False;
	}

	/*
	 * Ok - we have an anonymous connection to the IPC$ share.
	 * Now start the NT Domain stuff :-).
	 */

	fstrcpy(dom3, "");
	fstrcpy(dom5, "");
	if (sid3 != NULL)
	{
		ZERO_STRUCTP(sid3);
	}
	if (sid5 != NULL)
	{
		ZERO_STRUCTP(sid5);
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, global_myname);
	strupper(srv_name);

	/* open LSARPC session. */
	res = res ? cli_nt_session_open(&cli, PIPE_LSARPC, &nt_pipe_fnum) : False;

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(&cli, nt_pipe_fnum, srv_name, &pol, False) : False;

	if (sid3 != NULL)
	{
		/* send client info query, level 3.  receive domain name and sid */
		res = res ? lsa_query_info_pol(&cli, nt_pipe_fnum, &pol, 3, dom3, sid3) : False;
	}

	if (sid5 != NULL)
	{
		/* send client info query, level 5.  receive domain name and sid */
		res = res ? lsa_query_info_pol(&cli, nt_pipe_fnum, &pol, 5, dom5, sid5) : False;
	}

	/* close policy handle */
	res = res ? lsa_close(&cli, nt_pipe_fnum, &pol) : False;

	/* close the session */
	cli_nt_session_close(&cli, nt_pipe_fnum);
	cli_ulogoff(&cli);
	cli_shutdown(&cli);

	if (res)
	{
		pstring sid;
		DEBUG(2,("LSA Query Info Policy\n"));
		if (sid3 != NULL)
		{
			sid_to_string(sid, sid3);
			DEBUG(2,("Domain Member     - Domain: %s SID: %s\n", dom3, sid));
		}
		if (sid5 != NULL)
		{
			sid_to_string(sid, sid5);
			DEBUG(2,("Domain Controller - Domain: %s SID: %s\n", dom5, sid));
		}
	}
	else
	{
		DEBUG(1,("lsa query info failed\n"));
	}

	return res;
}

/****************************************************************************
 creates some useful well known sids
****************************************************************************/
void generate_wellknown_sids(void)
{
	string_to_sid(&global_sid_S_1_5_20, "S-1-5-32");
	string_to_sid(&global_sid_S_1_1   , "S-1-1"   );
	string_to_sid(&global_sid_S_1_3   , "S-1-3"   );
	string_to_sid(&global_sid_S_1_5   , "S-1-5"   );
}

/****************************************************************************
 Generate the global machine sid. Look for the DOMAINNAME.SID file first, if
 not found then look in smb.conf and use it to create the DOMAINNAME.SID file.
****************************************************************************/
BOOL generate_sam_sid(char *domain_name)
{
	int fd;
	int i;
	char *p;
	pstring sid_file;
	pstring machine_sid_file;
	fstring sid_string;
	fstring file_name;
	SMB_STRUCT_STAT st;
	uchar raw_sid_data[12];

	pstrcpy(sid_file, lp_smb_passwd_file());

	if (sid_file[0] == 0)
	{
		DEBUG(0,("cannot find smb passwd file\n"));
		return False;
	}

	p = strrchr(sid_file, '/');
	if (p != NULL)
	{
		*++p = '\0';
	}

	if (!directory_exist(sid_file, NULL)) {
		if (mkdir(sid_file, 0700) != 0) {
			DEBUG(0,("can't create private directory %s : %s\n",
				 sid_file, strerror(errno)));
			return False;
		}
	}

	pstrcpy(machine_sid_file, sid_file);
	pstrcat(machine_sid_file, "MACHINE.SID");

	slprintf(file_name, sizeof(file_name)-1, "%s.SID", domain_name);
	strupper(file_name);
	pstrcat(sid_file, file_name);
    
	if (file_exist(machine_sid_file, NULL))
	{
		if (file_exist(sid_file, NULL))
		{
			DEBUG(0,("both %s and %s exist when only one should, unable to continue\n",
			          machine_sid_file, sid_file));
			return False;
		}
		if (file_rename(machine_sid_file, sid_file))
		{
			DEBUG(0,("could not rename %s to %s.  Error was %s\n",
			          machine_sid_file, sid_file, strerror(errno)));
			return False;
		}
	}
	
	if ((fd = sys_open(sid_file, O_RDWR | O_CREAT, 0644)) == -1) {
		DEBUG(0,("unable to open or create file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		return False;
	} 
  
	/*
	 * Check if the file contains data.
	 */
	
	if (sys_fstat( fd, &st) < 0) {
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if (st.st_size > 0) {
		/*
		 * We have a valid SID - read it.
		 */
		if (!read_sid_from_file( fd, sid_file)) {
			DEBUG(0,("unable to read file %s. Error was %s\n",
				 sid_file, strerror(errno) ));
			close(fd);
			return False;
		}
		close(fd);
		return True;
	} 
  
	/*
	 * Generate the new sid data & turn it into a string.
	 */
	generate_random_buffer( raw_sid_data, 12, True);
		
	fstrcpy( sid_string, "S-1-5-21");
	for( i = 0; i < 3; i++) {
		fstring tmp_string;
		slprintf( tmp_string, sizeof(tmp_string) - 1, "-%u", IVAL(raw_sid_data, i*4));
		fstrcat( sid_string, tmp_string);
	}
	
	fstrcat(sid_string, "\n");
	
	/*
	 * Ensure our new SID is valid.
	 */
	
	if (!string_to_sid( &global_sam_sid, sid_string)) {
		DEBUG(0,("unable to generate machine SID.\n"));
		return False;
	} 
  
	/*
	 * Do an exclusive blocking lock on the file.
	 */
	
	if (!do_file_lock( fd, 60, F_WRLCK)) {
		DEBUG(0,("unable to lock file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	/*
	 * At this point we have a blocking lock on the SID
	 * file - check if in the meantime someone else wrote
	 * SID data into the file. If so - they were here first,
	 * use their data.
	 */
	
	if (sys_fstat( fd, &st) < 0) {
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if (st.st_size > 0) {
		/*
		 * Unlock as soon as possible to reduce
		 * contention on the exclusive lock.
		 */ 
		do_file_lock( fd, 60, F_UNLCK);
		
		/*
		 * We have a valid SID - read it.
		 */
		
		if (!read_sid_from_file( fd, sid_file)) {
			DEBUG(0,("unable to read file %s. Error was %s\n",
				 sid_file, strerror(errno) ));
			close(fd);
			return False;
		}
		close(fd);
		return True;
	} 
	
	/*
	 * The file is still empty and we have an exlusive lock on it.
	 * Write out out SID data into the file.
	 */
	
	if (fchmod(fd, 0644) < 0) {
		DEBUG(0,("unable to set correct permissions on file %s. \
Error was %s\n", sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
	
	if (write( fd, sid_string, strlen(sid_string)) != strlen(sid_string)) {
		DEBUG(0,("unable to write file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
	
	/*
	 * Unlock & exit.
	 */
	
	do_file_lock( fd, 60, F_UNLCK);
	close(fd);
	return True;
}   

/**************************************************************************
 turns a domain name into a SID.

 *** side-effect: if the domain name is NULL, it is set to our domain ***

***************************************************************************/
BOOL map_domain_name_to_sid(DOM_SID *sid, char **nt_domain)
{
	int i = 0;

	if (nt_domain == NULL)
	{
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	if ((*nt_domain) == NULL)
	{
		DEBUG(5,("map_domain_name_to_sid: overriding NULL name to %s\n",
		          global_sam_name));
		(*nt_domain) = strdup(global_sam_name);
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	if ((*nt_domain)[0] == 0)
	{
		free(*nt_domain);
		(*nt_domain) = strdup(global_sam_name);
		DEBUG(5,("map_domain_name_to_sid: overriding blank name to %s\n",
		          (*nt_domain)));
		sid_copy(sid, &global_sam_sid);
		return True;
	}

	DEBUG(5,("map_domain_name_to_sid: %s\n", (*nt_domain)));

	while (sid_name_map[i].name != NULL)
	{
		DEBUG(5,("compare: %s\n", sid_name_map[i].name));
		if (strequal(sid_name_map[i].name, (*nt_domain)))
		{
			fstring sid_str;
			sid_copy(sid, sid_name_map[i].sid);
			sid_to_string(sid_str, sid_name_map[i].sid);
			DEBUG(5,("found %s\n", sid_str));
			return True;
		}
		i++;
	}

	DEBUG(0,("map_domain_name_to_sid: mapping to %s NOT IMPLEMENTED\n",
		  (*nt_domain)));
	return False;
}

/**************************************************************************
 turns a domain SID into a name.

***************************************************************************/
BOOL map_domain_sid_to_name(DOM_SID *sid, char *nt_domain)
{
	fstring sid_str;
	int i = 0;
	sid_to_string(sid_str, sid);

	DEBUG(5,("map_domain_sid_to_name: %s\n", sid_str));

	if (nt_domain == NULL)
	{
		return False;
	}

	while (sid_name_map[i].sid != NULL)
	{
		sid_to_string(sid_str, sid_name_map[i].sid);
		DEBUG(5,("compare: %s\n", sid_str));
		if (sid_equal(sid_name_map[i].sid, sid))
		{
			fstrcpy(nt_domain, sid_name_map[i].name);
			DEBUG(5,("found %s\n", nt_domain));
			return True;
		}
		i++;
	}

	DEBUG(0,("map_domain_sid_to_name: mapping NOT IMPLEMENTED\n"));

	return False;
}

/**************************************************************************
 splits a name of format \DOMAIN\name or name into its two components.
 sets the DOMAIN name to global_sam_name if it has not been specified.
***************************************************************************/
BOOL split_domain_name(const char *fullname, char *domain, char *name)
{
	fstring full_name;
	char *p;

	if (fullname == NULL || domain == NULL || name == NULL)
	{
		return False;
	}

	if (fullname[0] == '\\')
	{
		fullname++;
	}
	fstrcpy(full_name, fullname);
	p = strchr(full_name+1, '\\');

	if (p != NULL)
	{
		*p = 0;
		fstrcpy(domain, full_name);
		fstrcpy(name, p+1);
	}
	else
	{
		fstrcpy(domain, global_sam_name);
		fstrcpy(name, full_name);
	}

	DEBUG(10,("name '%s' split into domain:%s and nt name:%s'\n", fullname, domain, name));
	return True;
}
