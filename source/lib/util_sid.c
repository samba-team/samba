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


/*****************************************************************
 Convert a SID to an ascii string.
*****************************************************************/

char *sid_to_string(pstring sidstr_out, const DOM_SID *sid)
{
  char subauth[16];
  int i;
  /* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
  uint32 ia = (sid->id_auth[5]) +
              (sid->id_auth[4] << 8 ) +
              (sid->id_auth[3] << 16) +
              (sid->id_auth[2] << 24);

  slprintf(sidstr_out, sizeof(pstring) - 1, "S-%u-%lu", (unsigned int)sid->sid_rev_num, (unsigned long)ia);

  for (i = 0; i < sid->num_auths; i++)
  {
    slprintf(subauth, sizeof(subauth)-1, "-%lu", (unsigned long)sid->sub_auths[i]);
    pstrcat(sidstr_out, subauth);
  }

  DEBUG(20, ("sid_to_string returning %s\n", sidstr_out));
  return sidstr_out;
}

/*****************************************************************
 Convert a string to a SID. Returns True on success, False on fail.
*****************************************************************/  
   
BOOL string_to_sid(DOM_SID *sidout, const char *sidstr)
{
	const char *p = sidstr;
	/* BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 */
	uint32 ia;

	memset((char *)sidout, '\0', sizeof(DOM_SID));

	if (StrnCaseCmp( sidstr, "S-", 2))
	{
		DEBUG(0,("string_to_sid: Sid %s does not start with 'S-'.\n", sidstr));
		return False;
	}

	if ((p = strchr(p, '-')) == NULL)
	{
		DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
		return False;
	}

	p++;

	/* Get the revision number. */
	sidout->sid_rev_num = (uint8)strtoul(p,NULL,10);

	if ((p = strchr(p, '-')) == NULL)
	{
		DEBUG(0,("string_to_sid: Sid %s is not in a valid format.\n", sidstr));
		return False;
	}

	p++;

	/* identauth in decimal should be <  2^32 */
	ia = (uint32)strtoul(p,NULL,10);

	/* NOTE - the ia value is in big-endian format. */
	sidout->id_auth[0] = 0;
	sidout->id_auth[1] = 0;
	sidout->id_auth[2] = (ia & 0xff000000) >> 24;
	sidout->id_auth[3] = (ia & 0x00ff0000) >> 16;
	sidout->id_auth[4] = (ia & 0x0000ff00) >> 8;
	sidout->id_auth[5] = (ia & 0x000000ff);

	sidout->num_auths = 0;

	while (((p = strchr(p, '-')) != NULL) && sidout->num_auths < MAXSUBAUTHS)
	{
		p++;
		/*
		 * NOTE - the subauths are in native machine-endian format. They
		 * are converted to little-endian when linearized onto the wire.
		 */
		sid_append_rid(sidout, (uint32)strtoul(p, NULL, 10));
	}

	return True;
}

/*****************************************************************
 add a rid to the end of a sid
*****************************************************************/  
BOOL sid_append_rid(DOM_SID *sid, uint32 rid)
{
	if (sid->num_auths < MAXSUBAUTHS)
	{
		sid->sub_auths[sid->num_auths++] = rid;
		return True;
	}
	return False;
}

/*****************************************************************
 removes the last rid from the end of a sid
*****************************************************************/  
BOOL sid_split_rid(DOM_SID *sid, uint32 *rid)
{
	if (sid->num_auths > 0)
	{
		sid->num_auths--;
		if (rid != NULL)
		{
			(*rid) = sid->sub_auths[sid->num_auths];
		}
		return True;
	}
	return False;
}

/*****************************************************************
 copies a sid
*****************************************************************/  
void sid_copy(DOM_SID *sid1, const DOM_SID *sid2)
{
	int i;

	for (i = 0; i < 6; i++)
	{
		sid1->id_auth[i] = sid2->id_auth[i];
	}

	for (i = 0; i < sid2->num_auths; i++)
	{
		sid1->sub_auths[i] = sid2->sub_auths[i];
	}

	sid1->num_auths   = sid2->num_auths;
	sid1->sid_rev_num = sid2->sid_rev_num;
}

/*****************************************************************
 compare two sids up to the auths of the first sid
*****************************************************************/  
BOOL sid_front_equal(const DOM_SID *sid1, const DOM_SID *sid2)
{
	int i;

	/* compare most likely different rids, first: i.e start at end */
	for (i = sid1->num_auths-1; i >= 0; --i)
	{
		if (sid1->sub_auths[i] != sid2->sub_auths[i]) return False;
	}

	if (sid1->num_auths   >  sid2->num_auths  ) return False;
	if (sid1->sid_rev_num != sid2->sid_rev_num) return False;

	for (i = 0; i < 6; i++)
	{
		if (sid1->id_auth[i] != sid2->id_auth[i]) return False;
	}

	return True;
}

/*****************************************************************
 compare two sids
*****************************************************************/  
BOOL sid_equal(const DOM_SID *sid1, const DOM_SID *sid2)
{
	int i;

	/* compare most likely different rids, first: i.e start at end */
	for (i = sid1->num_auths-1; i >= 0; --i)
	{
		if (sid1->sub_auths[i] != sid2->sub_auths[i]) return False;
	}

	if (sid1->num_auths   != sid2->num_auths  ) return False;
	if (sid1->sid_rev_num != sid2->sid_rev_num) return False;

	for (i = 0; i < 6; i++)
	{
		if (sid1->id_auth[i] != sid2->id_auth[i]) return False;
	}

	return True;
}


/*****************************************************************
 calculates size of a sid
*****************************************************************/  
int sid_size(const DOM_SID *sid)
{
	if (sid == NULL)
	{
		return 0;
	}
	return sid->num_auths * sizeof(uint32) + 8;
}


/*****************************************************************
 Duplicates a sid - mallocs the target.
*****************************************************************/

DOM_SID *sid_dup(const DOM_SID *src)
{
  DOM_SID *dst;

  if(!src)
    return NULL;

  if((dst = (DOM_SID*)malloc(sizeof(DOM_SID))) != NULL) {
       memset(dst, '\0', sizeof(DOM_SID));
       sid_copy( dst, src);
  }

  return dst;
}


/****************************************************************************
 Read a SID from a file.
****************************************************************************/

static BOOL read_sid_from_file(int fd, char *sid_file, DOM_SID *sid)
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
  if (!string_to_sid(sid, fline)) {
    DEBUG(0,("unable to read sid.\n"));
    return False;
  }

	sid_to_string(sid_str, sid);
	DEBUG(5,("read_sid_from_file %s: sid %s\n", sid_file, sid_str));

  return True;
}

/****************************************************************************
 Generate the global machine sid. Look for the DOMAINNAME.SID file first, if
 not found then look in smb.conf and use it to create the DOMAINNAME.SID file.
****************************************************************************/
BOOL read_sid(char *domain_name, DOM_SID *sid)
{
	int fd;
	char *p;
	pstring sid_file;
	fstring file_name;
	SMB_STRUCT_STAT st;

	pstrcpy(sid_file, lp_smb_passwd_file());

	DEBUG(10,("read_sid: Domain: %s\n", domain_name));

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

	if (!directory_exist(sid_file, NULL))
	{
		if (mkdir(sid_file, 0700) != 0)
		{
			DEBUG(0,("can't create private directory %s : %s\n",
				 sid_file, strerror(errno)));
			return False;
		}
	}

	slprintf(file_name, sizeof(file_name)-1, "%s.SID", domain_name);
	strupper(file_name);
	pstrcat(sid_file, file_name);
    
	if ((fd = sys_open(sid_file, O_RDWR | O_CREAT, 0644)) == -1) {
		DEBUG(0,("unable to open or create file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		return False;
	} 
  
	/*
	 * Check if the file contains data.
	 */
	
	if (sys_fstat(fd, &st) < 0) {
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if (st.st_size == 0)
	{
		close(fd);
		return False;
	}

	/*
	 * We have a valid SID - read it.
	 */

	if (!read_sid_from_file(fd, sid_file, sid))
	{
		DEBUG(0,("unable to read file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	}
	close(fd);
	return True;
}   


/****************************************************************************
 Generate the global machine sid. Look for the DOMAINNAME.SID file first, if
 not found then look in smb.conf and use it to create the DOMAINNAME.SID file.
****************************************************************************/
BOOL write_sid(char *domain_name, DOM_SID *sid)
{
	int fd;
	char *p;
	pstring sid_file;
	fstring sid_string;
	fstring file_name;
	SMB_STRUCT_STAT st;

	pstrcpy(sid_file, lp_smb_passwd_file());
	sid_to_string(sid_string, sid);

	DEBUG(10,("write_sid: Domain: %s SID: %s\n", domain_name, sid_string));
	fstrcat(sid_string, "\n");

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

	slprintf(file_name, sizeof(file_name)-1, "%s.SID", domain_name);
	strupper(file_name);
	pstrcat(sid_file, file_name);
    
	if ((fd = sys_open(sid_file, O_RDWR | O_CREAT, 0644)) == -1) {
		DEBUG(0,("unable to open or create file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		return False;
	} 
  
	/*
	 * Check if the file contains data.
	 */
	
	if (sys_fstat(fd, &st) < 0) {
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if (st.st_size > 0)
	{
		/*
		 * We have a valid SID already.
		 */
		close(fd);
		DEBUG(0,("SID file %s already exists\n", sid_file));
		return False;
	} 
  
	if (!do_file_lock(fd, 60, F_WRLCK))
	{
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
	
	if (sys_fstat(fd, &st) < 0)
	{
		DEBUG(0,("unable to stat file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
  
	if (st.st_size > 0)
	{
		/*
		 * Unlock as soon as possible to reduce
		 * contention on the exclusive lock.
		 */ 
		do_file_lock(fd, 60, F_UNLCK);
		
		/*
		 * We have a valid SID already.
		 */
		
		DEBUG(0,("SID file %s already exists\n", sid_file));
		close(fd);
		return False;
	} 
	
	/*
	 * The file is still empty and we have an exlusive lock on it.
	 * Write out out SID data into the file.
	 */
	
	if (fchmod(fd, 0644) < 0)
	{
		DEBUG(0,("unable to set correct permissions on file %s. \
Error was %s\n", sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
	
	if (write(fd, sid_string, strlen(sid_string)) != strlen(sid_string))
	{
		DEBUG(0,("unable to write file %s. Error was %s\n",
			 sid_file, strerror(errno) ));
		close(fd);
		return False;
	} 
	
	/*
	 * Unlock & exit.
	 */
	
	do_file_lock(fd, 60, F_UNLCK);
	close(fd);
	return True;
}   

/****************************************************************************
create a random SID.
****************************************************************************/
BOOL create_new_sid(DOM_SID *sid)
{
	uchar raw_sid_data[12];
	fstring sid_string;
	int i;

	/*
	 * Generate the new sid data & turn it into a string.
	 */
	generate_random_buffer(raw_sid_data, 12, True);
		
	fstrcpy(sid_string, "S-1-5-21");
	for(i = 0; i < 3; i++)
	{
		fstring tmp_string;
		slprintf(tmp_string, sizeof(tmp_string) - 1, "-%u", IVAL(raw_sid_data, i*4));
		fstrcat(sid_string, tmp_string);
	}
	
	fstrcat(sid_string, "\n");
	
	/*
	 * Ensure our new SID is valid.
	 */
	
	if (!string_to_sid(sid, sid_string))
	{
		DEBUG(0,("unable to generate machine SID.\n"));
		return False;
	} 

	return True;
}
  
