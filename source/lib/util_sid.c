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

  DEBUG(7,("sid_to_string returning %s\n", sidstr_out));
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

DOM_SID *sid_dup(DOM_SID *src)
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
