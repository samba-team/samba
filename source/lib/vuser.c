/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
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

/* this holds info on user ids that are already validated for this VC */
static int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated.
****************************************************************************/
BOOL is_valid_user_struct(const vuser_key *key)
{
	if (key == NULL)
	{
		return False;
	}

	if (key->vuid == UID_FIELD_INVALID)
	{
		return False;
	}
	return tdb_lookup_vuid(key, NULL);
}

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(const vuser_key *key)
{
	user_struct *usr = NULL;
	if (key == NULL)
	{
		return NULL;
	}

	if (key->vuid == UID_FIELD_INVALID)
	{
		return NULL;
	}
	if (!tdb_lookup_vuid(key, &usr))
	{
		vuid_free_user_struct(usr);
		return NULL;
	}
	if (usr->uid == (uid_t)-1 || usr->gid == (gid_t)-1)
	{
		vuid_free_user_struct(usr);
	}
	return usr;
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(vuser_key *key)
{
	tdb_delete_vuid(key);
}


/****************************************************************************
return a validated username
****************************************************************************/
BOOL validated_username(vuser_key *key, char *name, size_t len)
{
	user_struct *vuser = get_valid_user_struct(key);
	if (vuser == NULL)
	{
		return False;
	}
	safe_strcpy(name, vuser->name, len-1);
	return True;
}


/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 create_vuid(pid_t pid,
				uid_t uid, gid_t gid,
				int n_groups, gid_t *groups,
				const char *unix_name,
				const char *requested_name,
				const char *real_name,
				BOOL guest, const NET_USER_INFO_3 *info3)
{
	user_struct vuser;
	vuser_key key;
	uint16 vuid;

	vuser.uid = uid;
	vuser.gid = gid;
	vuser.guest = guest;
	fstrcpy(vuser.name,unix_name);
	fstrcpy(vuser.requested_name,requested_name);
	fstrcpy(vuser.real_name,real_name);
	memcpy(&vuser.usr, info3, sizeof(vuser.usr));

	vuser.n_groups = n_groups;
	vuser.groups = groups;

	num_validated_users++;
	vuid = (uint16)((num_validated_users - 1) + VUID_OFFSET);

	DEBUG(3,("uid %d vuid %d registered to unix name %s\n",
	               (int)uid, vuid, unix_name));
	dump_data_pw("vuid usr sess key:\n", vuser.usr.user_sess_key,
	       sizeof(vuser.usr.user_sess_key));

	key.pid = (uint32)pid;
	key.vuid = vuid;

	if (!tdb_store_vuid(&key, &vuser))
	{
		return UID_FIELD_INVALID;
	}

	return vuid;
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 register_vuid(pid_t pid,
				uid_t uid,gid_t gid,
				const char *unix_name,
				const char *requested_name,
				BOOL guest,
				const NET_USER_INFO_3 *info3)
{
	int n_groups = 0;
	gid_t *groups = NULL;
	fstring real_name;
  struct passwd *pwfile; /* for getting real name from passwd file */

  /* Ensure no vuid gets registered in share level security. */
  if(lp_security() == SEC_SHARE)
    return UID_FIELD_INVALID;

  /* Find all the groups this uid is in and store them. 
     Used by become_user() */
  get_unixgroups(unix_name,uid,gid,
	       &n_groups,
	       &groups);

  DEBUG(3,("uid %d registered to name %s\n",(int)uid,unix_name));

  DEBUG(3, ("Clearing default real name\n"));
  fstrcpy(real_name, "<Full Name>\0");
  if (lp_unix_realname())
	{
    if ((pwfile=hashed_getpwnam(unix_name))!= NULL)
      {
      DEBUG(3, ("User name: %s\tReal name: %s\n",unix_name,pwfile->pw_gecos));
      fstrcpy(real_name, pwfile->pw_gecos);
      }
  }

  return create_vuid(pid, uid, gid, n_groups, groups,
				unix_name, requested_name,
				real_name,
				guest, info3);
}

/*******************************************************************
check if a username is OK
********************************************************************/
BOOL check_vuser_ok(struct uid_cache *cache, user_struct *vuser,int snum)
{
  int i;
  for (i=0;i<cache->entries;i++)
    if (cache->list[i] == vuser->uid) return(True);

  if (!user_ok(vuser->name,snum)) return(False);

  i = cache->entries % UID_CACHE_SIZE;
  cache->list[i] = vuser->uid;

  if (cache->entries < UID_CACHE_SIZE)
    cache->entries++;

  return(True);
}

