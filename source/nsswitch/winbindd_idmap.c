/* 
   Unix SMB/CIFS implementation.
   Winbind ID Mapping
   Copyright (C) Tim Potter 2000
   Copyright (C) Anthony Liguori <aliguor@us.ibm.com>	2003

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

#include "winbindd.h"

static struct {
  const char *name;
  /* Function to create a member of the idmap_methods list */
  BOOL (*reg_meth)(struct idmap_methods **methods);
  struct idmap_methods *methods;
} builtin_idmap_functions[] = {
  { "tdb", winbind_idmap_reg_tdb, NULL },
  /*  { "ldap", winbind_idmap_reg_ldap, NULL },*/
  { NULL, NULL, NULL }
};

/* singleton pattern: uberlazy evaluation */
static struct idmap_methods *impl;

static struct idmap_methods *get_impl(const char *name)
{
  int i = 0;
  struct idmap_methods *ret = NULL;

  while (builtin_idmap_functions[i].name && 
         strcmp(builtin_idmap_functions[i].name, name)) {
    i++;
  }

  if (builtin_idmap_functions[i].name) {
    if (!builtin_idmap_functions[i].methods) {
      builtin_idmap_functions[i].reg_meth(&builtin_idmap_functions[i].methods);
    }

    ret = builtin_idmap_functions[i].methods;
  }

  return ret;
}

/* Initialize backend */
BOOL winbindd_idmap_init(void)
{
  BOOL ret = False;

  DEBUG(3, ("winbindd_idmap_init: using '%s' as backend\n", 
            lp_idmap_backend()));

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->init();
  }

  DEBUG(3, ("winbind_idmap_init: returning %s\n", ret ? "true" : "false"));

  return ret;
}

/* Get UID from SID */
BOOL winbindd_idmap_get_uid_from_sid(DOM_SID *sid, uid_t *uid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->get_uid_from_sid(sid, uid);
  }

  return ret;
}

/* Get GID from SID */
BOOL winbindd_idmap_get_gid_from_sid(DOM_SID *sid, gid_t *gid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->get_gid_from_sid(sid, gid);
  }

  return ret;
}

/* Get UID from RID */
BOOL winbindd_idmap_get_uid_from_rid(const char *dom_name, uint32 rid, 
                                     uid_t *uid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->get_uid_from_rid(dom_name, rid, uid);
  }

  return ret;
}

/* Get GID From RID */
BOOL winbindd_idmap_get_gid_from_rid(const char *dom_name, uint32 rid, 
                                     gid_t *gid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->get_gid_from_rid(dom_name, rid, gid);
  }

  return ret;
}

/* Get SID from UID */
BOOL winbindd_idmap_get_sid_from_uid(uid_t uid, DOM_SID *sid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
    if (!impl) {
      DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
                lp_idmap_backend()));
    }
  }

  if (impl) {
    ret = impl->get_sid_from_uid(uid, sid);
  }

  return ret;
}

/* Get SID from GID */
BOOL winbindd_idmap_get_sid_from_gid(gid_t gid, DOM_SID *sid)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
  }

  if (impl) {
    ret = impl->get_sid_from_gid(gid, sid);
  } else {
    DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
              lp_idmap_backend()));
  }

  return ret;
}

/* Get RID From UID */
BOOL winbindd_idmap_get_rid_from_uid(uid_t uid, uint32 *user_rid,
                                     struct winbindd_domain **domain)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
  }

  if (impl) {
    ret = impl->get_rid_from_uid(uid, user_rid, domain);
  } else {
    DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
              lp_idmap_backend()));
  }

  return ret;
}

/* Get RID from GID */
BOOL winbindd_idmap_get_rid_from_gid(gid_t gid, uint32 *group_rid, 
                                     struct winbindd_domain **domain)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
  }

  if (impl) {
    ret = impl->get_rid_from_gid(gid, group_rid, domain);
  } else {
    DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
              lp_idmap_backend()));
  }

  return ret;
}

/* Close backend */
BOOL winbindd_idmap_close(void)
{
  BOOL ret = False;

  if (!impl) {
    impl = get_impl(lp_idmap_backend());
  }

  if (impl) {
    ret = impl->close();
  } else {
    DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
              lp_idmap_backend()));
  }

  return ret;
}

/* Dump backend status */
void winbindd_idmap_status(void)
{
  if (!impl) {
    impl = get_impl(lp_idmap_backend());
  }

  if (impl) {
    impl->status();
  } else {
    DEBUG(0, ("winbindd_idmap_init: could not load backend '%s'\n",
              lp_idmap_backend()));
  }
}

