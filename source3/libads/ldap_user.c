/* 
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Jim McDonough 2002
   
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

#ifdef HAVE_ADS

/*
  find a user account
*/
ADS_STATUS ads_find_user_acct(ADS_STRUCT *ads, void **res, const char *user)
{
	ADS_STATUS status;
	char *exp;
	const char *attrs[] = {"*", NULL};

	asprintf(&exp, "(samAccountName=%s)", user);
	status = ads_search(ads, res, exp, attrs);
	free(exp);
	return status;
}

ADS_STATUS ads_add_user_acct(ADS_STRUCT *ads, const char *user, 
			     const char *fullname)
{
	TALLOC_CTX *ctx;
	ADS_MODLIST mods;
	ADS_STATUS status;
	char *upn, *new_dn, *name, *controlstr;

	if (fullname && *fullname) name = fullname;
	else name = user;

	if (!(ctx = talloc_init_named("ads_add_user_acct")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	status = ADS_ERROR(LDAP_NO_MEMORY);

	if (!(upn = talloc_asprintf(ctx, "%s@%s", user, ads->realm)))
		goto done;
	if (!(new_dn = talloc_asprintf(ctx, "cn=%s,cn=Users,%s", name, 
				       ads->bind_path)))
		goto done;
	if (!(controlstr = talloc_asprintf(ctx, "%u", UF_NORMAL_ACCOUNT)))
		goto done;
	if (!(mods = ads_init_mods(ctx)))
		goto done;

	ads_mod_add(ctx, &mods, "cn", name);
	ads_mod_add_var(ctx, &mods, LDAP_MOD_ADD, "objectClass", "top",
			"person", "organizationalPerson", "user", NULL);
	ads_mod_add(ctx, &mods, "userPrincipalName", upn);
	ads_mod_add(ctx, &mods, "name", name);
	ads_mod_add(ctx, &mods, "displayName", name);
	ads_mod_add(ctx, &mods, "sAMAccountName", user);
	ads_mod_add(ctx, &mods, "userAccountControl", controlstr);
	status = ads_gen_add(ads, new_dn, mods);

 done:
	talloc_destroy(ctx);
	return status;
}

ADS_STATUS ads_add_group_acct(ADS_STRUCT *ads, const char *group, 
			      const char *comment)
{
	TALLOC_CTX *ctx;
	ADS_MODLIST mods;
	ADS_STATUS status;
	char *new_dn;

	if (!(ctx = talloc_init_named("ads_add_group_acct")))
		return ADS_ERROR(LDAP_NO_MEMORY);

	status = ADS_ERROR(LDAP_NO_MEMORY);

	if (!(new_dn = talloc_asprintf(ctx, "cn=%s,cn=Users,%s", group, 
				       ads->bind_path)))
		goto done;
	if (!(mods = ads_init_mods(ctx)))
		goto done;

	ads_mod_add(ctx, &mods, "cn", group);
	ads_mod_add_var(ctx, &mods, LDAP_MOD_ADD, "objectClass", "top",
			"group", NULL);
	ads_mod_add(ctx, &mods, "name", group);
	if (comment)
		ads_mod_add(ctx, &mods, "description", comment);
	ads_mod_add(ctx, &mods, "sAMAccountName", group);
	status = ads_gen_add(ads, new_dn, mods);

 done:
	talloc_destroy(ctx);
	return status;
}
#endif
