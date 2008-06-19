/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "libwbclient.h"

/**
 *
 **/

static struct passwd *copy_passwd_entry(struct winbindd_pw *p)
{
	struct passwd *pwd = NULL;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	pwd = talloc(NULL, struct passwd);
	BAIL_ON_PTR_ERROR(pwd, wbc_status);

	pwd->pw_name = talloc_strdup(pwd,p->pw_name);
	BAIL_ON_PTR_ERROR(pwd->pw_name, wbc_status);

	pwd->pw_passwd = talloc_strdup(pwd, p->pw_passwd);
	BAIL_ON_PTR_ERROR(pwd->pw_passwd, wbc_status);

	pwd->pw_gecos = talloc_strdup(pwd, p->pw_gecos);
	BAIL_ON_PTR_ERROR(pwd->pw_gecos, wbc_status);

	pwd->pw_shell = talloc_strdup(pwd, p->pw_shell);
	BAIL_ON_PTR_ERROR(pwd->pw_shell, wbc_status);

	pwd->pw_dir = talloc_strdup(pwd, p->pw_dir);
	BAIL_ON_PTR_ERROR(pwd->pw_dir, wbc_status);

	pwd->pw_uid = p->pw_uid;
	pwd->pw_gid = p->pw_gid;

done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		talloc_free(pwd);
		pwd = NULL;
	}

	return pwd;
}

/**
 *
 **/

static struct group *copy_group_entry(struct winbindd_gr *g,
				      char *mem_buf)
{
	struct group *grp = NULL;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	int i;
	char *mem_p, *mem_q;

	grp = talloc(NULL, struct group);
	BAIL_ON_PTR_ERROR(grp, wbc_status);

	grp->gr_name = talloc_strdup(grp, g->gr_name);
	BAIL_ON_PTR_ERROR(grp->gr_name, wbc_status);

	grp->gr_passwd = talloc_strdup(grp, g->gr_passwd);
	BAIL_ON_PTR_ERROR(grp->gr_passwd, wbc_status);

	grp->gr_gid = g->gr_gid;

	grp->gr_mem = talloc_array(grp, char*, g->num_gr_mem+1);

	mem_p = mem_q = mem_buf;
	for (i=0; i<g->num_gr_mem && mem_p; i++) {
		if ((mem_q = strchr(mem_p, ',')) != NULL) {
			*mem_q = '\0';
		}

		grp->gr_mem[i] = talloc_strdup(grp, mem_p);
		BAIL_ON_PTR_ERROR(grp->gr_mem[i], wbc_status);

		if (mem_q == NULL) {
			i += 1;
			break;
		}
		mem_p = mem_q + 1;
	}
	grp->gr_mem[i] = NULL;

	wbc_status = WBC_ERR_SUCCESS;

done:
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		talloc_free(grp);
		grp = NULL;
	}

	return grp;
}

/** @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *name     Username to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetpwnam(const char *name, struct passwd **pwd)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!name || !pwd) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* dst is already null terminated from the memset above */

	strncpy(request.data.username, name, sizeof(request.data.username)-1);

	wbc_status = wbcRequestResponse(WINBINDD_GETPWNAM,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*pwd = copy_passwd_entry(&response.data.pw);
	BAIL_ON_PTR_ERROR(*pwd, wbc_status);

 done:
	return wbc_status;
}

/** @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param uid       Uid to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetpwuid(uid_t uid, struct passwd **pwd)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!pwd) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = uid;

	wbc_status = wbcRequestResponse(WINBINDD_GETPWUID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*pwd = copy_passwd_entry(&response.data.pw);
	BAIL_ON_PTR_ERROR(*pwd, wbc_status);

 done:
	return wbc_status;
}

/** @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *name     Username to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetgrnam(const char *name, struct group **grp)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!name || !grp) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* dst is already null terminated from the memset above */

	strncpy(request.data.groupname, name, sizeof(request.data.groupname)-1);

	wbc_status = wbcRequestResponse(WINBINDD_GETGRNAM,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*grp = copy_group_entry(&response.data.gr,
				(char*)response.extra_data.data);
	BAIL_ON_PTR_ERROR(*grp, wbc_status);

 done:
	if (response.extra_data.data)
		free(response.extra_data.data);

	return wbc_status;
}

/** @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param gid       Uid to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetgrgid(gid_t gid, struct group **grp)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!grp) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	request.data.gid = gid;

	wbc_status = wbcRequestResponse(WINBINDD_GETGRGID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*grp = copy_group_entry(&response.data.gr,
				(char*)response.extra_data.data);
	BAIL_ON_PTR_ERROR(*grp, wbc_status);

 done:
	if (response.extra_data.data)
		free(response.extra_data.data);

	return wbc_status;
}

/** @brief Reset the passwd iterator
 *
 * @return #wbcErr
 **/

wbcErr wbcSetpwent(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcRequestResponse(WINBINDD_SETPWENT,
					NULL, NULL);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/** @brief Close the passwd iterator
 *
 * @return #wbcErr
 **/

wbcErr wbcEndpwent(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcRequestResponse(WINBINDD_ENDPWENT,
					NULL, NULL);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/** @brief Return the next struct passwd* entry from the pwent iterator
 *
 * @param **pwd       Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetpwent(struct passwd **pwd)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/** @brief Reset the group iterator
 *
 * @return #wbcErr
 **/

wbcErr wbcSetgrent(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcRequestResponse(WINBINDD_SETGRENT,
					NULL, NULL);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/** @brief Close the group iterator
 *
 * @return #wbcErr
 **/

wbcErr wbcEndgrent(void)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	wbc_status = wbcRequestResponse(WINBINDD_ENDGRENT,
					NULL, NULL);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/** @brief Return the next struct passwd* entry from the pwent iterator
 *
 * @param **grp       Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/

wbcErr wbcGetgrent(struct group **grp)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/** @brief Return the unix group array belonging to the given user
 *
 * @param *account       The given user name
 * @param *num_groups    Number of elements returned in the groups array
 * @param **groups       Pointer to resulting gid_t array.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetGroups(const char *account,
		    uint32_t *num_groups,
		    gid_t **_groups)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;
	uint32_t i;
	gid_t *groups = NULL;

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!account) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Send request */

	strncpy(request.data.username, account, sizeof(request.data.username)-1);

	wbc_status = wbcRequestResponse(WINBINDD_GETGROUPS,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	groups = talloc_array(NULL, gid_t, response.data.num_entries);
	BAIL_ON_PTR_ERROR(groups, wbc_status);

	for (i = 0; i < response.data.num_entries; i++) {
		groups[i] = ((gid_t *)response.extra_data.data)[i];
	}

	*num_groups = response.data.num_entries;
	*_groups = groups;
	groups = NULL;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	if (response.extra_data.data) {
		free(response.extra_data.data);
	}
	if (groups) {
		talloc_free(groups);
	}

	return wbc_status;
}
