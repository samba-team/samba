/*
   Python interface to passdb

   Copyright (C) Amitay Isaacs 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include <pytalloc.h>
#include "includes.h"
#include "python/py3compat.h"
#include "lib/util/talloc_stack.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/idmap.h"
#include "passdb.h"
#include "secrets.h"
#include "idmap.h"

#ifndef Py_TYPE /* Py_TYPE is only available on Python > 2.6 */
#define Py_TYPE(ob)             (((PyObject*)(ob))->ob_type)
#endif

#ifndef PY_CHECK_TYPE
#define PY_CHECK_TYPE(type, var, fail) \
	if (!PyObject_TypeCheck(var, type)) {\
		PyErr_Format(PyExc_TypeError, __location__ ": Expected type '%s' for '%s' of type '%s'", (type)->tp_name, #var, Py_TYPE(var)->tp_name); \
		fail; \
	}
#endif


static PyTypeObject *dom_sid_Type = NULL;
static PyTypeObject *security_Type = NULL;
static PyTypeObject *guid_Type = NULL;

static PyTypeObject PySamu;
static PyTypeObject PyGroupmap;
static PyTypeObject PyPDB;

static PyObject *py_pdb_error;

void initpassdb(void);


/************************** PIDL Autogeneratd ******************************/

static PyObject *py_samu_get_logon_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_logon_time;

	py_logon_time = PyLong_FromLong(pdb_get_logon_time(sam_acct));
	talloc_free(frame);
	return py_logon_time;
}

static int py_samu_set_logon_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_logon_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_logoff_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_logoff_time;

	py_logoff_time = PyLong_FromLong(pdb_get_logoff_time(sam_acct));
	talloc_free(frame);
	return py_logoff_time;
}

static int py_samu_set_logoff_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_logoff_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_kickoff_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_kickoff_time;

	py_kickoff_time = PyLong_FromLong(pdb_get_kickoff_time(sam_acct));
	talloc_free(frame);
	return py_kickoff_time;
}

static int py_samu_set_kickoff_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_kickoff_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_bad_password_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_bad_password_time;

	py_bad_password_time = PyLong_FromLong(pdb_get_bad_password_time(sam_acct));
	talloc_free(frame);
	return py_bad_password_time;
}

static int py_samu_set_bad_password_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_bad_password_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_pass_last_set_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_pass_last_set_time;

	py_pass_last_set_time = PyLong_FromLong(pdb_get_pass_last_set_time(sam_acct));
	talloc_free(frame);
	return py_pass_last_set_time;
}

static int py_samu_set_pass_last_set_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_pass_last_set_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_pass_can_change_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_pass_can_change_time;

	py_pass_can_change_time = PyLong_FromLong(pdb_get_pass_can_change_time(sam_acct));
	talloc_free(frame);
	return py_pass_can_change_time;
}

static int py_samu_set_pass_can_change_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_pass_can_change_time(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_pass_must_change_time(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_pass_must_change_time;

	py_pass_must_change_time = PyLong_FromLong(pdb_get_pass_must_change_time(sam_acct));
	talloc_free(frame);
	return py_pass_must_change_time;
}

static int py_samu_set_pass_must_change_time(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);

	/* TODO: make this not a get/set or give a better exception */
	talloc_free(frame);
	return -1;
}

static PyObject *py_samu_get_username(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_username;
	const char *username;

	username = pdb_get_username(sam_acct);
	if (username == NULL) {
		Py_RETURN_NONE;
	}

	py_username = PyUnicode_FromString(username);
	talloc_free(frame);
	return py_username;
}

static int py_samu_set_username(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_username(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_domain(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_domain;
	const char *domain;

	domain = pdb_get_domain(sam_acct);
	if (domain == NULL) {
		Py_RETURN_NONE;
	}

	py_domain = PyUnicode_FromString(domain);
	talloc_free(frame);
	return py_domain;
}

static int py_samu_set_domain(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_domain(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_nt_username(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_nt_username;
	const char *nt_username;

	nt_username = pdb_get_nt_username(sam_acct);
	if (nt_username == NULL) {
		Py_RETURN_NONE;
	}

	py_nt_username = PyUnicode_FromString(nt_username);
	talloc_free(frame);
	return py_nt_username;
}

static int py_samu_set_nt_username(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_nt_username(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_full_name(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_full_name;
	const char *full_name;

	full_name = pdb_get_fullname(sam_acct);
	if (full_name == NULL) {
		Py_RETURN_NONE;
	}

	py_full_name = PyUnicode_FromString(full_name);
	talloc_free(frame);
	return py_full_name;
}

static int py_samu_set_full_name(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_fullname(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_home_dir(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_home_dir;
	const char *home_dir;

	home_dir = pdb_get_homedir(sam_acct);
	if (home_dir == NULL) {
		Py_RETURN_NONE;
	}

	py_home_dir = PyUnicode_FromString(home_dir);
	talloc_free(frame);
	return py_home_dir;
}

static int py_samu_set_home_dir(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_homedir(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_dir_drive(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_dir_drive;
	const char *dir_drive;

	dir_drive = pdb_get_dir_drive(sam_acct);
	if (dir_drive == NULL) {
		Py_RETURN_NONE;
	}

	py_dir_drive = PyUnicode_FromString(dir_drive);
	talloc_free(frame);
	return py_dir_drive;
}

static int py_samu_set_dir_drive(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_dir_drive(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_logon_script(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_logon_script;
	const char *logon_script;

	logon_script = pdb_get_logon_script(sam_acct);
	if (logon_script == NULL) {
		Py_RETURN_NONE;
	}

	py_logon_script = PyUnicode_FromString(logon_script);
	talloc_free(frame);
	return py_logon_script;
}

static int py_samu_set_logon_script(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_logon_script(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_profile_path(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_profile_path;
	const char *profile_path;

	profile_path = pdb_get_profile_path(sam_acct);
	if (profile_path == NULL) {
		Py_RETURN_NONE;
	}

	py_profile_path = PyUnicode_FromString(profile_path);
	talloc_free(frame);
	return py_profile_path;
}

static int py_samu_set_profile_path(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_profile_path(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_acct_desc(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_acct_desc;
	const char *acct_desc;

	acct_desc = pdb_get_acct_desc(sam_acct);
	if (acct_desc == NULL) {
		Py_RETURN_NONE;
	}

	py_acct_desc = PyUnicode_FromString(acct_desc);
	talloc_free(frame);
	return py_acct_desc;
}

static int py_samu_set_acct_desc(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_acct_desc(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_workstations(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_workstations;
	const char *workstations;

	workstations = pdb_get_workstations(sam_acct);
	if (workstations == NULL) {
		Py_RETURN_NONE;
	}

	py_workstations = PyUnicode_FromString(workstations);
	talloc_free(frame);
	return py_workstations;
}

static int py_samu_set_workstations(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_workstations(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_comment(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_comment;
	const char *comment;

	comment = pdb_get_comment(sam_acct);
	if (comment == NULL) {
		Py_RETURN_NONE;
	}

	py_comment = PyUnicode_FromString(comment);
	talloc_free(frame);
	return py_comment;
}

static int py_samu_set_comment(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_comment(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_munged_dial(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_munged_dial;
	const char *munged_dial;

	munged_dial = pdb_get_munged_dial(sam_acct);
	if (munged_dial == NULL) {
		Py_RETURN_NONE;
	}

	py_munged_dial = PyUnicode_FromString(munged_dial);
	talloc_free(frame);
	return py_munged_dial;
}

static int py_samu_set_munged_dial(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (!pdb_set_munged_dial(sam_acct, PyUnicode_AsUTF8(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_user_sid(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_user_sid;
	const struct dom_sid *user_sid;
	struct dom_sid *copy_user_sid;
	TALLOC_CTX *mem_ctx;

	user_sid = pdb_get_user_sid(sam_acct);
	if(user_sid == NULL) {
		Py_RETURN_NONE;
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}
	copy_user_sid = dom_sid_dup(mem_ctx, user_sid);
	if (copy_user_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		talloc_free(frame);
		return NULL;
	}

	py_user_sid = pytalloc_steal(dom_sid_Type, copy_user_sid);

	talloc_free(mem_ctx);

	talloc_free(frame);
	return py_user_sid;
}

static int py_samu_set_user_sid(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(dom_sid_Type, value, return -1;);
	if (!pdb_set_user_sid(sam_acct, (struct dom_sid *)pytalloc_get_ptr(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_group_sid(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	const struct dom_sid *group_sid;
	struct dom_sid *copy_group_sid;

	group_sid = pdb_get_group_sid(sam_acct);
	if (group_sid == NULL) {
		Py_RETURN_NONE;
	}

	copy_group_sid = dom_sid_dup(NULL, group_sid);
	if (copy_group_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return pytalloc_steal(dom_sid_Type, copy_group_sid);
}

static int py_samu_set_group_sid(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(dom_sid_Type, value, return -1;);
	if (!pdb_set_group_sid(sam_acct, (struct dom_sid *)pytalloc_get_ptr(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_lanman_passwd(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_lm_pw;
	const char *lm_pw;

	lm_pw = (const char *)pdb_get_lanman_passwd(sam_acct);
	if (lm_pw == NULL) {
		Py_RETURN_NONE;
	}

	py_lm_pw = PyBytes_FromStringAndSize(lm_pw, LM_HASH_LEN);
	talloc_free(frame);
	return py_lm_pw;
}

static int py_samu_set_lanman_passwd(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyBytes_Type, value, return -1;);
	if (!pdb_set_lanman_passwd(sam_acct, (uint8_t *)PyBytes_AsString(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_nt_passwd(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_nt_pw;
	const char *nt_pw;

	nt_pw = (const char *)pdb_get_nt_passwd(sam_acct);
	if (nt_pw == NULL) {
		Py_RETURN_NONE;
	}

	py_nt_pw = PyBytes_FromStringAndSize(nt_pw, NT_HASH_LEN);
	talloc_free(frame);
	return py_nt_pw;
}

static int py_samu_set_nt_passwd(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	if (!pdb_set_nt_passwd(sam_acct, (uint8_t *)PyBytes_AsString(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_pw_history(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_nt_pw_his;
	const char *nt_pw_his;
	uint32_t hist_len;

	nt_pw_his = (const char *)pdb_get_pw_history(sam_acct, &hist_len);
	if (nt_pw_his == NULL) {
		Py_RETURN_NONE;
	}

	py_nt_pw_his = PyBytes_FromStringAndSize(nt_pw_his, hist_len*PW_HISTORY_ENTRY_LEN);
	talloc_free(frame);
	return py_nt_pw_his;
}

static int py_samu_set_pw_history(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	char *nt_pw_his;
	Py_ssize_t len;
	uint32_t hist_len;

	PyBytes_AsStringAndSize(value, &nt_pw_his, &len);
	hist_len = len / PW_HISTORY_ENTRY_LEN;
	if (!pdb_set_pw_history(sam_acct, (uint8_t *)nt_pw_his, hist_len, PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_plaintext_passwd(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_plaintext_pw;
	const char *plaintext_pw;

	plaintext_pw = pdb_get_plaintext_passwd(sam_acct);
	if (plaintext_pw == NULL) {
		Py_RETURN_NONE;
	}

	py_plaintext_pw = PyUnicode_FromString(plaintext_pw);
	talloc_free(frame);
	return py_plaintext_pw;
}

static int py_samu_set_plaintext_passwd(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	if (!pdb_set_plaintext_passwd(sam_acct, PyUnicode_AsUTF8(value))) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_acct_ctrl(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_acct_ctrl;

	py_acct_ctrl = PyLong_FromLong(pdb_get_acct_ctrl(sam_acct));
	talloc_free(frame);
	return py_acct_ctrl;
}

static int py_samu_set_acct_ctrl(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_acct_ctrl(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_logon_divs(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_logon_divs;

	py_logon_divs = PyLong_FromLong(pdb_get_logon_divs(sam_acct));
	talloc_free(frame);
	return py_logon_divs;
}

static int py_samu_set_logon_divs(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_logon_divs(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_hours_len(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_hours_len;

	py_hours_len = PyLong_FromLong(pdb_get_hours_len(sam_acct));
	talloc_free(frame);
	return py_hours_len;
}

static int py_samu_set_hours_len(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_hours_len(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_hours(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_hours;
	const char *hours;
	int hours_len, i;

	hours = (const char *)pdb_get_hours(sam_acct);
	if(! hours) {
		Py_RETURN_NONE;
	}

	hours_len = pdb_get_hours_len(sam_acct);
	if ((py_hours = PyList_New(hours_len)) == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for (i=0; i<hours_len; i++) {
		PyList_SetItem(py_hours, i, PyLong_FromLong(hours[i]));
	}
	talloc_free(frame);
	return py_hours;
}

static int py_samu_set_hours(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	int i;
	uint8_t *hours;
	int hours_len;
	bool status;

	PY_CHECK_TYPE(&PyList_Type, value, return -1;);

	hours_len = PyList_GET_SIZE(value);

	hours = talloc_array(pytalloc_get_mem_ctx(obj), uint8_t, hours_len);
	if (!hours) {
		PyErr_NoMemory();
		talloc_free(frame);
		return -1;
	}

	for (i=0; i < hours_len; i++) {
		PY_CHECK_TYPE(&PyLong_Type, PyList_GET_ITEM(value,i), return -1;);
		hours[i] = PyLong_AsLong(PyList_GET_ITEM(value, i));
	}

	status = pdb_set_hours(sam_acct, hours, hours_len, PDB_CHANGED);
	talloc_free(hours);

	if(! status) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_bad_password_count(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_bad_password_count;

	py_bad_password_count = PyLong_FromLong(pdb_get_bad_password_count(sam_acct));
	talloc_free(frame);
	return py_bad_password_count;
}

static int py_samu_set_bad_password_count(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_bad_password_count(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_logon_count(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_logon_count;

	py_logon_count = PyLong_FromLong(pdb_get_logon_count(sam_acct));
	talloc_free(frame);
	return py_logon_count;
}

static int py_samu_set_logon_count(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_logon_count(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_country_code(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_country_code;

	py_country_code = PyLong_FromLong(pdb_get_country_code(sam_acct));
	talloc_free(frame);
	return py_country_code;
}

static int py_samu_set_country_code(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_country_code(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_samu_get_code_page(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);
	PyObject *py_code_page;

	py_code_page = PyLong_FromLong(pdb_get_code_page(sam_acct));
	talloc_free(frame);
	return py_code_page;
}

static int py_samu_set_code_page(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct = (struct samu *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	if (!pdb_set_code_page(sam_acct, PyLong_AsLong(value), PDB_CHANGED)) {
		talloc_free(frame);
		return -1;
	}
	talloc_free(frame);
	return 0;
}

static PyGetSetDef py_samu_getsetters[] = {
	{
		.name = discard_const_p(char, "logon_time"),
		.get  = py_samu_get_logon_time,
		.set  = py_samu_set_logon_time,
	},
	{
		.name = discard_const_p(char, "logoff_time"),
		.get  = py_samu_get_logoff_time,
		.set  = py_samu_set_logoff_time,
	},
	{
		.name = discard_const_p(char, "kickoff_time"),
		.get  = py_samu_get_kickoff_time,
		.set  = py_samu_set_kickoff_time,
	},
	{
		.name = discard_const_p(char, "bad_password_time"),
		.get  = py_samu_get_bad_password_time,
		.set  = py_samu_set_bad_password_time,
	},
	{
		.name = discard_const_p(char, "pass_last_set_time"),
		.get  = py_samu_get_pass_last_set_time,
		.set  = py_samu_set_pass_last_set_time,
	},
	{
		.name = discard_const_p(char, "pass_can_change_time"),
		.get  = py_samu_get_pass_can_change_time,
		.set  = py_samu_set_pass_can_change_time,
	},
	{
		.name = discard_const_p(char, "pass_must_change_time"),
		.get  = py_samu_get_pass_must_change_time,
		.set  = py_samu_set_pass_must_change_time,
	},
	{
		.name = discard_const_p(char, "username"),
		.get  = py_samu_get_username,
		.set  = py_samu_set_username,
	},
	{
		.name = discard_const_p(char, "domain"),
		.get  = py_samu_get_domain,
		.set  = py_samu_set_domain,
	},
	{
		.name = discard_const_p(char, "nt_username"),
		.get  = py_samu_get_nt_username,
		.set  = py_samu_set_nt_username,
	},
	{
		.name = discard_const_p(char, "full_name"),
		.get  = py_samu_get_full_name,
		.set  = py_samu_set_full_name,
	},
	{
		.name = discard_const_p(char, "home_dir"),
		.get  = py_samu_get_home_dir,
		.set  = py_samu_set_home_dir,
	},
	{
		.name = discard_const_p(char, "dir_drive"),
		.get  = py_samu_get_dir_drive,
		.set  = py_samu_set_dir_drive,
	},
	{
		.name = discard_const_p(char, "logon_script"),
		.get  = py_samu_get_logon_script,
		.set  = py_samu_set_logon_script,
	},
	{
		.name = discard_const_p(char, "profile_path"),
		.get  = py_samu_get_profile_path,
		.set  = py_samu_set_profile_path,
	},
	{
		.name = discard_const_p(char, "acct_desc"),
		.get  = py_samu_get_acct_desc,
		.set  = py_samu_set_acct_desc,
	},
	{
		.name = discard_const_p(char, "workstations"),
		.get  = py_samu_get_workstations,
		.set  = py_samu_set_workstations,
	},
	{
		.name = discard_const_p(char, "comment"),
		.get  = py_samu_get_comment,
		.set  = py_samu_set_comment,
	},
	{
		.name = discard_const_p(char, "munged_dial"),
		.get  = py_samu_get_munged_dial,
		.set  = py_samu_set_munged_dial,
	},
	{
		.name = discard_const_p(char, "user_sid"),
		.get  = py_samu_get_user_sid,
		.set  = py_samu_set_user_sid,
	},
	{
		.name = discard_const_p(char, "group_sid"),
		.get  = py_samu_get_group_sid,
		.set  = py_samu_set_group_sid,
	},
	{
		.name = discard_const_p(char, "lanman_passwd"),
		.get  = py_samu_get_lanman_passwd,
		.set  = py_samu_set_lanman_passwd,
	},
	{
		.name = discard_const_p(char, "nt_passwd"),
		.get  = py_samu_get_nt_passwd,
		.set  = py_samu_set_nt_passwd,
	},
	{
		.name = discard_const_p(char, "pw_history"),
		.get  = py_samu_get_pw_history,
		.set  = py_samu_set_pw_history,
	},
	{
		.name = discard_const_p(char, "plaintext_passwd"),
		.get  = py_samu_get_plaintext_passwd,
		.set  = py_samu_set_plaintext_passwd,
	},
	{
		.name = discard_const_p(char, "acct_ctrl"),
		.get  = py_samu_get_acct_ctrl,
		.set  = py_samu_set_acct_ctrl,
	},
	{
		.name = discard_const_p(char, "logon_divs"),
		.get  = py_samu_get_logon_divs,
		.set  = py_samu_set_logon_divs,
	},
	{
		.name = discard_const_p(char, "hours_len"),
		.get  = py_samu_get_hours_len,
		.set  = py_samu_set_hours_len,
	},
	{
		.name = discard_const_p(char, "hours"),
		.get  = py_samu_get_hours,
		.set  = py_samu_set_hours,
	},
	{
		.name = discard_const_p(char, "bad_password_count"),
		.get  = py_samu_get_bad_password_count,
		.set  = py_samu_set_bad_password_count,
	},
	{
		.name = discard_const_p(char, "logon_count"),
		.get  = py_samu_get_logon_count,
		.set  = py_samu_set_logon_count,
	},
	{
		.name = discard_const_p(char, "country_code"),
		.get  = py_samu_get_country_code,
		.set  = py_samu_set_country_code,
	},
	{
		.name = discard_const_p(char, "code_page"),
		.get  = py_samu_get_code_page,
		.set  = py_samu_set_code_page,
	},
	{
		.name = NULL,
	}
};


/************************** PIDL Autogeneratd ******************************/

static PyObject *py_samu_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samu *sam_acct;

	sam_acct = samu_new(NULL);
	if (!sam_acct) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return pytalloc_steal(type, sam_acct);
}

static PyTypeObject PySamu = {
	.tp_name = "passdb.Samu",
	.tp_getset = py_samu_getsetters,
	.tp_methods = NULL,
	.tp_new = py_samu_new,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "Samu() -> samu object\n",
};


static PyObject *py_groupmap_get_gid(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);
	PyObject *py_gid;

	py_gid = Py_BuildValue("i", group_map->gid);
	talloc_free(frame);
	return py_gid;
}

static int py_groupmap_set_gid(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	group_map->gid = PyLong_AsLong(value);
	talloc_free(frame);
	return 0;
}

static PyObject *py_groupmap_get_sid(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);
	PyObject *py_sid;
	struct dom_sid *group_sid;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	group_sid = dom_sid_dup(mem_ctx, &group_map->sid);
	if (group_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		talloc_free(frame);
		return NULL;
	}

	py_sid = pytalloc_steal(dom_sid_Type, group_sid);

	talloc_free(mem_ctx);

	talloc_free(frame);
	return py_sid;
}

static int py_groupmap_set_sid(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(dom_sid_Type, value, return -1;);
	group_map->sid = *pytalloc_get_type(value, struct dom_sid);
	talloc_free(frame);
	return 0;
}

static PyObject *py_groupmap_get_sid_name_use(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);
	PyObject *py_sid_name_use;

	py_sid_name_use = PyLong_FromLong(group_map->sid_name_use);
	talloc_free(frame);
	return py_sid_name_use;
}

static int py_groupmap_set_sid_name_use(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyLong_Type, value, return -1;);
	group_map->sid_name_use = PyLong_AsLong(value);
	talloc_free(frame);
	return 0;
}

static PyObject *py_groupmap_get_nt_name(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);
	PyObject *py_nt_name;
	if (group_map->nt_name == NULL) {
		py_nt_name = Py_None;
		Py_INCREF(py_nt_name);
	} else {
		py_nt_name = PyUnicode_FromString(group_map->nt_name);
	}
	talloc_free(frame);
	return py_nt_name;
}

static int py_groupmap_set_nt_name(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (value == Py_None) {
		fstrcpy(group_map->nt_name, NULL);
	} else {
		fstrcpy(group_map->nt_name, PyUnicode_AsUTF8(value));
	}
	talloc_free(frame);
	return 0;
}

static PyObject *py_groupmap_get_comment(PyObject *obj, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);
	PyObject *py_comment;
	if (group_map->comment == NULL) {
		py_comment = Py_None;
		Py_INCREF(py_comment);
	} else {
		py_comment = PyUnicode_FromString(group_map->comment);
	}
	talloc_free(frame);
	return py_comment;
}

static int py_groupmap_set_comment(PyObject *obj, PyObject *value, void *closure)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map = (GROUP_MAP *)pytalloc_get_ptr(obj);

	PY_CHECK_TYPE(&PyUnicode_Type, value, return -1;);
	if (value == Py_None) {
		fstrcpy(group_map->comment, NULL);
	} else {
		fstrcpy(group_map->comment, PyUnicode_AsUTF8(value));
	}
	talloc_free(frame);
	return 0;
}

static PyGetSetDef py_groupmap_getsetters[] = {
	{
		.name = discard_const_p(char, "gid"),
		.get  = py_groupmap_get_gid,
		.set  = py_groupmap_set_gid,
	},
	{
		.name = discard_const_p(char, "sid"),
		.get  = py_groupmap_get_sid,
		.set  = py_groupmap_set_sid,
	},
	{
		.name = discard_const_p(char, "sid_name_use"),
		.get  = py_groupmap_get_sid_name_use,
		.set  = py_groupmap_set_sid_name_use,
	},
	{
		.name = discard_const_p(char, "nt_name"),
		.get  = py_groupmap_get_nt_name,
		.set  = py_groupmap_set_nt_name,
	},
	{
		.name = discard_const_p(char, "comment"),
		.get  = py_groupmap_get_comment,
		.set  = py_groupmap_set_comment,
	},
	{
		.name = NULL,
	},
};

static PyObject *py_groupmap_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	GROUP_MAP *group_map;
	TALLOC_CTX *mem_ctx;
	PyObject *py_group_map;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	group_map = talloc_zero(mem_ctx, GROUP_MAP);
	if (group_map == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		talloc_free(frame);
		return NULL;
	}

	py_group_map = pytalloc_steal(type, group_map);
	if (py_group_map == NULL) {
		PyErr_NoMemory();
		talloc_free(mem_ctx);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(mem_ctx);

	talloc_free(frame);
	return py_group_map;
}


static PyTypeObject PyGroupmap = {
	.tp_name = "passdb.Groupmap",
	.tp_getset = py_groupmap_getsetters,
	.tp_methods = NULL,
	.tp_new = py_groupmap_new,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = "Groupmap() -> group map object\n",
};


static PyObject *py_pdb_domain_info(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	struct pdb_domain_info *domain_info;
	PyObject *py_domain_info;
	struct dom_sid *sid;
	struct GUID *guid;
	PyObject *py_dom_sid = NULL;
	PyObject *py_guid = NULL;

	methods = pytalloc_get_ptr(self);

	domain_info = methods->get_domain_info(methods, frame);
	if (! domain_info) {
		Py_RETURN_NONE;
	}

	sid = dom_sid_dup(frame, &domain_info->sid);
	if (sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	guid = talloc(frame, struct GUID);
	if (guid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}
	*guid = domain_info->guid;

	py_dom_sid = pytalloc_steal(dom_sid_Type, sid);
	py_guid = pytalloc_steal(guid_Type, guid);

	py_domain_info = Py_BuildValue(
		"{s:s, s:s, s:s, s:O, s:O}",
		"name", domain_info->name,
		"dns_domain", domain_info->dns_domain,
		"dns_forest", domain_info->dns_forest,
		"dom_sid", py_dom_sid,
		"guid", py_guid);


	Py_CLEAR(py_dom_sid);
	Py_CLEAR(py_guid);
	talloc_free(frame);
	return py_domain_info;
}


static PyObject *py_pdb_getsampwnam(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	const char *username;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "s:getsampwnam", &username)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	py_sam_acct = py_samu_new(&PySamu, NULL, NULL);
	if (py_sam_acct == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}
	sam_acct = (struct samu *)pytalloc_get_ptr(py_sam_acct);

	status = methods->getsampwnam(methods, sam_acct, username);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get user information for '%s', (%d,%s)",
				username,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		Py_DECREF(py_sam_acct);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_sam_acct;
}

static PyObject *py_pdb_getsampwsid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;
	PyObject *py_user_sid;

	if (!PyArg_ParseTuple(args, "O:getsampwsid", &py_user_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	py_sam_acct = py_samu_new(&PySamu, NULL, NULL);
	if (py_sam_acct == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}
	sam_acct = (struct samu *)pytalloc_get_ptr(py_sam_acct);

	status = methods->getsampwsid(methods, sam_acct, pytalloc_get_ptr(py_user_sid));
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get user information from SID, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		Py_DECREF(py_sam_acct);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_sam_acct;
}

static PyObject *py_pdb_create_user(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *username;
	unsigned int acct_flags;
	unsigned int rid;

	if (!PyArg_ParseTuple(args, "sI:create_user", &username, &acct_flags)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->create_user(methods, frame, username, acct_flags, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to create user (%s), (%d,%s)",
				username,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return PyLong_FromLong(rid);
}

static PyObject *py_pdb_delete_user(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "O!:delete_user", &PySamu, &py_sam_acct)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->delete_user(methods, frame, sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete user, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_pdb_add_sam_account(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "O!:add_sam_account", &PySamu, &py_sam_acct)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->add_sam_account(methods, sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to add sam account '%s', (%d,%s)",
				sam_acct->username,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_pdb_update_sam_account(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "O!:update_sam_account", &PySamu, &py_sam_acct)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->update_sam_account(methods, sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to update sam account, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_pdb_delete_sam_account(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "O!:delete_sam_account", &PySamu, &py_sam_acct)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->delete_sam_account(methods, sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete sam account, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_pdb_rename_sam_account(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	struct samu *sam_acct;
	const char *new_username;
	PyObject *py_sam_acct;

	if (!PyArg_ParseTuple(args, "O!s:rename_sam_account", &PySamu, &py_sam_acct,
					&new_username)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->rename_sam_account(methods, sam_acct, new_username);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to rename sam account, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_getgrsid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	GROUP_MAP *group_map;
	struct dom_sid *domain_sid;
	PyObject *py_domain_sid, *py_group_map;

	if (!PyArg_ParseTuple(args, "O!:getgrsid", dom_sid_Type, &py_domain_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	domain_sid = pytalloc_get_ptr(py_domain_sid);

	py_group_map = py_groupmap_new(&PyGroupmap, NULL, NULL);
	if (py_group_map == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	group_map = pytalloc_get_ptr(py_group_map);

	status = methods->getgrsid(methods, group_map, *domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get group information by sid, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_group_map;
}


static PyObject *py_pdb_getgrgid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	GROUP_MAP *group_map;
	PyObject *py_group_map;
	unsigned int gid_value;

	if (!PyArg_ParseTuple(args, "I:getgrgid", &gid_value)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	py_group_map = py_groupmap_new(&PyGroupmap, NULL, NULL);
	if (py_group_map == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	group_map = pytalloc_get_ptr(py_group_map);

	status = methods->getgrgid(methods, group_map, gid_value);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get group information by gid, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_group_map;
}


static PyObject *py_pdb_getgrnam(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	GROUP_MAP *group_map;
	PyObject *py_group_map;
	const char *groupname;

	if (!PyArg_ParseTuple(args, "s:getgrnam", &groupname)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	py_group_map = py_groupmap_new(&PyGroupmap, NULL, NULL);
	if (py_group_map == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	group_map = pytalloc_get_ptr(py_group_map);

	status = methods->getgrnam(methods, group_map, groupname);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get group information by name, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_group_map;
}


static PyObject *py_pdb_create_dom_group(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *groupname;
	uint32_t group_rid;

	if (!PyArg_ParseTuple(args, "s:create_dom_group", &groupname)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->create_dom_group(methods, frame, groupname, &group_rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to create domain group (%s), (%d,%s)",
				groupname,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return PyLong_FromLong(group_rid);
}


static PyObject *py_pdb_delete_dom_group(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	unsigned int group_rid;

	if (!PyArg_ParseTuple(args, "I:delete_dom_group", &group_rid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->delete_dom_group(methods, frame, group_rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete domain group (rid=%d), (%d,%s)",
				group_rid,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_add_group_mapping_entry(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_group_map;
	GROUP_MAP *group_map;

	if (!PyArg_ParseTuple(args, "O!:add_group_mapping_entry", &PyGroupmap, &py_group_map)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	group_map = pytalloc_get_ptr(py_group_map);

	status = methods->add_group_mapping_entry(methods, group_map);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to add group mapping entry, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_update_group_mapping_entry(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_group_map;
	GROUP_MAP *group_map;

	if (!PyArg_ParseTuple(args, "O!:update_group_mapping_entry", &PyGroupmap, &py_group_map)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	group_map = pytalloc_get_ptr(py_group_map);

	status = methods->update_group_mapping_entry(methods, group_map);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to update group mapping entry, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_delete_group_mapping_entry(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_group_sid;
	struct dom_sid *group_sid;

	if (!PyArg_ParseTuple(args, "O!:delete_group_mapping_entry", dom_sid_Type, &py_group_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	group_sid = pytalloc_get_ptr(py_group_sid);

	status = methods->delete_group_mapping_entry(methods, *group_sid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete group mapping entry, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_enum_group_mapping(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	enum lsa_SidType sid_name_use;
	int lsa_sidtype_value = SID_NAME_UNKNOWN;
	int unix_only = 0;
	PyObject *py_domain_sid = Py_None;
	struct dom_sid *domain_sid = NULL;
	GROUP_MAP **gmap = NULL;
	GROUP_MAP *group_map;
	size_t num_entries;
	PyObject *py_gmap_list, *py_group_map;
	int i;

	if (!PyArg_ParseTuple(args, "|O!ii:enum_group_mapping", dom_sid_Type, &py_domain_sid,
					&lsa_sidtype_value, &unix_only)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sid_name_use = lsa_sidtype_value;

	if (py_domain_sid != Py_None) {
		domain_sid = pytalloc_get_ptr(py_domain_sid);
	}

	status = methods->enum_group_mapping(methods, domain_sid, sid_name_use,
						&gmap, &num_entries, unix_only);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to enumerate group mappings, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_gmap_list = PyList_New(0);
	if (py_gmap_list == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for(i=0; i<num_entries; i++) {
		py_group_map = py_groupmap_new(&PyGroupmap, NULL, NULL);
		if (py_group_map) {
			int res = 0;
			group_map = pytalloc_get_ptr(py_group_map);
			*group_map = *gmap[i];
			talloc_steal(group_map, gmap[i]->nt_name);
			talloc_steal(group_map, gmap[i]->comment);

			res = PyList_Append(py_gmap_list, py_group_map);
			Py_CLEAR(py_group_map);
			if (res == -1) {
				Py_CLEAR(py_gmap_list);
				talloc_free(frame);
				return NULL;
			}
		}
	}

	talloc_free(gmap);

	talloc_free(frame);
	return py_gmap_list;
}


static PyObject *py_pdb_enum_group_members(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_group_sid;
	struct dom_sid *group_sid;
	uint32_t *member_rids;
	size_t num_members;
	PyObject *py_sid_list;
	struct dom_sid *domain_sid, *member_sid;
	int i;

	if (!PyArg_ParseTuple(args, "O!:enum_group_members", dom_sid_Type, &py_group_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	group_sid = pytalloc_get_ptr(py_group_sid);

	status = methods->enum_group_members(methods, frame, group_sid,
						&member_rids, &num_members);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to enumerate group members, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_sid_list = PyList_New(0);
	if (py_sid_list == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	domain_sid = get_global_sam_sid();

	for(i=0; i<num_members; i++) {
		int res = 0;
		PyObject *py_member_sid = NULL;
		member_sid = dom_sid_add_rid(frame, domain_sid, member_rids[i]);
		py_member_sid = pytalloc_steal(dom_sid_Type, member_sid);
		res = PyList_Append(py_sid_list,
				    py_member_sid);
		Py_CLEAR(py_member_sid);
		if (res == -1) {
			talloc_free(frame);
			Py_CLEAR(py_sid_list);
			return NULL;
		}
	}

	talloc_free(frame);
	return py_sid_list;
}


static PyObject *py_pdb_enum_group_memberships(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	int i;

	struct samu *sam_acct;
	PyObject *py_sam_acct;
	PyObject *py_sid_list;
	struct dom_sid *user_group_sids = NULL;
	gid_t *user_group_ids = NULL;
	uint32_t num_groups = 0;

	if (!PyArg_ParseTuple(args, "O!:enum_group_memberships", &PySamu, &py_sam_acct)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sam_acct = pytalloc_get_ptr(py_sam_acct);

	status = methods->enum_group_memberships(methods, frame, sam_acct,
						 &user_group_sids, &user_group_ids, &num_groups);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to enumerate group memberships, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_sid_list = PyList_New(0);
	if (py_sid_list == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for(i=0; i<num_groups; i++) {
		PyObject *py_sid =
			pytalloc_steal(dom_sid_Type,
				       dom_sid_dup(NULL, &user_group_sids[i]));
		PyList_Append(py_sid_list, py_sid);
		Py_CLEAR(py_sid);
	}

	talloc_free(frame);
	return py_sid_list;
}


static PyObject *py_pdb_add_groupmem(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	uint32_t group_rid, member_rid;

	if (!PyArg_ParseTuple(args, "II:add_groupmem", &group_rid, &member_rid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->add_groupmem(methods, frame, group_rid, member_rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to add group member, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_del_groupmem(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	uint32_t group_rid, member_rid;

	if (!PyArg_ParseTuple(args, "II:del_groupmem", &group_rid, &member_rid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->del_groupmem(methods, frame, group_rid, member_rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to rename sam account, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_create_alias(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *alias_name;
	uint32_t rid;

	if (!PyArg_ParseTuple(args, "s:create_alias", &alias_name)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->create_alias(methods, alias_name, &rid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to create alias (%s), (%d,%s)",
				alias_name,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return PyLong_FromLong(rid);
}


static PyObject *py_pdb_delete_alias(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid;
	struct dom_sid *alias_sid;

	if (!PyArg_ParseTuple(args, "O!:delete_alias", dom_sid_Type, &py_alias_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);

	status = methods->delete_alias(methods, alias_sid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete alias, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_get_aliasinfo(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid;
	struct dom_sid *alias_sid;
	struct acct_info *alias_info;
	PyObject *py_alias_info;

	if (!PyArg_ParseTuple(args, "O!:get_aliasinfo", dom_sid_Type, &py_alias_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);

	alias_info = talloc_zero(frame, struct acct_info);
	if (!alias_info) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	status = methods->get_aliasinfo(methods, alias_sid, alias_info);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get alias information, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_alias_info = Py_BuildValue(
		"{s:s, s:s, s:l}",
		"acct_name", alias_info->acct_name,
		"acct_desc", alias_info->acct_desc,
		"rid", alias_info->rid);

	talloc_free(frame);
	return py_alias_info;
}


static PyObject *py_pdb_set_aliasinfo(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid, *py_alias_info;
	struct dom_sid *alias_sid;
	struct acct_info alias_info;

	if (!PyArg_ParseTuple(args, "O!O:set_alias_info", dom_sid_Type, &py_alias_sid,
				&py_alias_info)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);

	alias_info.acct_name = talloc_strdup(frame, PyUnicode_AsUTF8(PyDict_GetItemString(py_alias_info, "acct_name")));
	if (alias_info.acct_name == NULL) {
		PyErr_Format(py_pdb_error, "Unable to allocate memory");
		talloc_free(frame);
		return NULL;
	}
	alias_info.acct_desc = talloc_strdup(frame, PyUnicode_AsUTF8(PyDict_GetItemString(py_alias_info, "acct_desc")));
	if (alias_info.acct_desc == NULL) {
		PyErr_Format(py_pdb_error, "Unable to allocate memory");
		talloc_free(frame);
		return NULL;
	}

	status = methods->set_aliasinfo(methods, alias_sid, &alias_info);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to set alias information, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_add_aliasmem(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid, *py_member_sid;
	struct dom_sid *alias_sid, *member_sid;

	if (!PyArg_ParseTuple(args, "O!O!:add_aliasmem", dom_sid_Type, &py_alias_sid,
					dom_sid_Type, &py_member_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);
	member_sid = pytalloc_get_ptr(py_member_sid);

	status = methods->add_aliasmem(methods, alias_sid, member_sid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to add member to alias, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_del_aliasmem(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid, *py_member_sid;
	const struct dom_sid *alias_sid, *member_sid;

	if (!PyArg_ParseTuple(args, "O!O!:del_aliasmem", dom_sid_Type, &py_alias_sid,
					dom_sid_Type, &py_member_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);
	member_sid = pytalloc_get_ptr(py_member_sid);

	status = methods->del_aliasmem(methods, alias_sid, member_sid);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete member from alias, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_enum_aliasmem(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_alias_sid;
	struct dom_sid *alias_sid, *member_sid, *tmp_sid;
	PyObject *py_member_list, *py_member_sid;
	size_t num_members;
	int i;

	if (!PyArg_ParseTuple(args, "O!:enum_aliasmem", dom_sid_Type, &py_alias_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	alias_sid = pytalloc_get_ptr(py_alias_sid);

	status = methods->enum_aliasmem(methods, alias_sid, frame, &member_sid, &num_members);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to enumerate members for alias, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_member_list = PyList_New(0);
	if (py_member_list == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for(i=0; i<num_members; i++) {
		int res = 0;
		py_member_sid = pytalloc_new(struct dom_sid, dom_sid_Type);
		if (py_member_sid == NULL) {
			PyErr_NoMemory();
			Py_CLEAR(py_member_list);
			talloc_free(frame);
			return NULL;
		}
		tmp_sid = pytalloc_get_ptr(py_member_sid);
		*tmp_sid = member_sid[i];
		res = PyList_Append(py_member_list, py_member_sid);
		Py_CLEAR(py_member_sid);
		if (res == -1) {
			Py_CLEAR(py_member_list);
			talloc_free(frame);
			return NULL;
		}
	}

	talloc_free(frame);
	return py_member_list;
}


static PyObject *py_pdb_get_account_policy(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_acct_policy;
	uint32_t value;
	const char **names;
	int count, i;
	enum pdb_policy_type type;

	methods = pytalloc_get_ptr(self);

	py_acct_policy = PyDict_New();
	if (py_acct_policy == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	account_policy_names_list(frame, &names, &count);
	for (i=0; i<count; i++) {
		type = account_policy_name_to_typenum(names[i]);
		status = methods->get_account_policy(methods, type, &value);
		if (NT_STATUS_IS_OK(status)) {
			int res = 0;
			PyObject *py_value = Py_BuildValue("i", value);
			if (py_value == NULL) {
				Py_CLEAR(py_acct_policy);
				break;
			}
			res = PyDict_SetItemString(py_acct_policy,
						   names[i],
						   py_value);
			Py_CLEAR(py_value);
			if (res == -1) {
				Py_CLEAR(py_acct_policy);
				break;
			}
		}
	}

	talloc_free(frame);
	return py_acct_policy;
}


static PyObject *py_pdb_set_account_policy(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_acct_policy, *py_value;
	const char **names;
	int count, i;
	enum pdb_policy_type type;

	if (!PyArg_ParseTuple(args, "O!:set_account_policy", PyDict_Type, &py_acct_policy)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	account_policy_names_list(frame, &names, &count);
	for (i=0; i<count; i++) {
		if ((py_value = PyDict_GetItemString(py_acct_policy, names[i])) != NULL) {
			type = account_policy_name_to_typenum(names[i]);
			status = methods->set_account_policy(methods, type, PyLong_AsLong(py_value));
			if (!NT_STATUS_IS_OK(status)) {
				PyErr_Format(py_pdb_error, "Error setting account policy (%s), (%d,%s)",
						names[i],
						NT_STATUS_V(status),
						get_friendly_nt_error_msg(status));
			}
		}
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_pdb_search_users(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	unsigned int acct_flags;
	struct pdb_search *search;
	struct samr_displayentry *entry;
	PyObject *py_userlist, *py_dict;

	if (!PyArg_ParseTuple(args, "I:search_users", &acct_flags)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	search = talloc_zero(frame, struct pdb_search);
	if (search == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	if (!methods->search_users(methods, search, acct_flags)) {
		PyErr_Format(py_pdb_error, "Unable to search users");
		talloc_free(frame);
		return NULL;
	}

	entry = talloc_zero(frame, struct samr_displayentry);
	if (entry == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_userlist = PyList_New(0);
	if (py_userlist == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	while (search->next_entry(search, entry)) {
		int res = 1;
		py_dict = Py_BuildValue(
			"{s:l, s:l, s:l, s:s, s:s, s:s}",
			"idx", entry->idx,
			"rid", entry->rid,
			"acct_flags", entry->acct_flags,
			"account_name", entry->account_name,
			"fullname", entry->fullname,
			"description", entry->description);
		if (py_dict == NULL) {
			Py_CLEAR(py_userlist);
			goto out;
		}

		res = PyList_Append(py_userlist, py_dict);
		Py_CLEAR(py_dict);
		if (res == -1) {
			Py_CLEAR(py_userlist);
			goto out;
		}
	}
	search->search_end(search);

out:
	talloc_free(frame);
	return py_userlist;
}


static PyObject *py_pdb_search_groups(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	struct pdb_search *search;
	struct samr_displayentry *entry;
	PyObject *py_grouplist, *py_dict;

	methods = pytalloc_get_ptr(self);

	search = talloc_zero(frame, struct pdb_search);
	if (search == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	if (!methods->search_groups(methods, search)) {
		PyErr_Format(py_pdb_error, "Unable to search groups");
		talloc_free(frame);
		return NULL;
	}

	entry = talloc_zero(frame, struct samr_displayentry);
	if (entry == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_grouplist = PyList_New(0);
	if (py_grouplist == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	while (search->next_entry(search, entry)) {
		int res = 0;
		py_dict = Py_BuildValue(
			"{s:l, s:l, s:l, s:s, s:s, s:s}",
			"idx", entry->idx,
			"rid", entry->rid,
			"acct_flags", entry->acct_flags,
			"account_name", entry->account_name,
			"fullname", entry->fullname,
			"description", entry->description);

		if (py_dict == NULL) {
			Py_CLEAR(py_grouplist);
			goto out;
		}

		res = PyList_Append(py_grouplist, py_dict);
		Py_CLEAR(py_dict);
		if (res == -1) {
			Py_CLEAR(py_grouplist);
			goto out;
		}
	}
	search->search_end(search);
out:
	talloc_free(frame);
	return py_grouplist;
}


static PyObject *py_pdb_search_aliases(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	struct pdb_search *search;
	struct samr_displayentry *entry;
	PyObject *py_aliaslist, *py_dict;
	PyObject *py_domain_sid = Py_None;
	struct dom_sid *domain_sid = NULL;

	if (!PyArg_ParseTuple(args, "|O!:search_aliases", dom_sid_Type, &py_domain_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	if (py_domain_sid != Py_None) {
		domain_sid = pytalloc_get_ptr(py_domain_sid);
	}

	search = talloc_zero(frame, struct pdb_search);
	if (search == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	if (!methods->search_aliases(methods, search, domain_sid)) {
		PyErr_Format(py_pdb_error, "Unable to search aliases");
		talloc_free(frame);
		return NULL;
	}

	entry = talloc_zero(frame, struct samr_displayentry);
	if (entry == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_aliaslist = PyList_New(0);
	if (py_aliaslist == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	while (search->next_entry(search, entry)) {
		int res = 0;

		py_dict = Py_BuildValue(
			"{s:l, s:l, s:l, s:s, s:s, s:s}",
			"idx", entry->idx,
			"rid", entry->rid,
			"acct_flags", entry->acct_flags,
			"account_name", entry->account_name,
			"fullname", entry->fullname,
			"description", entry->description);

		if (py_dict == NULL) {
			Py_CLEAR(py_aliaslist);
			goto out;
		}
		res = PyList_Append(py_aliaslist, py_dict);
		Py_CLEAR(py_dict);
		if (res == -1) {
			Py_CLEAR(py_aliaslist);
			goto out;
		}
	}
	search->search_end(search);
out:
	talloc_free(frame);
	return py_aliaslist;
}


static PyObject *py_pdb_uid_to_sid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	struct unixid id;
	unsigned int uid;
	struct dom_sid user_sid, *copy_user_sid;
	PyObject *py_user_sid;

	if (!PyArg_ParseTuple(args, "I:uid_to_sid", &uid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	id.id = uid;
	id.type = ID_TYPE_UID;

	if (!methods->id_to_sid(methods, &id, &user_sid)) {
		PyErr_Format(py_pdb_error, "Unable to get sid for uid=%d", uid);
		talloc_free(frame);
		return NULL;
	}

	copy_user_sid = dom_sid_dup(frame, &user_sid);
	if (copy_user_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_user_sid = pytalloc_steal(dom_sid_Type, copy_user_sid);

	talloc_free(frame);
	return py_user_sid;
}


static PyObject *py_pdb_gid_to_sid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	struct unixid id;
	unsigned int gid;
	struct dom_sid group_sid, *copy_group_sid;
	PyObject *py_group_sid;

	if (!PyArg_ParseTuple(args, "I:gid_to_sid", &gid)) {
		talloc_free(frame);
		return NULL;
	}

	id.id = gid;
	id.type = ID_TYPE_GID;

	methods = pytalloc_get_ptr(self);

	if (!methods->id_to_sid(methods, &id, &group_sid)) {
		PyErr_Format(py_pdb_error, "Unable to get sid for gid=%d", gid);
		talloc_free(frame);
		return NULL;
	}

	copy_group_sid = dom_sid_dup(frame, &group_sid);
	if (copy_group_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_group_sid = pytalloc_steal(dom_sid_Type, copy_group_sid);

	talloc_free(frame);
	return py_group_sid;
}


static PyObject *py_pdb_sid_to_id(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	PyObject *py_sid;
	struct dom_sid *sid;
	struct unixid id;

	if (!PyArg_ParseTuple(args, "O!:sid_to_id", dom_sid_Type, &py_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	sid = pytalloc_get_ptr(py_sid);

	if (!methods->sid_to_id(methods, sid, &id)) {
		PyErr_Format(py_pdb_error, "Unable to get id for sid");
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return Py_BuildValue("(II)", id.id, id.type);
}


static PyObject *py_pdb_new_rid(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	uint32_t rid;

	methods = pytalloc_get_ptr(self);

	if (!methods->new_rid(methods, &rid)) {
		PyErr_Format(py_pdb_error, "Unable to get new rid");
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return PyLong_FromLong(rid);
}


static PyObject *py_pdb_get_trusteddom_pw(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	const char *domain;
	char *pwd;
	struct dom_sid sid, *copy_sid;
	PyObject *py_sid;
	time_t last_set_time;
	PyObject *py_value;

	if (!PyArg_ParseTuple(args, "s:get_trusteddom_pw", &domain)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	if (!methods->get_trusteddom_pw(methods, domain, &pwd, &sid, &last_set_time)) {
		PyErr_Format(py_pdb_error, "Unable to get trusted domain password");
		talloc_free(frame);
		return NULL;
	}

	copy_sid = dom_sid_dup(frame, &sid);
	if (copy_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_sid = pytalloc_steal(dom_sid_Type, copy_sid);
	if (py_sid == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_value = Py_BuildValue(
		"{s:s, s:O, s:l}",
		"pwd", pwd,
		"sid", py_sid,
		"last_set_tim", last_set_time);

	Py_CLEAR(py_sid);
	talloc_free(frame);
	return py_value;
}


static PyObject *py_pdb_set_trusteddom_pw(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	const char *domain;
	const char *pwd;
	const struct dom_sid *domain_sid;
	PyObject *py_domain_sid;

	if (!PyArg_ParseTuple(args, "ssO!:set_trusteddom_pw", &domain, &pwd,
					dom_sid_Type, &py_domain_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	domain_sid = pytalloc_get_ptr(py_domain_sid);

	if (!methods->set_trusteddom_pw(methods, domain, pwd, domain_sid)) {
		PyErr_Format(py_pdb_error, "Unable to set trusted domain password");
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_del_trusteddom_pw(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_methods *methods;
	const char *domain;

	if (!PyArg_ParseTuple(args, "s:del_trusteddom_pw", &domain)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	if (!methods->del_trusteddom_pw(methods, domain)) {
		PyErr_Format(py_pdb_error, "Unable to delete trusted domain password");
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_enum_trusteddoms(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	uint32_t num_domains;
	struct trustdom_info **domains;
	PyObject *py_domain_list, *py_dict;
	int i;

	methods = pytalloc_get_ptr(self);

	status = methods->enum_trusteddoms(methods, frame, &num_domains, &domains);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to enumerate trusted domains, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_domain_list = PyList_New(0);
	if (py_domain_list == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for(i=0; i<num_domains; i++) {
		int res = 0;
		PyObject *py_sid =
			pytalloc_steal(dom_sid_Type, &domains[i]->sid);
		py_dict = Py_BuildValue(
			"{s:s, s:O}",
			"name", domains[i]->name,
			"sid", py_sid);
		Py_CLEAR(py_sid);
		if (py_dict == NULL) {
			DBG_ERR("Failed to insert entry to dict\n");
				Py_CLEAR(py_domain_list);
				break;
		}

		res = PyList_Append(py_domain_list, py_dict);
		Py_CLEAR(py_dict);
		if (res == -1) {
			Py_CLEAR(py_domain_list);
			break;
		}
	}

	talloc_free(frame);
	return py_domain_list;
}


static PyObject *py_pdb_get_trusted_domain(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *domain;
	struct pdb_trusted_domain *td;
	PyObject *py_domain_info;
	PyObject *py_sid = NULL;

	if (!PyArg_ParseTuple(args, "s:get_trusted_domain", &domain)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->get_trusted_domain(methods, frame, domain, &td);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get trusted domain information, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_sid = pytalloc_steal(dom_sid_Type, &td->security_identifier);

	py_domain_info = Py_BuildValue(
		"{s:s, s:s, s:O,"
			" s:"PYARG_BYTES_LEN","
			" s:"PYARG_BYTES_LEN","
			" s:l, s:l, s:l,"
			" s:"PYARG_BYTES_LEN"}",
		"domain_name", td->domain_name,
		"netbios_name", td->netbios_name,
		"security_identifier", py_sid,
		"trust_auth_incoming",
			(const char *)td->trust_auth_incoming.data,
			td->trust_auth_incoming.length,
		"trust_auth_outgoing",
			(const char *)td->trust_auth_outgoing.data,
			td->trust_auth_outgoing.length,
		"trust_direction", td->trust_direction,
		"trust_type", td->trust_type,
		"trust_attributes", td->trust_attributes,
		"trust_forest_trust_info",
			(const char *)td->trust_forest_trust_info.data,
			td->trust_forest_trust_info.length);
	Py_CLEAR(py_sid);

	talloc_free(frame);
	return py_domain_info;
}


static PyObject *py_pdb_get_trusted_domain_by_sid(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	PyObject *py_domain_sid;
	struct dom_sid *domain_sid;
	struct pdb_trusted_domain *td;
	PyObject *py_domain_info;
	PyObject *py_sid = NULL;

	if (!PyArg_ParseTuple(args, "O!:get_trusted_domain_by_sid", dom_sid_Type, &py_domain_sid)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	domain_sid = pytalloc_get_ptr(py_domain_sid);

	status = methods->get_trusted_domain_by_sid(methods, frame, domain_sid, &td);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get trusted domain information, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_sid = pytalloc_steal(dom_sid_Type, &td->security_identifier);

	py_domain_info = Py_BuildValue(
		"{s:s, s:s, s:O,"
			" s:"PYARG_BYTES_LEN","
			" s:"PYARG_BYTES_LEN","
			" s:l, s:l, s:l,"
			" s:"PYARG_BYTES_LEN"}",
		"domain_name", td->domain_name,
		"netbios_name", td->netbios_name,
		"security_identifier", py_sid,
		"trust_auth_incoming",
			(const char *)td->trust_auth_incoming.data,
			td->trust_auth_incoming.length,
		"trust_auth_outgoing",
			(const char *)td->trust_auth_outgoing.data,
			td->trust_auth_outgoing.length,
		"trust_direction", td->trust_direction,
		"trust_type", td->trust_type,
		"trust_attributes", td->trust_attributes,
		"trust_forest_trust_info",
			(const char *)td->trust_forest_trust_info.data,
			td->trust_forest_trust_info.length);
	Py_CLEAR(py_sid);

	talloc_free(frame);
	return py_domain_info;
}


static PyObject *py_pdb_set_trusted_domain(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *domain;
	PyObject *py_td_info;
	struct pdb_trusted_domain td_info;
	PyObject *py_tmp;
	Py_ssize_t len;

	if (!PyArg_ParseTuple(args, "sO!:set_trusted_domain", &domain, &PyDict_Type, &py_td_info)) {
		talloc_free(frame);
		return NULL;
	}

	py_tmp = PyDict_GetItemString(py_td_info, "domain_name");
	td_info.domain_name = discard_const_p(char, PyUnicode_AsUTF8(py_tmp));

	py_tmp = PyDict_GetItemString(py_td_info, "netbios_name");
	td_info.netbios_name = discard_const_p(char, PyUnicode_AsUTF8(py_tmp));

	py_tmp = PyDict_GetItemString(py_td_info, "security_identifier");
	td_info.security_identifier = *pytalloc_get_type(py_tmp, struct dom_sid);

	py_tmp = PyDict_GetItemString(py_td_info, "trust_auth_incoming");
	PyBytes_AsStringAndSize(py_tmp, (char **)&td_info.trust_auth_incoming.data, &len);
	td_info.trust_auth_incoming.length = len;

	py_tmp = PyDict_GetItemString(py_td_info, "trust_auth_outgoing");
	PyBytes_AsStringAndSize(py_tmp, (char **)&td_info.trust_auth_outgoing.data, &len);
	td_info.trust_auth_outgoing.length = len;

	py_tmp = PyDict_GetItemString(py_td_info, "trust_direction");
	td_info.trust_direction = PyLong_AsLong(py_tmp);

	py_tmp = PyDict_GetItemString(py_td_info, "trust_type");
	td_info.trust_type = PyLong_AsLong(py_tmp);

	py_tmp = PyDict_GetItemString(py_td_info, "trust_attributes");
	td_info.trust_attributes = PyLong_AsLong(py_tmp);

	py_tmp = PyDict_GetItemString(py_td_info, "trust_forest_trust_info");
	PyBytes_AsStringAndSize(py_tmp, (char **)&td_info.trust_forest_trust_info.data, &len);
	td_info.trust_forest_trust_info.length = len;

	methods = pytalloc_get_ptr(self);

	status = methods->set_trusted_domain(methods, domain, &td_info);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to set trusted domain information, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_del_trusted_domain(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *domain;

	if (!PyArg_ParseTuple(args, "s:del_trusted_domain", &domain)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->del_trusted_domain(methods, domain);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete trusted domain, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_enum_trusted_domains(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	uint32_t num_domains;
	struct pdb_trusted_domain **td_info;
	PyObject *py_td_info, *py_domain_info;
	int i;

	methods = pytalloc_get_ptr(self);

	status = methods->enum_trusted_domains(methods, frame, &num_domains, &td_info);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete trusted domain, (%d,%s)",
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_td_info = PyList_New(0);
	if (py_td_info == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	for (i=0; i<num_domains; i++) {
		int res = 0;
		struct pdb_trusted_domain *td = td_info[i];
		PyObject *py_sid =
			pytalloc_steal(dom_sid_Type, &td->security_identifier);

		py_domain_info = Py_BuildValue(
			"{s:s, s:s, s:O,"
				" s:"PYARG_BYTES_LEN","
				" s:"PYARG_BYTES_LEN","
				" s:l, s:l, s:l,"
				" s:"PYARG_BYTES_LEN"}",
			"domain_name", td->domain_name,
			"netbios_name", td->netbios_name,
			"security_identifier", py_sid,
			"trust_auth_incoming",
				(const char *)td->trust_auth_incoming.data,
				td->trust_auth_incoming.length,
			"trust_auth_outgoing",
				(const char *)td->trust_auth_outgoing.data,
				td->trust_auth_outgoing.length,
			"trust_direction", td->trust_direction,
			"trust_type", td->trust_type,
			"trust_attributes", td->trust_attributes,
			"trust_forest_trust_info",
				(const char *)td->trust_forest_trust_info.data,
				td->trust_forest_trust_info.length);
		Py_CLEAR(py_sid);

		if (py_domain_info == NULL) {
			Py_CLEAR(py_td_info);
			break;
		}
		res = PyList_Append(py_td_info, py_domain_info);
		Py_CLEAR(py_domain_info);
		if (res == -1) {
			Py_CLEAR(py_td_info);
			break;
		}
	}

	talloc_free(frame);
	return py_td_info;
}


static PyObject *py_pdb_get_secret(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *secret_name;
	DATA_BLOB secret_current, secret_old;
	NTTIME secret_current_lastchange, secret_old_lastchange;
	PyObject *py_sd;
	struct security_descriptor *sd;
	PyObject *py_secret;

	if (!PyArg_ParseTuple(args, "s:get_secret_name", &secret_name)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	py_sd = pytalloc_new(struct security_descriptor, security_Type);
	if (py_sd == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}
	sd = pytalloc_get_ptr(py_sd);

	status = methods->get_secret(methods, frame, secret_name,
					&secret_current,
					&secret_current_lastchange,
					&secret_old,
					&secret_old_lastchange,
					&sd);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to get information for secret (%s), (%d,%s)",
				secret_name,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	py_secret = Py_BuildValue(
		"{s:"PYARG_BYTES_LEN","
			" s:K"
			" s:"PYARG_BYTES_LEN","
			" s:K, s:O}",
		"secret_current", (const char*)secret_current.data,
				secret_current.length,
		"secret_current_lastchange", secret_current_lastchange,
		"secret_old", (const char*)secret_old.data,
				secret_old.length,
		"secret_old_lastchange", secret_old_lastchange,
		"sd", py_sd);

	Py_CLEAR(py_sd);
	if (py_secret == NULL) {
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return py_secret;
}


static PyObject *py_pdb_set_secret(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *secret_name;
	PyObject *py_secret;
	PyObject *py_secret_cur, *py_secret_old, *py_sd;
	DATA_BLOB secret_current, secret_old;
	struct security_descriptor *sd;
	Py_ssize_t len;

	if (!PyArg_ParseTuple(args, "sO!:set_secret_name", &secret_name, PyDict_Type, &py_secret)) {
		talloc_free(frame);
		return NULL;
	}

	py_secret_cur = PyDict_GetItemString(py_secret, "secret_current");
	py_secret_old = PyDict_GetItemString(py_secret, "secret_old");
	py_sd = PyDict_GetItemString(py_secret, "sd");

	PY_CHECK_TYPE(&PyBytes_Type, py_secret_cur, return NULL;);
	PY_CHECK_TYPE(&PyBytes_Type, py_secret_old, return NULL;);
	PY_CHECK_TYPE(security_Type, py_sd, return NULL;);

	methods = pytalloc_get_ptr(self);

	PyBytes_AsStringAndSize(py_secret_cur, (char **)&secret_current.data, &len);
	secret_current.length = len;
	PyBytes_AsStringAndSize(py_secret_old, (char **)&secret_old.data, &len);
	secret_current.length = len;
	sd = pytalloc_get_ptr(py_sd);

	status = methods->set_secret(methods, secret_name, &secret_current, &secret_old, sd);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to set information for secret (%s), (%d,%s)",
				secret_name,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_pdb_delete_secret(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct pdb_methods *methods;
	const char *secret_name;

	if (!PyArg_ParseTuple(args, "s:delete_secret", &secret_name)) {
		talloc_free(frame);
		return NULL;
	}

	methods = pytalloc_get_ptr(self);

	status = methods->delete_secret(methods, secret_name);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Unable to delete secret (%s), (%d,%s)",
				secret_name,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyMethodDef py_pdb_methods[] = {
	{ "domain_info", py_pdb_domain_info, METH_NOARGS,
		"domain_info() -> str\n\n \
		Get domain information for the database." },
	{ "getsampwnam", py_pdb_getsampwnam, METH_VARARGS,
		"getsampwnam(username) -> samu object\n\n \
		Get user information by name." },
	{ "getsampwsid", py_pdb_getsampwsid, METH_VARARGS,
		"getsampwsid(user_sid) -> samu object\n\n \
		Get user information by sid (dcerpc.security.dom_sid object)." },
	{ "create_user", py_pdb_create_user, METH_VARARGS,
		"create_user(username, acct_flags) -> rid\n\n \
		Create user. acct_flags are samr account control flags." },
	{ "delete_user", py_pdb_delete_user, METH_VARARGS,
		"delete_user(samu object) -> None\n\n \
		Delete user." },
	{ "add_sam_account", py_pdb_add_sam_account, METH_VARARGS,
		"add_sam_account(samu object) -> None\n\n \
		Add SAM account." },
	{ "update_sam_account", py_pdb_update_sam_account, METH_VARARGS,
		"update_sam_account(samu object) -> None\n\n \
		Update SAM account." },
	{ "delete_sam_account", py_pdb_delete_sam_account, METH_VARARGS,
		"delete_sam_account(samu object) -> None\n\n \
		Delete SAM account." },
	{ "rename_sam_account", py_pdb_rename_sam_account, METH_VARARGS,
		"rename_sam_account(samu object1, new_username) -> None\n\n \
		Rename SAM account." },
	/* update_login_attempts */
	{ "getgrsid", py_pdb_getgrsid, METH_VARARGS,
		"getgrsid(group_sid) -> groupmap object\n\n \
		Get group information by sid (dcerpc.security.dom_sid object)." },
	{ "getgrgid", py_pdb_getgrgid, METH_VARARGS,
		"getgrsid(gid) -> groupmap object\n\n \
		Get group information by gid." },
	{ "getgrnam", py_pdb_getgrnam, METH_VARARGS,
		"getgrsid(groupname) -> groupmap object\n\n \
		Get group information by name." },
	{ "create_dom_group", py_pdb_create_dom_group, METH_VARARGS,
		"create_dom_group(groupname) -> group_rid\n\n \
		Create new domain group by name." },
	{ "delete_dom_group", py_pdb_delete_dom_group, METH_VARARGS,
		"delete_dom_group(group_rid) -> None\n\n \
		Delete domain group identified by rid" },
	{ "add_group_mapping_entry", py_pdb_add_group_mapping_entry, METH_VARARGS,
		"add_group_mapping_entry(groupmap) -> None\n \
		Add group mapping entry for groupmap object." },
	{ "update_group_mapping_entry", py_pdb_update_group_mapping_entry, METH_VARARGS,
		"update_group_mapping_entry(groupmap) -> None\n\n \
		Update group mapping entry for groupmap object." },
	{ "delete_group_mapping_entry", py_pdb_delete_group_mapping_entry, METH_VARARGS,
		"delete_group_mapping_entry(groupmap) -> None\n\n \
		Delete group mapping entry for groupmap object." },
	{ "enum_group_mapping", py_pdb_enum_group_mapping, METH_VARARGS,
		"enum_group_mapping([domain_sid, [type, [unix_only]]]) -> List\n\n \
		Return list of group mappings as groupmap objects. Optional arguments are domain_sid object, type of group, unix only flag." },
	{ "enum_group_members", py_pdb_enum_group_members, METH_VARARGS,
		"enum_group_members(group_sid) -> List\n\n \
		Return list of users (dom_sid object) in group." },
	{ "enum_group_memberships", py_pdb_enum_group_memberships, METH_VARARGS,
		"enum_group_memberships(samu object) -> List\n\n \
		Return list of groups (dom_sid object) this user is part of." },
	/* set_unix_primary_group */
	{ "add_groupmem", py_pdb_add_groupmem, METH_VARARGS,
		"add_groupmem(group_rid, member_rid) -> None\n\n \
		Add user to group." },
	{ "del_groupmem", py_pdb_del_groupmem, METH_VARARGS,
		"del_groupmem(group_rid, member_rid) -> None\n\n \
		Remove user from from group." },
	{ "create_alias", py_pdb_create_alias, METH_VARARGS,
		"create_alias(alias_name) -> alias_rid\n\n \
		Create alias entry." },
	{ "delete_alias", py_pdb_delete_alias, METH_VARARGS,
		"delete_alias(alias_sid) -> None\n\n \
		Delete alias entry." },
	{ "get_aliasinfo", py_pdb_get_aliasinfo, METH_VARARGS,
		"get_aliasinfo(alias_sid) -> Mapping\n\n \
		Get alias information as a dictionary with keys - acct_name, acct_desc, rid." },
	{ "set_aliasinfo", py_pdb_set_aliasinfo, METH_VARARGS,
		"set_alias_info(alias_sid, Mapping) -> None\n\n \
		Set alias information from a dictionary with keys - acct_name, acct_desc." },
	{ "add_aliasmem", py_pdb_add_aliasmem, METH_VARARGS,
		"add_aliasmem(alias_sid, member_sid) -> None\n\n \
		Add user to alias entry." },
	{ "del_aliasmem", py_pdb_del_aliasmem, METH_VARARGS,
		"del_aliasmem(alias_sid, member_sid) -> None\n\n \
		Remove a user from alias entry." },
	{ "enum_aliasmem", py_pdb_enum_aliasmem, METH_VARARGS,
		"enum_aliasmem(alias_sid) -> List\n\n \
		Return a list of members (dom_sid object) for alias entry." },
	/* enum_alias_memberships */
	/* lookup_rids */
	/* lookup_names */
	{ "get_account_policy", py_pdb_get_account_policy, METH_NOARGS,
		"get_account_policy() -> Mapping\n\n \
		Get account policy information as a dictionary." },
	{ "set_account_policy", py_pdb_set_account_policy, METH_VARARGS,
		"get_account_policy(Mapping) -> None\n\n \
		Set account policy settings from a dicionary." },
	/* get_seq_num */
	{ "search_users", py_pdb_search_users, METH_VARARGS,
		"search_users(acct_flags) -> List\n\n \
		Search users. acct_flags are samr account control flags.\n \
		Each list entry is dictionary with keys - idx, rid, acct_flags, account_name, fullname, description." },
	{ "search_groups", py_pdb_search_groups, METH_NOARGS,
		"search_groups() -> List\n\n \
		Search unix only groups. \n \
		Each list entry is dictionary with keys - idx, rid, acct_flags, account_name, fullname, description." },
	{ "search_aliases", py_pdb_search_aliases, METH_VARARGS,
		"search_aliases([domain_sid]) -> List\n\n \
		Search aliases. domain_sid is dcerpc.security.dom_sid object.\n \
		Each list entry is dictionary with keys - idx, rid, acct_flags, account_name, fullname, description." },
	{ "uid_to_sid", py_pdb_uid_to_sid, METH_VARARGS,
		"uid_to_sid(uid) -> sid\n\n \
		Return sid for given user id." },
	{ "gid_to_sid", py_pdb_gid_to_sid, METH_VARARGS,
		"gid_to_sid(gid) -> sid\n\n \
		Return sid for given group id." },
	{ "sid_to_id", py_pdb_sid_to_id, METH_VARARGS,
		"sid_to_id(sid) -> Tuple\n\n \
		Return id and type for given sid." },
	/* capabilities */
	{ "new_rid", py_pdb_new_rid, METH_NOARGS,
		"new_rid() -> rid\n\n \
		Get a new rid." },
	{ "get_trusteddom_pw", py_pdb_get_trusteddom_pw, METH_VARARGS,
		"get_trusteddom_pw(domain) -> Mapping\n\n \
		Get trusted domain password, sid and last set time in a dictionary." },
	{ "set_trusteddom_pw", py_pdb_set_trusteddom_pw, METH_VARARGS,
		"set_trusteddom_pw(domain, pwd, sid) -> None\n\n \
		Set trusted domain password." },
	{ "del_trusteddom_pw", py_pdb_del_trusteddom_pw, METH_VARARGS,
		"del_trusteddom_pw(domain) -> None\n\n \
		Delete trusted domain password." },
	{ "enum_trusteddoms", py_pdb_enum_trusteddoms, METH_NOARGS,
		"enum_trusteddoms() -> List\n\n \
		Get list of trusted domains. Each item is a dictionary with name and sid keys" },
	{ "get_trusted_domain", py_pdb_get_trusted_domain, METH_VARARGS,
		"get_trusted_domain(domain) -> Mapping\n\n \
		Get trusted domain information by name. Information is a dictionary with keys - domain_name, netbios_name, security_identifier, trust_auth_incoming, trust_auth_outgoing, trust_direction, trust_type, trust_attributes, trust_forest_trust_info." },
	{ "get_trusted_domain_by_sid", py_pdb_get_trusted_domain_by_sid, METH_VARARGS,
		"get_trusted_domain_by_sid(domain_sid) -> Mapping\n\n \
		Get trusted domain information by sid. Information is a dictionary with keys - domain_name, netbios_name, security_identifier, trust_auth_incoming, trust_auth_outgoing, trust_direction, trust_type, trust_attributes, trust_forest_trust_info" },
	{ "set_trusted_domain", py_pdb_set_trusted_domain, METH_VARARGS,
		"set_trusted_domain(domain, Mapping) -> None\n\n \
		Set trusted domain information for domain. Mapping is a dictionary with keys - domain_name, netbios_name, security_identifier, trust_auth_incoming, trust_auth_outgoing, trust_direction, trust_type, trust_attributes, trust_forest_trust_info." },
	{ "del_trusted_domain", py_pdb_del_trusted_domain, METH_VARARGS,
		"del_trusted_domain(domain) -> None\n\n \
		Delete trusted domain." },
	{ "enum_trusted_domains", py_pdb_enum_trusted_domains, METH_VARARGS,
		"enum_trusted_domains() -> List\n\n \
		Get list of trusted domains. Each entry is a dictionary with keys - domain_name, netbios_name, security_identifier, trust_auth_incoming, trust_auth_outgoing, trust_direction, trust_type, trust_attributes, trust_forest_trust_info." },
	{ "get_secret", py_pdb_get_secret, METH_VARARGS,
		"get_secret(secret_name) -> Mapping\n\n \
		Get secret information for secret_name. Information is a dictionary with keys - secret_current, secret_current_lastchange, secret_old, secret_old_lastchange, sd." },
	{ "set_secret", py_pdb_set_secret, METH_VARARGS,
		"set_secret(secret_name, Mapping) -> None\n\n \
		Set secret information for secret_name using dictionary with keys - secret_current, sd." },
	{ "delete_secret", py_pdb_delete_secret, METH_VARARGS,
		"delete_secret(secret_name) -> None\n\n \
		Delete secret information for secret_name." },
	{0},
};


static PyObject *py_pdb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *url = NULL;
	PyObject *pypdb;
	NTSTATUS status;
	struct pdb_methods *methods;

	if (!PyArg_ParseTuple(args, "s", &url)) {
		talloc_free(frame);
		return NULL;
	}

	/* Initialize list of methods */
	status = make_pdb_method_name(&methods, url);
	if (!NT_STATUS_IS_OK(status)) {
		PyErr_Format(py_pdb_error, "Cannot load backend methods for '%s' backend (%d,%s)",
				url,
				NT_STATUS_V(status),
				get_friendly_nt_error_msg(status));
		talloc_free(frame);
		return NULL;
	}

	if ((pypdb = pytalloc_steal(type, methods)) == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	return pypdb;
}


static PyTypeObject PyPDB = {
	.tp_name = "passdb.PDB",
	.tp_new = py_pdb_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_pdb_methods,
	.tp_doc = "PDB(url[, read_write_flags]) -> Password DB object\n",
};


/*
 * Return a list of passdb backends
 */
static PyObject *py_passdb_backends(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *py_blist;
	const struct pdb_init_function_entry *entry;

	entry = pdb_get_backends();
	if(! entry) {
		Py_RETURN_NONE;
	}

	if((py_blist = PyList_New(0)) == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	while(entry) {
		int res = 0;
		PyObject *entry_name = PyUnicode_FromString(entry->name);
		if (entry_name) {
			res = PyList_Append(py_blist, entry_name);
		} else {
			Py_CLEAR(entry_name);
			Py_CLEAR(py_blist);
			break;
		}
		Py_CLEAR(entry_name);
		if (res == -1) {
			Py_CLEAR(py_blist);
			break;
		}
		entry = entry->next;
	}

	talloc_free(frame);
	return py_blist;
}


static PyObject *py_set_smb_config(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *smb_config;

	if (!PyArg_ParseTuple(args, "s", &smb_config)) {
		talloc_free(frame);
		return NULL;
	}

	/* Load smbconf parameters */
	if (!lp_load_global(smb_config)) {
		PyErr_Format(py_pdb_error, "Cannot open '%s'", smb_config);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}


static PyObject *py_set_secrets_dir(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *private_dir;

	if (!PyArg_ParseTuple(args, "s", &private_dir)) {
		talloc_free(frame);
		return NULL;
	}

	/* Initialize secrets database */
	if (!secrets_init_path(private_dir)) {
		PyErr_Format(py_pdb_error, "Cannot open secrets file database in '%s'",
				private_dir);
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_reload_static_pdb(PyObject *self, PyObject *args)
{
	TALLOC_CTX *frame = talloc_stackframe();

	/* Initialize secrets database */
	if (!initialize_password_db(true, NULL)) {
		PyErr_Format(py_pdb_error, "Cannot re-open passdb backend %s", lp_passdb_backend());
		talloc_free(frame);
		return NULL;
	}

	talloc_free(frame);
	Py_RETURN_NONE;
}

static PyObject *py_get_domain_sid(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dom_sid domain_sid, *domain_sid_copy;
	PyObject *py_dom_sid = Py_None;
	bool ret = false;

	ret = secrets_fetch_domain_sid(lp_workgroup(), &domain_sid);
	if (!ret) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	domain_sid_copy = dom_sid_dup(frame, &domain_sid);
	if (domain_sid_copy == NULL) {
		talloc_free(frame);
		return PyErr_NoMemory();
	}

	py_dom_sid = pytalloc_steal(dom_sid_Type, domain_sid_copy);

	talloc_free(frame);
	return py_dom_sid;
}

static PyObject *py_get_global_sam_sid(PyObject *self, PyObject *unused)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dom_sid *domain_sid, *domain_sid_copy;
	PyObject *py_dom_sid;

	domain_sid = get_global_sam_sid();

	domain_sid_copy = dom_sid_dup(frame, domain_sid);
	if (domain_sid_copy == NULL) {
		PyErr_NoMemory();
		talloc_free(frame);
		return NULL;
	}

	py_dom_sid = pytalloc_steal(dom_sid_Type, domain_sid_copy);

	talloc_free(frame);
	return py_dom_sid;
}


static PyMethodDef py_passdb_methods[] = {
	{ "get_backends", py_passdb_backends, METH_NOARGS,
		"get_backends() -> list\n\n \
		Get a list of password database backends supported." },
	{ "set_smb_config", py_set_smb_config, METH_VARARGS,
		"set_smb_config(path) -> None\n\n \
		Set path to smb.conf file to load configuration parameters." },
	{ "set_secrets_dir", py_set_secrets_dir, METH_VARARGS,
		"set_secrets_dir(private_dir) -> None\n\n \
		Set path to private directory to load secrets database from non-default location." },
	{ "get_global_sam_sid", py_get_global_sam_sid, METH_NOARGS,
		"get_global_sam_sid() -> dom_sid\n\n \
		Return domain SID." },
	{ "get_domain_sid", py_get_domain_sid, METH_NOARGS,
		"get_domain_sid() -> dom_sid\n\n \
		Return domain SID from secrets database." },
	{ "reload_static_pdb", py_reload_static_pdb, METH_NOARGS,
		"reload_static_pdb() -> None\n\n \
		Re-initialise the static pdb used internally.  Needed if 'passdb backend' is changed." },
	{0},
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "passdb",
    .m_doc = "SAMBA Password Database",
    .m_size = -1,
    .m_methods = py_passdb_methods,
};

MODULE_INIT_FUNC(passdb)
{
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *m = NULL, *mod = NULL;
	char exception_name[] = "passdb.error";

	if (pytalloc_BaseObject_PyType_Ready(&PyPDB) < 0) {
		talloc_free(frame);
		return NULL;
	}

	if (pytalloc_BaseObject_PyType_Ready(&PySamu) < 0) {
		talloc_free(frame);
		return NULL;
	}

	if (pytalloc_BaseObject_PyType_Ready(&PyGroupmap) < 0) {
		talloc_free(frame);
		return NULL;
	}

	m = PyModule_Create(&moduledef);
	if (m == NULL) {
	    talloc_free(frame);
	    return NULL;
	}

	/* Create new exception for passdb module */
	py_pdb_error = PyErr_NewException(exception_name, NULL, NULL);
	Py_INCREF(py_pdb_error);
	PyModule_AddObject(m, "error", py_pdb_error);

	Py_INCREF(&PyPDB);
	PyModule_AddObject(m, "PDB", (PyObject *)&PyPDB);

	Py_INCREF(&PySamu);
	PyModule_AddObject(m, "Samu", (PyObject *)&PySamu);

	Py_INCREF(&PyGroupmap);
	PyModule_AddObject(m, "Groupmap", (PyObject *)&PyGroupmap);

	/* Import dom_sid type from dcerpc.security */
	mod = PyImport_ImportModule("samba.dcerpc.security");
	if (mod == NULL) {
		talloc_free(frame);
		return NULL;
	}

	dom_sid_Type = (PyTypeObject *)PyObject_GetAttrString(mod, "dom_sid");
	if (dom_sid_Type == NULL) {
		Py_DECREF(mod);
		talloc_free(frame);
		return NULL;
	}

	/* Import security_descriptor type from dcerpc.security */
	security_Type = (PyTypeObject *)PyObject_GetAttrString(mod, "descriptor");
	Py_DECREF(mod);
	if (security_Type == NULL) {
		Py_DECREF(dom_sid_Type);
		talloc_free(frame);
		return NULL;
	}

	/* Import GUID type from dcerpc.misc */
	mod = PyImport_ImportModule("samba.dcerpc.misc");
	if (mod == NULL) {
		Py_DECREF(security_Type);
		Py_DECREF(dom_sid_Type);
		talloc_free(frame);
		return NULL;
	}

	guid_Type = (PyTypeObject *)PyObject_GetAttrString(mod, "GUID");
	Py_DECREF(mod);
	if (guid_Type == NULL) {
		Py_DECREF(security_Type);
		Py_DECREF(dom_sid_Type);
		talloc_free(frame);
		return NULL;
	}
	talloc_free(frame);
	return m;
}
