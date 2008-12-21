/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

%module(docstring="Security-related classes.",package="samba.security") security

%{
#include "includes.h"
#include "libcli/security/security.h"

typedef struct dom_sid dom_sid;
typedef struct security_token security_token;
typedef struct security_descriptor security_descriptor;
%}

%import "../lib/talloc/talloc.i"
%{
#include "libcli/util/pyerrors.h"
%}

%typemap(out,noblock=1) NTSTATUS {
    if (NT_STATUS_IS_ERR($1)) {
        PyErr_SetNTSTATUS($1);
        SWIG_fail;
    } else if ($result == NULL) {
        $result = Py_None;
    }
};

%typemap(in,noblock=1) NTSTATUS {
	if (PyLong_Check($input))
		$1 = NT_STATUS(PyLong_AsUnsignedLong($input));
	else if (PyInt_Check($input))
		$1 = NT_STATUS(PyInt_AsLong($input));
	else {
		PyErr_SetString(PyExc_TypeError, "Expected a long or an int");
		return NULL;
	}
}

%import "stdint.i"

enum sec_privilege {
	SEC_PRIV_SECURITY=1,
	SEC_PRIV_BACKUP=2,
	SEC_PRIV_RESTORE=3,
	SEC_PRIV_SYSTEMTIME=4,
	SEC_PRIV_SHUTDOWN=5,
	SEC_PRIV_REMOTE_SHUTDOWN=6,
	SEC_PRIV_TAKE_OWNERSHIP=7,
	SEC_PRIV_DEBUG=8,
	SEC_PRIV_SYSTEM_ENVIRONMENT=9,
	SEC_PRIV_SYSTEM_PROFILE=10,
	SEC_PRIV_PROFILE_SINGLE_PROCESS=11,
	SEC_PRIV_INCREASE_BASE_PRIORITY=12,
	SEC_PRIV_LOAD_DRIVER=13,
	SEC_PRIV_CREATE_PAGEFILE=14,
	SEC_PRIV_INCREASE_QUOTA=15,
	SEC_PRIV_CHANGE_NOTIFY=16,
	SEC_PRIV_UNDOCK=17,
	SEC_PRIV_MANAGE_VOLUME=18,
	SEC_PRIV_IMPERSONATE=19,
	SEC_PRIV_CREATE_GLOBAL=20,
	SEC_PRIV_ENABLE_DELEGATION=21,
	SEC_PRIV_INTERACTIVE_LOGON=22,
	SEC_PRIV_NETWORK_LOGON=23,
	SEC_PRIV_REMOTE_INTERACTIVE_LOGON=24
};

%feature("docstring") random_sid "random_sid() -> sid\n" \
         "Generate a random SID";

%inline %{
static struct dom_sid *random_sid(TALLOC_CTX *mem_ctx)
{
    char *str = talloc_asprintf(mem_ctx, "S-1-5-21-%u-%u-%u", 
                                (unsigned)generate_random(), 
                                (unsigned)generate_random(), 
                                (unsigned)generate_random());

        return dom_sid_parse_talloc(mem_ctx, str);
}
%}

%rename(privilege_name) sec_privilege_name;
const char *sec_privilege_name(enum sec_privilege privilege);
%rename(privilege_id) sec_privilege_id;
enum sec_privilege sec_privilege_id(const char *name);
