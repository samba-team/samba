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
%include "../util/errors.i"
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

%rename(SecurityToken) security_token;

%talloctype(security_token);

typedef struct security_token { 
    %extend {
        security_token(TALLOC_CTX *mem_ctx) { return security_token_initialise(mem_ctx); }
        %feature("docstring") is_sid "S.is_sid(sid) -> bool\n" \
            "Check whether this token is of the specified SID.";
        bool is_sid(const struct dom_sid *sid);
        %feature("docstring") is_system "S.is_system() -> bool\n" \
                          "Check whether this is a system token.";
        bool is_system();
        %feature("docstring") is_anonymous "S.is_anonymus() -> bool\n" \
                          "Check whether this is an anonymous token.";
        bool is_anonymous();
        bool has_sid(const struct dom_sid *sid);
        bool has_builtin_administrators();
        bool has_nt_authenticated_users();
        bool has_privilege(enum sec_privilege privilege);
        void set_privilege(enum sec_privilege privilege);
    }
} security_token;

%talloctype(security_descriptor);

typedef struct security_descriptor {
    %extend {
        security_descriptor(TALLOC_CTX *mem_ctx) { return security_descriptor_initialise(mem_ctx); }
        %feature("docstring") sacl_add "S.sacl_add(ace) -> None\n" \
                              "Add a security ace to this security descriptor";
        NTSTATUS sacl_add(const struct security_ace *ace);
        NTSTATUS dacl_add(const struct security_ace *ace);
        NTSTATUS dacl_del(const struct dom_sid *trustee);
        NTSTATUS sacl_del(const struct dom_sid *trustee);
#ifdef SWIGPYTHON
        %rename(__eq__) equal;
#endif
        bool equal(const struct security_descriptor *other);
    }
} security_descriptor;

%rename(Sid) dom_sid;

%talloctype(dom_sid);

typedef struct dom_sid {
    %immutable;
    uint8_t sid_rev_num;
    int8_t num_auths;/* [range(0,15)] */
    uint8_t id_auth[6];
    uint32_t *sub_auths;
    %mutable;
    %extend {
        dom_sid(TALLOC_CTX *mem_ctx, const char *text) {
            return dom_sid_parse_talloc(mem_ctx, text);
        }
#ifdef SWIGPYTHON
        const char *__str__(TALLOC_CTX *mem_ctx) {
            return dom_sid_string(mem_ctx, $self);
        }
        %rename(__eq__) equal;
#endif
        bool equal(const struct dom_sid *other);
    }
%pythoncode {
    def __repr__(self):
        return "Sid(%r)" % str(self)
}
} dom_sid;

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
