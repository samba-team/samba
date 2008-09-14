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

%module(docstring="Credentials management.",package="samba.credentials") credentials

%{

/* Include headers */
#include <stdint.h>
#include <stdbool.h>

#include "includes.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "lib/cmdline/credentials.h"
typedef struct cli_credentials cli_credentials;
%}

%import "carrays.i"
%import "typemaps.i"
%import "param/param.i"

%typemap(default,noblock=1) struct cli_credentials * {
    $1 = NULL;
}

%constant int AUTO_USE_KERBEROS = CRED_AUTO_USE_KERBEROS;
%constant int DONT_USE_KERBEROS = CRED_DONT_USE_KERBEROS;
%constant int MUST_USE_KERBEROS = CRED_MUST_USE_KERBEROS;

%{
#include "librpc/gen_ndr/samr.h" /* for struct samr_Password */
%}

%typemap(out,noblock=1) struct samr_Password * {
    $result = PyString_FromStringAndSize((char *)$1->hash, 16);
}

%talloctype(cli_credentials);
%rename(Credentials) cli_credentials;
typedef struct cli_credentials {
    %extend {
        cli_credentials(void) {
            return cli_credentials_init(NULL);
        }
        /* username */
        %feature("docstring") get_username "S.get_username() -> username\nObtain username.";
        const char *get_username(void);
        %feature("docstring") set_username "S.set_username(name, obtained=CRED_SPECIFIED) -> None\nChange username.";
        bool set_username(const char *value, 
                          enum credentials_obtained obtained=CRED_SPECIFIED);

        /* password */
        %feature("docstring") get_password "S.get_password() -> password\n" \
                                           "Obtain password.";
        const char *get_password(void);
        %feature("docstring") set_password "S.set_password(password, obtained=CRED_SPECIFIED) -> None\n" \
                                           "Change password.";
        bool set_password(const char *val, 
                          enum credentials_obtained obtained=CRED_SPECIFIED);

        /* domain */
        %feature("docstring") get_password "S.get_domain() -> domain\nObtain domain name.";
        const char *get_domain(void);
        %feature("docstring") set_domain "S.set_domain(domain, obtained=CRED_SPECIFIED) -> None\n" \
                                         "Change domain name.";
        bool set_domain(const char *val, 
                        enum credentials_obtained obtained=CRED_SPECIFIED);

        /* realm */
        %feature("docstring") get_realm "S.get_realm() -> realm\nObtain realm name.";
        const char *get_realm(void);
        %feature("docstring") set_realm "S.set_realm(realm, obtained=CRED_SPECIFIED) -> None\n" \
                                        "Change realm name.";
        bool set_realm(const char *val, 
                       enum credentials_obtained obtained=CRED_SPECIFIED);

        /* Kerberos */
        void set_kerberos_state(enum credentials_use_kerberos use_kerberos);

        %feature("docstring") parse_string "S.parse_string(text, obtained=CRED_SPECIFIED) -> None\n" \
                                           "Parse credentials string.";
        void parse_string(const char *text,
                          enum credentials_obtained obtained=CRED_SPECIFIED);

        /* bind dn */
        %feature("docstring") get_bind_dn "S.get_bind_dn() -> bind dn\nObtain bind DN.";
        const char *get_bind_dn(void);
        %feature("docstring") set_bind_dn "S.set_bind_dn(bind_dn) -> None\nChange bind DN.";
        bool set_bind_dn(const char *bind_dn);

        %feature("docstring") set_anonymous "S.set_anonymous() -> None\nUse anonymous credentials.";
        void set_anonymous();

        /* workstation name */
        const char *get_workstation(void);
        bool set_workstation(const char *workstation, 
                             enum credentials_obtained obtained=CRED_SPECIFIED);

        NTSTATUS set_machine_account(struct loadparm_context *lp_ctx);

        void guess(struct loadparm_context *lp_ctx);
        bool is_anonymous(void);

        const struct samr_Password *get_nt_hash(TALLOC_CTX *mem_ctx);

        bool authentication_requested(void);

        %feature("docstring") wrong_password "S.wrong_password() -> bool\nIndicate the returned password was incorrect.";
        bool wrong_password(void);

        %feature("docstring") set_cmdline_callbacks "S.set_cmdline_callbacks() -> bool\nUse command-line to obtain credentials not explicitly set.";
        bool set_cmdline_callbacks();
    }
} cli_credentials;

%{
struct cli_credentials *cli_credentials_from_py_object(PyObject *py_obj)
{
    struct cli_credentials *ret;

    if (py_obj == Py_None) {
        return cli_credentials_init_anon(NULL);
    }

    if (SWIG_ConvertPtr(py_obj, (void *)&ret, SWIGTYPE_p_cli_credentials, 0 |  0 ) < 0) {
        return NULL; 
    }
    return ret;
}

%}
