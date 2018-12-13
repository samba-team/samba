/* 
   Unix SMB/CIFS implementation.
   Credentials popt routines

   Copyright (C) Jelmer Vernooij 2002,2003,2005

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

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "lib/cmdline/credentials.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"

/* Handle command line options:
 *		-U,--user
 *		-A,--authentication-file
 *		-k,--use-kerberos
 *		-N,--no-pass
 *		-S,--signing
 *		-P,--machine-pass
 *		--simple-bind-dn
 *		--password
 *		--krb5-ccache
 */

static bool dont_ask;
static bool machine_account_pending;

enum opt { OPT_SIMPLE_BIND_DN, OPT_PASSWORD, OPT_KERBEROS, OPT_SIGN, OPT_ENCRYPT, OPT_KRB5_CCACHE };

static void popt_common_credentials_callback(poptContext con, 
						enum poptCallbackReason reason,
						const struct poptOption *opt,
						const char *arg, const void *data)
{
	if (reason == POPT_CALLBACK_REASON_PRE) {
		popt_set_cmdline_credentials(cli_credentials_init(NULL));
		return;
	}
	
	if (reason == POPT_CALLBACK_REASON_POST) {
		cli_credentials_guess(popt_get_cmdline_credentials(),
				cmdline_lp_ctx);

		if (!dont_ask) {
			cli_credentials_set_cmdline_callbacks(
				popt_get_cmdline_credentials());
		}

		if (machine_account_pending) {
			cli_credentials_set_machine_account(
				popt_get_cmdline_credentials(), cmdline_lp_ctx);
		}

		return;

	}

	switch(opt->val) {
	case 'U':
	{
		char *lp;
		
		cli_credentials_parse_string(
			popt_get_cmdline_credentials(), arg, CRED_SPECIFIED);
		/* This breaks the abstraction, including the const above */
		if ((lp=strchr_m(arg,'%'))) {
			lp[0]='\0';
			lp++;
			/* Try to prevent this showing up in ps */
			memset(lp,0,strlen(lp));
		}
	}
	break;

	case OPT_PASSWORD:
		cli_credentials_set_password(popt_get_cmdline_credentials(),
			arg, CRED_SPECIFIED);
		/* Try to prevent this showing up in ps */
		memset(discard_const(arg),0,strlen(arg));
		break;

	case 'A':
		cli_credentials_parse_file(popt_get_cmdline_credentials(),
			arg, CRED_SPECIFIED);
		break;

	case 'P':
		/* Later, after this is all over, get the machine account details from the secrets.ldb */
		machine_account_pending = true;
		break;

	case OPT_KERBEROS:
	{
		bool use_kerberos = true;
		/* Force us to only use kerberos */
		if (arg) {
			if (!set_boolean(arg, &use_kerberos)) {
				fprintf(stderr, "Error parsing -k %s. Should be "
					"-k [yes|no]\n", arg);
				exit(1);
				break;
			}
		}
		
		cli_credentials_set_kerberos_state(
			popt_get_cmdline_credentials(),
						   use_kerberos 
						   ? CRED_MUST_USE_KERBEROS
						   : CRED_DONT_USE_KERBEROS);
		break;
	}
		
	case OPT_SIMPLE_BIND_DN:
	{
		cli_credentials_set_bind_dn(popt_get_cmdline_credentials(),
				arg);
		break;
	}
	case OPT_KRB5_CCACHE:
	{
		const char *error_string;
		if (cli_credentials_set_ccache(
			popt_get_cmdline_credentials(), cmdline_lp_ctx,
			arg, CRED_SPECIFIED,
					       &error_string) != 0) {
			fprintf(stderr, "Error reading krb5 credentials cache: '%s' %s", arg, error_string);
			exit(1);
		}
		break;
	}
	case OPT_SIGN:
	{
		uint32_t gensec_features;

		gensec_features = cli_credentials_get_gensec_features(
					popt_get_cmdline_credentials());

		gensec_features |= GENSEC_FEATURE_SIGN;
		cli_credentials_set_gensec_features(
					popt_get_cmdline_credentials(),
						    gensec_features);
		break;
	}
	case OPT_ENCRYPT:
	{
		uint32_t gensec_features;

		gensec_features = cli_credentials_get_gensec_features(
					popt_get_cmdline_credentials());

		gensec_features |= GENSEC_FEATURE_SEAL;
		cli_credentials_set_gensec_features(
					popt_get_cmdline_credentials(),
						    gensec_features);
		break;
	}
	}
}



struct poptOption popt_common_credentials4[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_credentials_callback,
	},
	{
		.longName   = "user",
		.shortName  = 'U',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'U',
		.descrip    = "Set the network username",
		.argDescrip = "[DOMAIN/]USERNAME[%PASSWORD]",
	},
	{
		.longName   = "no-pass",
		.shortName  = 'N',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &dont_ask,
		.val        = 'N',
		.descrip    = "Don't ask for a password",
	},
	{
		.longName   = "password",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_PASSWORD,
		.descrip    = "Password",
	},
	{
		.longName   = "authentication-file",
		.shortName  = 'A',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'A',
		.descrip    = "Get the credentials from a file",
		.argDescrip = "FILE",
	},
	{
		.longName   = "machine-pass",
		.shortName  = 'P',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'P',
		.descrip    = "Use stored machine account password",
	},
	{
		.longName   = "simple-bind-dn",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_SIMPLE_BIND_DN,
		.descrip    = "DN to use for a simple bind",
	},
	{
		.longName   = "kerberos",
		.shortName  = 'k',
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_KERBEROS,
		.descrip    = "Use Kerberos, -k [yes|no]",
	},
	{
		.longName   = "krb5-ccache",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_KRB5_CCACHE,
		.descrip    = "Credentials cache location for Kerberos",
	},
	{
		.longName   = "sign",
		.shortName  = 'S',
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_SIGN,
		.descrip    = "Sign connection to prevent modification in transit",
	},
	{
		.longName   = "encrypt",
		.shortName  = 'e',
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_ENCRYPT,
		.descrip    = "Encrypt connection for privacy",
	},
	POPT_TABLEEND
};
