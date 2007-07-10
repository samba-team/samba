/* 
   Unix SMB/CIFS implementation.

   provide a command line options parsing function for ejs

   Copyright (C) Andrew Tridgell 2005
   
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
#include "scripting/ejs/smbcalls.h"


/*
  usage:
      options = GetOptions(argv, 
                          "realm=s", 
                          "enablexx", 
                          "myint=i");

      the special options POPT_COMMON_* options are recognised and replaced
      with the Samba internal options

      resulting parsed options are placed in the options object

      additional command line arguments are placed in options.ARGV
*/

static int ejs_GetOptions(MprVarHandle eid, int argc, struct MprVar **argv)
{
	poptContext pc;
	int opt;
	struct {
		const char *name;
		struct poptOption *table;
		const char *description;
	} tables[] = {
		{ "POPT_AUTOHELP", poptHelpOptions, "Help options:" },
		{ "POPT_COMMON_SAMBA", popt_common_samba, "Common Samba options:" },
 		{ "POPT_COMMON_CONNECTION", popt_common_connection, "Connection options:" },
		{ "POPT_COMMON_CREDENTIALS", popt_common_credentials, "Authentication options:" },
		{ "POPT_COMMON_VERSION", popt_common_version, "Common Samba options:" }
	};

	struct MprVar *options = mprInitObject(eid, "options", 0, NULL);

	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	struct poptOption *long_options = NULL;
	int i, num_options = 0;
	int opt_argc;
	const char **opt_argv;
	const char **opt_names = NULL;
	const int BASE_OPTNUM = 0x100000;

	/* validate arguments */
	if (argc < 1 || argv[0]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "GetOptions invalid arguments");
		return -1;
	}

	opt_argv = mprToArray(tmp_ctx, argv[0]);
	opt_argc = str_list_length(opt_argv);

	long_options = talloc_array(tmp_ctx, struct poptOption, 1);
	if (long_options == NULL) {
		return -1;
	}

	/* create the long_options array */
	for (i=1;i<argc;i++) {
		const char *optstr = mprToString(argv[i]);
		int t, opt_type = POPT_ARG_NONE;
		const char *s;
		if (argv[i]->type != MPR_TYPE_STRING) {
			ejsSetErrorMsg(eid, "GetOptions string argument");
			return -1;
		}

		long_options = talloc_realloc(tmp_ctx, long_options, 
					      struct poptOption, num_options+2);
		if (long_options == NULL) {
			return -1;
		}
		ZERO_STRUCT(long_options[num_options]);

		/* see if its one of the special samba option tables */
		for (t=0;t<ARRAY_SIZE(tables);t++) {
			if (strcmp(tables[t].name, optstr) == 0) {
				break;
			}
		}
		if (t < ARRAY_SIZE(tables)) {
			opt_names = str_list_add(opt_names, optstr);
			talloc_steal(tmp_ctx, opt_names);
			long_options[num_options].argInfo = POPT_ARG_INCLUDE_TABLE;
			long_options[num_options].arg     = tables[t].table;
			long_options[num_options].descrip = tables[t].description;
			num_options++;
			continue;
		}

		s = strchr(optstr, '=');
		if (s) {
			char *name = talloc_strndup(tmp_ctx, optstr, (int)(s-optstr));
			opt_names = str_list_add(opt_names, name);
			if (s[1] == 's') {
				opt_type = POPT_ARG_STRING;
			} else if (s[1] == 'i') {
				opt_type = POPT_ARG_INT;
			} else {
				ejsSetErrorMsg(eid, "GetOptions invalid option type");
				return -1;
			}
			talloc_free(name);
		} else {
			opt_names = str_list_add(opt_names, optstr);
		}
		talloc_steal(tmp_ctx, opt_names);
		if (strlen(opt_names[num_options]) == 1) {
			long_options[num_options].shortName = opt_names[num_options][0];
		} else {
			long_options[num_options].longName = opt_names[num_options];
		}
		long_options[num_options].argInfo = opt_type;
		long_options[num_options].val = num_options + BASE_OPTNUM;
		num_options++;
	}

	ZERO_STRUCT(long_options[num_options]);

	pc = poptGetContext("smbscript", opt_argc, opt_argv, long_options, 0);

	/* parse the options */
	while((opt = poptGetNextOpt(pc)) != -1) {
		const char *arg;

		if (opt < BASE_OPTNUM || opt >= num_options + BASE_OPTNUM) {
			char *err;
			err = talloc_asprintf(tmp_ctx, "%s: %s",
					      poptBadOption(pc, POPT_BADOPTION_NOALIAS),
					      poptStrerror(opt));
			mprSetVar(options, "ERROR", mprString(err));
			talloc_free(tmp_ctx);
			mpr_Return(eid, mprCreateUndefinedVar());
			return 0;
		}
		opt -= BASE_OPTNUM;
		arg = poptGetOptArg(pc);
		if (arg == NULL) {
			mprSetVar(options, opt_names[opt], mprCreateBoolVar(1));
		} else if (long_options[opt].argInfo == POPT_ARG_INT) {
			int v = strtol(arg, NULL, 0);
			mprSetVar(options, opt_names[opt], mprCreateIntegerVar(v));
		} else {
			mprSetVar(options, opt_names[opt], mprString(arg));
		}
	}

	/* setup options.argv list */
	mprSetVar(options, "ARGV", mprList("ARGV", poptGetArgs(pc)));

	poptFreeContext(pc);

	talloc_free(tmp_ctx);

	/* setup methods */
	mprSetCFunction(options, "get_credentials", ejs_credentials_cmdline);

	return 0;
}



/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_options(void)
{
	ejsDefineCFunction(-1, "GetOptions", ejs_GetOptions, NULL, MPR_VAR_SCRIPT_HANDLE);
}
