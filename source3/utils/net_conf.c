/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Local configuration interface
 *  Copyright (C) Michael Adam 2007-2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is an interface to Samba's configuration as made available
 * by the libsmbconf interface (source/lib/smbconf/smbconf.c).
 *
 * This currently supports local interaction with the configuration
 * stored in the registry. But other backends and remote access via
 * rpc might get implemented in the future.
 */

#include "includes.h"
#include "utils/net.h"

/**********************************************************************
 *
 * usage functions
 *
 **********************************************************************/

static int net_conf_list_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf list\n");
	return -1;
}

static int net_conf_import_usage(int argc, const char**argv)
{
	d_printf("USAGE: net conf import [--test|-T] <filename> "
		 "[<servicename>]\n"
		 "\t[--test|-T]    testmode - do not act, just print "
			"what would be done\n"
		 "\t<servicename>  only import service <servicename>, "
			"ignore the rest\n");
	return -1;
}

static int net_conf_listshares_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf listshares\n");
	return -1;
}

static int net_conf_drop_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf drop\n");
	return -1;
}

static int net_conf_showshare_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf showshare <sharename>\n");
	return -1;
}

static int net_conf_addshare_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf addshare <sharename> <path> "
		 "[writeable={y|N} [guest_ok={y|N} [<comment>]]\n"
		 "\t<sharename>      the new share name.\n"
		 "\t<path>           the path on the filesystem to export.\n"
		 "\twriteable={y|N}  set \"writeable to \"yes\" or "
		 "\"no\" (default) on this share.\n"
		 "\tguest_ok={y|N}   set \"guest ok\" to \"yes\" or "
		 "\"no\" (default)   on this share.\n"
		 "\t<comment>        optional comment for the new share.\n");
	return -1;
}

static int net_conf_delshare_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf delshare <sharename>\n");
	return -1;
}

static int net_conf_setparm_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf setparm <section> <param> <value>\n");
	return -1;
}

static int net_conf_getparm_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf getparm <section> <param>\n");
	return -1;
}

static int net_conf_delparm_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf delparm <section> <param>\n");
	return -1;
}

static int net_conf_getincludes_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf getincludes <section>\n");
	return -1;
}

static int net_conf_setincludes_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf setincludes <section> [<filename>]*\n");
	return -1;
}

static int net_conf_delincludes_usage(int argc, const char **argv)
{
	d_printf("USAGE: net conf delincludes <section>\n");
	return -1;
}


/**********************************************************************
 *
 * Helper functions
 *
 **********************************************************************/

/**
 * This functions process a service previously loaded with libsmbconf.
 */
static WERROR import_process_service(struct smbconf_ctx *conf_ctx,
				     struct smbconf_service *service)
{
	uint32_t idx;
	WERROR werr = WERR_OK;
	uint32_t num_includes = 0;
	char **includes = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (opt_testmode) {
		const char *indent = "";
		if (service->name != NULL) {
			d_printf("[%s]\n", service->name);
			indent = "\t";
		}
		for (idx = 0; idx < service->num_params; idx++) {
			d_printf("%s%s = %s\n", indent,
				 service->param_names[idx],
				 service->param_values[idx]);
		}
		d_printf("\n");
		goto done;
	}

	if (smbconf_share_exists(conf_ctx, service->name)) {
		werr = smbconf_delete_share(conf_ctx, service->name);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}
	werr = smbconf_create_share(conf_ctx, service->name);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	for (idx = 0; idx < service->num_params; idx ++) {
		if (strequal(service->param_names[idx], "include")) {
			includes = TALLOC_REALLOC_ARRAY(mem_ctx,
							includes,
							char *,
							num_includes+1);
			if (includes == NULL) {
				werr = WERR_NOMEM;
				goto done;
			}
			includes[num_includes] = talloc_strdup(includes,
						service->param_values[idx]);
			if (includes[num_includes] == NULL) {
				werr = WERR_NOMEM;
				goto done;
			}
			num_includes++;
		} else {
			werr = smbconf_set_parameter(conf_ctx,
						     service->name,
						     service->param_names[idx],
						     service->param_values[idx]);
			if (!W_ERROR_IS_OK(werr)) {
				goto done;
			}
		}
	}

	werr = smbconf_set_includes(conf_ctx, service->name, num_includes,
				    (const char **)includes);

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}


/**********************************************************************
 *
 * the main conf functions
 *
 **********************************************************************/

static int net_conf_list(struct smbconf_ctx *conf_ctx,
			 int argc, const char **argv)
{
	WERROR werr = WERR_OK;
	int ret = -1;
	TALLOC_CTX *mem_ctx;
	uint32_t num_shares;
	uint32_t share_count, param_count;
	struct smbconf_service **shares = NULL;

	mem_ctx = talloc_stackframe();

	if (argc != 0) {
		net_conf_list_usage(argc, argv);
		goto done;
	}

	werr = smbconf_get_config(conf_ctx, mem_ctx, &num_shares, &shares);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error getting config: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	for (share_count = 0; share_count < num_shares; share_count++) {
		const char *indent = "";
		if (shares[share_count]->name != NULL) {
			d_printf("[%s]\n", shares[share_count]->name);
			indent = "\t";
		}
		for (param_count = 0;
		     param_count < shares[share_count]->num_params;
		     param_count++)
		{
			d_printf("%s%s = %s\n",
				 indent,
				 shares[share_count]->param_names[param_count],
				 shares[share_count]->param_values[param_count]);
		}
		d_printf("\n");
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_import(struct smbconf_ctx *conf_ctx,
			   int argc, const char **argv)
{
	int ret = -1;
	const char *filename = NULL;
	const char *servicename = NULL;
	char *conf_source = NULL;
	TALLOC_CTX *mem_ctx;
	struct smbconf_ctx *txt_ctx;
	WERROR werr;

	mem_ctx = talloc_stackframe();

	switch (argc) {
		case 0:
		default:
			net_conf_import_usage(argc, argv);
			goto done;
		case 2:
			servicename = talloc_strdup_lower(mem_ctx, argv[1]);
			if (servicename == NULL) {
				d_printf("error: out of memory!\n");
				goto done;
			}
		case 1:
			filename = argv[0];
			break;
	}

	DEBUG(3,("net_conf_import: reading configuration from file %s.\n",
		filename));

	conf_source = talloc_asprintf(mem_ctx, "file:%s", filename);
	if (conf_source == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_init(mem_ctx, &txt_ctx, conf_source);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("error loading file '%s': %s\n", filename,
			 dos_errstr(werr));
		goto done;
	}

	if (opt_testmode) {
		d_printf("\nTEST MODE - "
			 "would import the following configuration:\n\n");
	}

	if (servicename != NULL) {
		struct smbconf_service *service = NULL;

		werr = smbconf_get_share(txt_ctx, mem_ctx,
					 servicename,
					 &service);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
		werr = import_process_service(conf_ctx, service);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	} else {
		struct smbconf_service **services = NULL;
		uint32_t num_shares, sidx;

		werr = smbconf_get_config(txt_ctx, mem_ctx,
					  &num_shares,
					  &services);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
		if (!opt_testmode) {
			werr = smbconf_drop(conf_ctx);
			if (!W_ERROR_IS_OK(werr)) {
				goto done;
			}
		}
		for (sidx = 0; sidx < num_shares; sidx++) {
			werr = import_process_service(conf_ctx, services[sidx]);
			if (!W_ERROR_IS_OK(werr)) {
				goto done;
			}
		}
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_listshares(struct smbconf_ctx *conf_ctx,
			       int argc, const char **argv)
{
	WERROR werr = WERR_OK;
	int ret = -1;
	uint32_t count, num_shares = 0;
	char **share_names = NULL;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_stackframe();

	if (argc != 0) {
		net_conf_listshares_usage(argc, argv);
		goto done;
	}

	werr = smbconf_get_share_names(conf_ctx, mem_ctx, &num_shares,
				       &share_names);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	for (count = 0; count < num_shares; count++)
	{
		d_printf("%s\n", share_names[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_drop(struct smbconf_ctx *conf_ctx,
			 int argc, const char **argv)
{
	int ret = -1;
	WERROR werr;

	if (argc != 0) {
		net_conf_drop_usage(argc, argv);
		goto done;
	}

	werr = smbconf_drop(conf_ctx);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error deleting configuration: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	return ret;
}

static int net_conf_showshare(struct smbconf_ctx *conf_ctx,
			      int argc, const char **argv)
{
	int ret = -1;
	WERROR werr = WERR_OK;
	const char *sharename = NULL;
	TALLOC_CTX *mem_ctx;
	uint32_t count;
	struct smbconf_service *service = NULL;

	mem_ctx = talloc_stackframe();

	if (argc != 1) {
		net_conf_showshare_usage(argc, argv);
		goto done;
	}

	sharename = talloc_strdup_lower(mem_ctx, argv[0]);
	if (sharename == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_get_share(conf_ctx, mem_ctx, sharename, &service);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("error getting share parameters: %s\n",
			 dos_errstr(werr));
		goto done;
	}

	d_printf("[%s]\n", sharename);

	for (count = 0; count < service->num_params; count++) {
		d_printf("\t%s = %s\n", service->param_names[count],
			 service->param_values[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * Add a share, with a couple of standard parameters, partly optional.
 *
 * This is a high level utility function of the net conf utility,
 * not a direct frontend to the smbconf API.
 */
static int net_conf_addshare(struct smbconf_ctx *conf_ctx,
			     int argc, const char **argv)
{
	int ret = -1;
	WERROR werr = WERR_OK;
	char *sharename = NULL;
	const char *path = NULL;
	const char *comment = NULL;
	const char *guest_ok = "no";
	const char *writeable = "no";
	SMB_STRUCT_STAT sbuf;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	switch (argc) {
		case 0:
		case 1:
		default:
			net_conf_addshare_usage(argc, argv);
			goto done;
		case 5:
			comment = argv[4];
		case 4:
			if (!strnequal(argv[3], "guest_ok=", 9)) {
				net_conf_addshare_usage(argc, argv);
				goto done;
			}
			switch (argv[3][9]) {
				case 'y':
				case 'Y':
					guest_ok = "yes";
					break;
				case 'n':
				case 'N':
					guest_ok = "no";
					break;
				default:
					net_conf_addshare_usage(argc, argv);
					goto done;
			}
		case 3:
			if (!strnequal(argv[2], "writeable=", 10)) {
				net_conf_addshare_usage(argc, argv);
				goto done;
			}
			switch (argv[2][10]) {
				case 'y':
				case 'Y':
					writeable = "yes";
					break;
				case 'n':
				case 'N':
					writeable = "no";
					break;
				default:
					net_conf_addshare_usage(argc, argv);
					goto done;
			}
		case 2:
			path = argv[1];
			sharename = talloc_strdup_lower(mem_ctx, argv[0]);
			if (sharename == NULL) {
				d_printf("error: out of memory!\n");
				goto done;
			}

			break;
	}

	/*
	 * validate arguments
	 */

	/* validate share name */

	if (!validate_net_name(sharename, INVALID_SHARENAME_CHARS,
			       strlen(sharename)))
	{
		d_fprintf(stderr, "ERROR: share name %s contains "
                        "invalid characters (any of %s)\n",
                        sharename, INVALID_SHARENAME_CHARS);
		goto done;
	}

	if (getpwnam(sharename)) {
		d_fprintf(stderr, "ERROR: share name %s is already a valid "
			  "system user name.\n", sharename);
		goto done;
	}

	if (strequal(sharename, GLOBAL_NAME)) {
		d_fprintf(stderr,
			  "ERROR: 'global' is not a valid share name.\n");
		goto done;
	}

	if (smbconf_share_exists(conf_ctx, sharename)) {
		d_fprintf(stderr, "ERROR: share %s already exists.\n",
			  sharename);
		goto done;
	}

	/* validate path */

	if (path[0] != '/') {
		d_fprintf(stderr,
			  "Error: path '%s' is not an absolute path.\n",
			  path);
		goto done;
	}

	if (sys_stat(path, &sbuf) != 0) {
		d_fprintf(stderr,
			  "ERROR: cannot stat path '%s' to ensure "
			  "this is a directory.\n"
			  "Error was '%s'.\n",
			  path, strerror(errno));
		goto done;
	}

	if (!S_ISDIR(sbuf.st_mode)) {
		d_fprintf(stderr,
			  "ERROR: path '%s' is not a directory.\n",
			  path);
		goto done;
	}

	/*
	 * create the share
	 */

	werr = smbconf_create_share(conf_ctx, sharename);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error creating share %s: %s\n",
			  sharename, dos_errstr(werr));
		goto done;
	}

	/*
	 * fill the share with parameters
	 */

	werr = smbconf_set_parameter(conf_ctx, sharename, "path", path);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error setting parameter %s: %s\n",
			  "path", dos_errstr(werr));
		goto done;
	}

	if (comment != NULL) {
		werr = smbconf_set_parameter(conf_ctx, sharename, "comment",
					     comment);
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, "Error setting parameter %s: %s\n",
				  "comment", dos_errstr(werr));
			goto done;
		}
	}

	werr = smbconf_set_parameter(conf_ctx, sharename, "guest ok", guest_ok);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error setting parameter %s: %s\n",
			  "'guest ok'", dos_errstr(werr));
		goto done;
	}

	werr = smbconf_set_parameter(conf_ctx, sharename, "writeable",
				     writeable);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error setting parameter %s: %s\n",
			  "writeable", dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delshare(struct smbconf_ctx *conf_ctx,
			     int argc, const char **argv)
{
	int ret = -1;
	const char *sharename = NULL;
	WERROR werr = WERR_OK;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1) {
		net_conf_delshare_usage(argc, argv);
		goto done;
	}
	sharename = talloc_strdup_lower(mem_ctx, argv[0]);
	if (sharename == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_delete_share(conf_ctx, sharename);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error deleting share %s: %s\n",
			  sharename, dos_errstr(werr));
		goto done;
	}

	ret = 0;
done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_setparm(struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	WERROR werr = WERR_OK;
	char *service = NULL;
	char *param = NULL;
	const char *value_str = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 3) {
		net_conf_setparm_usage(argc, argv);
		goto done;
	}
	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}
	param = talloc_strdup_lower(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}
	value_str = argv[2];

	if (!smbconf_share_exists(conf_ctx, service)) {
		werr = smbconf_create_share(conf_ctx, service);
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, "Error creating share '%s': %s\n",
				  service, dos_errstr(werr));
			goto done;
		}
	}

	werr = smbconf_set_parameter(conf_ctx, service, param, value_str);

	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error setting value '%s': %s\n",
			  param, dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_getparm(struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	WERROR werr = WERR_OK;
	char *service = NULL;
	char *param = NULL;
	char *valstr = NULL;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_stackframe();

	if (argc != 2) {
		net_conf_getparm_usage(argc, argv);
		goto done;
	}
	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}
	param = talloc_strdup_lower(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_get_parameter(conf_ctx, mem_ctx, service, param, &valstr);

	if (W_ERROR_EQUAL(werr, WERR_NO_SUCH_SERVICE)) {
		d_fprintf(stderr,
			  "Error: given service '%s' does not exist.\n",
			  service);
		goto done;
	} else if (W_ERROR_EQUAL(werr, WERR_INVALID_PARAM)) {
		d_fprintf(stderr,
			  "Error: given parameter '%s' is not set.\n",
			  param);
		goto done;
	} else if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error getting value '%s': %s.\n",
			  param, dos_errstr(werr));
		goto done;
	}

	d_printf("%s\n", valstr);

	ret = 0;
done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delparm(struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	WERROR werr = WERR_OK;
	char *service = NULL;
	char *param = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 2) {
		net_conf_delparm_usage(argc, argv);
		goto done;
	}
	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}
	param = talloc_strdup_lower(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_delete_parameter(conf_ctx, service, param);

	if (W_ERROR_EQUAL(werr, WERR_NO_SUCH_SERVICE)) {
		d_fprintf(stderr,
			  "Error: given service '%s' does not exist.\n",
			  service);
		goto done;
	} else if (W_ERROR_EQUAL(werr, WERR_INVALID_PARAM)) {
		d_fprintf(stderr,
			  "Error: given parameter '%s' is not set.\n",
			  param);
		goto done;
	} else if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error deleting value '%s': %s.\n",
			  param, dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_getincludes(struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	WERROR werr;
	uint32_t num_includes;
	uint32_t count;
	char *service;
	char **includes = NULL;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1) {
		net_conf_getincludes_usage(argc, argv);
		goto done;
	}

	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_get_includes(conf_ctx, mem_ctx, service,
				    &num_includes, &includes);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("error getting includes: %s\n", dos_errstr(werr));
		goto done;
	}

	for (count = 0; count < num_includes; count++) {
		d_printf("include = %s\n", includes[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_setincludes(struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	WERROR werr;
	char *service;
	uint32_t num_includes;
	const char **includes;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc < 1) {
		net_conf_setincludes_usage(argc, argv);
		goto done;
	}

	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	num_includes = argc - 1;
	if (num_includes == 0) {
		includes = NULL;
	} else {
		includes = argv + 1;
	}

	werr = smbconf_set_includes(conf_ctx, service, num_includes, includes);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("error setting includes: %s\n", dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delincludes(struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	WERROR werr;
	char *service;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1) {
		net_conf_delincludes_usage(argc, argv);
		goto done;
	}

	service = talloc_strdup_lower(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	werr = smbconf_delete_includes(conf_ctx, service);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("error deleting includes: %s\n", dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


/**********************************************************************
 *
 * Wrapper and net_conf_run_function mechanism.
 *
 **********************************************************************/

/**
 * Wrapper function to call the main conf functions.
 * The wrapper calls handles opening and closing of the
 * configuration.
 */
static int net_conf_wrap_function(int (*fn)(struct smbconf_ctx *,
					    int, const char **),
				  int argc, const char **argv)
{
	WERROR werr;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx;
	int ret = -1;

	werr = smbconf_init(mem_ctx, &conf_ctx, "registry:");

	if (!W_ERROR_IS_OK(werr)) {
		return -1;
	}

	ret = fn(conf_ctx, argc, argv);

	smbconf_shutdown(conf_ctx);

	return ret;
}

/*
 * We need a functable struct of our own, because the
 * functions are called through a wrapper that handles
 * the opening and closing of the configuration, and so on.
 */
struct conf_functable {
	const char *funcname;
	int (*fn)(struct smbconf_ctx *ctx, int argc, const char **argv);
	const char *helptext;
};

/**
 * This imitates net_run_function2 but calls the main functions
 * through the wrapper net_conf_wrap_function().
 */
static int net_conf_run_function(int argc, const char **argv,
				 const char *whoami,
				 struct conf_functable *table)
{
	int i;

	if (argc != 0) {
		for (i=0; table[i].funcname; i++) {
			if (StrCaseCmp(argv[0], table[i].funcname) == 0)
				return net_conf_wrap_function(table[i].fn,
							      argc-1,
							      argv+1);
		}
	}

	for (i=0; table[i].funcname; i++) {
		d_printf("%s %-15s %s\n", whoami, table[i].funcname,
			 table[i].helptext);
	}

	return -1;
}

/*
 * Entry-point for all the CONF functions.
 */

int net_conf(int argc, const char **argv)
{
	int ret = -1;
	struct conf_functable func_table[] = {
		{"list", net_conf_list,
		 "Dump the complete configuration in smb.conf like format."},
		{"import", net_conf_import,
		 "Import configuration from file in smb.conf format."},
		{"listshares", net_conf_listshares,
		 "List the share names."},
		{"drop", net_conf_drop,
		 "Delete the complete configuration."},
		{"showshare", net_conf_showshare,
		 "Show the definition of a share."},
		{"addshare", net_conf_addshare,
		 "Create a new share."},
		{"delshare", net_conf_delshare,
		 "Delete a share."},
		{"setparm", net_conf_setparm,
		 "Store a parameter."},
		{"getparm", net_conf_getparm,
		 "Retrieve the value of a parameter."},
		{"delparm", net_conf_delparm,
		 "Delete a parameter."},
		{"getincludes", net_conf_getincludes,
		 "Show the includes of a share definition."},
		{"setincludes", net_conf_setincludes,
		 "Set includes for a share."},
		{"delincludes", net_conf_delincludes,
		 "Delete includes from a share definition."},
		{NULL, NULL, NULL}
	};

	ret = net_conf_run_function(argc, argv, "net conf", func_table);

	return ret;
}

