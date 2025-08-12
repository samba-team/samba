/*
   Samba Unix/Linux SMB client library
   net join commands
   Copyright (C) 2021 Guenther Deschner (gd@samba.org)

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
#include "utils/net.h"
#include <netapi.h>
#include "netapi/netapi_net.h"
#include "libcli/registry/util_reg.h"
#include "libcli/security/dom_sid.h"
#include "lib/cmdline/cmdline.h"
#include "lib/util/util_file.h"

int net_offlinejoin_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin [misc. options]\n"
		   "\tjoins a computer to a domain\n"));
	d_printf(_("Valid commands:\n"));
	d_printf(_("\tprovision\t\t\tProvision machine account in AD\n"));
	d_printf(_("\trequestodj\t\t\tRequest offline domain join\n"));
	d_printf(_("\tcomposeodj\t\t\tCompose offline domain join blob\n"));
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin(struct net_context *c, int argc, const char **argv)
{
	int ret;
	NET_API_STATUS status;

	if ((argc > 0) && (strcasecmp_m(argv[0], "HELP") == 0)) {
		net_offlinejoin_usage(c, argc, argv);
		return 0;
	}

	if (argc == 0) {
		net_offlinejoin_usage(c, argc, argv);
		return -1;
	}

	net_warn_member_options();

	status = libnetapi_net_init(&c->netapi_ctx, c->lp_ctx, c->creds);
	if (status != 0) {
		return -1;
	}

	if (strcasecmp_m(argv[0], "provision") == 0) {
		ret = net_offlinejoin_provision(c, argc, argv);
		if (ret != 0) {
			return ret;
		}
	}

	if (strcasecmp_m(argv[0], "requestodj") == 0) {
		ret = net_offlinejoin_requestodj(c, argc, argv);
		if (ret != 0) {
			return ret;
		}
	}

	if (strcasecmp_m(argv[0], "composeodj") == 0) {
		ret = net_offlinejoin_composeodj(c, argc, argv);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static int net_offlinejoin_provision_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin provision [misc. options]\n"
		   "\tProvisions machine account in AD\n"));
	d_printf(_("Valid options:\n"));
	d_printf(_("\tdomain=<DOMAIN>\t\t\t\tDefines AD Domain to join\n"));
	d_printf(_("\tmachine_name=<MACHINE_NAME>\t\tDefines the machine account name\n"));
	d_printf(_("\tmachine_account_ou=<OU>\t\t\tDefines the machine account organizational unit DN\n"));
	d_printf(_("\tdcname=<DCNAME>\t\t\t\tSpecify a Domain Controller to join to\n"));
	d_printf(_("\tdefpwd\t\t\t\t\tUse default machine account password\n"));
	d_printf(_("\treuse\t\t\t\t\tReuse existing machine account in AD\n"));
	d_printf(_("\tsavefile=<FILENAME>\t\t\tFile to store the ODJ data\n"));
	d_printf(_("\tprintblob\t\t\t\tPrint the base64 encoded ODJ data on stdout\n"));
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin_provision(struct net_context *c,
			      int argc, const char **argv)
{
	NET_API_STATUS status;
	const char *dcname = NULL;
	const char *domain = NULL;
	const char *machine_name = NULL;
	const char *machine_account_ou = NULL;
	const char *provision_text_data = NULL;
	uint32_t options = 0;
	const char *savefile = NULL;
	bool printblob = false;
	int i;

	if (c->display_usage || argc == 1) {
		return net_offlinejoin_provision_usage(c, argc, argv);
	}

	/* process additional command line args */

	for (i = 0; i < argc; i++) {

		if (strnequal(argv[i], "domain", strlen("domain"))) {
			domain = get_string_param(argv[i]);
			if (domain == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "machine_name", strlen("machine_name"))) {
			machine_name = get_string_param(argv[i]);
			if (machine_name == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "machine_account_ou", strlen("machine_account_ou"))) {
			machine_account_ou = get_string_param(argv[i]);
			if (machine_account_ou == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "dcname", strlen("dcname"))) {
			dcname = get_string_param(argv[i]);
			if (dcname == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "defpwd", strlen("defpwd"))) {
			options |= NETSETUP_PROVISION_USE_DEFAULT_PASSWORD;
		}
		if (strnequal(argv[i], "reuse", strlen("reuse"))) {
			options |= NETSETUP_PROVISION_REUSE_ACCOUNT;
		}
		if (strnequal(argv[i], "savefile", strlen("savefile"))) {
			savefile = get_string_param(argv[i]);
			if (savefile == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "printblob", strlen("printblob"))) {
			printblob = true;
		}
	}

	if (domain == NULL) {
		d_printf("Failed to provision computer account: %s\n",
			 libnetapi_errstr(W_ERROR_V(WERR_INVALID_DOMAINNAME)));
		return -1;
	}

	if (machine_name == NULL) {
		d_printf("Failed to provision computer account: %s\n",
			 libnetapi_errstr(W_ERROR_V(WERR_INVALID_COMPUTERNAME)));
		return -1;
	}

	status = NetProvisionComputerAccount(domain,
					     machine_name,
					     machine_account_ou,
					     dcname,
					     options,
					     NULL,
					     0,
					     &provision_text_data);
	if (status != 0) {
		d_printf("Failed to provision computer account: %s\n",
			libnetapi_get_error_string(c->netapi_ctx, status));
		return status;
	}

	if (savefile != NULL) {

		DATA_BLOB ucs2_blob, blob;
		bool ok;

		/*
		 * Windows produces and consumes UTF16/UCS2 encoded blobs
		 * so we also do it for compatibility. Someone may provision an
		 * account for a Windows machine with samba.
		 */
		ok = push_reg_sz(c, &ucs2_blob, provision_text_data);
		if (!ok) {
			return -1;
		}

		/* Add the unicode BOM mark */
		blob = data_blob_talloc(c, NULL, ucs2_blob.length + 2);
		if (blob.data == NULL) {
			d_printf("Failed to allocate blob: %s\n",
				 strerror(errno));
			return -1;
		}

		blob.data[0] = 0xff;
		blob.data[1] = 0xfe;

		memcpy(blob.data + 2, ucs2_blob.data, ucs2_blob.length);

		ok = file_save(savefile, blob.data, blob.length);
		if (!ok) {
			d_printf("Failed to save %s: %s\n", savefile,
					strerror(errno));
			return -1;
		}
	}

	d_printf("Successfully provisioned computer '%s' in domain '%s'\n",
			machine_name, domain);

	if (printblob) {
		printf("%s\n", provision_text_data);
	}

	return 0;
}

static int net_offlinejoin_requestodj_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin requestodj [misc. options]\n"
		   "\tRequests offline domain join\n"));
	d_printf(_("Valid options:\n"));
	d_printf(_("\t-i\t\t\t\t\tRead ODJ data from STDIN\n"));
	d_printf(_("\tloadfile=<FILENAME>\t\t\tFile that provides the ODJ data\n"));
	/*d_printf(_("\tlocalos\t\t\t\t\tModify the local machine\n"));*/
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin_requestodj(struct net_context *c,
			       int argc, const char **argv)
{
	NET_API_STATUS status;
	uint8_t *provision_bin_data = NULL;
	size_t provision_bin_data_size = 0;
	uint32_t options = NETSETUP_PROVISION_ONLINE_CALLER;
	const char *windows_path = NULL;
	int i;

	if (c->display_usage) {
		return net_offlinejoin_requestodj_usage(c, argc, argv);
	}

	/* process additional command line args */

	for (i = 0; i < argc; i++) {

		if (strnequal(argv[i], "loadfile", strlen("loadfile"))) {
			const char *loadfile = NULL;

			loadfile = get_string_param(argv[i]);
			if (loadfile == NULL) {
				return -1;
			}

			provision_bin_data =
				(uint8_t *)file_load(loadfile,
						     &provision_bin_data_size,
						     0,
						     c);
			if (provision_bin_data == NULL) {
				d_printf("Failed to read loadfile: %s\n",
				loadfile);
				return -1;
			}
		}
#if 0
		if (strnequal(argv[i], "localos", strlen("localos"))) {
			options |= NETSETUP_PROVISION_ONLINE_CALLER;
		}
#endif
	}

	if (c->opt_stdin) {
		if (isatty(STDIN_FILENO) == 1) {
			d_fprintf(stderr,
				  "hint: stdin waiting for ODJ blob, end "
				  "with <crtl-D>.\n");
		}
		provision_bin_data =
			(uint8_t *)fd_load(STDIN_FILENO,
					   &provision_bin_data_size, 0, c);
		if (provision_bin_data == NULL) {
			d_printf("Failed to read ODJ blob from stdin\n");
			return -1;
		}

		/* Strip last newline */
		if (provision_bin_data[provision_bin_data_size - 1] == '\n') {
			provision_bin_data[provision_bin_data_size - 1] = '\0';
		}
	}

	if (provision_bin_data == NULL || provision_bin_data_size == 0) {
		d_printf("Please provide provision data either from file "
			 "(using loadfile parameter) or from stdin (-i)\n");
		return -1;
	}
	if (provision_bin_data_size > UINT32_MAX) {
		d_printf("provision binary data size too big: %zu\n",
			 provision_bin_data_size);
		TALLOC_FREE(provision_bin_data);
		return -1;
	}

	status = NetRequestOfflineDomainJoin(provision_bin_data,
					     provision_bin_data_size,
					     options,
					     windows_path);
	if (status != 0 && status != 0x00000a99) {
		/* NERR_JoinPerformedMustRestart */
		printf("Failed to call NetRequestOfflineDomainJoin: %s\n",
			libnetapi_get_error_string(c->netapi_ctx, status));
		TALLOC_FREE(provision_bin_data);
		return -1;
	}

	d_printf("Successfully requested Offline Domain Join\n");

	TALLOC_FREE(provision_bin_data);

	return 0;
}

static int net_offlinejoin_composeodj_usage(struct net_context *c,
					    int argc,
					    const char **argv)
{
	d_printf(_("\nnet offlinejoin composeodj [misc. options]\n"
		   "\tComposes offline domain join blob\n"));
	d_printf(_("Valid options:\n"));
	d_printf(_("\tdomain_sid=<SID>\t\t\tThe domain SID\n"));
	d_printf(_("\tdomain_guid=<GUID>\t\t\tThe domain GUID\n"));
	d_printf(_("\tforest_name=<NAME>\t\t\tThe forest name\n"));
	d_printf(_("\tdomain_is_nt4\t\t\t\tThe domain not AD but NT4\n"));
	d_printf(_("\tsavefile=<FILENAME>\t\t\tFile to store the ODJ data\n"));
	d_printf(_("\tprintblob\t\t\t\tPrint the base64 encoded ODJ data on stdout\n"));
	net_common_flags_usage(c, argc, argv);
	d_printf(_("Example:\n"));
	d_printf("\tnet offlinejoin composeodj --realm=<realm> "
		 "--workgroup=<domain> domain_sid=<sid> domain_guid=<guid> "
		 "forest_name=<name> -S <dc name> -I <dc address> "
		 "--password=<password> printblob\n");
	return -1;
}

int net_offlinejoin_composeodj(struct net_context *c,
			       int argc,
			       const char **argv)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();
	NET_API_STATUS status;
	const char *dns_domain_name = NULL;
	const char *netbios_domain_name = NULL;
	const char *machine_account_name = NULL;
	const char *machine_account_password = NULL;
	const char *domain_sid_str = NULL;
	const char *domain_guid_str = NULL;
	struct dom_sid domain_sid;
	struct GUID domain_guid;
	const char *forest_name = NULL;
	const char *dc_name = NULL;
	char dc_address[INET6_ADDRSTRLEN] = { 0 };
	bool domain_is_ad = true;
	const char *provision_text_data = NULL;
	const char *savefile = NULL;
	bool printblob = false;
	enum credentials_obtained obtained;
	bool ok;
	NTSTATUS ntstatus;
	int i;

	if (c->display_usage || argc < 4) {
		return net_offlinejoin_composeodj_usage(c, argc, argv);
	}

	dns_domain_name = cli_credentials_get_realm(creds);
	netbios_domain_name = cli_credentials_get_domain(creds);

	machine_account_name = cli_credentials_get_username_and_obtained(creds, &obtained);
	if (obtained < CRED_CALLBACK_RESULT) {
		const char *netbios_name = cli_credentials_get_workstation(creds);
		cli_credentials_set_username(
			creds,
			talloc_asprintf(c, "%s$", netbios_name),
			CRED_SPECIFIED);
	}

	machine_account_name = cli_credentials_get_username(creds);
	machine_account_password = cli_credentials_get_password(creds);
	dc_name = c->opt_host;

	if (c->opt_have_ip) {
		struct sockaddr_in *in4 = NULL;
		struct sockaddr_in6 *in6 = NULL;
		const char *p = NULL;

		switch(c->opt_dest_ip.ss_family) {
		case AF_INET:
			in4 = (struct sockaddr_in *)&c->opt_dest_ip;
			p = inet_ntop(AF_INET, &in4->sin_addr, dc_address, sizeof(dc_address));
			break;
		case AF_INET6:
			in6 = (struct sockaddr_in6 *)&c->opt_dest_ip;
			p = inet_ntop(AF_INET6, &in6->sin6_addr, dc_address, sizeof(dc_address));
			break;
		default:
			d_printf("Unknown IP address family\n");
			return -1;
		}

		if (p == NULL) {
			d_fprintf(stderr, "Failed to parse IP address: %s\n", strerror(errno));
			return -1;
		}
	}

	/* process additional command line args */

	for (i = 0; i < argc; i++) {
		if (strnequal(argv[i], "domain_sid", strlen("domain_sid"))) {
			domain_sid_str = get_string_param(argv[i]);
			if (domain_sid_str == NULL) {
				return -1;
			}
		}

		if (strnequal(argv[i], "domain_guid", strlen("domain_guid"))) {
			domain_guid_str = get_string_param(argv[i]);
			if (domain_guid_str == NULL) {
				return -1;
			}
		}

		if (strnequal(argv[i], "forest_name", strlen("forest_name"))) {
			forest_name = get_string_param(argv[i]);
			if (forest_name == NULL) {
				return -1;
			}
		}

		if (strnequal(argv[i], "savefile", strlen("savefile"))) {
			savefile = get_string_param(argv[i]);
			if (savefile == NULL) {
				return -1;
			}
		}

		if (strnequal(argv[i], "printblob", strlen("printblob"))) {
			printblob = true;
		}

		if (strnequal(argv[i], "domain_is_nt4", strlen("domain_is_nt4"))) {
			domain_is_ad = false;
		}
	}

	/* Check command line arguments */

	if (savefile == NULL && !printblob) {
		d_printf("Choose either save the blob to a file or print it\n");
		return -1;
	}

	if (dns_domain_name == NULL) {
		d_printf("Please provide a valid realm parameter (--realm)\n");
		return -1;
	}

	if (netbios_domain_name == NULL) {
		d_printf("Please provide a valid domain parameter (--workgroup)\n");
		return -1;
	}

	if (dc_name == NULL) {
		d_printf("Please provide a valid DC name parameter (-S)\n");
		return -1;
	}

	if (strlen(dc_address) == 0) {
		d_printf("Please provide a valid domain controller address parameter (-I)\n");
		return -1;
	}

	if (machine_account_name == NULL) {
		d_printf("Please provide a valid netbios name parameter\n");
		return -1;
	}

	if (machine_account_password == NULL) {
		d_printf("Please provide a valid password parameter\n");
		return -1;
	}

	if (domain_sid_str == NULL) {
		d_printf("Please provide a valid <domain_sid> parameter\n");
		return -1;
	}

	if (domain_guid_str == NULL) {
		d_printf("Please provide a valid <domain_guid> parameter\n");
		return -1;
	}

	if (forest_name == NULL) {
		d_printf("Please provide a valid <forest_name> parameter\n");
		return -1;
	}

	ok = dom_sid_parse(domain_sid_str, &domain_sid);
	if (!ok) {
		d_fprintf(stderr, _("Failed to parse domain SID\n"));
		return -1;
	}

	ntstatus = GUID_from_string(domain_guid_str, &domain_guid);
	if (NT_STATUS_IS_ERR(ntstatus)) {
		d_fprintf(stderr, _("Failed to parse domain GUID\n"));
		return -1;
	}

	status = NetComposeOfflineDomainJoin(dns_domain_name,
					     netbios_domain_name,
					     (struct domsid *)&domain_sid,
					     &domain_guid,
					     forest_name,
					     machine_account_name,
					     machine_account_password,
					     dc_name,
					     dc_address,
					     domain_is_ad,
					     NULL,
					     0,
					     &provision_text_data);
	if (status != 0) {
		d_printf("Failed to compose offline domain join blob: %s\n",
			libnetapi_get_error_string(c->netapi_ctx, status));
		return status;
	}

	if (savefile != NULL) {
		DATA_BLOB ucs2_blob, blob;

		/*
		 * Windows produces and consumes UTF16/UCS2 encoded blobs
		 * so we also do it for compatibility. Someone may provision an
		 * account for a Windows machine with samba.
		 */
		ok = push_reg_sz(c, &ucs2_blob, provision_text_data);
		if (!ok) {
			return -1;
		}

		/* Add the unicode BOM mark */
		blob = data_blob_talloc(c, NULL, ucs2_blob.length + 2);
		if (blob.data == NULL) {
			d_printf("Failed to allocate blob: %s\n",
				 strerror(errno));
			return -1;
		}

		blob.data[0] = 0xff;
		blob.data[1] = 0xfe;

		memcpy(blob.data + 2, ucs2_blob.data, ucs2_blob.length);

		ok = file_save(savefile, blob.data, blob.length);
		if (!ok) {
			d_printf("Failed to save %s: %s\n", savefile,
					strerror(errno));
			return -1;
		}
	}

	if (printblob) {
		printf("%s\n", provision_text_data);
	}

	return 0;
}
