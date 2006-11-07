/* 
   Unix SMB/CIFS implementation.
   mask_match tester
   Copyright (C) Andrew Tridgell 1999
   
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
#include "system/filesys.h"
#include "system/dir.h"
#include "libcli/libcli.h"
#include "libcli/raw/libcliraw.h"
#include "system/time.h"
#include "pstring.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

static struct cli_credentials *credentials;
static BOOL showall = False;
static BOOL old_list = False;
static const char *maskchars = "<>\"?*abc.";
static const char *filechars = "abcdefghijklm.";
static int verbose;
static int die_on_error;
static int NumLoops = 0;
static int max_length = 20;

static BOOL reg_match_one(struct smbcli_state *cli, const char *pattern, const char *file)
{
	/* oh what a weird world this is */
	if (old_list && strcmp(pattern, "*.*") == 0) return True;

	if (ISDOT(pattern)) return False;

	if (ISDOTDOT(file)) file = ".";

	return ms_fnmatch(pattern, file, cli->transport->negotiate.protocol)==0;
}

static char *reg_test(struct smbcli_state *cli, char *pattern, char *long_name, char *short_name)
{
	static fstring ret;
	fstrcpy(ret, "---");

	pattern = 1+strrchr_m(pattern,'\\');

	if (reg_match_one(cli, pattern, ".")) ret[0] = '+';
	if (reg_match_one(cli, pattern, "..")) ret[1] = '+';
	if (reg_match_one(cli, pattern, long_name) || 
	    (*short_name && reg_match_one(cli, pattern, short_name))) ret[2] = '+';
	return ret;
}


/***************************************************** 
return a connection to a server
*******************************************************/
static struct smbcli_state *connect_one(char *share)
{
	struct smbcli_state *c;
	fstring server;
	NTSTATUS status;

	fstrcpy(server,share+2);
	share = strchr_m(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	cli_credentials_set_workstation(credentials, "masktest", CRED_SPECIFIED);

	status = smbcli_full_connection(NULL, &c,
					server, 
					share, NULL,
					credentials, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	return c;
}

static char *resultp;
static struct {
	pstring long_name;
	pstring short_name;
} last_hit;
static BOOL f_info_hit;

static void listfn(struct clilist_file_info *f, const char *s, void *state)
{
	if (ISDOT(f->name)) {
		resultp[0] = '+';
	} else if (ISDOTDOT(f->name)) {
		resultp[1] = '+';		
	} else {
		resultp[2] = '+';
	}
	pstrcpy(last_hit.long_name, f->name);
	pstrcpy(last_hit.short_name, f->short_name);
	f_info_hit = True;
}

static void get_real_name(struct smbcli_state *cli, 
			  pstring long_name, fstring short_name)
{
	const char *mask;
	if (cli->transport->negotiate.protocol <= PROTOCOL_LANMAN1) {
		mask = "\\masktest\\*.*";
	} else {
		mask = "\\masktest\\*";
	}

	f_info_hit = False;

	smbcli_list_new(cli->tree, mask, 
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY, 
			RAW_SEARCH_DATA_BOTH_DIRECTORY_INFO,
			listfn, NULL);

	if (f_info_hit) {
		fstrcpy(short_name, last_hit.short_name);
		strlower(short_name);
		pstrcpy(long_name, last_hit.long_name);
		strlower(long_name);
	}

	if (*short_name == 0) {
		fstrcpy(short_name, long_name);
	}
}

static void testpair(struct smbcli_state *cli, char *mask, char *file)
{
	int fnum;
	fstring res1;
	char *res2;
	static int count;
	fstring short_name;
	pstring long_name;

	count++;

	fstrcpy(res1, "---");

	fnum = smbcli_open(cli->tree, file, O_CREAT|O_TRUNC|O_RDWR, 0);
	if (fnum == -1) {
		DEBUG(0,("Can't create %s\n", file));
		return;
	}
	smbcli_close(cli->tree, fnum);

	resultp = res1;
	fstrcpy(short_name, "");
	get_real_name(cli, long_name, short_name);
	fstrcpy(res1, "---");
	smbcli_list_new(cli->tree, mask, 
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY, 
			RAW_SEARCH_DATA_BOTH_DIRECTORY_INFO,
			listfn, NULL);

	res2 = reg_test(cli, mask, long_name, short_name);

	if (showall || strcmp(res1, res2)) {
		d_printf("%s %s %d mask=[%s] file=[%s] rfile=[%s/%s]\n",
			 res1, res2, count, mask, file, long_name, short_name);
		if (die_on_error) exit(1);
	}

	smbcli_unlink(cli->tree, file);

	if (count % 100 == 0) DEBUG(0,("%d\n", count));

	resultp = NULL;
}

static void test_mask(int argc, char *argv[], 
		      struct smbcli_state *cli)
{
	pstring mask, file;
	int l1, l2, i, l;
	int mc_len = strlen(maskchars);
	int fc_len = strlen(filechars);

	smbcli_mkdir(cli->tree, "\\masktest");

	smbcli_unlink(cli->tree, "\\masktest\\*");

	if (argc >= 2) {
		while (argc >= 2) {
			pstrcpy(mask,"\\masktest\\");
			pstrcpy(file,"\\masktest\\");
			pstrcat(mask, argv[0]);
			pstrcat(file, argv[1]);
			testpair(cli, mask, file);
			argv += 2;
			argc -= 2;
		}
		goto finished;
	}

	while (1) {
		l1 = 1 + random() % max_length;
		l2 = 1 + random() % max_length;
		pstrcpy(mask,"\\masktest\\");
		pstrcpy(file,"\\masktest\\");
		l = strlen(mask);
		for (i=0;i<l1;i++) {
			mask[i+l] = maskchars[random() % mc_len];
		}
		mask[l+l1] = 0;

		for (i=0;i<l2;i++) {
			file[i+l] = filechars[random() % fc_len];
		}
		file[l+l2] = 0;

		if (ISDOT(file+l) || ISDOTDOT(file+l) || ISDOTDOT(mask+l)) {
			continue;
		}

		if (strspn(file+l, ".") == strlen(file+l)) continue;

		testpair(cli, mask, file);
		if (NumLoops && (--NumLoops == 0))
			break;
	}

 finished:
	smbcli_rmdir(cli->tree, "\\masktest");
}


static void usage(void)
{
	printf(
"Usage:\n\
  masktest //server/share [options..]\n\
  options:\n\
	-d debuglevel\n\
	-n numloops\n\
        -W workgroup\n\
        -U user%%pass\n\
        -s seed\n\
        -l max test length\n\
        -M max protocol\n\
        -f filechars (default %s)\n\
        -m maskchars (default %s)\n\
	-v                             verbose mode\n\
	-E                             die on error\n\
        -a                             show all tests\n\
\n\
  This program tests wildcard matching between two servers. It generates\n\
  random pairs of filenames/masks and tests that they match in the same\n\
  way on the servers and internally\n\
", 
  filechars, maskchars);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *share;
	struct smbcli_state *cli;	
	int opt;
	int seed;

	setlinebuf(stdout);

	setup_logging("masktest", DEBUG_STDOUT);

	lp_set_cmdline("log level", "0");

	if (argc < 2 || argv[1][0] == '-') {
		usage();
		exit(1);
	}

	share = argv[1];

	all_string_sub(share,"/","\\",0);

	setup_logging(argv[0], DEBUG_STDOUT);

	argc -= 1;
	argv += 1;

	lp_load();

	credentials = cli_credentials_init(talloc_autofree_context());
	cli_credentials_guess(credentials);

	seed = time(NULL);

	init_iconv();

	while ((opt = getopt(argc, argv, "n:d:U:s:hm:f:aoW:M:vEl:")) != EOF) {
		switch (opt) {
		case 'n':
			NumLoops = atoi(optarg);
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'E':
			die_on_error = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'M':
			lp_set_cmdline("max protocol", optarg);
			break;
		case 'U':
			cli_credentials_parse_string(credentials, optarg, CRED_SPECIFIED);
			break;
		case 's':
			seed = atoi(optarg);
			break;
		case 'h':
			usage();
			exit(1);
		case 'm':
			maskchars = optarg;
			break;
		case 'l':
			max_length = atoi(optarg);
			break;
		case 'f':
			filechars = optarg;
			break;
		case 'a':
			showall = 1;
			break;
		case 'o':
			old_list = True;
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	gensec_init();

	argc -= optind;
	argv += optind;

	cli = connect_one(share);
	if (!cli) {
		DEBUG(0,("Failed to connect to %s\n", share));
		exit(1);
	}

	/* need to init seed after connect as clientgen uses random numbers */
	DEBUG(0,("seed=%d     format --- --- (server, correct)\n", seed));
	srandom(seed);

	test_mask(argc, argv, cli);

	return(0);
}
