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

static fstring password;
static fstring username;
static BOOL showall = False;
static BOOL old_list = False;
static const char *maskchars = "<>\"?*abc.";
static const char *filechars = "abcdefghijklm.";
static int verbose;
static int die_on_error;
static int NumLoops = 0;

/* a test fn for LANMAN mask support */
static int ms_fnmatch_lanman_core(const char *pattern, const char *string)
{
	const char *p = pattern, *n = string;
	char c;

	if (strcmp(p,"?")==0 && strcmp(n,".")==0) goto match;

	while ((c = *p++)) {
		switch (c) {
		case '.':
			/* if (! *n && ! *p) goto match; */
			if (*n != '.') goto nomatch;
			n++;
			break;

		case '?':
			if ((*n == '.' && n[1] != '.') || ! *n) goto next;
			n++;
			break;

		case '>':
			if (n[0] == '.') {
				if (! n[1] && ms_fnmatch_lanman_core(p, n+1) == 0) goto match;
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
				goto nomatch;
			}
			if (! *n) goto next;
			n++;
			break;

		case '*':
			if (! *p) goto match;
			for (; *n; n++) {
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
			}
			break;

		case '<':
			for (; *n; n++) {
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
				if (*n == '.' && !strchr_m(n+1,'.')) {
					n++;
					break;
				}
			}
			break;

		case '"':
			if (*n == 0 && ms_fnmatch_lanman_core(p, n) == 0) goto match;
			if (*n != '.') goto nomatch;
			n++;
			break;

		default:
			if (c != *n) goto nomatch;
			n++;
		}
	}
	
	if (! *n) goto match;
	
 nomatch:
	if (verbose) printf("NOMATCH pattern=[%s] string=[%s]\n", pattern, string);
	return -1;

next:
	if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
        goto nomatch;

 match:
	if (verbose) printf("MATCH   pattern=[%s] string=[%s]\n", pattern, string);
	return 0;
}

static int ms_fnmatch_lanman(const char *pattern, const char *string)
{
	if (!strpbrk(pattern, "?*<>\"")) {
		if (strcmp(string,"..") == 0) 
			string = ".";

		return strcmp(pattern, string);
	}

	if (strcmp(string,"..") == 0 || strcmp(string,".") == 0) {
		return ms_fnmatch_lanman_core(pattern, "..") &&
			ms_fnmatch_lanman_core(pattern, ".");
	}

	return ms_fnmatch_lanman_core(pattern, string);
}

static BOOL reg_match_one(struct smbcli_state *cli, const char *pattern, const char *file)
{
	/* oh what a weird world this is */
	if (old_list && strcmp(pattern, "*.*") == 0) return True;

	if (strcmp(pattern,".") == 0) return False;

	if (cli->transport->negotiate.protocol <= PROTOCOL_LANMAN1) {
		return ms_fnmatch_lanman(pattern, file)==0;
	}

	if (strcmp(file,"..") == 0) file = ".";

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
	uint_t flags = 0;
	NTSTATUS status;

	fstrcpy(server,share+2);
	share = strchr_m(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	status = smbcli_full_connection(&c, "masktest",
				     server, NULL, 
				     share, "?????", 
				     username, lp_workgroup(), 
				     password, flags, NULL);

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

static void listfn(file_info *f, const char *s, void *state)
{
	if (strcmp(f->name,".") == 0) {
		resultp[0] = '+';
	} else if (strcmp(f->name,"..") == 0) {
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
	smbcli_list(cli->tree, mask, 
		 FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY, 
		 listfn, NULL);

	res2 = reg_test(cli, mask, long_name, short_name);

	if (showall || strcmp(res1, res2)) {
		d_printf("%s %s %d mask=[%s] file=[%s] rfile=[%s/%s]\n",
			 res1, res2, count, mask, file, long_name, short_name);
		if (die_on_error) exit(1);
	}

	smbcli_unlink(cli->tree, file);

	if (count % 100 == 0) DEBUG(0,("%d\n", count));
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
		l1 = 1 + random() % 20;
		l2 = 1 + random() % 20;
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

		if (strcmp(file+l,".") == 0 || 
		    strcmp(file+l,"..") == 0 ||
		    strcmp(mask+l,"..") == 0) continue;

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
	char *p;
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

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();

	if (getenv("USER")) {
		fstrcpy(username,getenv("USER"));
	}

	seed = time(NULL);

	while ((opt = getopt(argc, argv, "n:d:U:s:hm:f:aoW:M:vE")) != EOF) {
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
			fstrcpy(username,optarg);
			p = strchr_m(username,'%');
			if (p) {
				*p = 0;
				fstrcpy(password, p+1);
			}
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
