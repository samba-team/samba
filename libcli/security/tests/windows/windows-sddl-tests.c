/*
 * Test Windows SDDL handling.
 *
 * Copyright (c) 2023 Douglas Bagnall <dbagnall@samba.org>
 *
 * GPLv3+.
 *
 * This can be compiled on Windows under Cygwin, like this:
 *
 *
 * gcc -o windows-sddl-tests  windows-sddl-tests.c \
 *	      C:/Windows/System32/advapi32.dll	-ladvapi32
 *
 *
 * then run like this:
 *
 * ./windows-sddl-tests.exe
 *
 *
 * That will show you a mix of success and failure.
 *
 * To run the tests in python/samba/tests/sddl.py, edit the method
 * _test_write_test_strings(), removing the leading underscore so it starts
 * with "test_". Then running
 *
 * make test TESTS='sddl\\b'
 *
 * will write some files into /tmp, containing lines like this:
 *
 * D:(A;;GA;;;RU) -> D:(A;;GA;;;RU)
 *
 * Copy these files to Windows. Then in Cygwin, run this:
 *
 * ./windows-sddl-tests.exe -i non_canonical.txt canonical.txt [...]
 *
 * and the part of each line before the " -> " will be fed into the SDDL
 * parser, and back through the serialiser, which should result in the string
 * after the " -> ". These are the tests that sddl.py does.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <windows.h>
#include <sddl.h>

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define AMBER "\033[33m"
#define CYAN "\033[1;36m"
#define C_NORMAL "\033[0m"

/*
 * Note that the SIDs SA, CA, RS, EA, PA, RO, and CN cannot be set by
 * an ordinary local Administrator (error 1337, invalid SID). For this
 * reason we use other SIDs instead/as well, so the list differs from
 * the python/samba/tests/sddl.py list, which it is otherwise based on.
 */
const char *strings[] = {
	"D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)",

	"D:(A;;GA;;;RU)",

	"D:(A;;GA;;;LG)",

	("D:(A;;RP;;;WD)"
	 "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
	 "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
	 "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)"
	 "(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
	 "(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
	 "(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
	 "(A;;RPLCLORC;;;AU)"
	 "(A;;RPWPCRLCLOCCRCWDWOSW;;;BO)"
	 "(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)"
	 "(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
	 "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;ES)"
	 "(A;CI;LC;;;RU)"
	 "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)"
	 "(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)"
	 "(A;;RPRC;;;RU)"
	 "(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)"
	 "(A;;LCRPLORC;;;ED)"
	 "(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)"
	 "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)"
	 "(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)"
	 "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)"
	 "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)"
	 "(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)"
	 "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;NO)"
	 "(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)"
	 "(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;SU)"
	 "(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)"
	 "(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)"
	 "(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)"),

	("S:(AU;SA;CR;;;WD)"
	 "(AU;SA;CR;;;WD)"),

	("S:""(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
	 "(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"),

	("D:(A;;RPLCLORC;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPCRLCLORCSDDT;;;CO)"
	 "(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)"
	 "(A;;RPLCLORC;;;AU)"
	 "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
	 "(A;;CCDC;;;PS)"
	 "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
	 "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
	 "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)"
	 "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
	 "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)"
	 "(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)"
	 "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
	 "(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
	 "(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
	 "(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
	 "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"
	 "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
	 "(A;;RPLCLORC;;;PS)"
	 "(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
	 "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)"
	 "(A;;RPLCLORC;;;PS)"
	 "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)"
	 "(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)"
	 "(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)"
	 "(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)"
	 "(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)"
	 "(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)"
	 "(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RD)"
	 "(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RD)"
	 "(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RD)"
	 "(A;;RC;;;AU)"
	 "(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)"
	 "(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)"
	 "(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)"
	 "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
	 "(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
	 "(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RD)"
	 "(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;SY)"
	 "(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;SU)"
	 "(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;SU)"),

	"D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"
	 "(A;;LCRPLORC;;;ED)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)"
	 "(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)"
	 "(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)"
	 "(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)"
	 "(A;;RPLCLORC;;;AU)"
	 "(A;;LCRPLORC;;;ED)"
	 "(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"),

	("D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"),

	("D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;BO)"
	 "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
	 "(A;;RPLCLORC;;;AU)"),

	"D:S:",
	"D:PS:",
	NULL
};


static int test_pair(const char *s, const char *canonical)
{
	PSECURITY_DESCRIPTOR sd = NULL;
	ULONG len;
	char *return_string = NULL;
	ULONG return_len;
	int ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(s,
								      1,
								      &sd,
								      &len);
	if (!ok) {
		int e = GetLastError();
		const char *ename = NULL;
		switch(e) {
		case 1337:
			ename = " invalid sid";
			break;
		case 1336:
			ename = " insufficient privs/SACL vs DACL/something something";
			break;
		case 1804:
			ename = " invalid datatype";
			break;
		default:
			ename = "";
		}

		printf(RED "not ok:" AMBER " %d%s" C_NORMAL ": %s\n",
		       e, ename, s);
		return e;
	}
	if (sd == NULL) {
		printf(RED "NULL sd" C_NORMAL": %s\n", s);
		return -1;
	}

	ok = ConvertSecurityDescriptorToStringSecurityDescriptorA(
		sd,
		1,
		~BACKUP_SECURITY_INFORMATION,
		&return_string,
		&return_len);
	if (strncmp(return_string, canonical, return_len) != 0) {
		printf(RED "return differs:" AMBER " %u vs %u" C_NORMAL "\n",
		       len, return_len);
		printf(RED "original:" C_NORMAL ": %s\n", s);
		printf(RED "returned:" C_NORMAL ": %s\n", return_string);
		return -2;
	}
	printf(GREEN "GOOD" C_NORMAL ": %s\n", s);
	if (strncmp(return_string, s, return_len) != 0) {
		printf(CYAN "original:" C_NORMAL ": %s\n", s);
		printf(CYAN "returned:" C_NORMAL ": %s\n", return_string);
		return -2;
	}
	return 0;
}


int test_from_files(int argc, const char *argv[])
{
	size_t i, j;
	static char buf[100000];

	for (i = 0; i < argc; i++) {
		char *orig = NULL;
		char *canon = NULL;
		size_t len;
		FILE *f = fopen(argv[i], "r");
		if (f == NULL) {
			printf(RED "bad filename? %s\n" C_NORMAL,
			       argv[i]);
		}
		len = fread(buf, 1, sizeof(buf), f);

		if (len >= sizeof(buf) - 1 || len == 0) {
			printf(RED "couldn't read %s\n" C_NORMAL, argv[i]);
			continue;
		}
		printf(CYAN "%s\n" C_NORMAL, argv[i]);
		buf[len] = 0;
		orig = buf;
		for (j = 0; j < len; j++) {
			char c = buf[j];
			if (c == '\n') {
				buf[j] = 0;
				if (j != 0 && buf[j - 1] == '\r') {
					buf[j - 1] = 0;
				}
				if (orig && canon) {
					test_pair(orig, canon);
					canon = NULL;
				} else {
					printf(RED "bad pair %s -> %s\n" C_NORMAL,
					       orig, canon);
				}
				orig = buf + j + 1;
			} else if (c == ' ' && j + 4 < len &&
				   buf[j + 1] == '-' &&
				   buf[j + 2] == '>' &&
				   buf[j + 3] == ' ') {
				buf[j] = 0;
				canon = buf + j + 4;
			}
		}
	}
}

int main(int argc, const char *argv[])
{
	uint32_t i;
	if (argc < 2) {
		for (i = 0; strings[i] != NULL; i++) {
			test_pair(strings[i], strings[i]);
		}
	} else if (strncmp("-i", argv[1], 2) == 0) {
		return test_from_files(argc - 2, argv + 2);
	} else {
		for (i = 1; i < argc; i++) {
			test_pair(argv[i], argv[i]);
		}
	}
	return 0;
}
