/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldbedit
 *
 *  Description: utility for ldb database editing
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

/*
  modify a database record so msg1 becomes msg2
  returns the number of modified elements
*/
static int modify_record(struct ldb_context *ldb, 
			 struct ldb_message *msg1,
			 struct ldb_message *msg2)
{
	struct ldb_message mod;
	struct ldb_message_element *el;
	int i;
	int count = 0;

	mod.dn = msg1->dn;
	mod.num_elements = 0;
	mod.elements = NULL;

	/* look in msg2 to find elements that need to be added
	   or modified */
	for (i=0;i<msg2->num_elements;i++) {
		el = ldb_msg_find_element(msg1, msg2->elements[i].name);

		if (el && ldb_msg_element_compare(el, &msg2->elements[i]) == 0) {
			continue;
		}

		if (ldb_msg_add(ldb, &mod, 
				&msg2->elements[i],
				el?LDB_FLAG_MOD_REPLACE:LDB_FLAG_MOD_ADD) != 0) {
			return -1;
		}
		count++;
	}

	/* look in msg1 to find elements that need to be deleted */
	for (i=0;i<msg1->num_elements;i++) {
		el = ldb_msg_find_element(msg2, msg1->elements[i].name);
		if (!el) {
			if (ldb_msg_add_empty(ldb, &mod, 
					      msg1->elements[i].name,
					      LDB_FLAG_MOD_DELETE) != 0) {
				return -1;
			}
			count++;
		}
	}

	if (mod.num_elements == 0) {
		return 0;
	}

	if (ldb_modify(ldb, &mod) != 0) {
		fprintf(stderr, "failed to modify %s - %s\n", 
			msg1->dn, ldb_errstring(ldb));
		return -1;
	}

	return count;
}

/*
  find dn in msgs[]
*/
static struct ldb_message *msg_find(struct ldb_message **msgs, int count,
				    const char *dn)
{
	int i;
	for (i=0;i<count;i++) {
		if (ldb_dn_cmp(dn, msgs[i]->dn) == 0) {
			return msgs[i];
		}
	}
	return NULL;
}

/*
  merge the changes in msgs2 into the messages from msgs1
*/
static int merge_edits(struct ldb_context *ldb,
		       struct ldb_message **msgs1, int count1,
		       struct ldb_message **msgs2, int count2)
{
	int i;
	struct ldb_message *msg;
	int ret = 0;
	int adds=0, modifies=0, deletes=0;

	/* do the adds and modifies */
	for (i=0;i<count2;i++) {
		msg = msg_find(msgs1, count1, msgs2[i]->dn);
		if (!msg) {
			if (ldb_add(ldb, msgs2[i]) != 0) {
				fprintf(stderr, "failed to add %s - %s\n",
					msgs2[i]->dn, ldb_errstring(ldb));
				return -1;
			}
			adds++;
		} else {
			if (modify_record(ldb, msg, msgs2[i]) > 0) {
				modifies++;
			}
		}
	}

	/* do the deletes */
	for (i=0;i<count1;i++) {
		msg = msg_find(msgs2, count2, msgs1[i]->dn);
		if (!msg) {
			if (ldb_delete(ldb, msgs1[i]->dn) != 0) {
				fprintf(stderr, "failed to delete %s - %s\n",
					msgs1[i]->dn, ldb_errstring(ldb));
				return -1;
			}
			deletes++;
		}
	}

	printf("# %d adds  %d modifies  %d deletes\n", adds, modifies, deletes);

	return ret;
}

/*
  save a set of messages as ldif to a file
*/
static int save_ldif(struct ldb_context *ldb, 
		     FILE *f, struct ldb_message **msgs, int count)
{
	int i;

	fprintf(f, "# editing %d records\n", count);

	for (i=0;i<count;i++) {
		struct ldb_ldif ldif;
		fprintf(f, "# record %d\n", i+1);

		ldif.changetype = LDB_CHANGETYPE_NONE;
		ldif.msg = *msgs[i];

		ldif_write_file(ldb, f, &ldif);
	}

	return 0;
}


/*
  edit the ldb search results in msgs using the user selected editor
*/
static int do_edit(struct ldb_context *ldb, struct ldb_message **msgs1, int count1,
		   const char *editor)
{
	int fd, ret;
	FILE *f;
	char template[] = "/tmp/ldbedit.XXXXXX";
	char *cmd;
	struct ldb_ldif *ldif;
	struct ldb_message **msgs2 = NULL;
	int count2 = 0;

	/* write out the original set of messages to a temporary
	   file */
	fd = mkstemp(template);

	if (fd == -1) {
		perror(template);
		return -1;
	}

	f = fdopen(fd, "r+");

	if (!f) {
		perror("fopen");
		close(fd);
		unlink(template);
		return -1;
	}

	if (save_ldif(ldb, f, msgs1, count1) != 0) {
		return -1;
	}

	fclose(f);

	ldb_asprintf(ldb, &cmd, "%s %s", editor, template);

	if (!cmd) {
		unlink(template);
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	/* run the editor */
	ret = system(cmd);
	free(cmd);

	if (ret != 0) {
		unlink(template);
		fprintf(stderr, "edit with %s failed\n", editor);
		return -1;
	}

	/* read the resulting ldif into msgs2 */
	f = fopen(template, "r");
	if (!f) {
		perror(template);
		return -1;
	}

	while ((ldif = ldif_read_file(ldb, f))) {
		msgs2 = ldb_realloc_p(ldb, msgs2, struct ldb_message *, count2+1);
		if (!msgs2) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		msgs2[count2++] = &ldif->msg;
	}

	fclose(f);
	unlink(template);

	return merge_edits(ldb, msgs1, count1, msgs2, count2);
}

static void usage(void)
{
	printf("Usage: ldbedit <options> <expression>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("  -s base|sub|one  choose search scope\n");
	printf("  -b basedn        choose baseDN\n");
	printf("  -a               edit all records (expression 'objectclass=*')\n");
	printf("  -e editor        choose editor (or $VISUAL or $EDITOR)\n");
	exit(1);
}

 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	struct ldb_message **msgs;
	int ret;
	const char *expression = NULL;
	const char *ldb_url;
	const char *basedn = NULL;
	int opt;
	enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	const char *editor;

	ldb_url = getenv("LDB_URL");

	/* build the editor command to run -
	   use the same editor priorities as vipw */
	editor = getenv("VISUAL");
	if (!editor) {
		editor = getenv("EDITOR");
	}
	if (!editor) {
		editor = "vi";
	}

	while ((opt = getopt(argc, argv, "hab:e:H:s:")) != EOF) {
		switch (opt) {
		case 'b':
			basedn = optarg;
			break;

		case 'H':
			ldb_url = optarg;
			break;

		case 's':
			if (strcmp(optarg, "base") == 0) {
				scope = LDB_SCOPE_BASE;
			} else if (strcmp(optarg, "sub") == 0) {
				scope = LDB_SCOPE_SUBTREE;
			} else if (strcmp(optarg, "one") == 0) {
				scope = LDB_SCOPE_ONELEVEL;
			}
			break;

		case 'e':
			editor = optarg;
			break;

		case 'a':
			expression = "(|(objectclass=*)(dn=*))";
			break;
			
		case 'h':
		default:
			usage();
			break;
		}
	}

	if (!ldb_url) {
		fprintf(stderr, "You must specify a ldb URL\n\n");
		usage();
	}

	argc -= optind;
	argv += optind;

	if (!expression) {
		if (argc == 0) {
			usage();
		}
		expression = argv[0];
	}

	ldb = ldb_connect(ldb_url, 0, NULL);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ldb_set_debug_stderr(ldb);

	ret = ldb_search(ldb, basedn, scope, expression, NULL, &msgs);

	if (ret == -1) {
		printf("search failed - %s\n", ldb_errstring(ldb));
		exit(1);
	}

	if (ret == 0) {
		printf("no matching records - cannot edit\n");
		return 0;
	}

	do_edit(ldb, msgs, ret, editor);

	if (ret > 0) {
		ret = ldb_search_free(ldb, msgs);
		if (ret == -1) {
			fprintf(stderr, "search_free failed - %s\n", ldb_errstring(ldb));
			exit(1);
		}
	}

	ldb_close(ldb);
	return 0;
}
