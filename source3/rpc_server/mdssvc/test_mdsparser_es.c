/*
 *  Unix SMB/CIFS implementation.
 *  Copyright (C) Ralph Boehme 2019
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include <setjmp.h>
#include <cmocka.h>
#include <jansson.h>
#include <talloc.h>
#include "popt.h"
#include "popt_common_cmdline.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/samba_util.h"
#include "lib/torture/torture.h"
#include "lib/param/param.h"
#include "rpc_server/mdssvc/es_parser.tab.h"

#define PATH_QUERY_SUBEXPR \
	" AND path.real.fulltext:\\\"/foo/bar\\\""

static struct {
	const char *mds;
	const char *es;
} map[] = {
	{
		"*==\"samba\"",
		"(samba)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemTextContent==\"samba\"",
		"(content:samba)" PATH_QUERY_SUBEXPR
	}, {
		"_kMDItemGroupId==\"11\"",
		"(file.content_type:(application\\\\/pdf))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemContentType==\"1\"",
		"(file.content_type:(message\\\\/rfc822))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemContentType==\"public.content\"",
		"(file.content_type:(message\\\\/rfc822 application\\\\/pdf application\\\\/vnd.oasis.opendocument.presentation image\\\\/* text\\\\/*))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemContentTypeTree==\"1\"",
		"(file.content_type:(message\\\\/rfc822))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSContentChangeDate==$time.iso(2018-10-01T10:00:00Z)",
		"(file.last_modified:2018\\\\-10\\\\-01T10\\\\:00\\\\:00Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSContentChangeDate==\"1\"",
		"(file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSCreationDate==\"1\"",
		"(file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSName==\"samba*\"",
		"(file.filename:samba*)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSOwnerGroupID==\"0\"",
		"(attributes.owner:0)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSOwnerUserID==\"0\"",
		"(attributes.group:0)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSSize==\"1\"",
		"(file.filesize:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemPath==\"/foo/bar\"",
		"(path.real:\\\\/foo\\\\/bar)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemAttributeChangeDate==\"1\"",
		"(file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemAuthors==\"Chouka\"",
		"(meta.author:Chouka)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemContentCreationDate==\"1\"",
		"(file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemContentModificationDate==\"1\"",
		"(file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemCreator==\"Chouka\"",
		"(meta.raw.creator:Chouka)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemDescription==\"Dog\"",
		"(meta.raw.description:Dog)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemDisplayName==\"Samba\"",
		"(file.filename:Samba)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemDurationSeconds==\"1\"",
		"(meta.raw.xmpDM\\\\:duration:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemNumberOfPages==\"1\"",
		"(meta.raw.xmpTPg\\\\:NPages:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemTitle==\"Samba\"",
		"(meta.title:Samba)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemAlbum==\"Red Roses for Me\"",
		"(meta.raw.xmpDM\\\\:album:Red\\\\ Roses\\\\ for\\\\ Me)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemBitsPerSample==\"1\"",
		"(meta.raw.tiff\\\\:BitsPerSample:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemPixelHeight==\"1\"",
		"(meta.raw.Image\\\\ Height:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemPixelWidth==\"1\"",
		"(meta.raw.Image\\\\ Width:1)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemResolutionHeightDPI==\"72\"",
		"(meta.raw.Y\\\\ Resolution:72)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemResolutionWidthDPI==\"72\"",
		"(meta.raw.X\\\\ Resolution:72)" PATH_QUERY_SUBEXPR
	},{
		"*!=\"samba\"",
		"((NOT samba))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSSize!=\"1\"",
		"((NOT file.filesize:1))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSSize>\"1\"",
		"(file.filesize:{1 TO *})" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSSize<\"1\"",
		"(file.filesize:{* TO 1})" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSCreationDate!=\"1\"",
		"((NOT file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z))" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSCreationDate>\"1\"",
		"(file.created:{2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z TO *})" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSCreationDate<\"1\"",
		"(file.created:{* TO 2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z})" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSName==\"Samba\"||kMDItemTextContent==\"Samba\"",
		"(file.filename:Samba OR content:Samba)" PATH_QUERY_SUBEXPR
	}, {
		"kMDItemFSName==\"Samba\"&&kMDItemTextContent==\"Samba\"",
		"((file.filename:Samba) AND (content:Samba))" PATH_QUERY_SUBEXPR
	}, {
		"InRange(kMDItemFSCreationDate,1,2)",
		"(file.created:[2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z TO 2001\\\\-01\\\\-01T00\\\\:00\\\\:02Z])" PATH_QUERY_SUBEXPR
	}, {
		"InRange(kMDItemFSSize,1,2)",
		"(file.filesize:[1 TO 2])" PATH_QUERY_SUBEXPR
	}
};

static void test_mdsparser_es(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *path_scope = "/foo/bar";
	char *es_query = NULL;
	const char *path = NULL;
	json_t *mappings = NULL;
	json_error_t json_error;
	int i;
	bool ok;

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "mappings",
				    NULL);
	assert_non_null(path);

	mappings = json_load_file(path, 0, &json_error);
	assert_non_null(mappings);

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		DBG_DEBUG("Mapping: %s\n", map[i].mds);
		ok = map_spotlight_to_es_query(frame,
					       mappings,
					       path_scope,
					       map[i].mds,
					       &es_query);
		assert_true(ok);
		assert_string_equal(es_query, map[i].es);
	}

	json_decref(mappings);
	TALLOC_FREE(frame);
}

int main(int argc, const char *argv[])
{
	const char **argv_const = discard_const_p(const char *, argv);
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_mdsparser_es),
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	poptContext pc;
	int opt;

	smb_init_locale();
	setup_logging(argv[0], DEBUG_STDERR);
	lp_set_cmdline("log level", "1");

	pc = poptGetContext(argv[0], argc, argv_const, long_options, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		    default:
			    fprintf(stderr, "Unknown Option: %c\n", opt);
			    exit(1);
		}
	}

	lp_load_global(get_dyn_CONFIGFILE());

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
