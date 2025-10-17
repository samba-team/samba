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
#include "lib/cmdline/cmdline.h"
#include "libcli/util/ntstatus.h"
#include "lib/util/samba_util.h"
#include "lib/torture/torture.h"
#include "lib/param/param.h"
#include "rpc_server/mdssvc/es_parser.tab.h"

static struct {
	const char *mds;
	const char *es;
} map[] = {
	{
		"*==\"samba\"",
		"samba"
	}, {
		"kMDItemTextContent==\"samba\"",
		"content:samba"
	}, {
		"_kMDItemGroupId==\"11\"",
		"file.content_type:(application\\\\/pdf)"
	}, {
		"kMDItemContentType==\"1\"",
		"file.content_type:(message\\\\/rfc822)"
	}, {
		"kMDItemContentType==\"public.content\"",
		"file.content_type:(message\\\\/rfc822 application\\\\/pdf application\\\\/vnd.oasis.opendocument.presentation image\\\\/* text\\\\/*)"
	}, {
		"kMDItemContentTypeTree==\"1\"",
		"file.content_type:(message\\\\/rfc822)"
	}, {
		"kMDItemFSContentChangeDate==$time.iso(2018-10-01T10:00:00Z)",
		"file.last_modified:2018\\\\-10\\\\-01T10\\\\:00\\\\:00Z"
	}, {
		"kMDItemFSContentChangeDate==\"1\"",
		"file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z"
	}, {
		"kMDItemFSCreationDate==\"1\"",
		"file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z"
	}, {
		"kMDItemFSName==\"samba*\"",
		"file.filename:samba*"
	}, {
		"kMDItemFSOwnerGroupID==\"0\"",
		"attributes.owner:0"
	}, {
		"kMDItemFSOwnerUserID==\"0\"",
		"attributes.group:0"
	}, {
		"kMDItemFSSize==\"1\"",
		"file.filesize:1"
	}, {
		"kMDItemPath==\"/foo/bar\"",
		"path.real:\\\\/foo\\\\/bar"
	}, {
		"kMDItemAttributeChangeDate==\"1\"",
		"file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z"
	}, {
		"kMDItemAuthors==\"Chouka\"",
		"meta.author:Chouka"
	}, {
		"kMDItemContentCreationDate==\"1\"",
		"file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z"
	}, {
		"kMDItemContentModificationDate==\"1\"",
		"file.last_modified:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z"
	}, {
		"kMDItemCreator==\"Chouka\"",
		"meta.raw.creator:Chouka"
	}, {
		"kMDItemDescription==\"Dog\"",
		"meta.raw.description:Dog"
	}, {
		"kMDItemDisplayName==\"Samba\"",
		"file.filename:Samba"
	}, {
		"kMDItemDurationSeconds==\"1\"",
		"meta.raw.xmpDM\\\\:duration:1"
	}, {
		"kMDItemNumberOfPages==\"1\"",
		"meta.raw.xmpTPg\\\\:NPages:1"
	}, {
		"kMDItemTitle==\"Samba\"",
		"meta.title:Samba"
	}, {
		"kMDItemAlbum==\"Red Roses for Me\"",
		"meta.raw.xmpDM\\\\:album:Red\\\\ Roses\\\\ for\\\\ Me"
	}, {
		"kMDItemBitsPerSample==\"1\"",
		"meta.raw.tiff\\\\:BitsPerSample:1"
	}, {
		"kMDItemPixelHeight==\"1\"",
		"meta.raw.Image\\\\ Height:1"
	}, {
		"kMDItemPixelWidth==\"1\"",
		"meta.raw.Image\\\\ Width:1"
	}, {
		"kMDItemResolutionHeightDPI==\"72\"",
		"meta.raw.Y\\\\ Resolution:72"
	}, {
		"kMDItemResolutionWidthDPI==\"72\"",
		"meta.raw.X\\\\ Resolution:72"
	},{
		"*!=\"samba\"",
		"(NOT samba)"
	}, {
		"kMDItemFSSize!=\"1\"",
		"(NOT file.filesize:1)"
	}, {
		"kMDItemFSSize>\"1\"",
		"file.filesize:{1 TO *}"
	}, {
		"kMDItemFSSize<\"1\"",
		"file.filesize:{* TO 1}"
	}, {
		"kMDItemFSCreationDate!=\"1\"",
		"(NOT file.created:2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z)"
	}, {
		"kMDItemFSCreationDate>\"1\"",
		"file.created:{2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z TO *}"
	}, {
		"kMDItemFSCreationDate<\"1\"",
		"file.created:{* TO 2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z}"
	}, {
		"kMDItemFSName==\"Samba\"||kMDItemTextContent==\"Samba\"",
		"file.filename:Samba OR content:Samba"
	}, {
		"kMDItemFSName==\"Samba\"&&kMDItemTextContent==\"Samba\"",
		"(file.filename:Samba) AND (content:Samba)"
	}, {
		"InRange(kMDItemFSCreationDate,1,2)",
		"file.created:[2001\\\\-01\\\\-01T00\\\\:00\\\\:01Z TO 2001\\\\-01\\\\-01T00\\\\:00\\\\:02Z]"
	}, {
		"InRange(kMDItemFSSize,1,2)",
		"file.filesize:[1 TO 2]"
	}, {
		"InRange(kMDItemContentCreationDate,$time.iso(2024-12-31T23:00:00Z),$time.iso(2025-12-31T23:00:00Z))",
		"file.created:[2024\\\\-12\\\\-31T23\\\\:00\\\\:00Z TO 2025\\\\-12\\\\-31T23\\\\:00\\\\:00Z]"
	}
};

static struct {
	const char *mds;
	const char *es;
} map_ignore_failures[] = {
	{
		"*==\"Samba\"||foo==\"bar\"",
		"Samba"
	}, {
		"*==\"Samba\"&&foo==\"bar\"",
		"Samba"
	}, {
		"*==\"Samba\"||kMDItemContentType==\"666\"",
		"Samba"
	}, {
		"*==\"Samba\"&&kMDItemContentType==\"666\"",
		"Samba"
	}, {
		"*==\"Samba\"||foo==\"bar\"||kMDItemContentType==\"666\"",
		"Samba"
	}, {
		"*==\"Samba\"&&foo==\"bar\"&&kMDItemContentType==\"666\"",
		"Samba"
	}, {
		"foo==\"bar\"||kMDItemContentType==\"666\"||*==\"Samba\"||x!=\"6\"",
		"Samba"
	}, {
		"*==\"Samba\"||InRange(foo,1,2)",
		"Samba"
	}, {
		"*==\"Samba\"||foo==$time.iso(2018-10-01T10:00:00Z)",
		"Samba"
	}
};

static void test_mdsparser_es(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *es_query = NULL;
	char *default_path = NULL;
	const char *path = NULL;
	json_t *mappings = NULL;
	json_error_t json_error;
	int i;
	bool ok;

	default_path = talloc_asprintf(
		frame,
		"%s/mdssvc/elasticsearch_mappings.json",
		get_dyn_SAMBA_DATADIR());
	assert_non_null(default_path);

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "mappings",
				    default_path);
	assert_non_null(path);

	mappings = json_load_file(path, 0, &json_error);
	assert_non_null(mappings);

	for (i = 0; i < ARRAY_SIZE(map); i++) {
		DBG_DEBUG("Mapping: %s\n", map[i].mds);
		ok = map_spotlight_to_es_query(frame,
					       mappings,
					       map[i].mds,
					       &es_query);
		assert_true(ok);
		assert_string_equal(es_query, map[i].es);
	}

	if (!lp_parm_bool(GLOBAL_SECTION_SNUM,
			  "elasticsearch",
			  "test mapping failures",
			  false))
	{
		goto done;
	}

	for (i = 0; i < ARRAY_SIZE(map_ignore_failures); i++) {
		DBG_DEBUG("Mapping: %s\n", map_ignore_failures[i].mds);
		ok = map_spotlight_to_es_query(frame,
					       mappings,
					       map_ignore_failures[i].mds,
					       &es_query);
		assert_true(ok);
		assert_string_equal(es_query, map_ignore_failures[i].es);
	}

done:
	json_decref(mappings);
	TALLOC_FREE(frame);
}

int main(int argc, const char *argv[])
{
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
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx = NULL;

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	lpcfg_set_cmdline(lp_ctx, "log level", "1");

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		    default:
			    fprintf(stderr, "Unknown Option: %c\n", opt);
			    exit(1);
		}
	}

	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);

	return cmocka_run_group_tests(tests, NULL, NULL);
}
