/*
   Unix SMB/CIFS implementation.
   test suite for clusapi ndr operations

   Copyright (C) Guenther Deschner 2015

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
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_clusapi.h"
#include "torture/ndr/proto.h"
#include "param/param.h"
#include "libcli/registry/util_reg.h"

static const uint8_t clusapi_PROPERTY_LIST_data[] = {
	0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00,
	0x46, 0x00, 0x69, 0x00, 0x78, 0x00, 0x51, 0x00, 0x75, 0x00, 0x6f, 0x00,
	0x72, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x50, 0x00, 0x72, 0x00,
	0x65, 0x00, 0x76, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x51, 0x00,
	0x75, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x3e, 0x00, 0x00, 0x00,
	0x49, 0x00, 0x67, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00,
	0x50, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x73, 0x00,
	0x74, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x53, 0x00, 0x74, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x4f, 0x00, 0x6e, 0x00, 0x53, 0x00,
	0x74, 0x00, 0x61, 0x00, 0x72, 0x00, 0x74, 0x00, 0x75, 0x00, 0x70, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x24, 0x00, 0x00, 0x00, 0x53, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00,
	0x65, 0x00, 0x64, 0x00, 0x56, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x75, 0x00,
	0x6d, 0x00, 0x65, 0x00, 0x73, 0x00, 0x52, 0x00, 0x6f, 0x00, 0x6f, 0x00,
	0x74, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00,
	0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x43, 0x00, 0x6c, 0x00, 0x75, 0x00,
	0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x53, 0x00, 0x74, 0x00,
	0x6f, 0x00, 0x72, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00, 0x00,
	0x57, 0x00, 0x69, 0x00, 0x74, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x73, 0x00,
	0x73, 0x00, 0x44, 0x00, 0x79, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x6d, 0x00,
	0x69, 0x00, 0x63, 0x00, 0x57, 0x00, 0x65, 0x00, 0x69, 0x00, 0x67, 0x00,
	0x68, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x22, 0x00, 0x00, 0x00, 0x41, 0x00, 0x64, 0x00,
	0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x41, 0x00, 0x63, 0x00, 0x63, 0x00,
	0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x50, 0x00, 0x6f, 0x00, 0x69, 0x00,
	0x6e, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static bool clusapi_PROPERTY_LIST_check(struct torture_context *tctx,
					struct clusapi_PROPERTY_LIST *r)
{
	DATA_BLOB blob_dword_null = data_blob_talloc_zero(tctx, 4);
	DATA_BLOB blob_dword_one = data_blob(NULL, 4);
	const char *str;

	SIVAL(blob_dword_one.data, 0, 1);

	torture_assert_int_equal(tctx, r->propertyCount, 6, "propertyCount");

	torture_assert_int_equal(tctx, r->propertyValues[0].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[0].size, 20, "size");
	torture_assert_str_equal(tctx, r->propertyValues[0].buffer, "FixQuorum", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[0].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[0].PropertyValues.Buffer, blob_dword_null, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[0].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[1].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[1].size, 28, "size");
	torture_assert_str_equal(tctx, r->propertyValues[1].buffer, "PreventQuorum", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[1].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[1].PropertyValues.Buffer, blob_dword_null, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[1].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[2].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[2].size, 62, "size");
	torture_assert_str_equal(tctx, r->propertyValues[2].buffer, "IgnorePersistentStateOnStartup", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[2].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[2].PropertyValues.Buffer, blob_dword_null, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[2].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[3].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[3].size, 36, "size");
	torture_assert_str_equal(tctx, r->propertyValues[3].buffer, "SharedVolumesRoot", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[3].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_SZ, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Size, 36, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Buffer.length, 36, "PropertyValues.Buffer.length");
	pull_reg_sz(tctx, &r->propertyValues[3].PropertyValues.Buffer, &str);
	torture_assert_str_equal(tctx, str, "C:\\ClusterStorage", "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[3].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[4].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[4].size, 42, "size");
	torture_assert_str_equal(tctx, r->propertyValues[4].buffer, "WitnessDynamicWeight", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[4].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[4].PropertyValues.Buffer, blob_dword_one, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[4].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[5].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[5].size, 34, "size");
	torture_assert_str_equal(tctx, r->propertyValues[5].buffer, "AdminAccessPoint", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[5].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[5].PropertyValues.Buffer, blob_dword_one, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[5].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	data_blob_free(&blob_dword_null);
	data_blob_free(&blob_dword_one);

	return true;
}

static const uint8_t clusapi_PROPERTY_LIST_data2[] = {
	0x0c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x12, 0x00, 0x00, 0x00,
	0x4e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x65, 0x00, 0x4e, 0x00, 0x61, 0x00,
	0x6d, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00,
	0x0c, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x65, 0x00,
	0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x26, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x65, 0x00,
	0x48, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x65, 0x00, 0x73, 0x00,
	0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00,
	0x6f, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x80, 0x25, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x24, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x6f, 0x00,
	0x64, 0x00, 0x65, 0x00, 0x4c, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x65, 0x00,
	0x73, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00,
	0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x80, 0x25, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x61, 0x00,
	0x6a, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x56, 0x00, 0x65, 0x00, 0x72, 0x00,
	0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x1a, 0x00, 0x00, 0x00,
	0x4d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x56, 0x00,
	0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x18, 0x00, 0x00, 0x00, 0x42, 0x00, 0x75, 0x00, 0x69, 0x00, 0x6c, 0x00,
	0x64, 0x00, 0x4e, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x62, 0x00, 0x65, 0x00,
	0x72, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x80, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x16, 0x00, 0x00, 0x00, 0x43, 0x00, 0x53, 0x00, 0x44, 0x00, 0x56, 0x00,
	0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x1e, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x65, 0x00,
	0x49, 0x00, 0x6e, 0x00, 0x73, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6e, 0x00,
	0x63, 0x00, 0x65, 0x00, 0x49, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x01, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x2d, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2d, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x30, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
	0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00,
	0x4e, 0x00, 0x6f, 0x00, 0x64, 0x00, 0x65, 0x00, 0x44, 0x00, 0x72, 0x00,
	0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x53, 0x00, 0x74, 0x00, 0x61, 0x00,
	0x74, 0x00, 0x75, 0x00, 0x73, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x20, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x6f, 0x00,
	0x64, 0x00, 0x65, 0x00, 0x44, 0x00, 0x72, 0x00, 0x61, 0x00, 0x69, 0x00,
	0x6e, 0x00, 0x54, 0x00, 0x61, 0x00, 0x72, 0x00, 0x67, 0x00, 0x65, 0x00,
	0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x1c, 0x00, 0x00, 0x00, 0x44, 0x00, 0x79, 0x00, 0x6e, 0x00, 0x61, 0x00,
	0x6d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x57, 0x00, 0x65, 0x00, 0x69, 0x00,
	0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x04, 0x00, 0x26, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x65, 0x00,
	0x65, 0x00, 0x64, 0x00, 0x73, 0x00, 0x50, 0x00, 0x72, 0x00, 0x65, 0x00,
	0x76, 0x00, 0x65, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x51, 0x00, 0x75, 0x00,
	0x6f, 0x00, 0x72, 0x00, 0x75, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static bool clusapi_PROPERTY_LIST_check2(struct torture_context *tctx,
					 struct clusapi_PROPERTY_LIST *r)
{
	DATA_BLOB blob_dword_null = data_blob_talloc_zero(tctx, 4);
	DATA_BLOB blob_dword_one = data_blob(NULL, 4);
	DATA_BLOB blob_dword = data_blob(NULL, 4);
	const char *str;

	SIVAL(blob_dword_one.data, 0, 1);

	torture_assert_int_equal(tctx, r->propertyCount, 12, "propertyCount");

	torture_assert_int_equal(tctx, r->propertyValues[0].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[0].size, 18, "size");
	torture_assert_str_equal(tctx, r->propertyValues[0].buffer, "NodeName", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[0].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_SZ, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Size, 12, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Buffer.length, 12, "PropertyValues.Buffer.length");
	pull_reg_sz(tctx, &r->propertyValues[0].PropertyValues.Buffer, &str);
	torture_assert_str_equal(tctx, str, "node1", "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[0].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[0].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[1].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[1].size, 38, "size");
	torture_assert_str_equal(tctx, r->propertyValues[1].buffer, "NodeHighestVersion", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[1].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0x00082580);
	torture_assert_data_blob_equal(tctx, r->propertyValues[1].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[1].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[1].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[2].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[2].size, 36, "size");
	torture_assert_str_equal(tctx, r->propertyValues[2].buffer, "NodeLowestVersion", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[2].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0x00082580);
	torture_assert_data_blob_equal(tctx, r->propertyValues[2].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[2].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[2].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[3].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[3].size, 26, "size");
	torture_assert_str_equal(tctx, r->propertyValues[3].buffer, "MajorVersion", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[3].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0x06);
	torture_assert_data_blob_equal(tctx, r->propertyValues[3].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[3].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[3].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[4].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[4].size, 26, "size");
	torture_assert_str_equal(tctx, r->propertyValues[4].buffer, "MinorVersion", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[4].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0x03);
	torture_assert_data_blob_equal(tctx, r->propertyValues[4].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[4].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[4].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[5].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[5].size, 24, "size");
	torture_assert_str_equal(tctx, r->propertyValues[5].buffer, "BuildNumber", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[5].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0x00002580);
	torture_assert_data_blob_equal(tctx, r->propertyValues[5].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[5].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[5].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[6].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[6].size, 22, "size");
	torture_assert_str_equal(tctx, r->propertyValues[6].buffer, "CSDVersion", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[6].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[6].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_SZ, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[6].PropertyValues.Size, 2, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[6].PropertyValues.Buffer.length, 2, "PropertyValues.Buffer.length");
	pull_reg_sz(tctx, &r->propertyValues[6].PropertyValues.Buffer, &str);
	torture_assert_str_equal(tctx, str, "", "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[6].PropertyValues.Padding.length, 2, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[6].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[7].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[7].size, 30, "size");
	torture_assert_str_equal(tctx, r->propertyValues[7].buffer, "NodeInstanceID", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[7].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[7].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_SZ, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[7].PropertyValues.Size, 74, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[7].PropertyValues.Buffer.length, 74, "PropertyValues.Buffer.length");
	pull_reg_sz(tctx, &r->propertyValues[7].PropertyValues.Buffer, &str);
	torture_assert_str_equal(tctx, str, "00000000-0000-0000-0000-000000000002", "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[7].PropertyValues.Padding.length, 2, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[7].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[8].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[8].size, 32, "size");
	torture_assert_str_equal(tctx, r->propertyValues[8].buffer, "NodeDrainStatus", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[8].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[8].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[8].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[8].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[8].PropertyValues.Buffer, blob_dword_null, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[8].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[8].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[9].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[9].size, 32, "size");
	torture_assert_str_equal(tctx, r->propertyValues[9].buffer, "NodeDrainTarget", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[9].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[9].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[9].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[9].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	SIVAL(blob_dword.data, 0, 0xffffffff);
	torture_assert_data_blob_equal(tctx, r->propertyValues[9].PropertyValues.Buffer, blob_dword, "PropertyValues.Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[9].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[9].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[10].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[10].size, 28, "size");
	torture_assert_str_equal(tctx, r->propertyValues[10].buffer, "DynamicWeight", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[10].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[10].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[10].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[10].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[10].PropertyValues.Buffer, blob_dword_one, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[10].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[10].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	torture_assert_int_equal(tctx, r->propertyValues[11].syntax_name, CLUSPROP_SYNTAX_NAME, "syntax_name");
	torture_assert_int_equal(tctx, r->propertyValues[11].size, 38, "size");
	torture_assert_str_equal(tctx, r->propertyValues[11].buffer, "NeedsPreventQuorum", "buffer");
	torture_assert_int_equal(tctx, r->propertyValues[11].padding.length, 0, "padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[11].PropertyValues.Syntax, CLUSPROP_SYNTAX_LIST_VALUE_DWORD, "PropertyValues.Syntax");
	torture_assert_int_equal(tctx, r->propertyValues[11].PropertyValues.Size, 4, "PropertyValues.Size");
	torture_assert_int_equal(tctx, r->propertyValues[11].PropertyValues.Buffer.length, 4, "PropertyValues.Buffer.length");
	torture_assert_data_blob_equal(tctx, r->propertyValues[11].PropertyValues.Buffer, blob_dword_null, "Buffer");
	torture_assert_int_equal(tctx, r->propertyValues[11].PropertyValues.Padding.length, 0, "PropertyValues.Padding.length");
	torture_assert_int_equal(tctx, r->propertyValues[11].end_mark, CLUSPROP_SYNTAX_ENDMARK, "end_mark");

	data_blob_free(&blob_dword_null);
	data_blob_free(&blob_dword_one);
	data_blob_free(&blob_dword);

	return true;
}

struct torture_suite *ndr_clusapi_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "clusapi");

	torture_suite_add_ndr_pull_validate_test(suite,
					    clusapi_PROPERTY_LIST,
					    clusapi_PROPERTY_LIST_data,
					    clusapi_PROPERTY_LIST_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    clusapi_PROPERTY_LIST,
					    clusapi_PROPERTY_LIST_data2,
					    clusapi_PROPERTY_LIST_check2);

	return suite;
}
