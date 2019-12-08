/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2007

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

#ifndef __TORTURE_NDR_H__
#define __TORTURE_NDR_H__

#include "torture/torture.h"
#include "librpc/ndr/libndr.h"
#include "libcli/security/security.h"

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pullpush_test(
					struct torture_suite *suite,
					const char *name,
					ndr_pull_flags_fn_t pull_fn,
					ndr_push_flags_fn_t push_fn,
					ndr_print_fn_t print_fn,
					ndr_print_function_t print_function,
					DATA_BLOB db,
					size_t struct_size,
					int ndr_flags,
					int flags,
					bool (*check_fn) (struct torture_context *, void *data));

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pull_inout_test(
					struct torture_suite *suite,
					const char *name,
					ndr_pull_flags_fn_t pull_fn,
					ndr_print_function_t print_fn,
					DATA_BLOB db_in,
					DATA_BLOB db_out,
					size_t struct_size,
					int flags,
					bool (*check_fn) (struct torture_context *ctx, void *data));

_PUBLIC_ struct torture_test *_torture_suite_add_ndr_pull_invalid_data_test(
	struct torture_suite *suite,
	const char *name,
	ndr_pull_flags_fn_t pull_fn,
	DATA_BLOB db,
	size_t struct_size,
	int ndr_flags,
	int flags,
	enum ndr_err_code ndr_err);

#define torture_suite_add_ndr_pull_test(suite,name,data,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 NULL, \
			 (ndr_print_fn_t)ndr_print_ ## name, \
			 NULL, \
			 data_blob_const(data, sizeof(data)), \
			 sizeof(struct name), \
			 NDR_SCALARS|NDR_BUFFERS, 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_invalid_data_test(suite,name,data,ndr_err) \
		_torture_suite_add_ndr_pull_invalid_data_test( \
			suite, \
			#name, \
			(ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			data_blob_const(data, sizeof(data)), \
			sizeof(struct name), \
			NDR_SCALARS|NDR_BUFFERS, 0, \
			ndr_err);

#define torture_suite_add_ndr_pull_fn_test(suite,name,data,flags,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name "_" #flags, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 NULL, \
			 NULL, \
			 (ndr_print_function_t)ndr_print_ ## name, \
			 data_blob_const(data, sizeof(data)), \
			 sizeof(struct name), \
			 flags, 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_fn_test_flags(suite,name,data,flags,flags2,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name "_" #flags "_" #flags2, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 NULL, \
			 NULL, \
			 (ndr_print_function_t)ndr_print_ ## name, \
			 data_blob_const(data, sizeof(data)), \
			 sizeof(struct name), \
			 flags, flags2, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_validate_test(suite,name,data,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name "_VALIDATE", \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_push_flags_fn_t)ndr_push_ ## name, \
			 (ndr_print_fn_t)ndr_print_ ## name, \
			 NULL, \
			 data_blob_const(data, sizeof(data)), \
			 sizeof(struct name), \
			 NDR_SCALARS|NDR_BUFFERS, 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_validate_test_blob(suite,name,data_blob,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name "_VALIDATE", \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_push_flags_fn_t)ndr_push_ ## name, \
			 (ndr_print_fn_t)ndr_print_ ## name, \
			 NULL, \
			 data_blob, \
			 sizeof(struct name), \
			 NDR_SCALARS|NDR_BUFFERS, 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_validate_test_b64(suite,name,tname,b64,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name "_" tname, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_push_flags_fn_t)ndr_push_ ## name, \
			 (ndr_print_fn_t)ndr_print_ ## name, \
			 NULL, \
			 base64_decode_data_blob_talloc(suite, b64), \
			 sizeof(struct name), \
			 NDR_SCALARS|NDR_BUFFERS, 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pullpush_fn_test_flags(suite,name,data,flags,flags2,check_fn) \
		_torture_suite_add_ndr_pullpush_test(suite, #name, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_push_flags_fn_t)ndr_push_ ## name, \
			 NULL, \
			 (ndr_print_function_t)ndr_print_ ## name, \
			 data_blob_const(data, sizeof(data)), \
			 sizeof(struct name), \
			 flags, flags2, \
			 (bool (*) (struct torture_context *, void *)) check_fn);

#define torture_suite_add_ndr_pull_io_test(suite,name,data_in,data_out,check_fn_out) \
		_torture_suite_add_ndr_pull_inout_test(suite, #name "_INOUT", \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_print_function_t)ndr_print_ ## name, \
			 data_blob_const(data_in, sizeof(data_in)), \
			 data_blob_const(data_out, sizeof(data_out)), \
			 sizeof(struct name), \
			 0, \
			 (bool (*) (struct torture_context *, void *)) check_fn_out);

#define torture_suite_add_ndr_pull_io_test_flags(suite,name,data_in,data_out,flags,check_fn_out) \
		_torture_suite_add_ndr_pull_inout_test(suite, #name "_INOUT_" #flags, \
			 (ndr_pull_flags_fn_t)ndr_pull_ ## name, \
			 (ndr_print_function_t)ndr_print_ ## name, \
			 data_blob_const(data_in, sizeof(data_in)), \
			 data_blob_const(data_out, sizeof(data_out)), \
			 sizeof(struct name), \
			 flags, \
			 (bool (*) (struct torture_context *, void *)) check_fn_out);
#endif /* __TORTURE_NDR_H__ */
