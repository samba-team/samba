/*
 * Unix SMB/CIFS implementation.
 *
 * Common helpers for cmocka based unit tests.
 *
 * Copyright (C) 2026 Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CMOCKA_SAMBA_H__
#define __CMOCKA_SAMBA_H__

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/replace/replace.h"
#include <talloc.h>
#include "lib/util/talloc_stack.h"
#include "libcli/util/ntstatus.h"

static inline int setup_talloc_context(void **state)
{
	TALLOC_CTX *frame = talloc_stackframe();

	*state = frame;
	return 0;
}

static inline int teardown_talloc_context(void **state)
{
	TALLOC_CTX *frame = *state;
	TALLOC_FREE(frame);
	return 0;
}

#define assert_ntstatus_equal(got, expected)                    \
	do {                                                    \
		NTSTATUS __got = (got);                         \
		NTSTATUS __expected = (expected);               \
		if (!NT_STATUS_EQUAL(__got, __expected)) {      \
			fail_msg("status: got %s, expected %s", \
				 nt_errstr(__got),              \
				 nt_errstr(__expected));        \
		}                                               \
	} while (0)

#define assert_ntstatus_ok(status)                                        \
	do {                                                              \
		NTSTATUS __status = (status);                             \
		if (!NT_STATUS_IS_OK(__status)) {                         \
			fail_msg("status: got %s, expected NT_STATUS_OK", \
				 nt_errstr(__status));                    \
		}                                                         \
	} while (0)

#endif /* __CMOCKA_SAMBA_H__ */
