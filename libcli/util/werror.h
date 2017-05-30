/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup, plus a whole lot more.
   
   Copyright (C) Andrew Tridgell              2001
   
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

#ifndef _WERROR_H_
#define _WERROR_H_

#include <stdint.h>

/* the following rather strange looking definitions of NTSTATUS and WERROR
   and there in order to catch common coding errors where different error types
   are mixed up. This is especially important as we slowly convert Samba
   from using bool for internal functions 
*/

#if defined(HAVE_IMMEDIATE_STRUCTURES)
typedef struct {uint32_t w;} WERROR;
#define W_ERROR(x) ((WERROR) { x })
#define W_ERROR_V(x) ((x).w)
#else
typedef uint32_t WERROR;
#define W_ERROR(x) (x)
#define W_ERROR_V(x) (x)
#endif

#include "libcli/util/werror_gen.h"

#define W_ERROR_IS_OK(x) (W_ERROR_V(x) == 0)
#define W_ERROR_EQUAL(x,y) (W_ERROR_V(x) == W_ERROR_V(y))

#define W_ERROR_HAVE_NO_MEMORY(x) do { \
	if (!(x)) {\
		return WERR_NOT_ENOUGH_MEMORY;\
	}\
} while (0)

#define W_ERROR_HAVE_NO_MEMORY_AND_FREE(x, ctx) do { \
	if (!(x)) {\
		talloc_free(ctx); \
		return WERR_NOT_ENOUGH_MEMORY;\
	}\
} while (0)

#define W_ERROR_IS_OK_RETURN(x) do { \
	if (W_ERROR_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define W_ERROR_NOT_OK_RETURN(x) do { \
	if (!W_ERROR_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define W_ERROR_NOT_OK_GOTO_DONE(x) do { \
	if (!W_ERROR_IS_OK(x)) {\
		goto done;\
	}\
} while (0)

#define W_ERROR_NOT_OK_GOTO(x, y) do {\
	if (!W_ERROR_IS_OK(x)) {\
		goto y;\
	}\
} while(0)

/* these are win32 error codes. There are only a few places where
   these matter for Samba, primarily in the NT printing code */
#define WERR_OK W_ERROR(0x00000000)
#define WERR_STATUS_MORE_ENTRIES W_ERROR(0x00000105)

#define WERR_MULTIPLE_FAULT_VIOLATION   W_ERROR(0x00000280)
#define WERR_SERVICE_NOTIFICATION       W_ERROR(0x000002CC)
#define WERR_LOG_HARD_ERROR     W_ERROR(0x000002CE)
#define WERR_WAIT_1     W_ERROR(0x000002DB)
#define WERR_WAIT_2     W_ERROR(0x000002DC)
#define WERR_WAIT_3     W_ERROR(0x000002DD)
#define WERR_WAIT_63    W_ERROR(0x000002DE)
#define WERR_ABANDONED_WAIT_63  W_ERROR(0x000002E0)
#define WERR_USER_APC   W_ERROR(0x000002E1)
#define WERR_KERNEL_APC W_ERROR(0x000002E2)
#define WERR_ALERTED    W_ERROR(0x000002E3)
#define WERR_INVALID_PRIMARY_GROUP      W_ERROR(0x0000051C)

#define WERR_DS_DRA_SECRETS_DENIED			W_ERROR(0x000021B6)
#define WERR_DS_DRA_RECYCLED_TARGET			W_ERROR(0x000021BF)

#define WERR_DNS_ERROR_KEYMASTER_REQUIRED               W_ERROR(0x0000238D)
#define WERR_DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE       W_ERROR(0x0000238E)
#define WERR_DNS_ERROR_INVALID_NSEC3_PARAMETERS         W_ERROR(0x0000238F)
#define WERR_DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS       W_ERROR(0x00002390)
#define WERR_DNS_ERROR_UNSUPPORTED_ALGORITHM            W_ERROR(0x00002391)
#define WERR_DNS_ERROR_INVALID_KEY_SIZE                 W_ERROR(0x00002392)
#define WERR_DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE       W_ERROR(0x00002393)
#define WERR_DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION  W_ERROR(0x00002394)
#define WERR_DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR W_ERROR(0x00002395)
#define WERR_DNS_ERROR_UNEXPECTED_CNG_ERROR             W_ERROR(0x00002396)
#define WERR_DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION        W_ERROR(0x00002397)
#define WERR_DNS_ERROR_KSP_NOT_ACCESSIBLE               W_ERROR(0x00002398)
#define WERR_DNS_ERROR_TOO_MANY_SKDS                    W_ERROR(0x00002399)
#define WERR_DNS_ERROR_INVALID_ROLLOVER_PERIOD          W_ERROR(0x0000239A)
#define WERR_DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET  W_ERROR(0x0000239B)
#define WERR_DNS_ERROR_ROLLOVER_IN_PROGRESS             W_ERROR(0x0000239C)
#define WERR_DNS_ERROR_STANDBY_KEY_NOT_PRESENT          W_ERROR(0x0000239D)
#define WERR_DNS_ERROR_NOT_ALLOWED_ON_ZSK               W_ERROR(0x0000239E)
#define WERR_DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD        W_ERROR(0x0000239F)
#define WERR_DNS_ERROR_ROLLOVER_ALREADY_QUEUED          W_ERROR(0x000023A0)
#define WERR_DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE     W_ERROR(0x000023A1)
#define WERR_DNS_ERROR_BAD_KEYMASTER                    W_ERROR(0x000023A2)
#define WERR_DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD        W_ERROR(0x000023A3)
#define WERR_DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT    W_ERROR(0x000023A4)
#define WERR_DNS_ERROR_DNSSEC_IS_DISABLED               W_ERROR(0x000023A5)
#define WERR_DNS_ERROR_INVALID_XML                      W_ERROR(0x000023A6)
#define WERR_DNS_ERROR_NO_VALID_TRUST_ANCHORS           W_ERROR(0x000023A7)
#define WERR_DNS_ERROR_ROLLOVER_NOT_POKEABLE            W_ERROR(0x000023A8)
#define WERR_DNS_ERROR_NSEC3_NAME_COLLISION             W_ERROR(0x000023A9)

#define WERR_DNS_REQUEST_PENDING        W_ERROR(0x00002522)
#define WERR_DNS_ERROR_NOT_ALLOWED_UNDER_DNAME  W_ERROR(0x00002562)
#define WERR_DNS_ERROR_DELEGATION_REQUIRED      W_ERROR(0x00002563)
#define WERR_DNS_ERROR_INVALID_POLICY_TABLE     W_ERROR(0x00002564)
#define WERR_DNS_ERROR_NODE_IS_DNMAE	WERR_DNS_ERROR_NODE_IS_DNAME
#define WERR_DNS_ERROR_NODE_IS_DNAME    W_ERROR(0x000025F8) /* Used to be: "WERR_DNS_ERROR_NODE_IS_DNMAE" */
#define WERR_DNS_ERROR_DNAME_COLLISION  W_ERROR(0x000025F9)
#define WERR_DNS_ERROR_ALIAS_LOOP       W_ERROR(0x000025FA)

/* Configuration Manager Errors */
/* Basically Win32 errors meanings are specific to the \ntsvcs pipe */
#define WERR_CM_INVALID_POINTER W_ERROR(3)
#define WERR_CM_BUFFER_SMALL W_ERROR(26)
#define WERR_CM_NO_MORE_HW_PROFILES W_ERROR(35)
#define WERR_CM_NO_SUCH_VALUE W_ERROR(37)

/* DFS errors */

#ifndef NERR_BASE
#define NERR_BASE (2100)
#endif

#ifndef MAX_NERR
#define MAX_NERR (NERR_BASE+899)
#endif

/* Generic error code aliases */
#define WERR_FOOBAR WERR_GEN_FAILURE

/*****************************************************************************
 returns a windows error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/
const char *win_errstr(WERROR werror);

const char *get_friendly_werror_msg(WERROR werror);


#endif
