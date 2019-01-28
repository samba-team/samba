/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling special NEGOEX structures

   Copyright (C) Stefan Metzmacher 2015

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

#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/negoex.h"

_PUBLIC_ void ndr_print_negoex_BYTE_VECTOR(struct ndr_print *ndr, const char *name, const struct negoex_BYTE_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_push_negoex_BYTE_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_BYTE_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_BYTE_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_BYTE_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_push_negoex_AUTH_SCHEME_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_AUTH_SCHEME_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_AUTH_SCHEME_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_AUTH_SCHEME_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_push_negoex_EXTENSION_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_EXTENSION_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_EXTENSION_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_EXTENSION_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_push_negoex_ALERT_VECTOR(struct ndr_push *ndr, int ndr_flags, const struct negoex_ALERT_VECTOR *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_ALERT_VECTOR(struct ndr_pull *ndr, int ndr_flags, struct negoex_ALERT_VECTOR *r);
_PUBLIC_ size_t ndr_negoex_MESSAGE_header_length(const struct negoex_MESSAGE *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_MESSAGE(struct ndr_pull *ndr, int ndr_flags, struct negoex_MESSAGE *r);
_PUBLIC_ enum ndr_err_code ndr_push_negoex_MESSAGE_ARRAY(struct ndr_push *ndr, int ndr_flags, const struct negoex_MESSAGE_ARRAY *r);
_PUBLIC_ enum ndr_err_code ndr_pull_negoex_MESSAGE_ARRAY(struct ndr_pull *ndr, int ndr_flags, struct negoex_MESSAGE_ARRAY *r);
