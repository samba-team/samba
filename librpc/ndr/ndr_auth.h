/* 
   Unix SMB/CIFS implementation.

   Helper routines for marshalling the internal 'auth.idl'

   Copyright (C) Andrew Bartlett 2011
   
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

/*
  cli_credentials does not have a network representation, just pull/push a NULL pointer
*/

#include "librpc/gen_ndr/ndr_auth.h"

struct cli_credentials;
_PUBLIC_ enum ndr_err_code ndr_pull_cli_credentials(struct ndr_pull *ndr, int ndr_flags, struct cli_credentials *v);
_PUBLIC_ enum ndr_err_code ndr_push_cli_credentials(struct ndr_push *ndr, int ndr_flags, struct cli_credentials *v);

_PUBLIC_ void ndr_print_cli_credentials(struct ndr_print *ndr, const char *name, struct cli_credentials *v);
