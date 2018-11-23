/*
 *  Unix SMB/CIFS implementation.
 *  Kerberos error mapping functions
 *  Copyright (C) Guenther Deschner 2005
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
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __KRB5_ERRS_H__
#define __KRB5_ERRS_H__

#include "replace.h"
#include "libcli/util/ntstatus.h"
#include <krb5.h>

NTSTATUS krb5_to_nt_status(krb5_error_code kerberos_error);
krb5_error_code nt_status_to_krb5(NTSTATUS nt_status);

#endif
