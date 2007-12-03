/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

%module(package="samba.auth") auth

%{

/* Include headers */
#include <stdint.h>
#include <stdbool.h>

#include "includes.h"
#include "auth/session.h"
#include "auth/system_session_proto.h"
%}

%include "carrays.i"
%include "stdint.i"
%include "typemaps.i"
%import "../lib/talloc/talloc.i"

%typemap(default) struct auth_session_info * {
    $1 = system_session_anon(NULL, global_loadparm);
}

%typemap(freearg) struct auth_session_info * {
    talloc_free($1);
}

struct auth_session_info *system_session(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);
struct auth_session_info *system_session_anon(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);
