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

%module(docstring="Event management.",package="samba.events") events;

%import "../../../lib/talloc/talloc.i";

%{
#include "events.h"
typedef struct event_context event;
%}

typedef struct event_context {
    %extend {
        %feature("docstring") event "S.__init__()";
        event(TALLOC_CTX *mem_ctx) { return event_context_init(mem_ctx); }
        %feature("docstring") loop_once "S.loop_once() -> int";
        int loop_once(void);
        %feature("docstring") loop_wait "S.loop_wait() -> int";
        int loop_wait(void);
    }
} event;
%talloctype(event);

%typemap(default,noblock=1) struct event_context * {
    $1 = event_context_init(NULL);
}

%typemap(default,noblock=1) struct event_context * {
    $1 = event_context_init(NULL);
}

struct event_context *event_context_init_byname(TALLOC_CTX *mem_ctx, const char *name);

%feature("docstring") event_backend_list "event_backend_list() -> list";
const char **event_backend_list(TALLOC_CTX *mem_ctx);
%feature("docstring") event_set_default_backend "event_set_default_backend(name) -> None";
%rename(set_default_backend) event_set_default_backend;
void event_set_default_backend(const char *backend);
