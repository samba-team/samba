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

%module(package="samba.param") param

%{
#include <stdint.h>
#include <stdbool.h>

#include "includes.h"
#include "param/param.h"

typedef struct param_context param;
typedef struct loadparm_context loadparm_context;
typedef struct loadparm_service loadparm_service;
typedef struct param_section param_section;
%}

%import "stdint.i"
%import "carrays.i"
%import "typemaps.i"
%import "../lib/talloc/talloc.i"

%typemap(default) struct loadparm_context * {
    $1 = loadparm_init(NULL);
}

%typemap(freearg) struct loadparm_context * {
    talloc_free($1);     
}

%rename(LoadParm) loadparm_context;

typedef struct loadparm_context {
    %extend {
        loadparm_context(TALLOC_CTX *mem_ctx) { return loadparm_init(mem_ctx); }
        ~loadparm_context() { talloc_free($self); }
        bool load(const char *filename) { return lp_load($self, filename); }
#ifdef SWIGPYTHON
        int __len__() { return lp_numservices($self); }
        struct loadparm_service *__getitem__(const char *name) { return lp_service($self, name); }
#endif
        const char *configfile() { return lp_configfile($self); }
        bool is_mydomain(const char *domain) { return lp_is_mydomain($self, domain); }
        bool is_myname(const char *name) { return lp_is_myname($self, name); }
    }
} loadparm_context;

%nodefaultctor loadparm_service;
%nodefaultdtor loadparm_service;

typedef struct loadparm_service {
    %extend { 
        const char *volume_label() { return volume_label($self); }
        const char *printername() { return lp_printername($self); }
        int maxprintjobs() { return lp_maxprintjobs($self); } 
    }
} loadparm_service;

%rename(ParamFile) param_context;

typedef struct param_context {
    %extend { 
        param(TALLOC_CTX *mem_ctx) { return param_init(mem_ctx); }
        ~param() { talloc_free($self); }
        struct param_section *get_section(const char *name);
        struct param_opt *get(const char *section_name, const char *name);
        int set_string(const char *section, const char *param, const char *value);
        int read(const char *fn);
        int use(struct param_context *);
        int write(const char *fn);
    }
} param;

typedef struct param_section {
    %extend {
        struct param_opt *get(const char *name);
    }
} param_section;

%rename(default_config) global_loadparm;
struct loadparm_context *global_loadparm;
