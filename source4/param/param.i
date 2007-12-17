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
typedef struct param_opt param_opt;
%}

%import "stdint.i"
%import "carrays.i"
%import "typemaps.i"
%import "../lib/talloc/talloc.i"

%typemap(default) struct loadparm_context * {
    $1 = loadparm_init(NULL);
}

%rename(LoadParm) loadparm_context;

%talloctype(loadparm_context);

typedef struct loadparm_context {
    %extend {
        loadparm_context(TALLOC_CTX *mem_ctx) { return loadparm_init(mem_ctx); }
        bool load(const char *filename) { return lp_load($self, filename); }
#ifdef SWIGPYTHON
        int __len__() { return lp_numservices($self); }
        struct loadparm_service *__getitem__(const char *name) { return lp_service($self, name); }
#endif
        const char *configfile() { return lp_configfile($self); }
        bool is_mydomain(const char *domain) { return lp_is_mydomain($self, domain); }
        bool is_myname(const char *name) { return lp_is_myname($self, name); }
        int use(struct param_context *param) { return param_use($self, param); }
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

%talloctype(param_context);
typedef struct param_context {
    %extend { 
        param(TALLOC_CTX *mem_ctx) { return param_init(mem_ctx); }
        struct param_section *get_section(const char *name);
        struct param_section *add_section(const char *name);
        struct param_opt *get(const char *name, const char *section_name="global");
        const char *get_string(const char *name, const char *section_name="global");
        int set_string(const char *param, const char *value, const char *section="global");
        int set(const char *param, PyObject *ob, const char *section_name="global")
        {
            struct param_opt *opt = param_get_add($self, param, section_name);

            talloc_free(opt->value);
            opt->value = talloc_strdup(opt, PyObject_Str(ob));

            return 0;
        }

        int read(const char *fn);
        int write(const char *fn);
    }
    %pythoncode {
        def __getitem__(self, name):
            ret = self.get_section(name)
            if ret is None:
                raise KeyError("No such section %s" % name)
            return ret
    }
} param;

%talloctype(param_opt);

typedef struct param_opt {
    %extend {
#ifdef SWIGPYTHON
        const char *__str__() { return $self->value; }
#endif
    }
} param_opt;

%talloctype(param);
typedef struct param_section {
    %extend {
        struct param_opt *get(const char *name);
    }
    %pythoncode {
        def __getitem__(self, name):
            ret = self.get(name)
            if ret is None:
                raise KeyError("No such option %s" % name)
            return ret
    }
} param_section;

%rename(default_config) global_loadparm;
struct loadparm_context *global_loadparm;
