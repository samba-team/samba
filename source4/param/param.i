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
#include "param/loadparm.h"

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
        bool set(const char *parm_name, const char *parm_value) {
            return lp_set_cmdline($self, parm_name, parm_value);
        }

        PyObject *get(const char *param_name, const char *service_name)
        {
            struct parm_struct *parm = NULL;
            void *parm_ptr = NULL;
            int i;

            if (service_name != NULL) {
                struct loadparm_service *service;
                /* its a share parameter */
                service = lp_service($self, service_name);
                if (service == NULL) {
                    return Py_None;
                }
                if (strchr(param_name, ':')) {
                    /* its a parametric option on a share */
                    const char *type = talloc_strndup($self, 
                                      param_name, 
                                      strcspn(param_name, ":"));
                    const char *option = strchr(param_name, ':') + 1;
                    const char *value;
                    if (type == NULL || option == NULL) {
                        return Py_None;
                    }
                    value = lp_get_parametric($self, service, type, option);
                    if (value == NULL) {
                        return Py_None;
                    }
                    return PyString_FromString(value);
                }

                parm = lp_parm_struct(param_name);
                if (parm == NULL || parm->class == P_GLOBAL) {
                    return Py_None;
                }
                parm_ptr = lp_parm_ptr($self, service, parm);
            } else if (strchr(param_name, ':')) {
                /* its a global parametric option */
                const char *type = talloc_strndup($self, 
                                  param_name, strcspn(param_name, ":"));
                const char *option = strchr(param_name, ':') + 1;
                const char *value;
                if (type == NULL || option == NULL) {
                    return Py_None;
                }
                value = lp_get_parametric($self, NULL, type, option);
                if (value == NULL)
                    return Py_None;
                return PyString_FromString(value);
            } else {
                /* its a global parameter */
                parm = lp_parm_struct(param_name);
                if (parm == NULL) {
                    return Py_None;
                }
                parm_ptr = lp_parm_ptr($self, NULL, parm);
            }

            if (parm == NULL || parm_ptr == NULL) {
                return Py_None;
            }

            /* construct and return the right type of python object */
            switch (parm->type) {
            case P_STRING:
            case P_USTRING:
                return PyString_FromString(*(char **)parm_ptr);
            case P_BOOL:
                return PyBool_FromLong(*(bool *)parm_ptr);
            case P_INTEGER:
            case P_OCTAL:
            case P_BYTES:
                return PyLong_FromLong(*(int *)parm_ptr);
            case P_ENUM:
                for (i=0; parm->enum_list[i].name; i++) {
                    if (*(int *)parm_ptr == parm->enum_list[i].value) {
                        return PyString_FromString(parm->enum_list[i].name);
                    }
                }
                return Py_None;
            case P_LIST: 
                {
                    int i;
                    const char **strlist = *(const char ***)parm_ptr;
                    PyObject *pylist = PyList_New(str_list_length(strlist));
                    for (i = 0; strlist[i]; i++) 
                        PyList_SetItem(pylist, i, 
                                       PyString_FromString(strlist[i]));
                    return pylist;
                }

                break;
            }
            return Py_None;
        }
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
