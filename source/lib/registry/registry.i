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

%module registry

%{
/* Include headers */
#include <stdint.h>
#include <stdbool.h>

#include "includes.h"
#include "registry.h"
#include "param/param.h"

typedef struct registry_context reg;
typedef struct hive_key hive_key;
%}

/* FIXME: This should be in another file */
%typemap(default,noblock=1) struct auth_session_info * {
    $1 = NULL; 
}

%import "stdint.i"
%import "../../lib/talloc/talloc.i"
%import "../../auth/credentials/credentials.i"
%import "../../libcli/util/errors.i"
%import "../../param/param.i"

/* Utility functions */

const char *reg_get_predef_name(uint32_t hkey);
const char *str_regtype(int type);

/* Registry contexts */
%typemap(in,noblock=1,numinputs=0) struct registry_context ** (struct registry_context *tmp) {
    $1 = &tmp; 
}

%typemap(argout,noblock=1) struct registry_context ** {
    $result = SWIG_NewPointerObj(*$1, SWIGTYPE_p_registry_context, 0);
}

%rename(Registry) reg_open_local;
WERROR reg_open_local(TALLOC_CTX *parent_ctx, struct registry_context **ctx,
                      struct auth_session_info *session_info,
                      struct cli_credentials *credentials);

%typemap(in,noblock=1) const char ** {
  /* Check if is a list */
  if (PyList_Check($input)) {
    int size = PyList_Size($input);
    int i = 0;
    $1 = (char **) malloc((size+1)*sizeof(const char *));
    for (i = 0; i < size; i++) {
      PyObject *o = PyList_GetItem($input,i);
      if (PyString_Check(o))
    $1[i] = PyString_AsString(PyList_GetItem($input,i));
      else {
    PyErr_SetString(PyExc_TypeError,"list must contain strings");
    free($1);
    return NULL;
      }
    }
    $1[i] = 0;
  } else {
    PyErr_SetString(PyExc_TypeError,"not a list");
    return NULL;
  }
}

%typemap(freearg,noblock=1) const char ** {
  free((char **) $1);
}

%talloctype(reg);

typedef struct registry_context {
    %extend {

    WERROR get_predefined_key_by_name(const char *name, 
                                      struct registry_key **key);

    WERROR key_del_abs(const char *path);
    WERROR get_predefined_key(uint32_t hkey_id, struct registry_key **key);
    WERROR diff_apply(const char *filename);
    WERROR generate_diff(struct registry_context *ctx2, const struct reg_diff_callbacks *callbacks,
                         void *callback_data);

    WERROR mount_hive(struct hive_key *key, uint32_t hkey_id,
                      const char **elements=NULL);

    struct registry_key *import_hive_key(struct hive_key *hive, uint32_t predef_key, const char **elements);
    WERROR mount_hive(struct hive_key *key, const char *predef_name)
    {
        int i;
        for (i = 0; reg_predefined_keys[i].name; i++) {
            if (!strcasecmp(reg_predefined_keys[i].name, predef_name))
                return reg_mount_hive($self, key, 
                                      reg_predefined_keys[i].handle, NULL);
        }
        return WERR_INVALID_NAME;
    }

    }
} reg;

/* Hives */
%typemap(in,noblock=1,numinputs=0) struct hive_key ** (struct hive_key *tmp) {
    $1 = &tmp; 
}

%typemap(argout,noblock=1) struct hive_key ** {
    Py_XDECREF($result);
    $result = SWIG_NewPointerObj(*$1, SWIGTYPE_p_hive_key, 0);
}

%rename(hive_key) reg_open_hive;
WERROR reg_open_hive(TALLOC_CTX *parent_ctx, const char *location,
                     struct auth_session_info *session_info,
                     struct cli_credentials *credentials,
                     struct loadparm_context *lp_ctx,
                     struct hive_key **root);

%rename(open_ldb) reg_open_ldb_file;
WERROR reg_open_ldb_file(TALLOC_CTX *parent_ctx, const char *location,
             struct auth_session_info *session_info,
             struct cli_credentials *credentials,
             struct loadparm_context *lp_ctx,
             struct hive_key **k);

%rename(create_dir) reg_create_directory;
WERROR reg_create_directory(TALLOC_CTX *parent_ctx,
                const char *location, struct hive_key **key);

%rename(open_dir) reg_open_directory;
WERROR reg_open_directory(TALLOC_CTX *parent_ctx,
             const char *location, struct hive_key **key);

%talloctype(hive_key);

typedef struct hive_key {
    %extend {
        WERROR del(const char *name);
        WERROR flush(void);
        WERROR del_value(const char *name);
        WERROR set_value(const char *name, uint32_t type, const DATA_BLOB data);
    }
} hive_key;

%rename(open_samba) reg_open_samba;

WERROR reg_open_samba(TALLOC_CTX *mem_ctx,
                      struct registry_context **ctx,
                      struct loadparm_context *lp_ctx,
                      struct auth_session_info *session_info,
                      struct cli_credentials *credentials);

/* Constants */
%constant uint32_t HKEY_CLASSES_ROOT = HKEY_CLASSES_ROOT;
%constant uint32_t HKEY_CURRENT_USER = HKEY_CURRENT_USER;
%constant uint32_t HKEY_LOCAL_MACHINE = HKEY_LOCAL_MACHINE;
%constant uint32_t HKEY_USERS = HKEY_USERS;
%constant uint32_t HKEY_PERFORMANCE_DATA = HKEY_PERFORMANCE_DATA;
%constant uint32_t HKEY_CURRENT_CONFIG = HKEY_CURRENT_CONFIG;
%constant uint32_t HKEY_DYN_DATA = HKEY_DYN_DATA;
%constant uint32_t HKEY_PERFORMANCE_TEXT = HKEY_PERFORMANCE_TEXT;
%constant uint32_t HKEY_PERFORMANCE_NLSTEXT = HKEY_PERFORMANCE_NLSTEXT;
