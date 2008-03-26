/*
   Unix SMB/CIFS implementation.

   Swig interface to ldb.

   Copyright (C) 2005,2006 Tim Potter <tpot@samba.org>
   Copyright (C) 2006 Simo Sorce <idra@samba.org>
   Copyright (C) 2007-2008 Jelmer Vernooij <jelmer@samba.org>

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

%module ldb

%{

#include <stdint.h>
#include <stdbool.h>
#include "talloc.h"
#include "ldb.h"
#include "ldb_errors.h"
#include "ldb_private.h"

typedef struct ldb_message ldb_msg;
typedef struct ldb_context ldb;
typedef struct ldb_dn ldb_dn;
typedef struct ldb_ldif ldb_ldif;
typedef struct ldb_message_element ldb_msg_element;
typedef int ldb_error;
typedef int ldb_int_error;

%}

%import "carrays.i"
%import "typemaps.i"
%include "exception.i"
%import "stdint.i"

/* Don't expose talloc contexts in Python code. Python does reference 
   counting for us, so just create a new top-level talloc context.
 */
%typemap(in, numinputs=0, noblock=1) TALLOC_CTX * {
    $1 = NULL;
}



%constant int SCOPE_DEFAULT = LDB_SCOPE_DEFAULT;
%constant int SCOPE_BASE = LDB_SCOPE_BASE;
%constant int SCOPE_ONELEVEL = LDB_SCOPE_ONELEVEL;
%constant int SCOPE_SUBTREE = LDB_SCOPE_SUBTREE;

%constant int CHANGETYPE_NONE = LDB_CHANGETYPE_NONE;
%constant int CHANGETYPE_ADD = LDB_CHANGETYPE_ADD;
%constant int CHANGETYPE_DELETE = LDB_CHANGETYPE_DELETE;
%constant int CHANGETYPE_MODIFY = LDB_CHANGETYPE_MODIFY;

/* 
 * Wrap struct ldb_context
 */

/* The ldb functions will crash if a NULL ldb context is passed so
   catch this before it happens. */

%typemap(check,noblock=1) struct ldb_context* {
	if ($1 == NULL)
		SWIG_exception(SWIG_ValueError, 
			"ldb context must be non-NULL");
}

%typemap(check,noblock=1) ldb_msg * {
	if ($1 == NULL)
		SWIG_exception(SWIG_ValueError, 
			"Message can not be None");
}

/*
 * Wrap struct ldb_val
 */

%typemap(in,noblock=1) struct ldb_val *INPUT (struct ldb_val temp) {
	$1 = &temp;
	if (!PyString_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "string arg expected");
		return NULL;
	}
	$1->length = PyString_Size($input);
	$1->data = PyString_AsString($input);
}

%inline %{
PyObject *ldb_val_to_py_object(struct ldb_context *ldb_ctx, 
                               struct ldb_message_element *el, 
                               struct ldb_val *val)
{
        const struct ldb_schema_attribute *a;
        struct ldb_val new_val;
        TALLOC_CTX *mem_ctx = talloc_new(NULL);
        PyObject *ret;
        
        new_val = *val;
        
        if (ldb_ctx != NULL) {        
        	a = ldb_schema_attribute_by_name(ldb_ctx, el->name);
        
        	if (a != NULL) {
        		if (a->syntax->ldif_write_fn(ldb_ctx, mem_ctx, val, &new_val) != 0) {
        			talloc_free(mem_ctx);
        			return NULL;
        		}
        	}
        } 
        
	ret = PyString_FromStringAndSize((const char *)new_val.data, new_val.length);
	
	talloc_free(mem_ctx);
	
	return ret;
}

%}

%typemap(out,noblock=1) struct ldb_val * {
	$result = PyString_FromStringAndSize((const char *)$1->data, $1->length)
}

%typemap(out,noblock=1) struct ldb_val {
	$result = PyString_FromStringAndSize((const char *)$1.data, $1.length)
}

/*
 * Wrap struct ldb_result
 */

%typemap(in,noblock=1,numinputs=0) struct ldb_result **OUT (struct ldb_result *temp_ldb_result) {
	$1 = &temp_ldb_result;
}

#ifdef SWIGPYTHON
%typemap(argout,noblock=1) struct ldb_result ** (int i) {
	$result = PyList_New((*$1)->count);
    for (i = 0; i < (*$1)->count; i++) {
        PyList_SetItem($result, i, 
            SWIG_NewPointerObj((*$1)->msgs[i], SWIGTYPE_p_ldb_message, 0)
        );
    }
}

%typemap(in,noblock=1,numinputs=1) const char * const *NULL_STR_LIST {
    if ($input == Py_None) {
        $1 = NULL;
    } else if (PySequence_Check($input)) {
        int i;
        $1 = talloc_array(NULL, char *, PySequence_Size($input)+1);
        for(i = 0; i < PySequence_Size($input); i++)
            $1[i] = PyString_AsString(PySequence_GetItem($input, i));
        $1[i] = NULL;
    } else {
        SWIG_exception(SWIG_TypeError, "expected sequence");
    }
}

%typemap(freearg,noblock=1) const char * const *NULL_STR_LIST {
    talloc_free($1);
}

%apply const char * const *NULL_STR_LIST { const char * const *attrs }
%apply const char * const *NULL_STR_LIST { const char * const *control_strings }

#endif

%types(struct ldb_result *);

/*
 * Wrap struct ldb_dn
 */

%rename(__str__) ldb_dn::get_linearized;
%rename(__cmp__) ldb_dn::compare;
%rename(__len__) ldb_dn::get_comp_num;
%rename(Dn) ldb_dn;
typedef struct ldb_dn {
    %extend {
        ldb_dn(ldb *ldb_ctx, const char *str)
        {
            ldb_dn *ret = ldb_dn_new(ldb_ctx, ldb_ctx, str);
            /* ldb_dn_new() doesn't accept NULL as memory context, so 
               we do it this way... */
            talloc_steal(NULL, ret);

            if (ret == NULL)
                SWIG_exception(SWIG_ValueError, 
                                "unable to parse dn string");
fail:
            return ret;
        }
        ~ldb_dn() { talloc_free($self); }
        bool validate();
        const char *get_casefold();
        const char *get_linearized();
        ldb_dn *parent() { return ldb_dn_get_parent(NULL, $self); }
        int compare(ldb_dn *other);
        bool is_valid();
        bool is_special();
        bool is_null();
        bool check_special(const char *name);
        int get_comp_num();
        bool add_child(ldb_dn *child);
        bool add_base(ldb_dn *base);
        const char *canonical_str() {
            return ldb_dn_canonical_string($self, $self);
        }
        const char *canonical_ex_str() {
            return ldb_dn_canonical_ex_string($self, $self);
        }
#ifdef SWIGPYTHON
        ldb_dn *__add__(ldb_dn *other)
        {
            ldb_dn *ret = ldb_dn_copy(NULL, $self);
            ldb_dn_add_child(ret, other);
            return ret;
        }

        /* FIXME: implement __getslice__ */
#endif
    %pythoncode {
        def __eq__(self, other):
            if isinstance(other, self.__class__):
                return self.__cmp__(other) == 0
            if isinstance(other, str):
                return str(self) == other
            return False
    }
    }
} ldb_dn;

#ifdef SWIGPYTHON
%{
int ldb_dn_from_pyobject(TALLOC_CTX *mem_ctx, PyObject *object, 
                         struct ldb_context *ldb_ctx, ldb_dn **dn)
{
    int ret;
    struct ldb_dn *odn;
    if (ldb_ctx != NULL && PyString_Check(object)) {
        odn = ldb_dn_new(mem_ctx, ldb_ctx, PyString_AsString(object));
	if (!odn) {
		return SWIG_ERROR;
	}
	*dn = odn;
        return 0;
    }
    ret = SWIG_ConvertPtr(object, (void **)&odn, SWIGTYPE_p_ldb_dn, 
                           SWIG_POINTER_EXCEPTION);
    *dn = ldb_dn_copy(mem_ctx, odn);
    if (odn && !*dn) {
 	return SWIG_ERROR;
    }
    return ret;
}

ldb_msg_element *ldb_msg_element_from_pyobject(TALLOC_CTX *mem_ctx,
                                               PyObject *set_obj, int flags,
                                               const char *attr_name)
{
    struct ldb_message_element *me = talloc(mem_ctx, struct ldb_message_element);
    me->name = attr_name;
    me->flags = flags;
    if (PyString_Check(set_obj)) {
        me->num_values = 1;
        me->values = talloc_array(me, struct ldb_val, me->num_values);
        me->values[0].length = PyString_Size(set_obj);
        me->values[0].data = (uint8_t *)talloc_strdup(me->values, 
                                           PyString_AsString(set_obj));
    } else if (PySequence_Check(set_obj)) {
        int i;
        me->num_values = PySequence_Size(set_obj);
        me->values = talloc_array(me, struct ldb_val, me->num_values);
        for (i = 0; i < me->num_values; i++) {
            PyObject *obj = PySequence_GetItem(set_obj, i);
            me->values[i].length = PyString_Size(obj);
            me->values[i].data = (uint8_t *)PyString_AsString(obj);
        }
    } else {
        talloc_free(me);
        me = NULL;
    }

    return me;
}

PyObject *ldb_msg_element_to_set(struct ldb_context *ldb_ctx, 
                                 ldb_msg_element *me)
{
    int i;
    PyObject *result;

    /* Python << 2.5 doesn't have PySet_New and PySet_Add. */
    result = PyList_New(me->num_values);

    for (i = 0; i < me->num_values; i++) {
        PyList_SetItem(result, i,
            ldb_val_to_py_object(ldb_ctx, me, &me->values[i]));
    }

    return result;
}

%}
#endif

/* ldb_message_element */
%rename(__cmp__) ldb_message_element::compare;
%rename(MessageElement) ldb_msg_element;
typedef struct ldb_message_element {
    %extend {
#ifdef SWIGPYTHON
        PyObject *__iter__(void)
        {
            return PyObject_GetIter(ldb_msg_element_to_set(NULL, $self));
        }

        PyObject *__set__(void)
        {
            return ldb_msg_element_to_set(NULL, $self);
        }

        ldb_msg_element(PyObject *set_obj, int flags=0, const char *name = NULL)
        {
            return ldb_msg_element_from_pyobject(NULL, set_obj, flags, name);
        }

        int __len__()
        {
            return $self->num_values;
        }
#endif

        PyObject *get(int i)
        {
            if (i < 0 || i >= $self->num_values)
                return Py_None;

            return ldb_val_to_py_object(NULL, $self, &$self->values[i]);
        }

        ~ldb_msg_element() { talloc_free($self); }
        int compare(ldb_msg_element *);
    }
    %pythoncode {
        def __getitem__(self, i):
            ret = self.get(i)
            if ret is None:
                raise KeyError("no such value")
            return ret

        def __eq__(self, other):
            if (len(self) == 1 and self.get(0) == other):
                return True
            if isinstance(other, self.__class__):
                return self.__cmp__(other) == 0
            o = iter(other)
            for i in range(len(self)):
                if self.get(i) != o.next():
                    return False
            return True
    }
} ldb_msg_element;

/* ldb_message */

%rename(Message) ldb_message;
#ifdef SWIGPYTHON
%rename(__delitem__) ldb_message::remove_attr;
%typemap(out) ldb_msg_element * {
	if ($1 == NULL)
		PyErr_SetString(PyExc_KeyError, "no such element");
    else
        $result = SWIG_NewPointerObj($1, SWIGTYPE_p_ldb_message_element, 0);
}
%rename(__getitem__) ldb_message::find_element;
//%typemap(out) ldb_msg_element *;


%inline {
    PyObject *ldb_msg_list_elements(ldb_msg *msg)
    {
        int i;
        PyObject *obj = PyList_New(msg->num_elements);
        for (i = 0; i < msg->num_elements; i++)
            PyList_SetItem(obj, i, PyString_FromString(msg->elements[i].name));
        return obj;
    }
}

#endif

typedef struct ldb_message {
	ldb_dn *dn;

    %extend {
        ldb_msg(ldb_dn *dn = NULL) { 
            ldb_msg *ret = ldb_msg_new(NULL); 
            ret->dn = talloc_reference(ret, dn);
            return ret;
        }
        ~ldb_msg() { talloc_free($self); }
        ldb_msg_element *find_element(const char *name);
        
#ifdef SWIGPYTHON
        void __setitem__(const char *attr_name, ldb_msg_element *val)
        {
            struct ldb_message_element *el;
            
            ldb_msg_remove_attr($self, attr_name);

            el = talloc($self, struct ldb_message_element);
            el->name = talloc_strdup(el, attr_name);
            el->num_values = val->num_values;
            el->values = talloc_reference(el, val->values);

            ldb_msg_add($self, el, val->flags);
        }

        void __setitem__(const char *attr_name, PyObject *val)
        {
            struct ldb_message_element *el = ldb_msg_element_from_pyobject(NULL,
                                                val, 0, attr_name);
            talloc_steal($self, el);
            ldb_msg_remove_attr($self, attr_name);
            ldb_msg_add($self, el, el->flags);
        }

        unsigned int __len__() { return $self->num_elements; }

        PyObject *keys(void)
        {
            return ldb_msg_list_elements($self);
        }

        PyObject *__iter__(void)
        {
            return PyObject_GetIter(ldb_msg_list_elements($self));
        }
#endif
        void remove_attr(const char *name);
    }
} ldb_msg;

/* FIXME: Convert ldb_result to 3-tuple:
   (msgs, refs, controls)
 */

typedef struct ldb_ldif ldb_ldif;

#ifdef SWIGPYTHON
%{
static void py_ldb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3, 0);

static void py_ldb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap)
{
    char *text;
    PyObject *fn = context;

    vasprintf(&text, fmt, ap);
    PyObject_CallFunction(fn, (char *)"(i,s)", level, text);
    free(text);
}
%}

%typemap(in,numinputs=1,noblock=1) (void (*debug)(void *context, enum ldb_debug_level level, const char *fmt, va_list ap), void *context) {
    $1 = py_ldb_debug;
    /* FIXME: Should be decreased somewhere as well. Perhaps register a 
       destructor and tie it to the ldb context ? */
    Py_INCREF($input);
    $2 = $input;
}
#endif

%inline {
    static PyObject *ldb_ldif_to_pyobject(ldb_ldif *ldif)
    {
        if (ldif == NULL) {
            return Py_None;
        } else {
            return Py_BuildValue((char *)"(iO)", ldif->changetype, 
                   SWIG_NewPointerObj(ldif->msg, SWIGTYPE_p_ldb_message, 0));
        }
    }
}

/*
 * Wrap ldb errors
 */

%{
PyObject *PyExc_LdbError;
%}

%pythoncode %{
    LdbError = _ldb.LdbError
%}

%init %{
    PyExc_LdbError = PyErr_NewException((char *)"_ldb.LdbError", NULL, NULL);
    PyDict_SetItemString(d, "LdbError", PyExc_LdbError);
%}

%ignore _LDB_ERRORS_H_;
%ignore LDB_SUCCESS;
%include "include/ldb_errors.h"

/*
 * Wrap ldb functions 
 */


%typemap(out,noblock=1) ldb_error {
    if ($1 != LDB_SUCCESS) {
        PyErr_SetObject(PyExc_LdbError, Py_BuildValue((char *)"(i,s)", $1, ldb_errstring(arg1)));
        SWIG_fail;
    }
    $result = Py_None;
};

%typemap(out,noblock=1) ldb_int_error {
    if ($1 != LDB_SUCCESS) {
        PyErr_SetObject(PyExc_LdbError, Py_BuildValue((char *)"(i,s)", $1, ldb_strerror($1)));
        SWIG_fail;
    }
    $result = Py_None;
};

%typemap(out,noblock=1) struct ldb_control ** {
    if ($1 == NULL) {
        PyErr_SetObject(PyExc_LdbError, Py_BuildValue((char *)"(s)", ldb_errstring(arg1)));
        SWIG_fail;
    }
    $result = SWIG_NewPointerObj($1, $1_descriptor, 0);
}

%rename(Ldb) ldb_context;

%typemap(in,noblock=1) struct ldb_dn * {
    if (ldb_dn_from_pyobject(NULL, $input, arg1, &$1) != 0) {
        SWIG_fail;
    }
};

%typemap(freearg,noblock=1) struct ldb_dn * {
    talloc_free($1);
};

%typemap(in,numinputs=1) ldb_msg *add_msg {
    Py_ssize_t dict_pos, msg_pos;
    ldb_msg_element *msgel;
    PyObject *key, *value;

    if (PyDict_Check($input)) {
 	PyObject *dn_value = PyDict_GetItemString($input, "dn");
        $1 = ldb_msg_new(NULL);
        $1->elements = talloc_zero_array($1, struct ldb_message_element, PyDict_Size($input));
        msg_pos = dict_pos = 0;
	if (dn_value) {
                /* using argp1 (magic SWIG value) here is a hack */
                if (ldb_dn_from_pyobject($1, dn_value, argp1, &$1->dn) != 0) {
                    SWIG_exception(SWIG_TypeError, "unable to import dn object");
                }
		if ($1->dn == NULL) {
		    SWIG_exception(SWIG_TypeError, "dn set but not found");
		}
	}

	while (PyDict_Next($input, &dict_pos, &key, &value)) {
	    char *key_str = PyString_AsString(key);
            if (strcmp(key_str, "dn") != 0) {
                msgel = ldb_msg_element_from_pyobject($1->elements, value, 0, key_str);
                if (msgel == NULL) {
                    SWIG_exception(SWIG_TypeError, "unable to import element");
                }
                memcpy(&$1->elements[msg_pos], msgel, sizeof(*msgel));
                msg_pos++;
            }
        }

        if ($1->dn == NULL) {
            SWIG_exception(SWIG_TypeError, "no dn set");
        }

        $1->num_elements = msg_pos;
    } else {
        if (SWIG_ConvertPtr($input, (void **)&$1, SWIGTYPE_p_ldb_message, 0) != 0) {
            SWIG_exception(SWIG_TypeError, "unable to convert ldb message");
        }
    }
}

/* Top-level ldb operations */
typedef struct ldb_context {
    %extend {
        ldb(void) { return ldb_init(NULL); }

        ldb_error connect(const char *url, unsigned int flags = 0, 
            const char *options[] = NULL);

        ~ldb() { talloc_free($self); }
        ldb_error search_ex(TALLOC_CTX *mem_ctx,
                   ldb_dn *base = NULL, 
                   enum ldb_scope scope = LDB_SCOPE_DEFAULT, 
                   const char *expression = NULL, 
                   const char *const *attrs = NULL, 
                   struct ldb_control **controls = NULL,
                   struct ldb_result **OUT) {
            int ret;
            struct ldb_result *res;
            struct ldb_request *req;
            res = talloc_zero(mem_ctx, struct ldb_result);
            if (!res) {
                return LDB_ERR_OPERATIONS_ERROR;
            }

            ret = ldb_build_search_req(&req, $self, mem_ctx,
                           base?base:ldb_get_default_basedn($self),
                           scope,
                           expression,
                           attrs,
                           controls,
                           res,
                           ldb_search_default_callback);

            if (ret != LDB_SUCCESS) {
                talloc_free(res);
                return ret;
            }

            ldb_set_timeout($self, req, 0); /* use default timeout */
                
            ret = ldb_request($self, req);
                
            if (ret == LDB_SUCCESS) {
                ret = ldb_wait(req->handle, LDB_WAIT_ALL);
            }

            talloc_free(req);

            *OUT = res;
            return ret;
        }

        ldb_error delete(ldb_dn *dn);
        ldb_error rename(ldb_dn *olddn, ldb_dn *newdn);
        struct ldb_control **parse_control_strings(TALLOC_CTX *mem_ctx, 
                                                   const char * const*control_strings);
        ldb_error add(ldb_msg *add_msg);
        ldb_error modify(ldb_msg *message);
        ldb_dn *get_config_basedn();
        ldb_dn *get_root_basedn();
        ldb_dn *get_schema_basedn();
        ldb_dn *get_default_basedn();
        PyObject *schema_format_value(const char *element_name, PyObject *val)
        {
        	const struct ldb_schema_attribute *a;
        	struct ldb_val old_val;
        	struct ldb_val new_val;
        	TALLOC_CTX *mem_ctx = talloc_new(NULL);
        	PyObject *ret;
        	
        	old_val.data = PyString_AsString(val);
        	old_val.length = PyString_Size(val);
                
        	a = ldb_schema_attribute_by_name($self, element_name);
        
        	if (a == NULL) {
        		return Py_None;
        	}
        	
        	if (a->syntax->ldif_write_fn($self, mem_ctx, &old_val, &new_val) != 0) {
        		talloc_free(mem_ctx);
        		return Py_None;
        	 }
        
		ret = PyString_FromStringAndSize((const char *)new_val.data, new_val.length);
		
		talloc_free(mem_ctx);
		
		return ret;
        }

        const char *errstring();
        void set_create_perms(unsigned int perms);
        void set_modules_dir(const char *path);
        ldb_error set_debug(void (*debug)(void *context, enum ldb_debug_level level, 
                                          const char *fmt, va_list ap),
                            void *context);
        ldb_error set_opaque(const char *name, void *value);
        void *get_opaque(const char *name);
        ldb_error transaction_start();
        ldb_error transaction_commit();
        ldb_error transaction_cancel();
        void schema_attribute_remove(const char *name);
        ldb_error schema_attribute_add(const char *attribute, unsigned flags, const char *syntax);
	ldb_error setup_wellknown_attributes(void);
	
#ifdef SWIGPYTHON
        %typemap(in,numinputs=0,noblock=1) struct ldb_result **result_as_bool (struct ldb_result *tmp) { $1 = &tmp; }
        %typemap(argout,noblock=1) struct ldb_result **result_as_bool { $result = ((*$1)->count > 0)?Py_True:Py_False; }
        %typemap(freearg,noblock=1) struct ldb_result **result_as_bool { talloc_free(*$1); }
        ldb_error __contains__(ldb_dn *dn, struct ldb_result **result_as_bool)
        {
            return ldb_search($self, dn, LDB_SCOPE_BASE, NULL, NULL, 
                             result_as_bool);
        }

        PyObject *parse_ldif(const char *s)
        {
            PyObject *list = PyList_New(0);
            struct ldb_ldif *ldif;
            while ((ldif = ldb_ldif_read_string($self, &s)) != NULL) {
                PyList_Append(list, ldb_ldif_to_pyobject(ldif));
            }
            return PyObject_GetIter(list);
        }

#endif
    }
    %pythoncode {
        def __init__(self, url=None, flags=0, options=None):
            _ldb.Ldb_swiginit(self,_ldb.new_Ldb())
            if url is not None:
                self.connect(url, flags, options)

        def search(self, base=None, scope=SCOPE_DEFAULT, expression=None, 
                   attrs=None, controls=None):
            parsed_controls = None
            if controls is not None:
                parsed_controls = self.parse_control_strings(controls)
            return self.search_ex(base, scope, expression, attrs, 
                                  parsed_controls)
    }

} ldb;

%typemap(in,noblock=1) struct ldb_dn *;
%typemap(freearg,noblock=1) struct ldb_dn *;

%nodefault ldb_message;
%nodefault ldb_context;
%nodefault Dn;

%rename(valid_attr_name) ldb_valid_attr_name;
int ldb_valid_attr_name(const char *s);

typedef unsigned long time_t;

%inline %{
static char *timestring(time_t t)
{
    char *tresult = ldb_timestring(NULL, t);
    char *result = strdup(tresult);
    talloc_free(tresult);
    return result; 
}
%}

%rename(string_to_time) ldb_string_to_time;
time_t ldb_string_to_time(const char *s);

%typemap(in,noblock=1) const struct ldb_module_ops * {
    $1 = talloc_zero(talloc_autofree_context(), struct ldb_module_ops);

    $1->name = (char *)PyObject_GetAttrString($input, (char *)"name");
}

%rename(register_module) ldb_register_module;
ldb_int_error ldb_register_module(const struct ldb_module_ops *);
