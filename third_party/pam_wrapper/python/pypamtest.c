/*
 * Copyright (c) 2015 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <Python.h>
#include <structmember.h>

#include "libpamtest.h"

#define PYTHON_MODULE_NAME  "pypamtest"

#ifndef discard_const_p
#if defined(__intptr_t_defined) || defined(HAVE_UINTPTR_T)
# define discard_const_p(type, ptr) ((type *)((uintptr_t)(ptr)))
#else
# define discard_const_p(type, ptr) ((type *)(ptr))
#endif
#endif

#define    __unused    __attribute__((__unused__))

#if PY_MAJOR_VERSION >= 3
#define IS_PYTHON3 1
#define RETURN_ON_ERROR return NULL
#else
#define IS_PYTHON3 0
#define RETURN_ON_ERROR return
#endif /* PY_MAJOR_VERSION */

/* We only return up to 16 messages from the PAM conversation */
#define PAM_CONV_MSG_MAX	16

#if IS_PYTHON3
PyMODINIT_FUNC PyInit_pypamtest(void);
#else
PyMODINIT_FUNC initpypamtest(void);
#endif

typedef struct {
	PyObject_HEAD

	enum pamtest_ops pam_operation;
	int expected_rv;
	int flags;
} TestCaseObject;

/**********************************************************
 *** module-specific exceptions
 **********************************************************/
static PyObject *PyExc_PamTestError;

/**********************************************************
 *** helper functions
 **********************************************************/

#define REPR_FMT "{ pam_operation [%d] " \
			      "expected_rv [%d] " \
			      "flags [%d] }"

static char *py_strdup(const char *string)
{
	char *copy;

	copy = PyMem_New(char, strlen(string) + 1);
	if (copy ==  NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return strcpy(copy, string);
}

static PyObject *get_utf8_string(PyObject *obj,
				 const char *attrname)
{
	const char *a = attrname ? attrname : "attribute";
	PyObject *obj_utf8 = NULL;

	if (PyBytes_Check(obj)) {
		obj_utf8 = obj;
		Py_INCREF(obj_utf8); /* Make sure we can DECREF later */
	} else if (PyUnicode_Check(obj)) {
		if ((obj_utf8 = PyUnicode_AsUTF8String(obj)) == NULL) {
			return NULL;
		}
	} else {
		PyErr_Format(PyExc_TypeError, "%s must be a string", a);
		return NULL;
	}

	return obj_utf8;
}

static void free_cstring_list(const char **list)
{
	int i;

	if (list == NULL) {
		return;
	}

	for (i=0; list[i]; i++) {
		PyMem_Free(discard_const_p(char, list[i]));
	}
	PyMem_Free(list);
}

static void free_string_list(char **list)
{
	int i;

	if (list == NULL) {
		return;
	}

	for (i=0; list[i]; i++) {
		PyMem_Free(list[i]);
	}
	PyMem_Free(list);
}

static char **new_conv_list(const size_t list_size)
{
	char **list;
	size_t i;

	if (list_size == 0) {
		return NULL;
	}

	if (list_size + 1 < list_size) {
		return NULL;
	}

	list = PyMem_New(char *, list_size + 1);
	if (list == NULL) {
		return NULL;
	}
	list[list_size] = NULL;

	for (i = 0; i < list_size; i++) {
		list[i] = PyMem_New(char, PAM_MAX_MSG_SIZE);
		if (list[i] == NULL) {
			PyMem_Free(list);
			return NULL;
		}
		memset(list[i], 0, PAM_MAX_MSG_SIZE);
	}

	return list;
}

static int sequence_as_string_list(PyObject *seq,
				   const char *paramname,
				   const char **str_list[],
				   size_t *num_str_list)
{
	const char *p = paramname ? paramname : "attribute values";
	const char **result;
	PyObject *utf_item;
	int i;
	Py_ssize_t len;
	PyObject *item;

	if (!PySequence_Check(seq)) {
		PyErr_Format(PyExc_TypeError,
			     "The object must be a sequence\n");
		return -1;
	}

	len = PySequence_Size(seq);
	if (len == -1) {
		return -1;
	}

	result = PyMem_New(const char *, (len + 1));
	if (result == NULL) {
		PyErr_NoMemory();
		return -1;
	}

	for (i = 0; i < len; i++) {
		item = PySequence_GetItem(seq, i);
		if (item == NULL) {
			break;
		}

		utf_item = get_utf8_string(item, p);
		if (utf_item == NULL) {
			Py_DECREF(item);
			return -1;
		}

		result[i] = py_strdup(PyBytes_AsString(utf_item));
		Py_DECREF(utf_item);
		if (result[i] == NULL) {
			Py_DECREF(item);
			return -1;
		}
		Py_DECREF(item);
	}

	result[i] = NULL;

	*str_list = result;
	*num_str_list = (size_t)len;

	return 0;
}

static PyObject *string_list_as_tuple(char **str_list)
{
	int rc;
	size_t len, i;
	PyObject *tup;
	PyObject *py_str;

	for (len=0; str_list[len] != NULL; len++) {
		if (str_list[len][0] == '\0') {
			/* unused string, stop counting */
			break;
		}
	}

	tup = PyTuple_New(len);
	if (tup == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	for (i = 0; i < len; i++) {
		py_str = PyUnicode_FromString(str_list[i]);
		if (py_str == NULL) {
			Py_DECREF(tup);
			PyErr_NoMemory();
			return NULL;
		}

		/* PyTuple_SetItem() steals the reference to
		 * py_str, so it's enough to decref the tuple
		 * pointer afterwards */
		rc = PyTuple_SetItem(tup, i, py_str);
		if (rc != 0) {
			/* cleanup */
			Py_DECREF(py_str);
			Py_DECREF(tup);
			PyErr_NoMemory();
			return NULL;
		}
	}

	return tup;
}

static void
set_pypamtest_exception(PyObject *exc,
			enum pamtest_err perr,
			struct pam_testcase *tests,
			size_t num_tests)
{
	PyObject *obj = NULL;
	/* REPR_FMT contains just %d expansions, so this is safe */
	char test_repr[256] = { '\0' };
	union {
		char *str;
		PyObject *obj;
	} pypam_str_object;
	const char *strerr;
	const struct pam_testcase *failed = NULL;

	if (exc == NULL) {
		PyErr_BadArgument();
		return;
	}

	strerr = pamtest_strerror(perr);

	if (perr == PAMTEST_ERR_CASE) {
		failed = _pamtest_failed_case(tests, num_tests);
		if (failed) {
			snprintf(test_repr, sizeof(test_repr), REPR_FMT,
				 failed->pam_operation,
				 failed->expected_rv,
				 failed->flags);
		}
	}

	if (test_repr[0] != '\0' && failed != NULL) {
		PyErr_Format(exc,
			     "Error [%d]: Test case %s returned [%d]",
			     perr, test_repr, failed->op_rv);
	} else {
		obj = Py_BuildValue(discard_const_p(char, "(i,s)"),
					perr,
					strerr ? strerr : "Unknown error");
		PyErr_SetObject(exc, obj);
	}

	pypam_str_object.str = test_repr;
	Py_XDECREF(pypam_str_object.obj);
	Py_XDECREF(obj);
}

/* Returned when doc(test_case) is invoked */
PyDoc_STRVAR(TestCaseObject__doc__,
"pamtest test case\n\n"
"Represents one operation in PAM transaction. An example is authentication, "
"opening a session or password change. Each operation has an expected error "
"code. The run_pamtest() function accepts a list of these test case objects\n"
"Params:\n\n"
"pam_operation: - the PAM operation to run. Use constants from pypamtest "
"such as pypamtest.PAMTEST_AUTHENTICATE. This argument is required.\n"
"expected_rv: - The PAM return value we expect the operation to return. "
"Defaults to 0 (PAM_SUCCESS)\n"
"flags: - Additional flags to pass to the PAM operation. Defaults to 0.\n"
);

static PyObject *
TestCase_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	TestCaseObject *self;

	(void) args; /* unused */
	(void) kwds; /* unused */

	self = (TestCaseObject *)type->tp_alloc(type, 0);
	if (self == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return (PyObject *) self;
}

/* The traverse and clear methods must be defined even though they do nothing
 * otherwise Garbage Collector is not happy
 */
static int TestCase_clear(TestCaseObject *self)
{
	(void) self; /* unused */

	return 0;
}

static void TestCase_dealloc(TestCaseObject *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int TestCase_traverse(TestCaseObject *self,
			     visitproc visit,
			     void *arg)
{
	(void) self; /* unused */
	(void) visit; /* unused */
	(void) arg; /* unused */

	return 0;
}

static int TestCase_init(TestCaseObject *self,
			 PyObject *args,
			 PyObject *kwargs)
{
	const char * const kwlist[] = { "pam_operation",
					"expected_rv",
					"flags",
					NULL };
	int pam_operation = -1;
	int expected_rv = PAM_SUCCESS;
	int flags = 0;
	int ok;

	ok = PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "i|ii",
					 discard_const_p(char *, kwlist),
					 &pam_operation,
					 &expected_rv,
					 &flags);
	if (!ok) {
		return -1;
	}

	switch (pam_operation) {
	case PAMTEST_AUTHENTICATE:
	case PAMTEST_SETCRED:
	case PAMTEST_ACCOUNT:
	case PAMTEST_OPEN_SESSION:
	case PAMTEST_CLOSE_SESSION:
	case PAMTEST_CHAUTHTOK:
	case PAMTEST_GETENVLIST:
	case PAMTEST_KEEPHANDLE:
		break;
	default:
		PyErr_Format(PyExc_ValueError,
			     "Unsupported PAM operation %d",
			     pam_operation);
		return -1;
	}

	self->flags = flags;
	self->expected_rv = expected_rv;
	self->pam_operation = pam_operation;

	return 0;
}

/*
 * This function returns string representation of the object, but one that
 * can be parsed by a machine.
 *
 * str() is also string represtentation, but just human-readable.
 */
static PyObject *TestCase_repr(TestCaseObject *self)
{
	return PyUnicode_FromFormat(REPR_FMT,
				    self->pam_operation,
				    self->expected_rv,
				    self->flags);
}

static PyMemberDef pypamtest_test_case_members[] = {
	{
		discard_const_p(char, "pam_operation"),
		T_INT,
		offsetof(TestCaseObject, pam_operation),
		READONLY,
		discard_const_p(char, "The PAM operation to run"),
	},

	{
		discard_const_p(char, "expected_rv"),
		T_INT,
		offsetof(TestCaseObject, expected_rv),
		READONLY,
		discard_const_p(char, "The expected PAM return code"),
	},

	{
		discard_const_p(char, "flags"),
		T_INT,
		offsetof(TestCaseObject, flags),
		READONLY,
		discard_const_p(char, "Additional flags for the PAM operation"),
	},

	{ NULL, 0, 0, 0, NULL } /* Sentinel */
};

static PyTypeObject pypamtest_test_case = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "pypamtest.TestCase",
	.tp_basicsize = sizeof(TestCaseObject),
	.tp_new = TestCase_new,
	.tp_dealloc = (destructor) TestCase_dealloc,
	.tp_traverse = (traverseproc) TestCase_traverse,
	.tp_clear = (inquiry) TestCase_clear,
	.tp_init = (initproc) TestCase_init,
	.tp_repr = (reprfunc) TestCase_repr,
	.tp_members = pypamtest_test_case_members,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
	.tp_doc   = TestCaseObject__doc__
};

PyDoc_STRVAR(TestResultObject__doc__,
"pamtest test result\n\n"
"The test result object is returned from run_pamtest on success. It contains"
"two lists of strings (up to 16 strings each) which contain the info and error"
"messages the PAM conversation printed\n\n"
"Attributes:\n"
"errors: PAM_ERROR_MSG-level messages printed during the PAM conversation\n"
"info: PAM_TEXT_INFO-level messages printed during the PAM conversation\n"
);

typedef struct {
	PyObject_HEAD

	PyObject *info_msg_list;
	PyObject *error_msg_list;
} TestResultObject;

static PyObject *
TestResult_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	TestResultObject *self;

	(void) args; /* unused */
	(void) kwds; /* unused */

	self = (TestResultObject *)type->tp_alloc(type, 0);
	if (self == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	return (PyObject *) self;
}

static int TestResult_clear(TestResultObject *self)
{
	(void) self; /* unused */

	return 0;
}

static void TestResult_dealloc(TestResultObject *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int TestResult_traverse(TestResultObject *self,
			       visitproc visit,
			       void *arg)
{
	(void) self;	/* unused */
	(void) visit;	/* unused */
	(void) arg;	/* unused */

	return 0;
}

static int TestResult_init(TestResultObject *self,
			   PyObject *args,
			   PyObject *kwargs)
{
	const char * const kwlist[] = { "info_msg_list",
					"error_msg_list",
					NULL };
	int ok;
	PyObject *py_info_list = NULL;
	PyObject *py_err_list = NULL;

	ok = PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "|OO",
					 discard_const_p(char *, kwlist),
					 &py_info_list,
					 &py_err_list);
	if (!ok) {
		return -1;
	}

	if (py_info_list) {
		ok = PySequence_Check(py_info_list);
		if (!ok) {
			PyErr_Format(PyExc_TypeError,
				"List of info messages must be a sequence\n");
			return -1;
		}

		self->info_msg_list = py_info_list;
		Py_XINCREF(py_info_list);
	} else {
		self->info_msg_list = PyList_New(0);
		if (self->info_msg_list == NULL) {
			PyErr_NoMemory();
			return -1;
		}
	}

	if (py_err_list) {
		ok = PySequence_Check(py_err_list);
		if (!ok) {
			PyErr_Format(PyExc_TypeError,
				"List of error messages must be a sequence\n");
			return -1;
		}

		self->error_msg_list = py_err_list;
		Py_XINCREF(py_err_list);
	} else {
		self->error_msg_list = PyList_New(0);
		if (self->error_msg_list == NULL) {
			PyErr_NoMemory();
			return -1;
		}
	}

	return 0;
}

static PyObject *test_result_list_concat(PyObject *list,
					 const char delim_pre,
					 const char delim_post)
{
	PyObject *res;
	PyObject *item;
	Py_ssize_t size;
	Py_ssize_t i;

	res = PyUnicode_FromString("");
	if (res == NULL) {
		return NULL;
	}

	size = PySequence_Size(list);

	for (i=0; i < size; i++) {
		item = PySequence_GetItem(list, i);
		if (item == NULL) {
			PyMem_Free(res);
			return NULL;
		}

#if IS_PYTHON3
		res = PyUnicode_FromFormat("%U%c%U%c",
					   res, delim_pre, item, delim_post);
#else
		res = PyUnicode_FromFormat("%U%c%s%c",
					   res,
					   delim_pre,
					   PyString_AsString(item),
					   delim_post);
#endif
		Py_XDECREF(item);
	}

	return res;
}

static PyObject *TestResult_repr(TestResultObject *self)
{
	PyObject *u_info = NULL;
	PyObject *u_error = NULL;
	PyObject *res = NULL;

	u_info = test_result_list_concat(self->info_msg_list, '{', '}');
	u_error = test_result_list_concat(self->info_msg_list, '{', '}');
	if (u_info == NULL || u_error == NULL) {
		Py_XDECREF(u_error);
		Py_XDECREF(u_info);
		return NULL;
	}

	res = PyUnicode_FromFormat("{ errors: { %U } infos: { %U } }",
				   u_info, u_error);
	Py_DECREF(u_error);
	Py_DECREF(u_info);
	return res;
}

static PyMemberDef pypamtest_test_result_members[] = {
	{
		discard_const_p(char, "errors"),
		T_OBJECT_EX,
		offsetof(TestResultObject, error_msg_list),
		READONLY,
		discard_const_p(char,
				"List of error messages from PAM conversation"),
	},

	{
		discard_const_p(char, "info"),
		T_OBJECT_EX,
		offsetof(TestResultObject, info_msg_list),
		READONLY,
		discard_const_p(char,
				"List of info messages from PAM conversation"),
	},

	{ NULL, 0, 0, 0, NULL } /* Sentinel */
};

static PyTypeObject pypamtest_test_result = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "pypamtest.TestResult",
	.tp_basicsize = sizeof(TestResultObject),
	.tp_new = TestResult_new,
	.tp_dealloc = (destructor) TestResult_dealloc,
	.tp_traverse = (traverseproc) TestResult_traverse,
	.tp_clear = (inquiry) TestResult_clear,
	.tp_init = (initproc) TestResult_init,
	.tp_repr = (reprfunc) TestResult_repr,
	.tp_members = pypamtest_test_result_members,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
	.tp_doc   = TestResultObject__doc__
};

/**********************************************************
 *** Methods of the module
 **********************************************************/

static TestResultObject *construct_test_conv_result(char **msg_info, char **msg_err)
{
	PyObject *py_msg_info = NULL;
	PyObject *py_msg_err = NULL;
	TestResultObject *result = NULL;
	PyObject *result_args = NULL;
	int rc;

	py_msg_info = string_list_as_tuple(msg_info);
	py_msg_err = string_list_as_tuple(msg_err);
	if (py_msg_info == NULL || py_msg_err == NULL) {
		/* The exception is raised in string_list_as_tuple() */
		Py_XDECREF(py_msg_err);
		Py_XDECREF(py_msg_info);
		return NULL;
	}

	result = (TestResultObject *) TestResult_new(&pypamtest_test_result,
						     NULL,
						     NULL);
	if (result == NULL) {
		/* The exception is raised in TestResult_new */
		Py_XDECREF(py_msg_err);
		Py_XDECREF(py_msg_info);
		return NULL;
	}

	result_args = PyTuple_New(2);
	if (result_args == NULL) {
		/* The exception is raised in TestResult_new */
		Py_XDECREF(result);
		Py_XDECREF(py_msg_err);
		Py_XDECREF(py_msg_info);
		return NULL;
	}

	/* Brand new tuples with fixed size don't need error checking */
	PyTuple_SET_ITEM(result_args, 0, py_msg_info);
	PyTuple_SET_ITEM(result_args, 1, py_msg_err);

	rc = TestResult_init(result, result_args, NULL);
	Py_XDECREF(result_args);
	if (rc != 0) {
		Py_XDECREF(result);
		return NULL;
	}

	return result;
}

static int py_testcase_get(PyObject *py_test,
			   const char *member_name,
			   long *_value)
{
	PyObject* item = NULL;

	/*
	 * PyPyObject_GetAttrString() increases the refcount on the
	 * returned value.
	 */
	item = PyObject_GetAttrString(py_test, member_name);
	if (item == NULL) {
		return EINVAL;
	}

	*_value = PyLong_AsLong(item);
	Py_DECREF(item);

	return 0;
}

static int py_testcase_to_cstruct(PyObject *py_test, struct pam_testcase *test)
{
	int rc;
	long value;

	rc = py_testcase_get(py_test, "pam_operation", &value);
	if (rc != 0) {
		return rc;
	}
	test->pam_operation = value;

	rc = py_testcase_get(py_test, "expected_rv", &value);
	if (rc != 0) {
		return rc;
	}
	test->expected_rv = value;

	rc = py_testcase_get(py_test, "flags", &value);
	if (rc != 0) {
		return rc;
	}
	test->flags = value;

	return 0;
}

static void free_conv_data(struct pamtest_conv_data *conv_data)
{
	if (conv_data == NULL) {
		return;
	}

	free_string_list(conv_data->out_err);
	free_string_list(conv_data->out_info);
	free_cstring_list(conv_data->in_echo_on);
	free_cstring_list(conv_data->in_echo_off);
}

/* conv_data must be a pointer to allocated conv_data structure.
 *
 * Use free_conv_data() to free the contents.
 */
static int fill_conv_data(PyObject *py_echo_off,
			  PyObject *py_echo_on,
			  struct pamtest_conv_data *conv_data)
{
	size_t conv_count = 0;
	size_t count = 0;
	int rc;

	conv_data->in_echo_on = NULL;
	conv_data->in_echo_off = NULL;
	conv_data->out_err = NULL;
	conv_data->out_info = NULL;

	if (py_echo_off != NULL) {
		rc = sequence_as_string_list(py_echo_off,
					     "echo_off",
					     &conv_data->in_echo_off,
					     &count);
		if (rc != 0) {
			free_conv_data(conv_data);
			return ENOMEM;
		}
		conv_count += count;
	}

	if (py_echo_on != NULL) {
		rc = sequence_as_string_list(py_echo_on,
					     "echo_on",
					     &conv_data->in_echo_on,
					     &count);
		if (rc != 0) {
			free_conv_data(conv_data);
			return ENOMEM;
		}
		conv_count += count;
	}

	if (conv_count > PAM_CONV_MSG_MAX) {
		free_conv_data(conv_data);
		return ENOMEM;
	}

	conv_data->out_info = new_conv_list(PAM_CONV_MSG_MAX);
	conv_data->out_err = new_conv_list(PAM_CONV_MSG_MAX);
	if (conv_data->out_info == NULL || conv_data->out_err == NULL) {
		free_conv_data(conv_data);
		return ENOMEM;
	}

	return 0;
}

/* test_list is allocated using PyMem_New and must be freed accordingly.
 * Returns errno that should be handled into exception in the caller
 */
static int py_tc_list_to_cstruct_list(PyObject *py_test_list,
				      Py_ssize_t num_tests,
				      struct pam_testcase **_test_list)
{
	Py_ssize_t i;
	PyObject *py_test;
	int rc;
	struct pam_testcase *test_list;

	test_list = PyMem_New(struct pam_testcase,
			    num_tests * sizeof(struct pam_testcase));
	if (test_list == NULL) {
		return ENOMEM;
	}

	for (i = 0; i < num_tests; i++) {
		/*
		 * PySequence_GetItem() increases the refcount on the
		 * returned value
		 */
		py_test = PySequence_GetItem(py_test_list, i);
		if (py_test == NULL) {
			PyMem_Free(test_list);
			return EIO;
		}

		rc = py_testcase_to_cstruct(py_test, &test_list[i]);
		Py_DECREF(py_test);
		if (rc != 0) {
			PyMem_Free(test_list);
			return EIO;
		}
	}

	*_test_list = test_list;
	return 0;
}

PyDoc_STRVAR(RunPamTest__doc__,
"Run PAM tests\n\n"
"This function runs PAM test cases and reports result\n"
"Parameters:\n"
"service: The PAM service to use in the conversation (string)\n"
"username: The user to run PAM conversation as\n"
"test_list: Sequence of pypamtest.TestCase objects\n"
"echo_off_list: Sequence of strings that will be used by PAM "
"conversation for PAM_PROMPT_ECHO_OFF input. These are typically "
"passwords.\n"
"echo_on_list: Sequence of strings that will be used by PAM "
"conversation for PAM_PROMPT_ECHO_ON input.\n"
);

static PyObject *pypamtest_run_pamtest(PyObject *module, PyObject *args)
{
	int ok;
	int rc;
	char *username = NULL;
	char *service = NULL;
	PyObject *py_test_list;
	PyObject *py_echo_off = NULL;
	PyObject *py_echo_on = NULL;
	Py_ssize_t num_tests;
	struct pam_testcase *test_list;
	enum pamtest_err perr;
	struct pamtest_conv_data conv_data;
	TestResultObject *result = NULL;

	(void) module;	/* unused */

	ok = PyArg_ParseTuple(args,
			      discard_const_p(char, "ssO|OO"),
			      &username,
			      &service,
			      &py_test_list,
			      &py_echo_off,
			      &py_echo_on);
	if (!ok) {
		return NULL;
	}

	ok = PySequence_Check(py_test_list);
	if (!ok) {
		PyErr_Format(PyExc_TypeError, "tests must be a sequence");
		return NULL;
	}

	num_tests = PySequence_Size(py_test_list);
	if (num_tests == -1) {
		PyErr_Format(PyExc_IOError, "Cannot get sequence length");
		return NULL;
	}

	rc = py_tc_list_to_cstruct_list(py_test_list, num_tests, &test_list);
	if (rc != 0) {
		if (rc == ENOMEM) {
			PyErr_NoMemory();
			return NULL;
		} else {
			PyErr_Format(PyExc_IOError,
				     "Cannot convert test to C structure");
			return NULL;
		}
	}

	rc = fill_conv_data(py_echo_off, py_echo_on, &conv_data);
	if (rc != 0) {
		PyMem_Free(test_list);
		PyErr_NoMemory();
		return NULL;
	}

	perr = _pamtest(service, username, &conv_data, test_list, num_tests);
	if (perr != PAMTEST_ERR_OK) {
		free_conv_data(&conv_data);
		set_pypamtest_exception(PyExc_PamTestError,
					perr,
					test_list,
					num_tests);
		PyMem_Free(test_list);
		return NULL;
	}
	PyMem_Free(test_list);

	result = construct_test_conv_result(conv_data.out_info,
					    conv_data.out_err);
	free_conv_data(&conv_data);
	if (result == NULL) {
		PyMem_Free(test_list);
		return NULL;
	}

	return (PyObject *)result;
}

static PyMethodDef pypamtest_module_methods[] = {
	{
		discard_const_p(char, "run_pamtest"),
		(PyCFunction) pypamtest_run_pamtest,
		METH_VARARGS,
		RunPamTest__doc__,
	},

	{ NULL, NULL, 0, NULL }  /* Sentinel */
};

/*
 * This is the module structure describing the module and
 * to define methods
 */
#if IS_PYTHON3
static struct PyModuleDef pypamtestdef = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = PYTHON_MODULE_NAME,
	.m_size = -1,
	.m_methods = pypamtest_module_methods,
};
#endif

/**********************************************************
 *** Initialize the module
 **********************************************************/

#if PY_VERSION_HEX >= 0x02070000 /* >= 2.7.0 */
PyDoc_STRVAR(PamTestError__doc__,
"pypamtest specific exception\n\n"
"This exception is raised if the _pamtest() function fails. If _pamtest() "
"returns PAMTEST_ERR_CASE (a test case returns unexpected error code), then "
"the exception also details which test case failed."
);
#endif

#if IS_PYTHON3
PyMODINIT_FUNC PyInit_pypamtest(void)
#else
PyMODINIT_FUNC initpypamtest(void)
#endif
{
	PyObject *m;
	union {
		PyTypeObject *type_obj;
		PyObject *obj;
	} pypam_object;
	int ret;

#if IS_PYTHON3
	m = PyModule_Create(&pypamtestdef);
	if (m == NULL) {
		RETURN_ON_ERROR;
	}
#else
	m = Py_InitModule(discard_const_p(char, PYTHON_MODULE_NAME),
			  pypamtest_module_methods);
#endif

#if PY_VERSION_HEX >= 0x02070000 /* >= 2.7.0 */
	PyExc_PamTestError = PyErr_NewExceptionWithDoc(discard_const_p(char, "pypamtest.PamTestError"),
						       PamTestError__doc__,
						       PyExc_EnvironmentError,
						       NULL);
#else /* < 2.7.0 */
	PyExc_PamTestError = PyErr_NewException(discard_const_p(char, "pypamtest.PamTestError"),
						       PyExc_EnvironmentError,
						       NULL);
#endif

	if (PyExc_PamTestError == NULL) {
		RETURN_ON_ERROR;
	}

	Py_INCREF(PyExc_PamTestError);
	ret = PyModule_AddObject(m, discard_const_p(char, "PamTestError"),
				 PyExc_PamTestError);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}

	ret = PyModule_AddIntMacro(m, PAMTEST_AUTHENTICATE);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_SETCRED);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_ACCOUNT);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_OPEN_SESSION);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_CLOSE_SESSION);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_CHAUTHTOK);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}

	ret = PyModule_AddIntMacro(m, PAMTEST_GETENVLIST);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}
	ret = PyModule_AddIntMacro(m, PAMTEST_KEEPHANDLE);
	if (ret == -1) {
		RETURN_ON_ERROR;
	}

	pypam_object.type_obj = &pypamtest_test_case;
	if (PyType_Ready(pypam_object.type_obj) < 0) {
		RETURN_ON_ERROR;
	}
	Py_INCREF(pypam_object.obj);
	PyModule_AddObject(m, "TestCase", pypam_object.obj);

	pypam_object.type_obj = &pypamtest_test_result;
	if (PyType_Ready(pypam_object.type_obj) < 0) {
		RETURN_ON_ERROR;
	}
	Py_INCREF(pypam_object.obj);
	PyModule_AddObject(m, "TestResult", pypam_object.obj);

#if IS_PYTHON3
	return m;
#endif
}
