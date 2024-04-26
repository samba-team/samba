/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2008-2010
   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2009
   Copyright (C) Alexander Bokovoy <ab@samba.org> 2012

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

#include "lib/replace/system/python.h"
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "py_net.h"
#include "libnet_export_keytab.h"
#include "pyldb.h"
#include "libcli/util/pyerrors.h"

static PyObject *py_net_export_keytab(py_net_Object *self, PyObject *args, PyObject *kwargs)
{
	struct libnet_export_keytab r = { .in = { .principal = NULL, }};
	PyObject *py_samdb = NULL;
	TALLOC_CTX *mem_ctx;
	const char *kwnames[] = { "keytab",
				  "samdb",
				  "principal",
				  "keep_stale_entries",
				  "only_current_keys",
				  "as_for_AS_REQ",
				  NULL };
	NTSTATUS status;
	/*
	 * int, with values true or false, to match expectation of
	 * PyArg_ParseTupleAndKeywords()
	 */
	int keep_stale_entries = false;
	int only_current_keys = false;
	int as_for_AS_REQ = false;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|Ozppp:export_keytab", discard_const_p(char *, kwnames),
					 &r.in.keytab_name,
					 &py_samdb,
					 &r.in.principal,
					 &keep_stale_entries,
					 &only_current_keys,
					 &as_for_AS_REQ)) {
		return NULL;
	}

	r.in.keep_stale_entries = keep_stale_entries;
	r.in.only_current_keys = only_current_keys;
	r.in.as_for_AS_REQ = as_for_AS_REQ;

	if (py_samdb == NULL) {
		r.in.samdb = NULL;
	} else {
		PyErr_LDB_OR_RAISE(py_samdb, r.in.samdb);
	}

	mem_ctx = talloc_new(self->mem_ctx);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	status = libnet_export_keytab(self->libnet_ctx, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		PyErr_SetNTSTATUS_and_string(status,
					     r.out.error_string
					     ? r.out.error_string
					     : nt_errstr(status));
		talloc_free(mem_ctx);
		return NULL;
	}

	talloc_free(mem_ctx);

	Py_RETURN_NONE;
}

static const char py_net_export_keytab_doc[] =
	"export_keytab(keytab, samdb=None, principal=None, "
	"keep_stale_entries=False, only_current_keys=False, "
	"as_for_AS_REQ=False)\n\n"
	"Export the DC keytab to a keytab file.\n\n"
	"Pass as_for_AS_REQ=True to simulate the combination of flags normally "
	"utilized for an AS‐REQ. Samba’s testsuite uses this to verify which "
	"keys the KDC would see — some combination of previous and current "
	"keys — for a Group Managed Service Account performing an AS‐REQ.";

static PyMethodDef export_keytab_method_table[] = {
	{"export_keytab", PY_DISCARD_FUNC_SIG(PyCFunction,
					      py_net_export_keytab),
		METH_VARARGS|METH_KEYWORDS, py_net_export_keytab_doc},
	{ NULL, NULL, 0, NULL }
};

/*
 * A fake Python module to inject export_keytab() method into existing samba.net.Net class.
 * Python enforces that every loaded module actually creates Python module record in
 * the global module table even if we don't really need that record. Thus, we initialize
 * dckeytab module but never use it.
 * */
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "dckeytab",
    .m_doc = "dckeytab",
    .m_size = -1,
    .m_methods = NULL
};

MODULE_INIT_FUNC(dckeytab)
{
	PyObject *m = NULL;
	PyObject *Net;
	PyObject *descr;
	int ret;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return m;

	m = PyImport_ImportModule("samba.net");
        if (m == NULL)
		return m;

	Net = (PyObject *)PyObject_GetAttrString(m, "Net");
	if (Net == NULL)
		return m;

	descr = PyDescr_NewMethod((PyTypeObject*)Net, &export_keytab_method_table[0]);
	if (descr == NULL)
		return m;

	ret = PyDict_SetItemString(((PyTypeObject*)Net)->tp_dict,
				     export_keytab_method_table[0].ml_name,
				     descr);
	if (ret != -1) {
		Py_DECREF(descr);
	}

	return m;
}
