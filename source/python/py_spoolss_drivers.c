/* 
   Python wrappers for DCERPC/SMB client routines.

   Copyright (C) Tim Potter, 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Structure/hash conversions */

struct pyconv py_DRIVER_INFO_1[] = {
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_1, name) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_2[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_2, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_2, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_2, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_2, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_2, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_2, configfile) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_3[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_3, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_3, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_3, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_3, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_3, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_3, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_3, helpfile) },
	/* dependentfiles */
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_3, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_3, defaultdatatype) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_6[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_6, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_6, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_6, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_6, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_6, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_6, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_6, helpfile) },
	/* dependentfiles */
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_6, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_6, defaultdatatype) },
	/* driver_date */

	{ "padding", PY_UINT32, offsetof(DRIVER_INFO_6, padding) },
	{ "driver_version_low", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_low) },
	{ "driver_version_high", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_high) },
	{ "mfg_name", PY_UNISTR, offsetof(DRIVER_INFO_6, mfgname) },
	{ "oem_url", PY_UNISTR, offsetof(DRIVER_INFO_6, oem_url) },
	{ "hardware_id", PY_UNISTR, offsetof(DRIVER_INFO_6, hardware_id) },
	{ "provider", PY_UNISTR, offsetof(DRIVER_INFO_6, provider) },
	
	{ NULL }
};

struct pyconv py_DRIVER_DIRECTORY_1[] = {
	{ "name", PY_UNISTR, offsetof(DRIVER_DIRECTORY_1, name) },
	{ NULL }
};

/* Enumerate printer drivers */

static PyObject *spoolss_enumprinterdrivers(PyObject *self, PyObject *args,
					    PyObject *kw)
{
	WERROR werror;
	PyObject *result = Py_None, *creds = NULL;
	PRINTER_DRIVER_CTR ctr;
	int level = 1, i;
	uint32 needed, num_drivers;
	char *arch = "Windows NT x86", *server_name;
	static char *kwlist[] = {"server", "level", "arch", "creds", NULL};
	struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|isO!", kwlist, 
					 &server_name, &level, &arch,
					 &PyDict_Type, &creds))
		return NULL;
	
	/* Call rpc function */
	
	if (!(cli = open_pipe_creds(server_name, creds, 
				    cli_spoolss_initialise, NULL))) {
		fprintf(stderr, "could not initialise cli state\n");
		goto done;
	}

	if (!(mem_ctx = talloc_init())) {
		fprintf(stderr, "unable to initialise talloc context\n");
		goto done;
	}	

	werror = cli_spoolss_enumprinterdrivers(
		cli, mem_ctx, 0, &needed, level, arch,
		&num_drivers, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enumprinterdrivers(
			cli, mem_ctx, needed, NULL, level, arch, 
			&num_drivers, &ctr);

	/* Return value */
	
	if (!W_ERROR_IS_OK(werror))
		goto done;

	switch (level) {
	case 1:
		result = PyList_New(num_drivers);
		
		for (i = 0; i < num_drivers; i++) {
			PyObject *value;
			
			value = from_struct(&ctr.info1, py_DRIVER_INFO_1);
			PyList_SetItem(result, i, value);
		}
		
		break;
	case 2: 
		result = PyList_New(num_drivers);

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;

			value = from_struct(&ctr.info2, py_DRIVER_INFO_2);
			PyList_SetItem(result, i, value);
		}

		break;
	case 6: 
		result = PyList_New(num_drivers);

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;

			value = from_struct(&ctr.info2, py_DRIVER_INFO_6);
			PyList_SetItem(result, i, value);
		}

		break;
	default:
		result = Py_None;
		break;
	}
	
 done:
	if (cli)
		cli_shutdown(cli);

	if (mem_ctx)
		talloc_destroy(mem_ctx);

	Py_INCREF(result);
	return result;
}

/* Fetch printer driver */

static PyObject *spoolss_getprinterdriver(PyObject *self, PyObject *args,
					  PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result = Py_None;
	PRINTER_DRIVER_CTR ctr;
	int level = 1;
	uint32 needed;
	char *arch = "Windows NT x86";
	static char *kwlist[] = {"level", "arch", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|is", kwlist, 
					 &level, &arch))
		return NULL;

	/* Call rpc function */

	werror = cli_spoolss_getprinterdriver(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level,
		arch, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinterdriver(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, arch, &ctr);

	/* Return value */
	
	if (W_ERROR_IS_OK(werror)) {
		switch (level) {
		case 1:
			result = from_struct(&ctr.info1, py_DRIVER_INFO_1);
			break;
		case 2: 
			result = from_struct(&ctr.info2, py_DRIVER_INFO_2);
			break;
		case 6:
			result = from_struct(&ctr.info6, py_DRIVER_INFO_6);
			break;
		default:
			break;
		}
	}
	
	Py_INCREF(result);
	return result;
}

/* Fetch printer driver directory */

static PyObject *spoolss_getprinterdriverdir(PyObject *self, PyObject *args,
					     PyObject *kw)
{
	WERROR werror;
	PyObject *result = Py_None, *creds = NULL;
	DRIVER_DIRECTORY_CTR ctr;
	uint32 needed, level;
	char *arch = "Windows NT x86", *server_name;
	static char *kwlist[] = {"server", "creds", NULL};
	struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx = NULL;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|is", kwlist, 
					 &server_name, &level, &arch))
		return NULL;

	/* Call rpc function */

	if (!(cli = open_pipe_creds(server_name, creds, 
				    cli_spoolss_initialise, NULL))) {
		fprintf(stderr, "could not initialise cli state\n");
		goto done;
	}

	if (!(mem_ctx = talloc_init())) {
		fprintf(stderr, "unable to initialise talloc context\n");
		goto done;
	}	

	werror = cli_spoolss_getprinterdriverdir(
		cli, mem_ctx, 0, &needed, level, arch, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinterdriverdir(
			cli, mem_ctx, needed, NULL, level, arch, &ctr);

	/* Return value */
	
	if (W_ERROR_IS_OK(werror)) {
		switch (level) {
		case 1:
			result = from_struct(
				&ctr.info1, py_DRIVER_DIRECTORY_1);
			break;
		default:
			break;
		}
	}
	
 done:
	if (cli)
		cli_shutdown(cli);
	
	if (mem_ctx)
		talloc_destroy(mem_ctx);

	Py_INCREF(result);
	return result;
}
