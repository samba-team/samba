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

#include "python/py_spoolss.h"

/* Enumerate jobs */

PyObject *spoolss_enumjobs(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result;
	int level = 1;
	uint32 i, needed, num_jobs;
	static char *kwlist[] = {"level", NULL};
	JOB_INFO_CTR ctr;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "|i", kwlist, &level))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_enumjobs(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level, 0,
		1000, &num_jobs, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enumjobs(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, 0, 1000, &num_jobs, &ctr);

	/* Return value */
	
	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

	result = PyList_New(num_jobs);

	switch (level) {
	case 1: 
		for (i = 0; i < num_jobs; i++) {
			PyObject *value;

			py_from_JOB_INFO_1(&value, &ctr.job.job_info_1[i]);

			PyList_SetItem(result, i, value);
		}

		break;
	case 2:
		for(i = 0; i < num_jobs; i++) {
			PyObject *value;

			py_from_JOB_INFO_2(&value, &ctr.job.job_info_2[i]);

			PyList_SetItem(result, i, value);
		}
		
		break;
	}

 done:
	Py_INCREF(result);
	return result;
}

/* Set job command */

PyObject *spoolss_setjob(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	uint32 level = 0, command, jobid;
	static char *kwlist[] = {"jobid", "command", "level", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "ii|i", kwlist, &jobid,
					 &command, &level))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_setjob(hnd->cli, hnd->mem_ctx, &hnd->pol,
				    jobid, level, command);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}
	
	Py_INCREF(Py_None);
	return Py_None;
}

/* Get job */

PyObject *spoolss_getjob(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	PyObject *result;
	uint32 level = 1, jobid, needed;
	static char *kwlist[] = {"jobid", "level", NULL};
	JOB_INFO_CTR ctr;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "i|i", kwlist, &jobid,
					 &level))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_getjob(hnd->cli, hnd->mem_ctx, 0, &needed,
				    &hnd->pol, jobid, level, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getjob(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			jobid, level, &ctr);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}

	switch(level) {
	case 1:
		py_from_JOB_INFO_1(&result, ctr.job.job_info_1);
		break;
	case 2:
		py_from_JOB_INFO_2(&result, ctr.job.job_info_2);
		break;
	}

	return result;
}

/* Start page printer.  This notifies the spooler that a page is about to be
   printed on the specified printer. */

PyObject *spoolss_startpageprinter(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	static char *kwlist[] = { NULL };

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "", kwlist))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_startpageprinter(
		hnd->cli, hnd->mem_ctx, &hnd->pol);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}
	
	Py_INCREF(Py_None);
	return Py_None;
}

/* End page printer.  This notifies the spooler that a page has finished
   being printed on the specified printer. */

PyObject *spoolss_endpageprinter(PyObject *self, PyObject *args, PyObject *kw)
{
	spoolss_policy_hnd_object *hnd = (spoolss_policy_hnd_object *)self;
	WERROR werror;
	static char *kwlist[] = { NULL };

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "", kwlist))
		return NULL;
	
	/* Call rpc function */
	
	werror = cli_spoolss_endpageprinter(
		hnd->cli, hnd->mem_ctx, &hnd->pol);

	if (!W_ERROR_IS_OK(werror)) {
		PyErr_SetObject(spoolss_werror, py_werror_tuple(werror));
		return NULL;
	}
	
	Py_INCREF(Py_None);
	return Py_None;
}
