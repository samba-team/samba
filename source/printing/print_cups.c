/*
 * Support code for the Common UNIX Printing System ("CUPS")
 *
 * Copyright 1999-2003 by Michael R Sweet.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "printing.h"

#ifdef HAVE_CUPS
#include <cups/cups.h>
#include <cups/language.h>


/*
 * CUPS printing interface definitions...
 */

static int cups_job_delete(int snum, struct printjob *pjob);
static int cups_job_pause(int snum, struct printjob *pjob);
static int cups_job_resume(int snum, struct printjob *pjob);
static int cups_job_submit(int snum, struct printjob *pjob);
static int cups_queue_get(int snum, print_queue_struct **q,
                          print_status_struct *status);
static int cups_queue_pause(int snum);
static int cups_queue_resume(int snum);


struct printif	cups_printif =
		{
		  cups_queue_get,
		  cups_queue_pause,
		  cups_queue_resume,
		  cups_job_delete,
		  cups_job_pause,
		  cups_job_resume,
		  cups_job_submit,
		};

/*
 * 'cups_passwd_cb()' - The CUPS password callback...
 */

static const char *				/* O - Password or NULL */
cups_passwd_cb(const char *prompt)	/* I - Prompt */
{
 /*
  * Always return NULL to indicate that no password is available...
  */

  return (NULL);
}


/*
 * 'cups_printer_fn()' - Call a function for every printer known to the
 *                       system.
 */

void cups_printer_fn(void (*fn)(char *, char *))
{
	/* I - Function to call */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	ipp_attribute_t	*attr;		/* Current attribute */
	cups_lang_t	*language;	/* Default language */
	char		*name,		/* printer-name attribute */
			*make_model,	/* printer-make-and-model attribute */
			*info;		/* printer-info attribute */
	static const char *requested[] =/* Requested attributes */
			{
			  "printer-name",
			  "printer-make-and-model",
			  "printer-info"
			};       


	DEBUG(5,("cups_printer_fn(%p)\n", fn));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return;
	}

       /*
	* Build a CUPS_GET_PRINTERS request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    requested-attributes
	*/

	request = ippNew();

	request->request.op.operation_id = CUPS_GET_PRINTERS;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
                     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, language->language);

        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	              "requested-attributes",
		      (sizeof(requested) / sizeof(requested[0])),
		      NULL, requested);

       /*
	* Do the request and get back a response...
	*/

	if ((response = cupsDoRequest(http, request, "/")) == NULL)
	{
		DEBUG(0,("Unable to get printer list - %s\n",
			 ippErrorString(cupsLastError())));
		httpClose(http);
		return;
	}

	for (attr = response->attrs; attr != NULL;)
	{
	       /*
		* Skip leading attributes until we hit a printer...
		*/

		while (attr != NULL && attr->group_tag != IPP_TAG_PRINTER)
			attr = attr->next;

		if (attr == NULL)
        		break;

	       /*
		* Pull the needed attributes from this printer...
		*/

		name       = NULL;
		make_model = NULL;
		info       = NULL;

		while (attr != NULL && attr->group_tag == IPP_TAG_PRINTER)
		{
        		if (strcmp(attr->name, "printer-name") == 0 &&
			    attr->value_tag == IPP_TAG_NAME)
				name = attr->values[0].string.text;

        		if (strcmp(attr->name, "printer-make-and-model") == 0 &&
			    attr->value_tag == IPP_TAG_TEXT)
				make_model = attr->values[0].string.text;

        		if (strcmp(attr->name, "printer-info") == 0 &&
			    attr->value_tag == IPP_TAG_TEXT)
				info = attr->values[0].string.text;

        		attr = attr->next;
		}

	       /*
		* See if we have everything needed...
		*/

		if (name == NULL)
			break;

 		if (info == NULL || !info[0])
			(*fn)(name, make_model);
		else
			(*fn)(name, info);
		

	}

	ippDelete(response);


       /*
	* Build a CUPS_GET_CLASSES request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    requested-attributes
	*/

	request = ippNew();

	request->request.op.operation_id = CUPS_GET_CLASSES;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
                     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, language->language);

        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	              "requested-attributes",
		      (sizeof(requested) / sizeof(requested[0])),
		      NULL, requested);

       /*
	* Do the request and get back a response...
	*/

	if ((response = cupsDoRequest(http, request, "/")) == NULL)
	{
		DEBUG(0,("Unable to get printer list - %s\n",
			 ippErrorString(cupsLastError())));
		httpClose(http);
		return;
	}

	for (attr = response->attrs; attr != NULL;)
	{
	       /*
		* Skip leading attributes until we hit a printer...
		*/

		while (attr != NULL && attr->group_tag != IPP_TAG_PRINTER)
			attr = attr->next;

		if (attr == NULL)
        		break;

	       /*
		* Pull the needed attributes from this printer...
		*/

		name       = NULL;
		make_model = NULL;
		info       = NULL;

		while (attr != NULL && attr->group_tag == IPP_TAG_PRINTER)
		{
        		if (strcmp(attr->name, "printer-name") == 0 &&
			    attr->value_tag == IPP_TAG_NAME)
				name = attr->values[0].string.text;

        		if (strcmp(attr->name, "printer-make-and-model") == 0 &&
			    attr->value_tag == IPP_TAG_TEXT)
				make_model = attr->values[0].string.text;

        		if (strcmp(attr->name, "printer-info") == 0 &&
			    attr->value_tag == IPP_TAG_TEXT)
				info = attr->values[0].string.text;

        		attr = attr->next;
		}

	       /*
		* See if we have everything needed...
		*/

		if (name == NULL)
			break;

 		if (info == NULL || !info[0])
			(*fn)(name, make_model);
		else
			(*fn)(name, info);
		

	}

	ippDelete(response);

       /*
        * Close the connection to the server...
	*/

	httpClose(http);
}


/*
 * 'cups_printername_ok()' - Provide the equivalent of pcap_printername_ok()
 *                           for CUPS.
 * O - 1 if printer name OK
 * I - Name of printer 
 */
int cups_printername_ok(const char *name)
{
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_printername_ok(\"%s\")\n", name));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (0);
	}

       /*
	* Build an IPP_GET_PRINTER_ATTRS request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    requested-attributes
	*    printer-uri
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_GET_PRINTER_ATTRIBUTES;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
                     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, language->language);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
                     "requested-attributes", NULL, "printer-uri");

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/printers/%s", name);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
                     "printer-uri", NULL, uri);

       /*
	* Do the request and get back a response...
	*/

	if ((response = cupsDoRequest(http, request, "/")) == NULL)
	{
		DEBUG(0,("Unable to get printer status for %s - %s\n", name,
			 ippErrorString(cupsLastError())));
		httpClose(http);
		return (0);
	}

	httpClose(http);

	if (response->request.status.status_code >= IPP_OK_CONFLICT)
	{
		DEBUG(0,("Unable to get printer status for %s - %s\n", name,
			 ippErrorString(response->request.status.status_code)));
		ippDelete(response);
		return (0);
	}
	else
	{
		ippDelete(response);
		return (1);
	}
}


/*
 * 'cups_job_delete()' - Delete a job.
 */

static int
cups_job_delete(int snum, struct printjob *pjob)
{
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_job_delete(%d, %p (%d))\n", snum, pjob, pjob->sysjob));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

       /*
	* Build an IPP_CANCEL_JOB request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    job-uri
	*    requesting-user-name
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_CANCEL_JOB;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/jobs/%d", pjob->sysjob);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, pjob->user);

       /*
	* Do the request and get back a response...
	*/

        ret = 1;

	if ((response = cupsDoRequest(http, request, "/jobs")) != NULL)
	{
	  if (response->request.status.status_code >= IPP_OK_CONFLICT)
		DEBUG(0,("Unable to cancel job %d - %s\n", pjob->sysjob,
			 ippErrorString(cupsLastError())));
          else
	  	ret = 0;

	  ippDelete(response);
	}
	else
	  DEBUG(0,("Unable to cancel job %d - %s\n", pjob->sysjob,
		   ippErrorString(cupsLastError())));

	httpClose(http);

	return (ret);
}


/*
 * 'cups_job_pause()' - Pause a job.
 */

static int
cups_job_pause(int snum, struct printjob *pjob)
{
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_job_pause(%d, %p (%d))\n", snum, pjob, pjob->sysjob));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

       /*
	* Build an IPP_HOLD_JOB request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    job-uri
	*    requesting-user-name
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_HOLD_JOB;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/jobs/%d", pjob->sysjob);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, pjob->user);

       /*
	* Do the request and get back a response...
	*/

        ret = 1;

	if ((response = cupsDoRequest(http, request, "/jobs")) != NULL)
	{
	  if (response->request.status.status_code >= IPP_OK_CONFLICT)
		DEBUG(0,("Unable to hold job %d - %s\n", pjob->sysjob,
			 ippErrorString(cupsLastError())));
          else
	  	ret = 0;

	  ippDelete(response);
	}
	else
	  DEBUG(0,("Unable to hold job %d - %s\n", pjob->sysjob,
		   ippErrorString(cupsLastError())));

	httpClose(http);

	return (ret);
}


/*
 * 'cups_job_resume()' - Resume a paused job.
 */

static int
cups_job_resume(int snum, struct printjob *pjob)
{
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_job_resume(%d, %p (%d))\n", snum, pjob, pjob->sysjob));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

       /*
	* Build an IPP_RELEASE_JOB request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    job-uri
	*    requesting-user-name
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_RELEASE_JOB;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/jobs/%d", pjob->sysjob);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "job-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, pjob->user);

       /*
	* Do the request and get back a response...
	*/

        ret = 1;

	if ((response = cupsDoRequest(http, request, "/jobs")) != NULL)
	{
	  if (response->request.status.status_code >= IPP_OK_CONFLICT)
		DEBUG(0,("Unable to release job %d - %s\n", pjob->sysjob,
			 ippErrorString(cupsLastError())));
          else
	  	ret = 0;

	  ippDelete(response);
	}
	else
	  DEBUG(0,("Unable to release job %d - %s\n", pjob->sysjob,
		   ippErrorString(cupsLastError())));

	httpClose(http);

	return (ret);
}


/*
 * 'cups_job_submit()' - Submit a job for printing.
 */

static int
cups_job_submit(int snum, struct printjob *pjob)
{
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_job_submit(%d, %p (%d))\n", snum, pjob, pjob->sysjob));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

       /*
	* Build an IPP_PRINT_JOB request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    printer-uri
	*    requesting-user-name
	*    [document-data]
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_PRINT_JOB;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/printers/%s",
	         PRINTERNAME(snum));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
        	     "printer-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, pjob->user);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	             "job-originating-host-name", NULL,
		     get_remote_machine_name());

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "job-name", NULL,
        	     pjob->jobname);

       /*
	* Do the request and get back a response...
	*/

	slprintf(uri, sizeof(uri) - 1, "/printers/%s", PRINTERNAME(snum));

        ret = 1;
	if ((response = cupsDoFileRequest(http, request, uri,
	                                  pjob->filename)) != NULL)
	{
		if (response->request.status.status_code >= IPP_OK_CONFLICT)
			DEBUG(0,("Unable to print file to %s - %s\n", PRINTERNAME(snum),
			         ippErrorString(cupsLastError())));
        	else
			ret = 0;

		ippDelete(response);
	}
	else
		DEBUG(0,("Unable to print file to `%s' - %s\n", PRINTERNAME(snum),
			 ippErrorString(cupsLastError())));

	httpClose(http);

	if ( ret == 0 )
		unlink(pjob->filename);
	/* else print_job_end will do it for us */

	return (ret);
}


/*
 * 'cups_queue_get()' - Get all the jobs in the print queue.
 */

static int
cups_queue_get(int snum, print_queue_struct **q, print_status_struct *status)
{
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	ipp_attribute_t	*attr;		/* Current attribute */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */
	int		qcount,		/* Number of active queue entries */
			qalloc;		/* Number of queue entries allocated */
	print_queue_struct *queue,	/* Queue entries */
			*temp;		/* Temporary pointer for queue */
	const char	*user_name,	/* job-originating-user-name attribute */
			*job_name;	/* job-name attribute */
	int		job_id;		/* job-id attribute */
	int		job_k_octets;	/* job-k-octets attribute */
	time_t		job_time;	/* time-at-creation attribute */
	ipp_jstate_t	job_status;	/* job-status attribute */
	int		job_priority;	/* job-priority attribute */
	static const char *jattrs[] =	/* Requested job attributes */
			{
			  "job-id",
			  "job-k-octets",
			  "job-name",
			  "job-originating-user-name",
			  "job-priority",
			  "job-state",
			  "time-at-creation",
			};
	static const char *pattrs[] =	/* Requested printer attributes */
			{
			  "printer-state",
			  "printer-state-message"
			};


	DEBUG(5,("cups_queue_get(%d, %p, %p)\n", snum, q, status));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (0);
	}

       /*
        * Generate the printer URI...
	*/

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/printers/%s",
	         PRINTERNAME(snum));

       /*
	* Build an IPP_GET_JOBS request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    requested-attributes
	*    printer-uri
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_GET_JOBS;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
                     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, language->language);

        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	              "requested-attributes",
		      (sizeof(jattrs) / sizeof(jattrs[0])),
		      NULL, jattrs);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
                     "printer-uri", NULL, uri);

       /*
	* Do the request and get back a response...
	*/

	if ((response = cupsDoRequest(http, request, "/")) == NULL)
	{
		DEBUG(0,("Unable to get jobs for %s - %s\n", uri,
			 ippErrorString(cupsLastError())));
		httpClose(http);
		return (0);
	}

	if (response->request.status.status_code >= IPP_OK_CONFLICT)
	{
		DEBUG(0,("Unable to get jobs for %s - %s\n", uri,
			 ippErrorString(response->request.status.status_code)));
		ippDelete(response);
		httpClose(http);

		return (0);
	}

       /*
        * Process the jobs...
	*/

        qcount = 0;
	qalloc = 0;
	queue  = NULL;

        for (attr = response->attrs; attr != NULL; attr = attr->next)
	{
	       /*
		* Skip leading attributes until we hit a job...
		*/

		while (attr != NULL && attr->group_tag != IPP_TAG_JOB)
        		attr = attr->next;

		if (attr == NULL)
			break;

	       /*
	        * Allocate memory as needed...
		*/
		if (qcount >= qalloc)
		{
			qalloc += 16;

			temp = Realloc(queue, sizeof(print_queue_struct) * qalloc);

			if (temp == NULL)
			{
				DEBUG(0,("cups_queue_get: Not enough memory!"));
				ippDelete(response);
				httpClose(http);

				SAFE_FREE(queue);
				return (0);
			}

			queue = temp;
		}

		temp = queue + qcount;
		memset(temp, 0, sizeof(print_queue_struct));

	       /*
		* Pull the needed attributes from this job...
		*/

		job_id       = 0;
		job_priority = 50;
		job_status   = IPP_JOB_PENDING;
		job_time     = 0;
		job_k_octets = 0;
		user_name    = NULL;
		job_name     = NULL;

		while (attr != NULL && attr->group_tag == IPP_TAG_JOB)
		{
        		if (attr->name == NULL)
			{
				attr = attr->next;
				break;
			}

        		if (strcmp(attr->name, "job-id") == 0 &&
			    attr->value_tag == IPP_TAG_INTEGER)
				job_id = attr->values[0].integer;

        		if (strcmp(attr->name, "job-k-octets") == 0 &&
			    attr->value_tag == IPP_TAG_INTEGER)
				job_k_octets = attr->values[0].integer;

        		if (strcmp(attr->name, "job-priority") == 0 &&
			    attr->value_tag == IPP_TAG_INTEGER)
				job_priority = attr->values[0].integer;

        		if (strcmp(attr->name, "job-state") == 0 &&
			    attr->value_tag == IPP_TAG_ENUM)
				job_status = (ipp_jstate_t)(attr->values[0].integer);

        		if (strcmp(attr->name, "time-at-creation") == 0 &&
			    attr->value_tag == IPP_TAG_INTEGER)
				job_time = attr->values[0].integer;

        		if (strcmp(attr->name, "job-name") == 0 &&
			    attr->value_tag == IPP_TAG_NAME)
				job_name = attr->values[0].string.text;

        		if (strcmp(attr->name, "job-originating-user-name") == 0 &&
			    attr->value_tag == IPP_TAG_NAME)
				user_name = attr->values[0].string.text;

        		attr = attr->next;
		}

	       /*
		* See if we have everything needed...
		*/

		if (user_name == NULL || job_name == NULL || job_id == 0)
		{
        	  if (attr == NULL)
		    break;
		  else
        	    continue;
		}

		temp->job      = job_id;
		temp->size     = job_k_octets * 1024;
		temp->status   = job_status == IPP_JOB_PENDING ? LPQ_QUEUED :
				 job_status == IPP_JOB_STOPPED ? LPQ_PAUSED :
                                 job_status == IPP_JOB_HELD ? LPQ_PAUSED :
			         LPQ_PRINTING;
		temp->priority = job_priority;
		temp->time     = job_time;
		strncpy(temp->fs_user, user_name, sizeof(temp->fs_user) - 1);
		strncpy(temp->fs_file, job_name, sizeof(temp->fs_file) - 1);

		qcount ++;

		if (attr == NULL)
        	  break;
	}

	ippDelete(response);

       /*
	* Build an IPP_GET_PRINTER_ATTRIBUTES request, which requires the
	* following attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    requested-attributes
	*    printer-uri
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_GET_PRINTER_ATTRIBUTES;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
                     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
                     "attributes-natural-language", NULL, language->language);

        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	              "requested-attributes",
		      (sizeof(pattrs) / sizeof(pattrs[0])),
		      NULL, pattrs);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
                     "printer-uri", NULL, uri);

       /*
	* Do the request and get back a response...
	*/

	if ((response = cupsDoRequest(http, request, "/")) == NULL)
	{
		DEBUG(0,("Unable to get printer status for %s - %s\n", PRINTERNAME(snum),
			 ippErrorString(cupsLastError())));
		httpClose(http);
		*q = queue;
		return (qcount);
	}

	if (response->request.status.status_code >= IPP_OK_CONFLICT)
	{
		DEBUG(0,("Unable to get printer status for %s - %s\n", PRINTERNAME(snum),
			 ippErrorString(response->request.status.status_code)));
		ippDelete(response);
		httpClose(http);
		*q = queue;
		return (qcount);
	}

       /*
        * Get the current printer status and convert it to the SAMBA values.
	*/

        if ((attr = ippFindAttribute(response, "printer-state", IPP_TAG_ENUM)) != NULL)
	{
		if (attr->values[0].integer == IPP_PRINTER_STOPPED)
			status->status = LPSTAT_STOPPED;
		else
			status->status = LPSTAT_OK;
	}

        if ((attr = ippFindAttribute(response, "printer-state-message",
	                             IPP_TAG_TEXT)) != NULL)
	        fstrcpy(status->message, attr->values[0].string.text);

        ippDelete(response);

       /*
        * Return the job queue...
	*/

	httpClose(http);

	*q = queue;
	return (qcount);
}


/*
 * 'cups_queue_pause()' - Pause a print queue.
 */

static int
cups_queue_pause(int snum)
{
	extern userdom_struct current_user_info;
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_queue_pause(%d)\n", snum));

	/*
	 * Make sure we don't ask for passwords...
	 */

        cupsSetPasswordCB(cups_passwd_cb);

	/*
	 * Try to connect to the server...
	 */

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

	/*
	 * Build an IPP_PAUSE_PRINTER request, which requires the following
	 * attributes:
	 *
	 *    attributes-charset
	 *    attributes-natural-language
	 *    printer-uri
	 *    requesting-user-name
	 */

	request = ippNew();

	request->request.op.operation_id = IPP_PAUSE_PRINTER;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/printers/%s",
	         PRINTERNAME(snum));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, current_user_info.unix_name);

       /*
	* Do the request and get back a response...
	*/

        ret = 1;

	if ((response = cupsDoRequest(http, request, "/admin/")) != NULL)
	{
	  if (response->request.status.status_code >= IPP_OK_CONFLICT)
		DEBUG(0,("Unable to pause printer %s - %s\n", PRINTERNAME(snum),
			 ippErrorString(cupsLastError())));
          else
	  	ret = 0;

	  ippDelete(response);
	}
	else
	  DEBUG(0,("Unable to pause printer %s - %s\n", PRINTERNAME(snum),
		   ippErrorString(cupsLastError())));

	httpClose(http);

	return (ret);
}


/*
 * 'cups_queue_resume()' - Restart a print queue.
 */

static int
cups_queue_resume(int snum)
{
	extern userdom_struct current_user_info;
	int		ret;		/* Return value */
	http_t		*http;		/* HTTP connection to server */
	ipp_t		*request,	/* IPP Request */
			*response;	/* IPP Response */
	cups_lang_t	*language;	/* Default language */
	char		uri[HTTP_MAX_URI]; /* printer-uri attribute */


	DEBUG(5,("cups_queue_resume(%d)\n", snum));

       /*
        * Make sure we don't ask for passwords...
	*/

        cupsSetPasswordCB(cups_passwd_cb);

       /*
	* Try to connect to the server...
	*/

	if ((http = httpConnect(cupsServer(), ippPort())) == NULL)
	{
		DEBUG(0,("Unable to connect to CUPS server %s - %s\n", 
			 cupsServer(), strerror(errno)));
		return (1);
	}

       /*
	* Build an IPP_RESUME_PRINTER request, which requires the following
	* attributes:
	*
	*    attributes-charset
	*    attributes-natural-language
	*    printer-uri
	*    requesting-user-name
	*/

	request = ippNew();

	request->request.op.operation_id = IPP_RESUME_PRINTER;
	request->request.op.request_id   = 1;

	language = cupsLangDefault();

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
        	     "attributes-charset", NULL, cupsLangEncoding(language));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
        	     "attributes-natural-language", NULL, language->language);

	slprintf(uri, sizeof(uri) - 1, "ipp://localhost/printers/%s",
	         PRINTERNAME(snum));

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);

	ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        	     NULL, current_user_info.unix_name);

       /*
	* Do the request and get back a response...
	*/

        ret = 1;

	if ((response = cupsDoRequest(http, request, "/admin/")) != NULL)
	{
	  if (response->request.status.status_code >= IPP_OK_CONFLICT)
		DEBUG(0,("Unable to resume printer %s - %s\n", PRINTERNAME(snum),
			 ippErrorString(cupsLastError())));
          else
	  	ret = 0;

	  ippDelete(response);
	}
	else
	  DEBUG(0,("Unable to resume printer %s - %s\n", PRINTERNAME(snum),
		   ippErrorString(cupsLastError())));

	httpClose(http);

	return (ret);
}


#else
 /* this keeps fussy compilers happy */
 void print_cups_dummy(void) {}
#endif /* HAVE_CUPS */
