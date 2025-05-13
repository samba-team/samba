/*
   Unix SMB/CIFS implementation.
   client print routines
   Copyright (C) Andrew Tridgell 1994-1998

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

#include "includes.h"
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "libsmb/clirap.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/util/string_wrappers.h"

/*****************************************************************************
 Convert a character pointer in a cli_call_api() response to a form we can use.
 This function contains code to prevent core dumps if the server returns
 invalid data.
*****************************************************************************/
static const char *fix_char_ptr(unsigned int datap, unsigned int converter,
			  char *rdata, int rdrcnt)
{
	unsigned int offset;

	if (datap == 0)	{
		/* turn NULL pointers into zero length strings */
		return "";
	}

	offset = datap - converter;

	if (offset >= rdrcnt) {
		DEBUG(1,("bad char ptr: datap=%u, converter=%u rdrcnt=%d>\n",
			 datap, converter, rdrcnt));
		return "<ERROR>";
	}
	return &rdata[offset];
}

/****************************************************************************
call fn() on each entry in a print queue
****************************************************************************/

NTSTATUS cli_print_queue(struct cli_state *cli,
			 void (*fn)(struct print_job_info *))
{
	uint8_t *rparam = NULL;
	uint8_t *rdata = NULL;
	char *p = NULL;
	uint32_t rdrcnt, rprcnt;
	char param[1024];
	int converter;
	int result_code=0;
	int i = -1;
	NTSTATUS status;

	memset(param,'\0',sizeof(param));

	p = param;
	SSVAL(p,0,76);         /* API function number 76 (DosPrintJobEnum) */
	p += 2;
	strlcpy_base(p,"zWrLeh", param, sizeof(param));   /* parameter description? */
	p = skip_string(param,sizeof(param),p);
	strlcpy_base(p,"WWzWWDDzz", param, sizeof(param));  /* returned data format */
	p = skip_string(param,sizeof(param),p);
	strlcpy_base(p,cli->share, param, sizeof(param));    /* name of queue */
	p = skip_string(param,sizeof(param),p);
	SSVAL(p,0,2);   /* API function level 2, PRJINFO_2 data structure */
	SSVAL(p,2,1000); /* size of bytes of returned data buffer */
	p += 4;
	strlcpy_base(p,"", param,sizeof(param));   /* subformat */
	p = skip_string(param,sizeof(param),p);

	DEBUG(4,("doing cli_print_queue for %s\n", cli->share));

	status = cli_trans(
		talloc_tos(),
		cli,
		SMBtrans,	   /* trans_cmd */
		"\\PIPE\\LANMAN",  /* name */
		0,		   /* fid */
		0,		   /* function */
		0,		   /* flags */
		NULL,		   /* setup */
		0,		   /* num_setup */
		0,		   /* max_setup */
		(uint8_t *)param,  /* param */
		PTR_DIFF(p,param), /* num_param */
		1024,		   /* max_param */
		NULL,		   /* data */
		0,		   /* num_data */
		CLI_BUFFER_SIZE,   /* max_data */
		NULL,		   /* recv_flags2 */
		NULL,		   /* rsetup */
		0,		   /* min_rsetup */
		NULL,		   /* num_rsetup */
		&rparam,	   /* rparam */
		8,		   /* min_rparam */
		&rprcnt,	   /* num_rparam */
		&rdata,		   /* rdata */
		0,		   /* min_rdata */
		&rdrcnt);	   /* num_rdata */
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	result_code = SVAL(rparam,0);
	converter = SVAL(rparam,2);       /* conversion factor */

	if (result_code == 0) {
		struct print_job_info job;

		p = (char *)rdata;

		for (i = 0; i < SVAL(rparam,4); ++i) {
			job.id = SVAL(p,0);
			job.priority = SVAL(p,2);
			fstrcpy(job.user,
				fix_char_ptr(SVAL(p,4), converter,
					     (char *)rdata, rdrcnt));
			job.t = make_unix_date3(
				p + 12, smb1cli_conn_server_time_zone(cli->conn));
			job.size = IVAL(p,16);
			fstrcpy(job.name,fix_char_ptr(SVAL(p,24),
						      converter,
						      (char *)rdata, rdrcnt));
			fn(&job);
			p += 28;
		}
	}

	/* If any parameters or data were returned, free the storage. */
	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);

	return NT_STATUS_OK;
}

/****************************************************************************
  cancel a print job
  ****************************************************************************/

NTSTATUS cli_printjob_del(struct cli_state *cli, int job)
{
	uint8_t *rparam = NULL;
	uint8_t *rdata = NULL;
	char *p = NULL;
	uint32_t rdrcnt, rprcnt;
	int result_code;
	char param[1024];
	NTSTATUS status = NT_STATUS_OK;

	memset(param,'\0',sizeof(param));

	p = param;
	SSVAL(p,0,81);		/* DosPrintJobDel() */
	p += 2;
	strlcpy_base(p,"W", param,sizeof(param));
	p = skip_string(param,sizeof(param),p);
	strlcpy_base(p,"", param,sizeof(param));
	p = skip_string(param,sizeof(param),p);
	SSVAL(p,0,job);
	p += 2;

	status = cli_trans(talloc_tos(),
			   cli,
			   SMBtrans,	       /* trans_cmd */
			   "\\PIPE\\LANMAN",   /* name */
			   0,		       /* fid */
			   0,		       /* function */
			   0,		       /* flags */
			   NULL,	       /* setup */
			   0,		       /* num_setup */
			   0,		       /* max_setup */
			   (uint8_t *)param,   /* param */
			   PTR_DIFF(p, param), /* num_param */
			   1024,	       /* max_param */
			   NULL,	       /* data */
			   0,		       /* num_data */
			   CLI_BUFFER_SIZE,    /* max_data */
			   NULL,	       /* recv_flags2 */
			   NULL,	       /* rsetup */
			   0,		       /* min_rsetup */
			   NULL,	       /* num_rsetup */
			   &rparam,	       /* rparam */
			   8,		       /* min_rparam */
			   &rprcnt,	       /* num_rparam */
			   &rdata,	       /* rdata */
			   0,		       /* min_rdata */
			   &rdrcnt);	       /* num_rdata */
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	result_code = SVAL(rparam, 0);

	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);

	if (result_code == ERRnosuchprintjob) {
		status = NT_STATUS_INVALID_PARAMETER;
	}

	return status;
}
