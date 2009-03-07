/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000,
 *  Copyright (C) Jeremy Allison                    2001,
 *  Copyright (C) Gerald Carter                2001-2002,
 *  Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*******************************************************************
 ********************************************************************/

static bool proxy_spoolss_call(pipes_struct *p, uint8_t opnum)
{
	struct api_struct *fns;
	int n_fns;

	spoolss_get_pipe_fns(&fns, &n_fns);

	if (opnum >= n_fns) {
		return false;
	}

	if (fns[opnum].opnum != opnum) {
		smb_panic("SPOOLSS function table not sorted");
	}

	return fns[opnum].fn(p);
}

/********************************************************************
 * api_spoolss_open_printer_ex (rarely seen - older call)
 ********************************************************************/

static bool api_spoolss_open_printer(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_OPENPRINTER);
}

/********************************************************************
 * api_spoolss_open_printer_ex
 ********************************************************************/

static bool api_spoolss_open_printer_ex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_OPENPRINTEREX);
}

/********************************************************************
 * api_spoolss_getprinterdata
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_getprinterdata(pipes_struct *p)
{
	SPOOL_Q_GETPRINTERDATA q_u;
	SPOOL_R_GETPRINTERDATA r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	/* read the stream and fill the struct */
	if (!spoolss_io_q_getprinterdata("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_getprinterdata: unable to unmarshall SPOOL_Q_GETPRINTERDATA.\n"));
		return False;
	}
	
	r_u.status = _spoolss_getprinterdata( p, &q_u, &r_u);

	if (!spoolss_io_r_getprinterdata("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_getprinterdata: unable to marshall SPOOL_R_GETPRINTERDATA.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_deleteprinterdata
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_deleteprinterdata(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTERDATA);
}

/********************************************************************
 * api_spoolss_closeprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_closeprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_CLOSEPRINTER);
}

/********************************************************************
 * api_spoolss_abortprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_abortprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ABORTPRINTER);
}

/********************************************************************
 * api_spoolss_deleteprinter
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_deleteprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTER);
}

/********************************************************************
 * api_spoolss_deleteprinterdriver
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_deleteprinterdriver(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTERDRIVER);
}


/********************************************************************
 * api_spoolss_rffpcnex
 * ReplyFindFirstPrinterChangeNotifyEx
 ********************************************************************/

static bool api_spoolss_rffpcnex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFYEX);
}


/********************************************************************
 * api_spoolss_rfnpcnex
 * ReplyFindNextPrinterChangeNotifyEx
 * called from the spoolss dispatcher

 * Note - this is the *ONLY* function that breaks the RPC call
 * symmetry in all the other calls. We need to do this to fix
 * the massive memory allocation problem with thousands of jobs...
 * JRA.
 ********************************************************************/

static bool api_spoolss_rfnpcnex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ROUTERREFRESHPRINTERCHANGENOTIFY);
}


/********************************************************************
 * api_spoolss_enumprinters
 * called from the spoolss dispatcher
 *
 ********************************************************************/

static bool api_spoolss_enumprinters(pipes_struct *p)
{
	SPOOL_Q_ENUMPRINTERS q_u;
	SPOOL_R_ENUMPRINTERS r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_enumprinters("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_enumprinters: unable to unmarshall SPOOL_Q_ENUMPRINTERS.\n"));
		return False;
	}

	r_u.status = _spoolss_enumprinters( p, &q_u, &r_u);

	if (!spoolss_io_r_enumprinters("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_enumprinters: unable to marshall SPOOL_R_ENUMPRINTERS.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

static bool api_spoolss_getprinter(pipes_struct *p)
{
	SPOOL_Q_GETPRINTER q_u;
	SPOOL_R_GETPRINTER r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!spoolss_io_q_getprinter("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_getprinter: unable to unmarshall SPOOL_Q_GETPRINTER.\n"));
		return False;
	}

	r_u.status = _spoolss_getprinter(p, &q_u, &r_u);

	if(!spoolss_io_r_getprinter("",&r_u,rdata,0)) {
		DEBUG(0,("spoolss_io_r_getprinter: unable to marshall SPOOL_R_GETPRINTER.\n"));
		return False;
	}

	return True;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

static bool api_spoolss_getprinterdriver2(pipes_struct *p)
{
	SPOOL_Q_GETPRINTERDRIVER2 q_u;
	SPOOL_R_GETPRINTERDRIVER2 r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if(!spoolss_io_q_getprinterdriver2("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_getprinterdriver2: unable to unmarshall SPOOL_Q_GETPRINTERDRIVER2.\n"));
		return False;
	}

	r_u.status = _spoolss_getprinterdriver2(p, &q_u, &r_u);
	
	if(!spoolss_io_r_getprinterdriver2("",&r_u,rdata,0)) {
		DEBUG(0,("spoolss_io_r_getprinterdriver2: unable to marshall SPOOL_R_GETPRINTERDRIVER2.\n"));
		return False;
	}
	
	return True;
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

static bool api_spoolss_startpageprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_STARTPAGEPRINTER);
}

/********************************************************************
 * api_spoolss_getprinter
 * called from the spoolss dispatcher
 *
 ********************************************************************/

static bool api_spoolss_endpageprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENDPAGEPRINTER);
}

/********************************************************************
********************************************************************/

static bool api_spoolss_startdocprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_STARTDOCPRINTER);
}

/********************************************************************
********************************************************************/

static bool api_spoolss_enddocprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENDDOCPRINTER);
}

/********************************************************************
********************************************************************/

static bool api_spoolss_writeprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_WRITEPRINTER);
}

/****************************************************************************

****************************************************************************/

static bool api_spoolss_setprinter(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_SETPRINTER);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_fcpn(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_FINDCLOSEPRINTERNOTIFY);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_addjob(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDJOB);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumjobs(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMJOBS);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_schedulejob(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_SCHEDULEJOB);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_setjob(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_SETJOB);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprinterdrivers(pipes_struct *p)
{
	SPOOL_Q_ENUMPRINTERDRIVERS q_u;
	SPOOL_R_ENUMPRINTERDRIVERS r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	if (!spoolss_io_q_enumprinterdrivers("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_enumprinterdrivers: unable to unmarshall SPOOL_Q_ENUMPRINTERDRIVERS.\n"));
		return False;
	}

	r_u.status = _spoolss_enumprinterdrivers(p, &q_u, &r_u);

	if (!spoolss_io_r_enumprinterdrivers("",&r_u,rdata,0)) {
		DEBUG(0,("spoolss_io_r_enumprinterdrivers: unable to marshall SPOOL_R_ENUMPRINTERDRIVERS.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_getform(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_GETFORM);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumforms(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMFORMS);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumports(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMPORTS);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_addprinterex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDPRINTEREX);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_addprinterdriver(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDPRINTERDRIVER);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_getprinterdriverdirectory(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_GETPRINTERDRIVERDIRECTORY);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprinterdata(pipes_struct *p)
{
	SPOOL_Q_ENUMPRINTERDATA q_u;
	SPOOL_R_ENUMPRINTERDATA r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!spoolss_io_q_enumprinterdata("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_enumprinterdata: unable to unmarshall SPOOL_Q_ENUMPRINTERDATA.\n"));
		return False;
	}
	
	r_u.status = _spoolss_enumprinterdata(p, &q_u, &r_u);
				
	if(!spoolss_io_r_enumprinterdata("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_enumprinterdata: unable to marshall SPOOL_R_ENUMPRINTERDATA.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_setprinterdata(pipes_struct *p)
{
	SPOOL_Q_SETPRINTERDATA q_u;
	SPOOL_R_SETPRINTERDATA r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!spoolss_io_q_setprinterdata("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_setprinterdata: unable to unmarshall SPOOL_Q_SETPRINTERDATA.\n"));
		return False;
	}
	
	r_u.status = _spoolss_setprinterdata(p, &q_u, &r_u);
				
	if(!spoolss_io_r_setprinterdata("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_setprinterdata: unable to marshall SPOOL_R_SETPRINTERDATA.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/
static bool api_spoolss_reset_printer(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_RESETPRINTER);
}

/****************************************************************************
****************************************************************************/
static bool api_spoolss_addform(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDFORM);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_deleteform(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEFORM);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_setform(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_SETFORM);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprintprocessors(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMPRINTPROCESSORS);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_addprintprocessor(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDPRINTPROCESSOR);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprintprocdatatypes(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMPRINTPROCDATATYPES);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprintmonitors(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ENUMMONITORS);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_getjob(pipes_struct *p)
{
	SPOOL_Q_GETJOB q_u;
	SPOOL_R_GETJOB r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!spoolss_io_q_getjob("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_getjob: unable to unmarshall SPOOL_Q_GETJOB.\n"));
		return False;
	}

	r_u.status = _spoolss_getjob(p, &q_u, &r_u);
	
	if(!spoolss_io_r_getjob("",&r_u,rdata,0)) {
		DEBUG(0,("spoolss_io_r_getjob: unable to marshall SPOOL_R_GETJOB.\n"));
		return False;
	}
		
	return True;
}

/********************************************************************
 * api_spoolss_getprinterdataex
 *
 * called from the spoolss dispatcher
 ********************************************************************/

static bool api_spoolss_getprinterdataex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_GETPRINTERDATAEX);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_setprinterdataex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_SETPRINTERDATAEX);
}


/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprinterkey(pipes_struct *p)
{
	SPOOL_Q_ENUMPRINTERKEY q_u;
	SPOOL_R_ENUMPRINTERKEY r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!spoolss_io_q_enumprinterkey("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_setprinterkey: unable to unmarshall SPOOL_Q_ENUMPRINTERKEY.\n"));
		return False;
	}
	
	r_u.status = _spoolss_enumprinterkey(p, &q_u, &r_u);
				
	if(!spoolss_io_r_enumprinterkey("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_enumprinterkey: unable to marshall SPOOL_R_ENUMPRINTERKEY.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_enumprinterdataex(pipes_struct *p)
{
	SPOOL_Q_ENUMPRINTERDATAEX q_u;
	SPOOL_R_ENUMPRINTERDATAEX r_u;
	prs_struct *data = &p->in_data.data;
	prs_struct *rdata = &p->out_data.rdata;
	
	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	
	if(!spoolss_io_q_enumprinterdataex("", &q_u, data, 0)) {
		DEBUG(0,("spoolss_io_q_enumprinterdataex: unable to unmarshall SPOOL_Q_ENUMPRINTERDATAEX.\n"));
		return False;
	}
	
	r_u.status = _spoolss_enumprinterdataex(p, &q_u, &r_u);
				
	if(!spoolss_io_r_enumprinterdataex("", &r_u, rdata, 0)) {
		DEBUG(0,("spoolss_io_r_enumprinterdataex: unable to marshall SPOOL_R_ENUMPRINTERDATAEX.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_getprintprocessordirectory(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_GETPRINTPROCESSORDIRECTORY);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_deleteprinterdataex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTERDATAEX);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_deleteprinterkey(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTERKEY);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_addprinterdriverex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_ADDPRINTERDRIVEREX);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_deleteprinterdriverex(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_DELETEPRINTERDRIVEREX);
}

/****************************************************************************
****************************************************************************/

static bool api_spoolss_xcvdataport(pipes_struct *p)
{
	return proxy_spoolss_call(p, NDR_SPOOLSS_XCVDATA);
}

/*******************************************************************
\pipe\spoolss commands
********************************************************************/

  struct api_struct api_spoolss_cmds[] = 
    {
 {"SPOOLSS_OPENPRINTER",               SPOOLSS_OPENPRINTER,               api_spoolss_open_printer              },
 {"SPOOLSS_OPENPRINTEREX",             SPOOLSS_OPENPRINTEREX,             api_spoolss_open_printer_ex           },
 {"SPOOLSS_GETPRINTERDATA",            SPOOLSS_GETPRINTERDATA,            api_spoolss_getprinterdata            },
 {"SPOOLSS_CLOSEPRINTER",              SPOOLSS_CLOSEPRINTER,              api_spoolss_closeprinter              },
 {"SPOOLSS_DELETEPRINTER",             SPOOLSS_DELETEPRINTER,             api_spoolss_deleteprinter             },
 {"SPOOLSS_ABORTPRINTER",              SPOOLSS_ABORTPRINTER,              api_spoolss_abortprinter              },
 {"SPOOLSS_RFFPCNEX",                  SPOOLSS_RFFPCNEX,                  api_spoolss_rffpcnex                  },
 {"SPOOLSS_RFNPCNEX",                  SPOOLSS_RFNPCNEX,                  api_spoolss_rfnpcnex                  },
 {"SPOOLSS_ENUMPRINTERS",              SPOOLSS_ENUMPRINTERS,              api_spoolss_enumprinters              },
 {"SPOOLSS_GETPRINTER",                SPOOLSS_GETPRINTER,                api_spoolss_getprinter                },
 {"SPOOLSS_GETPRINTERDRIVER2",         SPOOLSS_GETPRINTERDRIVER2,         api_spoolss_getprinterdriver2         }, 
 {"SPOOLSS_STARTPAGEPRINTER",          SPOOLSS_STARTPAGEPRINTER,          api_spoolss_startpageprinter          },
 {"SPOOLSS_ENDPAGEPRINTER",            SPOOLSS_ENDPAGEPRINTER,            api_spoolss_endpageprinter            }, 
 {"SPOOLSS_STARTDOCPRINTER",           SPOOLSS_STARTDOCPRINTER,           api_spoolss_startdocprinter           },
 {"SPOOLSS_ENDDOCPRINTER",             SPOOLSS_ENDDOCPRINTER,             api_spoolss_enddocprinter             },
 {"SPOOLSS_WRITEPRINTER",              SPOOLSS_WRITEPRINTER,              api_spoolss_writeprinter              },
 {"SPOOLSS_SETPRINTER",                SPOOLSS_SETPRINTER,                api_spoolss_setprinter                },
 {"SPOOLSS_FCPN",                      SPOOLSS_FCPN,                      api_spoolss_fcpn		        },
 {"SPOOLSS_ADDJOB",                    SPOOLSS_ADDJOB,                    api_spoolss_addjob                    },
 {"SPOOLSS_ENUMJOBS",                  SPOOLSS_ENUMJOBS,                  api_spoolss_enumjobs                  },
 {"SPOOLSS_SCHEDULEJOB",               SPOOLSS_SCHEDULEJOB,               api_spoolss_schedulejob               },
 {"SPOOLSS_SETJOB",                    SPOOLSS_SETJOB,                    api_spoolss_setjob                    },
 {"SPOOLSS_ENUMFORMS",                 SPOOLSS_ENUMFORMS,                 api_spoolss_enumforms                 },
 {"SPOOLSS_ENUMPORTS",                 SPOOLSS_ENUMPORTS,                 api_spoolss_enumports                 },
 {"SPOOLSS_ENUMPRINTERDRIVERS",        SPOOLSS_ENUMPRINTERDRIVERS,        api_spoolss_enumprinterdrivers        },
 {"SPOOLSS_ADDPRINTEREX",              SPOOLSS_ADDPRINTEREX,              api_spoolss_addprinterex              },
 {"SPOOLSS_ADDPRINTERDRIVER",          SPOOLSS_ADDPRINTERDRIVER,          api_spoolss_addprinterdriver          },
 {"SPOOLSS_DELETEPRINTERDRIVER",       SPOOLSS_DELETEPRINTERDRIVER,       api_spoolss_deleteprinterdriver       },
 {"SPOOLSS_GETPRINTERDRIVERDIRECTORY", SPOOLSS_GETPRINTERDRIVERDIRECTORY, api_spoolss_getprinterdriverdirectory },
 {"SPOOLSS_ENUMPRINTERDATA",           SPOOLSS_ENUMPRINTERDATA,           api_spoolss_enumprinterdata           },
 {"SPOOLSS_SETPRINTERDATA",            SPOOLSS_SETPRINTERDATA,            api_spoolss_setprinterdata            },
 {"SPOOLSS_RESETPRINTER",              SPOOLSS_RESETPRINTER,              api_spoolss_reset_printer             },
 {"SPOOLSS_DELETEPRINTERDATA",         SPOOLSS_DELETEPRINTERDATA,         api_spoolss_deleteprinterdata         },
 {"SPOOLSS_ADDFORM",                   SPOOLSS_ADDFORM,                   api_spoolss_addform                   },
 {"SPOOLSS_DELETEFORM",                SPOOLSS_DELETEFORM,                api_spoolss_deleteform                },
 {"SPOOLSS_GETFORM",                   SPOOLSS_GETFORM,                   api_spoolss_getform                   },
 {"SPOOLSS_SETFORM",                   SPOOLSS_SETFORM,                   api_spoolss_setform                   },
 {"SPOOLSS_ADDPRINTPROCESSOR",         SPOOLSS_ADDPRINTPROCESSOR,         api_spoolss_addprintprocessor         },
 {"SPOOLSS_ENUMPRINTPROCESSORS",       SPOOLSS_ENUMPRINTPROCESSORS,       api_spoolss_enumprintprocessors       },
 {"SPOOLSS_ENUMMONITORS",              SPOOLSS_ENUMMONITORS,              api_spoolss_enumprintmonitors         },
 {"SPOOLSS_GETJOB",                    SPOOLSS_GETJOB,                    api_spoolss_getjob                    },
 {"SPOOLSS_ENUMPRINTPROCDATATYPES",    SPOOLSS_ENUMPRINTPROCDATATYPES,    api_spoolss_enumprintprocdatatypes    },
 {"SPOOLSS_GETPRINTERDATAEX",          SPOOLSS_GETPRINTERDATAEX,          api_spoolss_getprinterdataex          },
 {"SPOOLSS_SETPRINTERDATAEX",          SPOOLSS_SETPRINTERDATAEX,          api_spoolss_setprinterdataex          },
 {"SPOOLSS_DELETEPRINTERDATAEX",       SPOOLSS_DELETEPRINTERDATAEX,       api_spoolss_deleteprinterdataex       },
 {"SPOOLSS_ENUMPRINTERDATAEX",         SPOOLSS_ENUMPRINTERDATAEX,         api_spoolss_enumprinterdataex         },
 {"SPOOLSS_ENUMPRINTERKEY",            SPOOLSS_ENUMPRINTERKEY,            api_spoolss_enumprinterkey            },
 {"SPOOLSS_DELETEPRINTERKEY",          SPOOLSS_DELETEPRINTERKEY,          api_spoolss_deleteprinterkey          },
 {"SPOOLSS_GETPRINTPROCESSORDIRECTORY",SPOOLSS_GETPRINTPROCESSORDIRECTORY,api_spoolss_getprintprocessordirectory},
 {"SPOOLSS_ADDPRINTERDRIVEREX",        SPOOLSS_ADDPRINTERDRIVEREX,        api_spoolss_addprinterdriverex        },
 {"SPOOLSS_DELETEPRINTERDRIVEREX",     SPOOLSS_DELETEPRINTERDRIVEREX,     api_spoolss_deleteprinterdriverex     },
 {"SPOOLSS_XCVDATAPORT",               SPOOLSS_XCVDATAPORT,               api_spoolss_xcvdataport               },
};

void spoolss2_get_pipe_fns( struct api_struct **fns, int *n_fns )
{
	*fns = api_spoolss_cmds;
	*n_fns = sizeof(api_spoolss_cmds) / sizeof(struct api_struct);
}

NTSTATUS rpc_spoolss2_init(void)
{
	return rpc_srv_register(
		SMB_RPC_INTERFACE_VERSION, "spoolss", "spoolss",
		&ndr_table_spoolss,
		api_spoolss_cmds,
		sizeof(api_spoolss_cmds) / sizeof(struct api_struct));
}
