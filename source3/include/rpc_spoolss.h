/* 
   Unix SMB/Netbios implementation.

   Copyright (C) Andrew Tridgell              1992-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Jean Francois Micouleau      1998-2000.
   Copyright (C) Gerald Carter                2001-2006.
   
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

#include "librpc/gen_ndr/spoolss.h"

#ifndef _RPC_SPOOLSS_H		/* _RPC_SPOOLSS_H */
#define _RPC_SPOOLSS_H

/* spoolss pipe: this are the calls which are not implemented ...
#define SPOOLSS_GETPRINTERDRIVER			0x0b
#define SPOOLSS_READPRINTER				0x16
#define SPOOLSS_WAITFORPRINTERCHANGE			0x1c
#define SPOOLSS_ADDPORT					0x25
#define SPOOLSS_CONFIGUREPORT				0x26
#define SPOOLSS_DELETEPORT				0x27
#define SPOOLSS_CREATEPRINTERIC				0x28
#define SPOOLSS_PLAYGDISCRIPTONPRINTERIC		0x29
#define SPOOLSS_DELETEPRINTERIC				0x2a
#define SPOOLSS_ADDPRINTERCONNECTION			0x2b
#define SPOOLSS_DELETEPRINTERCONNECTION			0x2c
#define SPOOLSS_PRINTERMESSAGEBOX			0x2d
#define SPOOLSS_ADDMONITOR				0x2e
#define SPOOLSS_DELETEMONITOR				0x2f
#define SPOOLSS_DELETEPRINTPROCESSOR			0x30
#define SPOOLSS_ADDPRINTPROVIDOR			0x31
#define SPOOLSS_DELETEPRINTPROVIDOR			0x32
#define SPOOLSS_FINDFIRSTPRINTERCHANGENOTIFICATION	0x36
#define SPOOLSS_FINDNEXTPRINTERCHANGENOTIFICATION	0x37
#define SPOOLSS_ROUTERFINDFIRSTPRINTERNOTIFICATIONOLD	0x39
#define SPOOLSS_ADDPORTEX				0x3d
#define SPOOLSS_REMOTEFINDFIRSTPRINTERCHANGENOTIFICATION0x3e
#define SPOOLSS_SPOOLERINIT				0x3f
#define SPOOLSS_RESETPRINTEREX				0x40
*/

/* those are implemented */
#define SPOOLSS_ENUMPRINTERS				0x00
#define SPOOLSS_OPENPRINTER				0x01
#define SPOOLSS_SETJOB					0x02
#define SPOOLSS_GETJOB					0x03
#define SPOOLSS_ENUMJOBS				0x04
#define SPOOLSS_ADDPRINTER				0x05
#define SPOOLSS_DELETEPRINTER				0x06
#define SPOOLSS_SETPRINTER				0x07
#define SPOOLSS_GETPRINTER				0x08
#define SPOOLSS_ADDPRINTERDRIVER			0x09
#define SPOOLSS_ENUMPRINTERDRIVERS			0x0a
#define SPOOLSS_GETPRINTERDRIVERDIRECTORY		0x0c
#define SPOOLSS_DELETEPRINTERDRIVER			0x0d
#define SPOOLSS_ADDPRINTPROCESSOR			0x0e
#define SPOOLSS_ENUMPRINTPROCESSORS			0x0f
#define SPOOLSS_GETPRINTPROCESSORDIRECTORY		0x10
#define SPOOLSS_STARTDOCPRINTER				0x11
#define SPOOLSS_STARTPAGEPRINTER			0x12
#define SPOOLSS_WRITEPRINTER				0x13
#define SPOOLSS_ENDPAGEPRINTER				0x14
#define SPOOLSS_ABORTPRINTER				0x15
#define SPOOLSS_ENDDOCPRINTER				0x17
#define SPOOLSS_ADDJOB					0x18
#define SPOOLSS_SCHEDULEJOB				0x19
#define SPOOLSS_GETPRINTERDATA				0x1a
#define SPOOLSS_SETPRINTERDATA				0x1b
#define SPOOLSS_CLOSEPRINTER				0x1d
#define SPOOLSS_ADDFORM					0x1e
#define SPOOLSS_DELETEFORM				0x1f
#define SPOOLSS_GETFORM					0x20
#define SPOOLSS_SETFORM					0x21
#define SPOOLSS_ENUMFORMS				0x22
#define SPOOLSS_ENUMPORTS				0x23
#define SPOOLSS_ENUMMONITORS				0x24
#define SPOOLSS_ENUMPRINTPROCDATATYPES			0x33
#define SPOOLSS_RESETPRINTER				0x34
#define SPOOLSS_GETPRINTERDRIVER2			0x35
#define SPOOLSS_FCPN					0x38	/* FindClosePrinterNotify */
#define SPOOLSS_REPLYOPENPRINTER			0x3a
#define SPOOLSS_ROUTERREPLYPRINTER			0x3b
#define SPOOLSS_REPLYCLOSEPRINTER			0x3c
#define SPOOLSS_RFFPCNEX				0x41	/* RemoteFindFirstPrinterChangeNotifyEx */
#define SPOOLSS_RRPCN					0x42	/* RouteRefreshPrinterChangeNotification */
#define SPOOLSS_RFNPCNEX				0x43	/* RemoteFindNextPrinterChangeNotifyEx */
#define SPOOLSS_OPENPRINTEREX				0x45
#define SPOOLSS_ADDPRINTEREX				0x46
#define SPOOLSS_ENUMPRINTERDATA				0x48
#define SPOOLSS_DELETEPRINTERDATA			0x49
#define SPOOLSS_SETPRINTERDATAEX			0x4d
#define SPOOLSS_GETPRINTERDATAEX			0x4e
#define SPOOLSS_ENUMPRINTERDATAEX			0x4f
#define SPOOLSS_ENUMPRINTERKEY				0x50
#define SPOOLSS_DELETEPRINTERDATAEX			0x51
#define SPOOLSS_DELETEPRINTERKEY			0x52
#define SPOOLSS_DELETEPRINTERDRIVEREX			0x54
#define SPOOLSS_XCVDATAPORT				0x58
#define SPOOLSS_ADDPRINTERDRIVEREX			0x59

/* 
 * Special strings for the OpenPrinter() call.  See the MSDN DDK
 * docs on the XcvDataPort() for more details.
 */

#define SPL_LOCAL_PORT            "Local Port"
#define SPL_TCPIP_PORT            "Standard TCP/IP Port"
#define SPL_XCV_MONITOR_LOCALMON  ",XcvMonitor Local Port"
#define SPL_XCV_MONITOR_TCPMON    ",XcvMonitor Standard TCP/IP Port"

/* Notify field types */

#define PRINTER_NOTIFY_TYPE 0x00
#define JOB_NOTIFY_TYPE     0x01

#define PRINTER_NOTIFY_SERVER_NAME		0x00
#define PRINTER_NOTIFY_PRINTER_NAME		0x01
#define PRINTER_NOTIFY_SHARE_NAME		0x02
#define PRINTER_NOTIFY_PORT_NAME		0x03
#define PRINTER_NOTIFY_DRIVER_NAME		0x04
#define PRINTER_NOTIFY_COMMENT			0x05
#define PRINTER_NOTIFY_LOCATION			0x06
#define PRINTER_NOTIFY_DEVMODE			0x07
#define PRINTER_NOTIFY_SEPFILE			0x08
#define PRINTER_NOTIFY_PRINT_PROCESSOR		0x09
#define PRINTER_NOTIFY_PARAMETERS		0x0A
#define PRINTER_NOTIFY_DATATYPE			0x0B
#define PRINTER_NOTIFY_SECURITY_DESCRIPTOR	0x0C
#define PRINTER_NOTIFY_ATTRIBUTES		0x0D
#define PRINTER_NOTIFY_PRIORITY			0x0E
#define PRINTER_NOTIFY_DEFAULT_PRIORITY		0x0F
#define PRINTER_NOTIFY_START_TIME		0x10
#define PRINTER_NOTIFY_UNTIL_TIME		0x11
#define PRINTER_NOTIFY_STATUS			0x12
#define PRINTER_NOTIFY_STATUS_STRING		0x13
#define PRINTER_NOTIFY_CJOBS			0x14
#define PRINTER_NOTIFY_AVERAGE_PPM		0x15
#define PRINTER_NOTIFY_TOTAL_PAGES		0x16
#define PRINTER_NOTIFY_PAGES_PRINTED		0x17
#define PRINTER_NOTIFY_TOTAL_BYTES		0x18
#define PRINTER_NOTIFY_BYTES_PRINTED		0x19

#define JOB_NOTIFY_PRINTER_NAME			0x00
#define JOB_NOTIFY_MACHINE_NAME			0x01
#define JOB_NOTIFY_PORT_NAME			0x02
#define JOB_NOTIFY_USER_NAME			0x03
#define JOB_NOTIFY_NOTIFY_NAME			0x04
#define JOB_NOTIFY_DATATYPE			0x05
#define JOB_NOTIFY_PRINT_PROCESSOR		0x06
#define JOB_NOTIFY_PARAMETERS			0x07
#define JOB_NOTIFY_DRIVER_NAME			0x08
#define JOB_NOTIFY_DEVMODE			0x09
#define JOB_NOTIFY_STATUS			0x0A
#define JOB_NOTIFY_STATUS_STRING		0x0B
#define JOB_NOTIFY_SECURITY_DESCRIPTOR		0x0C
#define JOB_NOTIFY_DOCUMENT			0x0D
#define JOB_NOTIFY_PRIORITY			0x0E
#define JOB_NOTIFY_POSITION			0x0F
#define JOB_NOTIFY_SUBMITTED			0x10
#define JOB_NOTIFY_START_TIME			0x11
#define JOB_NOTIFY_UNTIL_TIME			0x12
#define JOB_NOTIFY_TIME				0x13
#define JOB_NOTIFY_TOTAL_PAGES			0x14
#define JOB_NOTIFY_PAGES_PRINTED		0x15
#define JOB_NOTIFY_TOTAL_BYTES			0x16
#define JOB_NOTIFY_BYTES_PRINTED		0x17

/*
 * Set of macros for flagging what changed in the PRINTER_INFO_2 struct
 * when sending messages to other smbd's
 */
#define PRINTER_MESSAGE_NULL            0x00000000
#define PRINTER_MESSAGE_DRIVER		0x00000001
#define PRINTER_MESSAGE_COMMENT		0x00000002
#define PRINTER_MESSAGE_PRINTERNAME	0x00000004
#define PRINTER_MESSAGE_LOCATION	0x00000008
#define PRINTER_MESSAGE_DEVMODE		0x00000010	/* not curently supported */
#define PRINTER_MESSAGE_SEPFILE		0x00000020
#define PRINTER_MESSAGE_PRINTPROC	0x00000040
#define PRINTER_MESSAGE_PARAMS		0x00000080
#define PRINTER_MESSAGE_DATATYPE	0x00000100
#define PRINTER_MESSAGE_SECDESC		0x00000200
#define PRINTER_MESSAGE_CJOBS		0x00000400
#define PRINTER_MESSAGE_PORT		0x00000800
#define PRINTER_MESSAGE_SHARENAME	0x00001000
#define PRINTER_MESSAGE_ATTRIBUTES	0x00002000

typedef struct printer_message_info {
	uint32 low;		/* PRINTER_CHANGE_XXX */
	uint32 high;		/* PRINTER_CHANGE_XXX */
	fstring printer_name;
	uint32 flags;		/* PRINTER_MESSAGE_XXX */
}
PRINTER_MESSAGE_INFO;

/*
 * The printer attributes.
 * I #defined all of them (grabbed form MSDN)
 * I'm only using:
 * ( SHARED | NETWORK | RAW_ONLY )
 * RAW_ONLY _MUST_ be present otherwise NT will send an EMF file
 */

#define PRINTER_ATTRIBUTE_SAMBA			(PRINTER_ATTRIBUTE_RAW_ONLY|\
						 PRINTER_ATTRIBUTE_SHARED|\
						 PRINTER_ATTRIBUTE_LOCAL)
#define PRINTER_ATTRIBUTE_NOT_SAMBA		(PRINTER_ATTRIBUTE_NETWORK)

#define NO_PRIORITY	 0
#define MAX_PRIORITY	99
#define MIN_PRIORITY	 1
#define DEF_PRIORITY	 1

/* the flags of each printers */

#define DRIVER_ANY_VERSION		0xffffffff
#define DRIVER_MAX_VERSION		4


/* 
 * Devicemode structure
 */

typedef struct devicemode
{
	UNISTR devicename;
	uint16 specversion;
	uint16 driverversion;
	uint16 size;
	uint16 driverextra;
	uint32 fields;
	uint16 orientation;
	uint16 papersize;
	uint16 paperlength;
	uint16 paperwidth;
	uint16 scale;
	uint16 copies;
	uint16 defaultsource;
	uint16 printquality;
	uint16 color;
	uint16 duplex;
	uint16 yresolution;
	uint16 ttoption;
	uint16 collate;
	UNISTR formname;
	uint16 logpixels;
	uint32 bitsperpel;
	uint32 pelswidth;
	uint32 pelsheight;
	uint32 displayflags;
	uint32 displayfrequency;
	uint32 icmmethod;
	uint32 icmintent;
	uint32 mediatype;
	uint32 dithertype;
	uint32 reserved1;
	uint32 reserved2;
	uint32 panningwidth;
	uint32 panningheight;
	uint8 *dev_private;
}
DEVICEMODE;

/********************************************/

typedef struct spool_q_getprinterdata
{
	POLICY_HND handle;
	UNISTR2 valuename;
	uint32 size;
}
SPOOL_Q_GETPRINTERDATA;

typedef struct spool_r_getprinterdata
{
	uint32 type;
	uint32 size;
	uint8 *data;
	uint32 needed;
	WERROR status;
}
SPOOL_R_GETPRINTERDATA;

typedef struct add_jobinfo_1
{
	UNISTR path;
	uint32 job_number;
}
ADD_JOBINFO_1;


/*
 * I'm really wondering how many different time formats
 * I will have to cope with
 *
 * JFM, 09/13/98 In a mad mood ;-(
*/
typedef struct systemtime
{
	uint16 year;
	uint16 month;
	uint16 dayofweek;
	uint16 day;
	uint16 hour;
	uint16 minute;
	uint16 second;
	uint16 milliseconds;
}
SYSTEMTIME;

/********************************************/

typedef struct spool_q_enumprinterdata
{
	POLICY_HND handle;
	uint32 index;
	uint32 valuesize;
	uint32 datasize;
}
SPOOL_Q_ENUMPRINTERDATA;

typedef struct spool_r_enumprinterdata
{
	uint32 valuesize;
	uint16 *value;
	uint32 realvaluesize;
	uint32 type;
	uint32 datasize;
	uint8 *data;
	uint32 realdatasize;
	WERROR status;
}
SPOOL_R_ENUMPRINTERDATA;

typedef struct spool_q_setprinterdata
{
	POLICY_HND handle;
	UNISTR2 value;
	uint32 type;
	uint32 max_len;
	uint8 *data;
	uint32 real_len;
	uint32 numeric_data;
}
SPOOL_Q_SETPRINTERDATA;

typedef struct spool_r_setprinterdata
{
	WERROR status;
}
SPOOL_R_SETPRINTERDATA;

typedef struct spool_q_enumprinterkey
{
	POLICY_HND handle;
	UNISTR2 key;
	uint32 size;
}
SPOOL_Q_ENUMPRINTERKEY;

typedef struct spool_r_enumprinterkey
{
	BUFFER5 keys;
	uint32 needed;	/* in bytes */
	WERROR status;
}
SPOOL_R_ENUMPRINTERKEY;

typedef struct printer_enum_values
{
	UNISTR valuename;
	uint32 value_len;
	uint32 type;
	uint8  *data;
	uint32 data_len; 
	
}
PRINTER_ENUM_VALUES;

typedef struct printer_enum_values_ctr
{
	uint32 size;
	uint32 size_of_array;
	PRINTER_ENUM_VALUES *values;
}
PRINTER_ENUM_VALUES_CTR;

typedef struct spool_q_enumprinterdataex
{
	POLICY_HND handle;
	UNISTR2 key;
	uint32 size;
}
SPOOL_Q_ENUMPRINTERDATAEX;

typedef struct spool_r_enumprinterdataex
{
	PRINTER_ENUM_VALUES_CTR ctr;
	uint32 needed;
	uint32 returned;
	WERROR status;
}
SPOOL_R_ENUMPRINTERDATAEX;

#endif /* _RPC_SPOOLSS_H */

