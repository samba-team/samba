/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1998-2003
   
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

#include "includes.h"

/*
  error code stuff - put together by Merik Karman
  merik@blackadder.dsh.oz.au 
*/

struct err_code_struct {
	const char *name;
	int code;
	const char *message;
};

/* Dos Error Messages */
static const struct err_code_struct dos_msgs[] = {
  {"ERRbadfunc",ERRbadfunc,"Invalid function."},
  {"ERRbadfile",ERRbadfile,"File not found."},
  {"ERRbadpath",ERRbadpath,"Directory invalid."},
  {"ERRnofids",ERRnofids,"No file descriptors available"},
  {"ERRnoaccess",ERRnoaccess,"Access denied."},
  {"ERRbadfid",ERRbadfid,"Invalid file handle."},
  {"ERRbadmcb",ERRbadmcb,"Memory control blocks destroyed."},
  {"ERRnomem",ERRnomem,"Insufficient server memory to perform the requested function."},
  {"ERRbadmem",ERRbadmem,"Invalid memory block address."},
  {"ERRbadenv",ERRbadenv,"Invalid environment."},
  {"ERRbadformat",11,"Invalid format."},
  {"ERRbadaccess",ERRbadaccess,"Invalid open mode."},
  {"ERRbaddata",ERRbaddata,"Invalid data."},
  {"ERRres",ERRres,"reserved."},
  {"ERRbaddrive",ERRbaddrive,"Invalid drive specified."},
  {"ERRremcd",ERRremcd,"A Delete Directory request attempted  to  remove  the  server's  current directory."},
  {"ERRdiffdevice",ERRdiffdevice,"Not same device."},
  {"ERRnofiles",ERRnofiles,"A File Search command can find no more files matching the specified criteria."},
  {"ERRbadshare",ERRbadshare,"The sharing mode specified for an Open conflicts with existing  FIDs  on the file."},
  {"ERRlock",ERRlock,"A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRunsup", ERRunsup, "The operation is unsupported"},
  {"ERRnosuchshare", ERRnosuchshare, "You specified an invalid share name"},
  {"ERRfilexists",ERRfilexists,"The file named in a Create Directory, Make  New  File  or  Link  request already exists."},
  {"ERRinvalidname",ERRinvalidname, "Invalid name"},
  {"ERRbadpipe",ERRbadpipe,"Pipe invalid."},
  {"ERRpipebusy",ERRpipebusy,"All instances of the requested pipe are busy."},
  {"ERRpipeclosing",ERRpipeclosing,"Pipe close in progress."},
  {"ERRnotconnected",ERRnotconnected,"No process on other end of pipe."},
  {"ERRmoredata",ERRmoredata,"There is more data to be returned."},
  {"ERRinvgroup",ERRinvgroup,"Invalid workgroup (try the -W option)"},
  {"ERRlogonfailure",ERRlogonfailure,"Logon failure"},
  {"ERRdiskfull",ERRdiskfull,"Disk full"},
  {"ERRgeneral",ERRgeneral, "General failure"},
  {"ERRunknownlevel",ERRunknownlevel, "Unknown info level"},
  {NULL,-1,NULL}};

/* Server Error Messages */
static const struct err_code_struct server_msgs[] = {
  {"ERRerror",1,"Non-specific error code."},
  {"ERRbadpw",2,"Bad password - name/password pair in a Tree Connect or Session Setup are invalid."},
  {"ERRbadtype",3,"reserved."},
  {"ERRaccess",4,"The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."},
  {"ERRinvnid",5,"The tree ID (TID) specified in a command was invalid."},
  {"ERRinvnetname",6,"Invalid network name in tree connect."},
  {"ERRinvdevice",7,"Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."},
  {"ERRqfull",49,"Print queue full (files) -- returned by open print file."},
  {"ERRqtoobig",50,"Print queue full -- no space."},
  {"ERRqeof",51,"EOF on print queue dump."},
  {"ERRinvpfid",52,"Invalid print file FID."},
  {"ERRsmbcmd",64,"The server did not recognize the command received."},
  {"ERRsrverror",65,"The server encountered an internal error, e.g., system file unavailable."},
  {"ERRfilespecs",67,"The file handle (FID) and pathname parameters contained an invalid  combination of values."},
  {"ERRreserved",68,"reserved."},
  {"ERRbadpermits",69,"The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."},
  {"ERRreserved",70,"reserved."},
  {"ERRsetattrmode",71,"The attribute mode in the Set File Attribute request is invalid."},
  {"ERRpaused",81,"Server is paused."},
  {"ERRmsgoff",82,"Not receiving messages."},
  {"ERRnoroom",83,"No room to buffer message."},
  {"ERRrmuns",87,"Too many remote user names."},
  {"ERRtimeout",88,"Operation timed out."},
  {"ERRnoresource",89,"No resources currently available for request."},
  {"ERRtoomanyuids",90,"Too many UIDs active on this session."},
  {"ERRbaduid",91,"The UID is not known as a valid ID on this session."},
  {"ERRusempx",250,"Temp unable to support Raw, use MPX mode."},
  {"ERRusestd",251,"Temp unable to support Raw, use standard read/write."},
  {"ERRcontmpx",252,"Continue in MPX mode."},
  {"ERRreserved",253,"reserved."},
  {"ERRreserved",254,"reserved."},
  {"ERRnosupport",0xFFFF,"Function not supported."},
  {NULL,-1,NULL}};

/* Hard Error Messages */
static const struct err_code_struct hard_msgs[] = {
  {"ERRnowrite",19,"Attempt to write on write-protected diskette."},
  {"ERRbadunit",20,"Unknown unit."},
  {"ERRnotready",21,"Drive not ready."},
  {"ERRbadcmd",22,"Unknown command."},
  {"ERRdata",23,"Data error (CRC)."},
  {"ERRbadreq",24,"Bad request structure length."},
  {"ERRseek",25 ,"Seek error."},
  {"ERRbadmedia",26,"Unknown media type."},
  {"ERRbadsector",27,"Sector not found."},
  {"ERRnopaper",28,"Printer out of paper."},
  {"ERRwrite",29,"Write fault."},
  {"ERRread",30,"Read fault."},
  {"ERRgeneral",31,"General failure."},
  {"ERRbadshare",32,"An open conflicts with an existing open."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRwrongdisk",34,"The wrong disk was found in a drive."},
  {"ERRFCBUnavail",35,"No FCBs are available to process request."},
  {"ERRsharebufexc",36,"A sharing buffer has been exceeded."},
  {NULL,-1,NULL}};


static const struct {
	uint8_t class;
	const char *class_name;
	const struct err_code_struct *err_msgs;
} err_classes[] = { 
  {0,"SUCCESS",NULL},
  {0x01,"ERRDOS",dos_msgs},
  {0x02,"ERRSRV",server_msgs},
  {0x03,"ERRHRD",hard_msgs},
  {0x04,"ERRXOS",NULL},
  {0xE1,"ERRRMX1",NULL},
  {0xE2,"ERRRMX2",NULL},
  {0xE3,"ERRRMX3",NULL},
  {0xFF,"ERRCMD",NULL},
  {-1,NULL,NULL}};


/* return a dos error string given a error class and error code */
const char *dos_errstr(uint8_t class, uint16_t code)
{
	static char *msg;
	int i, j;
	const struct err_code_struct *err_msgs;

	if (msg) {
		free(msg);
		msg = NULL;
	}

	for (i=0;err_classes[i].class_name;i++) {
		if (class == err_classes[i].class) break;
	}
	if (!err_classes[i].class_name) {
		asprintf(&msg, "Unknown DOS error %d:%d\n", class, code);
		return msg;
	}

	err_msgs = err_classes[i].err_msgs;

	for (j=0;err_msgs && err_msgs[j].name;j++) {
		if (err_msgs[j].code == code) {
			asprintf(&msg, "%s:%s (%s)\n", 
				 err_classes[i].class_name, 
				 err_msgs[j].name, 
				 err_msgs[j].message);
			return msg;
		}
	}

	asprintf(&msg, "Unknown DOS error %s:%d\n", err_classes[i].class_name, code);
	return msg;
}
