  /* 
     Unix SMB/Netbios implementation.
     Version 1.9.
     Inter-process communication and named pipe handling
     Copyright (C) Andrew Tridgell 1992-2000

     SMB Version handling
     Copyright (C) John H Terpstra 1995-2000

     Copyright (C) Luke Kenneth Casson Leighton 1996-2000

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
/*
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"
#include "rpc_client.h"
#include "rpc_parse.h"
#include "nterr.h"

#ifdef CHECK_TYPES
#undef CHECK_TYPES
#endif
#define CHECK_TYPES 0

extern int DEBUGLEVEL;
extern int max_send;

extern fstring local_machine;
extern fstring global_myworkgroup;
extern fstring global_sam_name;

#define NERR_Success 0
#define NERR_badpass 86
#define NERR_notsupported 50

#define NERR_BASE (2100)
#define NERR_BufTooSmall (NERR_BASE+23)
#define NERR_JobNotFound (NERR_BASE+51)
#define NERR_DestNotFound (NERR_BASE+52)

#define ACCESS_READ 0x01
#define ACCESS_WRITE 0x02
#define ACCESS_CREATE 0x04

#define SHPWLEN 8		/* share password length */
#define NNLEN 12		/* 8.3 net name length */
#define SNLEN 15		/* service name length */
#define QNLEN 12		/* queue name maximum length */

extern int Client;
extern int smb_read_error;

static BOOL api_Unsupported(connection_struct * conn, uint16 vuid,
			    char *param, char *data, int mdrcnt, int mprcnt,
			    char **rdata, char **rparam, int *rdata_len,
			    int *rparam_len);
static BOOL api_TooSmall(connection_struct * conn, uint16 vuid, char *param,
			 char *data, int mdrcnt, int mprcnt, char **rdata,
			 char **rparam, int *rdata_len, int *rparam_len);

static size_t CopyUnistr2(char **p2, const UNISTR2 *uni_str, int *n)
{
	size_t l;
	unistr2_to_ascii((*p2), uni_str, (*n));
	(*p2) = skip_string((*p2), 1);
	l = strlen(*p2) + 1;
	(*p2) += l;
	(*n) -= l;
	return l;
}

static size_t CopyUnistr2Ptr(const char *base,
			     char *ptr, int ptr_off, uint32 ptr_str,
			     char **p2, const UNISTR2 *uni_str, int *n)
{
	if (ptr_str != 0)
	{
		SIVAL(ptr, ptr_off, PTR_DIFF((*p2), base));
		return CopyUnistr2(p2, uni_str, n);
	}
	SIVAL(ptr, ptr_off, 0);
	return 0;
}

static int CopyAndAdvance(char **dst, char *src, int *n)
{
	int l;
	if (!src || !dst || !n || !(*dst))
		return (0);
	StrnCpy(*dst, src, *n - 1);
	l = strlen(*dst) + 1;
	(*dst) += l;
	(*n) -= l;
	return l;
}

static char *Expand(connection_struct * conn, const vuser_key * key, int snum,
		    char *s)
{
	user_struct *vuser;
	static pstring buf;
	if (!s)
		return (NULL);
	StrnCpy(buf, s, sizeof(buf) / 2);
	pstring_sub(buf, "%S", lp_servicename(snum));
	vuser = get_valid_user_struct(key);
	standard_sub(conn, vuser, buf);
	return &buf[0];
}

/*******************************************************************
  check a API string for validity when we only need to check the prefix
  ******************************************************************/
static BOOL prefix_ok(char *str, char *prefix)
{
	return (strncmp(str, prefix, strlen(prefix)) == 0);
}

struct pack_desc
{
	char *format;		/* formatstring for structure */
	char *subformat;	/* subformat for structure */
	char *base;		/* baseaddress of buffer */
	int buflen;		/* remaining size for fixed part; on init: length of base */
	int subcount;		/* count of substructures */
	char *structbuf;	/* pointer into buffer for remaining fixed part */
	int stringlen;		/* remaining size for variable part */
	char *stringbuf;	/* pointer into buffer for remaining variable part */
	int neededlen;		/* total needed size */
	int usedlen;		/* total used size (usedlen <= neededlen and usedlen <= buflen) */
	char *curpos;		/* current position; pointer into format or subformat */
	int errcode;
};

static int get_counter(char **p)
{
	int i, n;
	if (!p || !(*p))
		return (1);
	if (!isdigit((int)**p))
		return 1;
	for (n = 0;;)
	{
		i = **p;
		if (isdigit(i))
			n = 10 * n + (i - '0');
		else
			return n;
		(*p)++;
	}
}

static int getlen(char *p)
{
	int n = 0;
	if (!p)
		return (0);
	while (*p)
	{
		switch (*p++)
		{
			case 'W':	/* word (2 byte) */
				n += 2;
				break;
			case 'N':	/* count of substructures (word) at end */
				n += 2;
				break;
			case 'D':	/* double word (4 byte) */
			case 'z':	/* offset to zero terminated string (4 byte) */
			case 'l':	/* offset to user data (4 byte) */
				n += 4;
				break;
			case 'b':	/* offset to data (with counter) (4 byte) */
				n += 4;
				get_counter(&p);
				break;
			case 'B':	/* byte (with optional counter) */
				n += get_counter(&p);
				break;
		}
	}
	return n;
}

static BOOL init_package(struct pack_desc *p, int count, int subcount)
{
	int n = p->buflen;
	int i;

	if (!p->format || !p->base)
		return (False);

	i = count * getlen(p->format);
	if (p->subformat)
		i += subcount * getlen(p->subformat);
	p->structbuf = p->base;
	p->neededlen = 0;
	p->usedlen = 0;
	p->subcount = 0;
	p->curpos = p->format;
	if (i > n)
	{
		p->neededlen = i;
		i = n = 0;
		p->errcode = ERRmoredata;
	}
	else
		p->errcode = NERR_Success;
	p->buflen = i;
	n -= i;
	p->stringbuf = p->base + i;
	p->stringlen = n;
	return (p->errcode == NERR_Success);
}

#ifdef HAVE_STDARG_H
static int package(struct pack_desc *p, ...)
{
#else
static int package(va_alist)
     va_dcl
{
	struct pack_desc *p;
#endif
	va_list args;
	int needed = 0, stringneeded;
	char *str = NULL;
	int is_string = 0, stringused;
	int32 temp;

#ifdef HAVE_STDARG_H
	va_start(args, p);
#else
	va_start(args);
	p = va_arg(args, struct pack_desc *);
#endif

	if (!*p->curpos)
	{
		if (!p->subcount)
			p->curpos = p->format;
		else
		{
			p->curpos = p->subformat;
			p->subcount--;
		}
	}
#if CHECK_TYPES
	str = va_arg(args, char *);
	SMB_ASSERT(strncmp(str, p->curpos, strlen(str)) == 0);
#endif
	stringneeded = -1;

	if (!p->curpos)
	{
		va_end(args);
		return (0);
	}

	switch (*p->curpos++)
	{
		case 'W':	/* word (2 byte) */
			needed = 2;
			temp = va_arg(args, int);
			if (p->buflen >= needed)
				SSVAL(p->structbuf, 0, temp);
			break;
		case 'N':	/* count of substructures (word) at end */
			needed = 2;
			p->subcount = va_arg(args, int);
			if (p->buflen >= needed)
				SSVAL(p->structbuf, 0, p->subcount);
			break;
		case 'D':	/* double word (4 byte) */
			needed = 4;
			temp = va_arg(args, int);
			if (p->buflen >= needed)
				SIVAL(p->structbuf, 0, temp);
			break;
		case 'B':	/* byte (with optional counter) */
			needed = get_counter(&p->curpos);
			{
				char *s = va_arg(args, char *);
				if (p->buflen >= needed)
					StrnCpy(p->structbuf, s ? s : "",
						needed - 1);
			}
			break;
		case 'z':	/* offset to zero terminated string (4 byte) */
			str = va_arg(args, char *);
			stringneeded = (str ? strlen(str) + 1 : 0);
			is_string = 1;
			break;
		case 'l':	/* offset to user data (4 byte) */
			str = va_arg(args, char *);
			stringneeded = va_arg(args, int);
			is_string = 0;
			break;
		case 'b':	/* offset to data (with counter) (4 byte) */
			str = va_arg(args, char *);
			stringneeded = get_counter(&p->curpos);
			is_string = 0;
			break;
	}
	va_end(args);
	if (stringneeded >= 0)
	{
		needed = 4;
		if (p->buflen >= needed)
		{
			stringused = stringneeded;
			if (stringused > p->stringlen)
			{
				stringused = (is_string ? p->stringlen : 0);
				if (p->errcode == NERR_Success)
					p->errcode = ERRmoredata;
			}
			if (!stringused)
				SIVAL(p->structbuf, 0, 0);
			else
			{
				SIVAL(p->structbuf, 0,
				      PTR_DIFF(p->stringbuf, p->base));
				memcpy(p->stringbuf, str ? str : "",
				       stringused);
				if (is_string)
					p->stringbuf[stringused - 1] = '\0';
				p->stringbuf += stringused;
				p->stringlen -= stringused;
				p->usedlen += stringused;
			}
		}
		p->neededlen += stringneeded;
	}
	p->neededlen += needed;
	if (p->buflen >= needed)
	{
		p->structbuf += needed;
		p->buflen -= needed;
		p->usedlen += needed;
	}
	else
	{
		if (p->errcode == NERR_Success)
			p->errcode = ERRmoredata;
	}
	return 1;
}

#if CHECK_TYPES
#define PACK(desc,t,v) package(desc,t,v,0,0,0,0)
#define PACKl(desc,t,v,l) package(desc,t,v,l,0,0,0,0)
#else
#define PACK(desc,t,v) package(desc,v)
#define PACKl(desc,t,v,l) package(desc,v,l)
#endif

static void PACKI(struct pack_desc *desc, char *t, int v)
{
	PACK(desc, t, v);
}

static void PACKS(struct pack_desc *desc, char *t, char *v)
{
	PACK(desc, t, v);
}


/****************************************************************************
  get a print queue
  ****************************************************************************/

static void PackDriverData(struct pack_desc *desc)
{
	char drivdata[4 + 4 + 32];
	SIVAL(drivdata, 0, sizeof drivdata);	/* cb */
	SIVAL(drivdata, 4, 1000);	/* lVersion */
	memset(drivdata + 8, 0, 32);	/* szDeviceName */
	pstrcpy(drivdata + 8, "NULL");
	PACKl(desc, "l", drivdata, sizeof drivdata);	/* pDriverData */
}

static int check_printq_info(struct pack_desc *desc,
			     int uLevel, char *id1, char *id2)
{
	desc->subformat = NULL;
	switch (uLevel)
	{
		case 0:
			desc->format = "B13";
			break;
		case 1:
			desc->format = "B13BWWWzzzzzWW";
			break;
		case 2:
			desc->format = "B13BWWWzzzzzWN";
			desc->subformat = "WB21BB16B10zWWzDDz";
			break;
		case 3:
			desc->format = "zWWWWzzzzWWzzl";
			break;
		case 4:
			desc->format = "zWWWWzzzzWNzzl";
			desc->subformat = "WWzWWDDzz";
			break;
		case 5:
			desc->format = "z";
			break;
		case 52:
			desc->format = "WzzzzzzzzN";
			desc->subformat = "z";
			break;
		default:
			return False;
	}
	if (strcmp(desc->format, id1) != 0)
		return False;
	if (desc->subformat && strcmp(desc->subformat, id2) != 0)
		return False;
	return True;
}

static void fill_printjob_info(connection_struct * conn, int snum, int uLevel,
			       struct pack_desc *desc,
			       print_queue_struct * queue, int n)
{
	time_t t = queue->time;

	/* the client expects localtime */
	t -= TimeDiff(t);

	PACKI(desc, "W", printjob_encode(snum, queue->job));	/* uJobId */
	if (uLevel == 1)
	{
		PACKS(desc, "B21", queue->user);	/* szUserName */
		PACKS(desc, "B", "");	/* pad */
		PACKS(desc, "B16", "");	/* szNotifyName */
		PACKS(desc, "B10", "PM_Q_RAW");	/* szDataType */
		PACKS(desc, "z", "");	/* pszParms */
		PACKI(desc, "W", n + 1);	/* uPosition */
		PACKI(desc, "W", queue->status);	/* fsStatus */
		PACKS(desc, "z", "");	/* pszStatus */
		PACKI(desc, "D", t);	/* ulSubmitted */
		PACKI(desc, "D", queue->size);	/* ulSize */
		PACKS(desc, "z", queue->file);	/* pszComment */
	}
	if (uLevel == 2 || uLevel == 3)
	{
		PACKI(desc, "W", queue->priority);	/* uPriority */
		PACKS(desc, "z", queue->user);	/* pszUserName */
		PACKI(desc, "W", n + 1);	/* uPosition */
		PACKI(desc, "W", queue->status);	/* fsStatus */
		PACKI(desc, "D", t);	/* ulSubmitted */
		PACKI(desc, "D", queue->size);	/* ulSize */
		PACKS(desc, "z", "Samba");	/* pszComment */
		PACKS(desc, "z", queue->file);	/* pszDocument */
		if (uLevel == 3)
		{
			PACKS(desc, "z", "");	/* pszNotifyName */
			PACKS(desc, "z", "PM_Q_RAW");	/* pszDataType */
			PACKS(desc, "z", "");	/* pszParms */
			PACKS(desc, "z", "");	/* pszStatus */
			PACKS(desc, "z", SERVICE(snum));	/* pszQueue */
			PACKS(desc, "z", "lpd");	/* pszQProcName */
			PACKS(desc, "z", "");	/* pszQProcParms */
			PACKS(desc, "z", "NULL");	/* pszDriverName */
			PackDriverData(desc);	/* pDriverData */
			PACKS(desc, "z", "");	/* pszPrinterName */
		}
	}
}

static void fill_printq_info(connection_struct * conn, const vuser_key * key,
			     int snum, int uLevel, struct pack_desc *desc,
			     int count, print_queue_struct * queue,
			     print_status_struct * status)
{
	switch (uLevel)
	{
		case 1:
		case 2:
			PACKS(desc, "B13", SERVICE(snum));
			break;
		case 3:
		case 4:
		case 5:
			PACKS(desc, "z",
			      Expand(conn, key, snum, SERVICE(snum)));
			break;
	}

	if (uLevel == 1 || uLevel == 2)
	{
		PACKS(desc, "B", "");	/* alignment */
		PACKI(desc, "W", 5);	/* priority */
		PACKI(desc, "W", 0);	/* start time */
		PACKI(desc, "W", 0);	/* until time */
		PACKS(desc, "z", "");	/* pSepFile */
		PACKS(desc, "z", "lpd");	/* pPrProc */
		PACKS(desc, "z", SERVICE(snum));	/* pDestinations */
		PACKS(desc, "z", "");	/* pParms */
		if (snum < 0)
		{
			PACKS(desc, "z", "UNKNOWN PRINTER");
			PACKI(desc, "W", LPSTAT_ERROR);
		}
		else if (!status || !status->message[0])
		{
			PACKS(desc, "z",
			      Expand(conn, key, snum, lp_comment(snum)));
			PACKI(desc, "W", LPSTAT_OK);	/* status */
		}
		else
		{
			PACKS(desc, "z", status->message);
			PACKI(desc, "W", status->status);	/* status */
		}
		PACKI(desc, (uLevel == 1 ? "W" : "N"), count);
	}
	if (uLevel == 3 || uLevel == 4)
	{
		PACKI(desc, "W", 5);	/* uPriority */
		PACKI(desc, "W", 0);	/* uStarttime */
		PACKI(desc, "W", 0);	/* uUntiltime */
		PACKI(desc, "W", 5);	/* pad1 */
		PACKS(desc, "z", "");	/* pszSepFile */
		PACKS(desc, "z", "WinPrint");	/* pszPrProc */
		PACKS(desc, "z", "");	/* pszParms */
		if (!status || !status->message[0])
		{
			PACKS(desc, "z", Expand(conn, key, snum, lp_comment(snum)));	/* pszComment */
			PACKI(desc, "W", LPSTAT_OK);	/* fsStatus */
		}
		else
		{
			PACKS(desc, "z", status->message);	/* pszComment */
			PACKI(desc, "W", status->status);	/* fsStatus */
		}
		PACKI(desc, (uLevel == 3 ? "W" : "N"), count);	/* cJobs */
		PACKS(desc, "z", SERVICE(snum));	/* pszPrinters */
		PACKS(desc, "z", lp_printerdriver(snum));	/* pszDriverName */
		PackDriverData(desc);	/* pDriverData */
	}
	if (uLevel == 2 || uLevel == 4)
	{
		int i;
		for (i = 0; i < count; i++)
			fill_printjob_info(conn, snum, uLevel == 2 ? 1 : 2,
					   desc, &queue[i], i);
	}

	if (uLevel == 52)
	{
		int i, ok = 0;
		pstring tok, driver, datafile, langmon, helpfile, datatype;
		char *p, *q;
		FILE *f;
		pstring fname;

		pstrcpy(fname, lp_driverfile());
		f = sys_fopen(fname, "r");
		if (!f)
		{
			DEBUG(3,
			      ("fill_printq_info: Can't open %s - %s\n",
			       fname, strerror(errno)));
			desc->errcode = NERR_notsupported;
			return;
		}

		if ((p = (char *)malloc(8192 * sizeof(char))) == NULL)
		{
			DEBUG(0, ("fill_printq_info: malloc fail !\n"));
			desc->errcode = NERR_notsupported;
			fclose(f);
			return;
		}

		memset(p, 0, 8192 * sizeof(char));
		q = p;

		/* lookup the long printer driver name in the file description */
		while (f && !feof(f) && !ok)
		{
			p = q;	/* reset string pointer */
			fgets(p, 8191, f);
			p[strlen(p) - 1] = '\0';
			if (next_token(&p, tok, ":", sizeof(tok)) &&
			    (strlen(lp_printerdriver(snum)) == strlen(tok)) &&
			    (!strncmp(tok, lp_printerdriver(snum),
				      strlen(lp_printerdriver(snum)))))
				ok = 1;
		}
		fclose(f);

		/* driver file name */
		if (ok && !next_token(&p, driver, ":", sizeof(driver)))
			ok = 0;
		/* data file name */
		if (ok && !next_token(&p, datafile, ":", sizeof(datafile)))
			ok = 0;
		/*
		 * for the next tokens - which may be empty - I have to check for empty
		 * tokens first because the next_token function will skip all empty
		 * token fields 
		 */
		if (ok)
		{
			/* help file */
			if (*p == ':')
			{
				*helpfile = '\0';
				p++;
			}
			else
				if (!next_token
				    (&p, helpfile, ":",
				     sizeof(helpfile))) ok = 0;
		}

		if (ok)
		{
			/* language monitor */
			if (*p == ':')
			{
				*langmon = '\0';
				p++;
			}
			else
				if (!next_token
				    (&p, langmon, ":", sizeof(langmon))) ok =
					0;
		}

		/* default data type */
		if (ok && !next_token(&p, datatype, ":", sizeof(datatype)))
			ok = 0;

		if (ok)
		{
			PACKI(desc, "W", 0x0400);	/* don't know */
			PACKS(desc, "z", lp_printerdriver(snum));	/* long printer name */
			PACKS(desc, "z", driver);	/* Driverfile Name */
			PACKS(desc, "z", datafile);	/* Datafile name */
			PACKS(desc, "z", langmon);	/* language monitor */
			PACKS(desc, "z", lp_driverlocation(snum));	/* share to retrieve files */
			PACKS(desc, "z", datatype);	/* default data type */
			PACKS(desc, "z", helpfile);	/* helpfile name */
			PACKS(desc, "z", driver);	/* driver name */
			DEBUG(3, ("Driver:%s:\n", driver));
			DEBUG(3, ("Data File:%s:\n", datafile));
			DEBUG(3, ("Language Monitor:%s:\n", langmon));
			DEBUG(3, ("Data Type:%s:\n", datatype));
			DEBUG(3, ("Help File:%s:\n", helpfile));
			PACKI(desc, "N", count);	/* number of files to copy */
			for (i = 0; i < count; i++)
			{
				/* no need to check return value here - it was already tested in
				 * get_printerdrivernumber
				 */
				next_token(&p, tok, ",", sizeof(tok));
				PACKS(desc, "z", tok);	/* driver files to copy */
				DEBUG(3, ("file:%s:\n", tok));
			}

			DEBUG(3,
			      ("fill_printq_info on <%s> gave %d entries\n",
			       SERVICE(snum), count));
		}
		else
		{
			DEBUG(3,
			      ("fill_printq_info: Can't supply driver files\n"));
			desc->errcode = NERR_notsupported;
		}
		free(q);
	}
}

/* This function returns the number of files for a given driver */
static int get_printerdrivernumber(int snum)
{
	int i = 0, ok = 0;
	pstring tok;
	char *p, *q;
	FILE *f;
	pstring fname;

	pstrcpy(fname, lp_driverfile());

	DEBUG(4, ("In get_printerdrivernumber: %s\n", fname));
	f = sys_fopen(fname, "r");
	if (!f)
	{
		DEBUG(3,
		      ("get_printerdrivernumber: Can't open %s - %s\n", fname,
		       strerror(errno)));
		return (0);
	}

	if ((p = (char *)malloc(8192 * sizeof(char))) == NULL)
	{
		DEBUG(3, ("get_printerdrivernumber: malloc fail !\n"));
		fclose(f);
		return 0;
	}

	q = p;			/* need it to free memory because p change ! */

	/* lookup the long printer driver name in the file description */
	while (!feof(f) && !ok)
	{
		p = q;		/* reset string pointer */
		fgets(p, 8191, f);
		if (next_token(&p, tok, ":", sizeof(tok)) &&
		    (!strncmp
		     (tok, lp_printerdriver(snum),
		      strlen(lp_printerdriver(snum)))))
			ok = 1;
	}
	fclose(f);

	if (ok)
	{
		/* skip 5 fields */
		i = 5;
		while (*p && i)
		{
			if (*p++ == ':')
				i--;
		}
		if (!*p || i)
			return (0);

		/* count the number of files */
		while (next_token(&p, tok, ",", sizeof(tok)))
			i++;
	}
	free(q);

	return (i);
}

static BOOL api_DosPrintQGetInfo(connection_struct * conn,
				 uint16 vuid, char *param, char *data,
				 int mdrcnt, int mprcnt,
				 char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *QueueName = p;
	int uLevel;
	int count = 0;
	int snum;
	char *str3;
	struct pack_desc desc;
	print_queue_struct *queue = NULL;
	print_status_struct status;

	VUSER_KEY;

	ZERO_STRUCT(status);
	ZERO_STRUCT(desc);

	p = skip_string(p, 1);
	uLevel = SVAL(p, 0);
	str3 = p + 4;

	/* remove any trailing username */
	if ((p = strchr(QueueName, '%')))
		*p = 0;

	DEBUG(3, ("PrintQueue uLevel=%d name=%s\n", uLevel, QueueName));

	/* check it's a supported variant */
	if (!prefix_ok(str1, "zWrLh"))
		return False;
	if (!check_printq_info(&desc, uLevel, str2, str3))
	{
		/*
		 * Patch from Scott Moomaw <scott@bridgewater.edu>
		 * to return the 'invalid info level' error if an
		 * unknown level was requested.
		 */
		*rdata_len = 0;
		*rparam_len = 6;
		*rparam = REALLOC(*rparam, *rparam_len);
		SSVALS(*rparam, 0, ERROR_INVALID_LEVEL);
		SSVAL(*rparam, 2, 0);
		SSVAL(*rparam, 4, 0);
		return (True);
	}

	snum = lp_servicenumber(QueueName);
	if (snum < 0 && pcap_printername_ok(QueueName, NULL))
	{
		int pnum = lp_servicenumber(PRINTERS_NAME);
		if (pnum >= 0)
		{
			lp_add_printer(QueueName, pnum);
			snum = lp_servicenumber(QueueName);
		}
	}

	if (snum < 0 || !VALID_SNUM(snum))
		return (False);

	if (uLevel == 52)
	{
		count = get_printerdrivernumber(snum);
		DEBUG(3,
		      ("api_DosPrintQGetInfo: Driver files count: %d\n",
		       count));
	}
	else
	{
		count = get_printqueue(snum, conn, &key, &queue, &status);
	}

	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	if (init_package(&desc, 1, count))
	{
		desc.subcount = count;
		fill_printq_info(conn, &key, snum, uLevel, &desc, count,
				 queue, &status);
	}
	else if (uLevel == 0)
	{
		/*
		 * This is a *disgusting* hack.
		 * This is *so* bad that even I'm embarrassed (and I
		 * have no shame). Here's the deal :
		 * Until we get the correct SPOOLSS code into smbd
		 * then when we're running with NT SMB support then
		 * NT makes this call with a level of zero, and then
		 * immediately follows it with an open request to
		 * the \\SRVSVC pipe. If we allow that open to
		 * succeed then NT barfs when it cannot open the
		 * \\SPOOLSS pipe immediately after and continually
		 * whines saying "Printer name is invalid" forever
		 * after. If we cause *JUST THIS NEXT OPEN* of \\SRVSVC
		 * to fail, then NT downgrades to using the downlevel code
		 * and everything works as well as before. I hate
		 * myself for adding this code.... JRA.
		 */

		fail_next_srvsvc_open();
	}

	*rdata_len = desc.usedlen;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, desc.neededlen);

	DEBUG(4, ("printqgetinfo: errorcode %d\n", desc.errcode));

	if (queue)
		free(queue);

	return (True);
}


/****************************************************************************
  view list of all print jobs on all queues
  ****************************************************************************/
static BOOL api_DosPrintQEnum(connection_struct * conn, uint16 vuid,
			      char *param, char *data, int mdrcnt, int mprcnt,
			      char **rdata, char **rparam, int *rdata_len,
			      int *rparam_len)
{
	char *param_format = param + 2;
	char *output_format1 = skip_string(param_format, 1);
	char *p = skip_string(output_format1, 1);
	int uLevel = SVAL(p, 0);
	char *output_format2 = p + 4;
	int services = lp_numservices();
	int i, n;
	struct pack_desc desc;
	print_queue_struct **queue = NULL;
	print_status_struct *status = NULL;
	int *subcntarr = NULL;
	int queuecnt, subcnt = 0, succnt = 0;
	VUSER_KEY;

	ZERO_STRUCT(desc);

	DEBUG(3, ("DosPrintQEnum uLevel=%d\n", uLevel));

	if (!prefix_ok(param_format, "WrLeh"))
		return False;
	if (!check_printq_info(&desc, uLevel, output_format1, output_format2))
	{
		/*
		 * Patch from Scott Moomaw <scott@bridgewater.edu>
		 * to return the 'invalid info level' error if an
		 * unknown level was requested.
		 */
		*rdata_len = 0;
		*rparam_len = 6;
		*rparam = REALLOC(*rparam, *rparam_len);
		SSVALS(*rparam, 0, ERROR_INVALID_LEVEL);
		SSVAL(*rparam, 2, 0);
		SSVAL(*rparam, 4, 0);
		return (True);
	}

	queuecnt = 0;
	for (i = 0; i < services; i++)
		if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i))
			queuecnt++;
	if (uLevel > 0)
	{
		if (
		    (queue =
		     (print_queue_struct **) malloc(queuecnt *
						    sizeof(print_queue_struct
							   *))) == NULL)
		{
			DEBUG(0, ("api_DosPrintQEnum: malloc fail !\n"));
			return False;
		}
		memset(queue, 0, queuecnt * sizeof(print_queue_struct *));
		if (
		    (status =
		     (print_status_struct *) malloc(queuecnt *
						    sizeof
						    (print_status_struct))) ==
		    NULL)
		{
			DEBUG(0, ("api_DosPrintQEnum: malloc fail !\n"));
			return False;
		}
		memset(status, 0, queuecnt * sizeof(print_status_struct));
		if ((subcntarr = (int *)malloc(queuecnt * sizeof(int))) ==
		    NULL)
		{
			DEBUG(0, ("api_DosPrintQEnum: malloc fail !\n"));
			return False;
		}
		subcnt = 0;
		n = 0;
		for (i = 0; i < services; i++)
			if (lp_snum_ok(i) && lp_print_ok(i)
			    && lp_browseable(i))
			{
				subcntarr[n] =
					get_printqueue(i, conn, &key,
						       &queue[n], &status[n]);
				subcnt += subcntarr[n];
				n++;
			}
	}
	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;

	if (init_package(&desc, queuecnt, subcnt))
	{
		n = 0;
		succnt = 0;
		for (i = 0; i < services; i++)
			if (lp_snum_ok(i) && lp_print_ok(i)
			    && lp_browseable(i))
			{
				fill_printq_info(conn, &key, i, uLevel, &desc,
						 subcntarr[n], queue[n],
						 &status[n]);
				n++;
				if (desc.errcode == NERR_Success)
					succnt = n;
			}
	}

	if (subcntarr)
		free(subcntarr);

	*rdata_len = desc.usedlen;
	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, queuecnt);

	for (i = 0; i < queuecnt; i++)
	{
		if (queue && queue[i])
			free(queue[i]);
	}

	if (queue)
		free(queue);
	if (status)
		free(status);

	return True;
}

/****************************************************************************
  get info level for a server list query
  ****************************************************************************/
static BOOL check_server_info(int uLevel, char *id)
{
	switch (uLevel)
	{
		case 0:
			if (strcmp(id, "B16") != 0)
				return False;
			break;
		case 1:
			if (strcmp(id, "B16BBDz") != 0)
				return False;
			break;
		default:
			return False;
	}
	return True;
}

struct srv_info_struct
{
	fstring name;
	uint32 type;
	fstring comment;
	fstring domain;
	BOOL server_added;
};


/*******************************************************************
  get server info lists from the files saved by nmbd. Return the
  number of entries
  ******************************************************************/
static int get_server_info(uint32 servertype,
			   struct srv_info_struct **servers, char *domain)
{
	FILE *f;
	pstring fname;
	int count = 0;
	int alloced = 0;
	pstring line;
	BOOL local_list_only;

	pstrcpy(fname, lp_lockdir());
	trim_string(fname, NULL, "/");
	pstrcat(fname, "/");
	pstrcat(fname, SERVER_LIST);

	f = sys_fopen(fname, "r");

	if (!f)
	{
		DEBUG(4, ("Can't open %s - %s\n", fname, strerror(errno)));
		return (0);
	}

	/* request for everything is code for request all servers */
	if (servertype == SV_TYPE_ALL)
		servertype &=
			~(SV_TYPE_DOMAIN_ENUM | SV_TYPE_LOCAL_LIST_ONLY);

	local_list_only = (servertype & SV_TYPE_LOCAL_LIST_ONLY);

	DEBUG(4, ("Servertype search: %8x\n", servertype));

	while (!feof(f))
	{
		fstring stype;
		struct srv_info_struct *s;
		char *ptr = line;
		BOOL ok = True;
		*ptr = 0;

		fgets(line, sizeof(line) - 1, f);
		if (!*line)
			continue;

		if (count == alloced)
		{
			alloced += 10;
			(*servers) = (struct srv_info_struct *)Realloc
				(*servers, sizeof(**servers) * alloced);
			if (!(*servers))
				return (0);
			memset((char *)((*servers) + count), 0,
			       sizeof(**servers) * (alloced - count));
		}
		s = &(*servers)[count];

		if (!next_token(&ptr, s->name, NULL, sizeof(s->name)))
			continue;
		if (!next_token(&ptr, stype, NULL, sizeof(stype)))
			continue;
		if (!next_token(&ptr, s->comment, NULL, sizeof(s->comment)))
			continue;
		if (!next_token(&ptr, s->domain, NULL, sizeof(s->domain)))
		{
			/* this allows us to cope with an old nmbd */
			pstrcpy(s->domain, global_myworkgroup);
		}

		if (sscanf(stype, "%X", &s->type) != 1)
		{
			DEBUG(4, ("r:host file "));
			ok = False;
		}

		/* Filter the servers/domains we return based on what was asked for. */

		/* Check to see if we are being asked for a local list only. */
		if (local_list_only
		    && ((s->type & SV_TYPE_LOCAL_LIST_ONLY) == 0))
		{
			DEBUG(4, ("r: local list only"));
			ok = False;
		}

		/* doesn't match up: don't want it */
		if (!(servertype & s->type))
		{
			DEBUG(4, ("r:serv type "));
			ok = False;
		}

		if ((servertype & SV_TYPE_DOMAIN_ENUM) !=
		    (s->type & SV_TYPE_DOMAIN_ENUM))
		{
			DEBUG(4, ("s: dom mismatch "));
			ok = False;
		}

		if (!strequal(domain, s->domain)
		    && !(servertype & SV_TYPE_DOMAIN_ENUM))
		{
			ok = False;
		}

		/* We should never return a server type with a SV_TYPE_LOCAL_LIST_ONLY set. */
		s->type &= ~SV_TYPE_LOCAL_LIST_ONLY;

		if (ok)
		{
			DEBUG(4, ("**SV** %20s %8x %25s %15s\n",
				  s->name, s->type, s->comment, s->domain));

			s->server_added = True;
			count++;
		}
		else
		{
			DEBUG(4, ("%20s %8x %25s %15s\n",
				  s->name, s->type, s->comment, s->domain));
		}
	}

	fclose(f);
	return (count);
}


/*******************************************************************
  fill in a server info structure
  ******************************************************************/
static int fill_srv_info(struct srv_info_struct *service,
			 int uLevel, char **buf, int *buflen,
			 char **stringbuf, int *stringspace, char *baseaddr)
{
	int struct_len;
	char *p;
	char *p2;
	int l2;
	int len;

	switch (uLevel)
	{
		case 0:
			struct_len = 16;
			break;
		case 1:
			struct_len = 26;
			break;
		default:
			return -1;
	}

	if (!buf)
	{
		len = 0;
		switch (uLevel)
		{
			case 1:
				len = strlen(service->comment) + 1;
				break;
		}

		if (buflen)
			*buflen = struct_len;
		if (stringspace)
			*stringspace = len;
		return struct_len + len;
	}

	len = struct_len;
	p = *buf;
	if (*buflen < struct_len)
		return -1;
	if (stringbuf)
	{
		p2 = *stringbuf;
		l2 = *stringspace;
	}
	else
	{
		p2 = p + struct_len;
		l2 = *buflen - struct_len;
	}
	if (!baseaddr)
		baseaddr = p;

	switch (uLevel)
	{
		case 0:
			StrnCpy(p, service->name, 15);
			break;

		case 1:
			StrnCpy(p, service->name, 15);
			SIVAL(p, 18, service->type);
			SIVAL(p, 22, PTR_DIFF(p2, baseaddr));
			len += CopyAndAdvance(&p2, service->comment, &l2);
			break;
	}

	if (stringbuf)
	{
		*buf = p + struct_len;
		*buflen -= struct_len;
		*stringbuf = p2;
		*stringspace = l2;
	}
	else
	{
		*buf = p2;
		*buflen -= len;
	}
	return len;
}


static BOOL srv_comp(struct srv_info_struct *s1, struct srv_info_struct *s2)
{
	return (strcmp(s1->name, s2->name));
}

/****************************************************************************
  view list of servers available (or possibly domains). The info is
  extracted from lists saved by nmbd on the local host
  ****************************************************************************/
static BOOL api_RNetServerEnum(connection_struct * conn, uint16 vuid,
			       char *param, char *data, int mdrcnt,
			       int mprcnt, char **rdata, char **rparam,
			       int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	uint32 servertype = IVAL(p, 4);
	char *p2;
	int data_len, fixed_len, string_len;
	int f_len = 0, s_len = 0;
	struct srv_info_struct *servers = NULL;
	int counted = 0, total = 0;
	int i, missed;
	fstring domain;
	BOOL domain_request;
	BOOL local_request;

	/* If someone sets all the bits they don't really mean to set
	   DOMAIN_ENUM and LOCAL_LIST_ONLY, they just want all the
	   known servers. */

	if (servertype == SV_TYPE_ALL)
		servertype &=
			~(SV_TYPE_DOMAIN_ENUM | SV_TYPE_LOCAL_LIST_ONLY);

	/* If someone sets SV_TYPE_LOCAL_LIST_ONLY but hasn't set
	   any other bit (they may just set this bit on it's own) they 
	   want all the locally seen servers. However this bit can be 
	   set on its own so set the requested servers to be 
	   ALL - DOMAIN_ENUM. */

	if ((servertype & SV_TYPE_LOCAL_LIST_ONLY)
	    && !(servertype & SV_TYPE_DOMAIN_ENUM))
		servertype = SV_TYPE_ALL & ~(SV_TYPE_DOMAIN_ENUM);

	domain_request = ((servertype & SV_TYPE_DOMAIN_ENUM) != 0);
	local_request = ((servertype & SV_TYPE_LOCAL_LIST_ONLY) != 0);

	p += 8;

	if (!prefix_ok(str1, "WrLehD"))
		return False;
	if (!check_server_info(uLevel, str2))
		return False;

	DEBUG(4, ("server request level: %s %8x ", str2, servertype));
	DEBUG(4, ("domains_req:%s ", BOOLSTR(domain_request)));
	DEBUG(4, ("local_only:%s\n", BOOLSTR(local_request)));

	if (strcmp(str1, "WrLehDz") == 0)
	{
		StrnCpy(domain, p, sizeof(fstring) - 1);
	}
	else
	{
		StrnCpy(domain, global_myworkgroup, sizeof(fstring) - 1);
	}

	if (lp_browse_list())
		total = get_server_info(servertype, &servers, domain);

	data_len = fixed_len = string_len = 0;
	missed = 0;

	qsort(servers, total, sizeof(servers[0]), QSORT_CAST srv_comp);

	{
		char *lastname = NULL;

		for (i = 0; i < total; i++)
		{
			struct srv_info_struct *s = &servers[i];
			if (lastname && strequal(lastname, s->name))
				continue;
			lastname = s->name;
			data_len +=
				fill_srv_info(s, uLevel, 0, &f_len, 0, &s_len,
					      0);
			DEBUG(4,
			      ("fill_srv_info %20s %8x %25s %15s\n", s->name,
			       s->type, s->comment, s->domain));

			if (data_len <= buf_len)
			{
				counted++;
				fixed_len += f_len;
				string_len += s_len;
			}
			else
			{
				missed++;
			}
		}
	}

	*rdata_len = fixed_len + string_len;
	*rdata = REALLOC(*rdata, *rdata_len);
	memset(*rdata, 0, *rdata_len);

	p2 = (*rdata) + fixed_len;	/* auxilliary data (strings) will go here */
	p = *rdata;
	f_len = fixed_len;
	s_len = string_len;

	{
		char *lastname = NULL;
		int count2 = counted;
		for (i = 0; i < total && count2; i++)
		{
			struct srv_info_struct *s = &servers[i];
			if (lastname && strequal(lastname, s->name))
				continue;
			lastname = s->name;
			fill_srv_info(s, uLevel, &p, &f_len, &p2, &s_len,
				      *rdata);
			DEBUG(4,
			      ("fill_srv_info %20s %8x %25s %15s\n", s->name,
			       s->type, s->comment, s->domain));
			count2--;
		}
	}

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, (missed == 0 ? NERR_Success : ERRmoredata));
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, counted);
	SSVAL(*rparam, 6, counted + missed);

	if (servers)
		free(servers);

	DEBUG(3, ("NetServerEnum domain = %s uLevel=%d counted=%d total=%d\n",
		  domain, uLevel, counted, counted + missed));

	return (True);
}

/****************************************************************************
  command 0x34 - suspected of being a "Lookup Names" stub api
  ****************************************************************************/
static BOOL api_RNetGroupGetUsers(connection_struct * conn, uint16 vuid,
				  char *param, char *data, int mdrcnt,
				  int mprcnt, char **rdata, char **rparam,
				  int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	int counted = 0;
	int missed = 0;

	DEBUG(5, ("RNetGroupGetUsers: %s %s %s %d %d\n",
		  str1, str2, p, uLevel, buf_len));

	if (!prefix_ok(str1, "zWrLeh"))
		return False;

	*rdata_len = 0;
	*rdata = NULL;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);

	SSVAL(*rparam, 0, 0x08AC);	/* informational warning message */
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, counted);
	SSVAL(*rparam, 6, counted + missed);

	return (True);
}

/****************************************************************************
  get info about a share
  ****************************************************************************/
static BOOL check_share_info(int uLevel, char *id)
{
	switch (uLevel)
	{
		case 0:
			if (strcmp(id, "B13") != 0)
				return False;
			break;
		case 1:
			if (strcmp(id, "B13BWz") != 0)
				return False;
			break;
		case 2:
			if (strcmp(id, "B13BWzWWWzB9B") != 0)
				return False;
			break;
		case 91:
			if (strcmp(id, "B13BWzWWWzB9BB9BWzWWzWW") != 0)
				return False;
			break;
		default:
			return False;
	}
	return True;
}

static int fill_share_info( const SHARE_INFO_2 * sh2,
			   int uLevel,
			   char **buf, int *buflen,
			   char **stringbuf, int *stringspace, char *baseaddr)
{
	int struct_len;
	char *p;
	char *p2;
	int l2;
	int len;

	switch (uLevel)
	{
		case 0:
			struct_len = 13;
			break;
		case 1:
			struct_len = 20;
			break;
		case 2:
			struct_len = 40;
			break;
		case 91:
			struct_len = 68;
			break;
		default:
			return -1;
	}


	if (!buf)
	{
		len = 0;
		if (uLevel > 0)
			len += sh2->info2_str.uni_remark.uni_str_len + 1;
		if (uLevel > 1)
			len += sh2->info2_str.uni_path.uni_str_len + 1;
		if (buflen)
			*buflen = struct_len;
		if (stringspace)
			*stringspace = len;
		return struct_len + len;
	}

	len = struct_len;
	p = *buf;
	if ((*buflen) < struct_len)
		return -1;
	if (stringbuf)
	{
		p2 = *stringbuf;
		l2 = *stringspace;
	}
	else
	{
		p2 = p + struct_len;
		l2 = (*buflen) - struct_len;
	}
	if (!baseaddr)
		baseaddr = p;

	unistr2_to_ascii(p, &sh2->info2_str.uni_netname, 13 - 1);

	if (uLevel > 0)
	{
		CVAL(p, 13) = 0;	/* maybe da string wurn't null-turminatid */
		SSVAL(p, 14, sh2->info2_hdr.type);
		len += CopyUnistr2Ptr(baseaddr, p, 16,
				      sh2->info2_hdr.ptr_remark, &p2,
				      &sh2->info2_str.uni_remark, &l2);
	}

	if (uLevel > 1)
	{
		SSVAL(p, 20, sh2->info2_hdr.perms);
		SSVALS(p, 22, sh2->info2_hdr.max_uses);
		SSVAL(p, 24, sh2->info2_hdr.num_uses);
		len += CopyUnistr2Ptr(baseaddr, p, 26,
				      sh2->info2_hdr.ptr_path, &p2,
				      &sh2->info2_str.uni_path, &l2);
		memset(p + 30, 0, SHPWLEN + 2);	/* passwd, pad field */
	}

	if (uLevel > 2)
	{
		memset(p + 40, 0, SHPWLEN + 2);
		SSVAL(p, 50, 0);
		SIVAL(p, 52, 0);
		SSVAL(p, 56, 0);
		SSVAL(p, 58, 0);
		SIVAL(p, 60, 0);
		SSVAL(p, 64, 0);
		SSVAL(p, 66, 0);
	}

	if (stringbuf)
	{
		(*buf) = p + struct_len;
		(*buflen) -= struct_len;
		(*stringbuf) = p2;
		(*stringspace) = l2;
	}
	else
	{
		(*buf) = p2;
		(*buflen) -= len;
	}
	return len;
}

static BOOL api_RNetShareGetInfo(connection_struct * conn, uint16 vuid,
				 char *param, char *data, int mdrcnt,
				 int mprcnt, char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *netname = skip_string(str2, 1);
	char *p = skip_string(netname, 1);
	int uLevel = SVAL(p, 0);
	SHARE_INFO_CTR ctr;
	uint32 status;
	VUSER_KEY;

	/* check it's a supported variant */
	if (!prefix_ok(str1, "zWrLh"))
		return False;
	if (!check_share_info(uLevel, str2))
		return False;

	ZERO_STRUCT(ctr);
	status = srv_net_srv_share_get_info("\\\\.", netname, 2, &ctr);

	if (status != 0x0)
	{
		srv_free_share_info_ctr(&ctr);
		return False;
	}

	*rdata = REALLOC(*rdata, mdrcnt);
	p = *rdata;
	*rdata_len = fill_share_info(ctr.info.id2, uLevel, &p, &mdrcnt, 0, 0,
				0);

	srv_free_share_info_ctr(&ctr);

	if (*rdata_len < 0)
		return False;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}

/****************************************************************************
  view list of shares available
  ****************************************************************************/
static BOOL api_RNetShareEnum(connection_struct * conn, uint16 vuid,
			      char *param, char *data, int mdrcnt, int mprcnt,
			      char **rdata, char **rparam, int *rdata_len,
			      int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	char *p2;
	int count = lp_numservices();
	int total = 0, counted = 0;
	BOOL missed = False;
	int i;
	int data_len, fixed_len, string_len;
	int f_len = 0, s_len = 0;
	SRV_SHARE_INFO_CTR ctr;
	ENUM_HND hnd;

	VUSER_KEY;

	ZERO_STRUCT(ctr);

	if (!prefix_ok(str1, "WrLeh"))
		return False;
	if (!check_share_info(uLevel, str2))
		return False;

	hnd.ptr_hnd = 0;
	hnd.handle = 0;

	if (!srv_net_srv_share_enum("\\\\.", 2, &ctr, mdrcnt, &hnd))
	{
		srv_free_srv_share_ctr(&ctr);
		return False;
	}

	data_len = fixed_len = string_len = 0;
	for (i = 0; i < count; i++)
	{
		SHARE_INFO_2 sh2;

		sh2.info2_hdr = *ctr.share.info2.info_2[i];
		sh2.info2_str = *ctr.share.info2.info_2_str[i];

		total++;
		data_len += fill_share_info(&sh2, uLevel, 0,
					    &f_len, 0, &s_len, 0);
		if (data_len <= buf_len)
		{
			counted++;
			fixed_len += f_len;
			string_len += s_len;
		}
		else
		{
			missed = True;
		}
	}

	*rdata_len = fixed_len + string_len;
	*rdata = REALLOC(*rdata, *rdata_len);
	memset(*rdata, 0, *rdata_len);

	p2 = (*rdata) + fixed_len;	/* auxilliary data (strings) will go here */
	p = *rdata;
	f_len = fixed_len;
	s_len = string_len;
	for (i = 0; i < count; i++)
	{
		SHARE_INFO_2 sh2;

		sh2.info2_hdr = *ctr.share.info2.info_2[i];
		sh2.info2_str = *ctr.share.info2.info_2_str[i];

		if (fill_share_info
		    (&sh2, uLevel, &p, &f_len, &p2, &s_len, *rdata) < 0)
		{
			break;
		}
	}
	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, missed ? ERRmoredata : NERR_Success);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, counted);
	SSVAL(*rparam, 6, total);

	DEBUG(3, ("RNetShareEnum gave %d entries of %d (%d %d %d %d)\n",
		  counted, total, uLevel, buf_len, *rdata_len, mdrcnt));

	srv_free_srv_share_ctr(&ctr);

	return (True);
}



/****************************************************************************
  get the time of day info
  ****************************************************************************/
static BOOL api_NetRemoteTOD(connection_struct * conn, uint16 vuid,
			     char *param, char *data, int mdrcnt, int mprcnt,
			     char **rdata, char **rparam, int *rdata_len,
			     int *rparam_len)
{
	TIME_OF_DAY_INFO tod;
	char *p;

	if (!srv_net_remote_tod("\\\\.", &tod))
	{
		return False;
	}

	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 21;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */

	p = *rdata;

	SIVAL(p, 0, tod.elapsedt);
	SIVAL(p, 4, tod.msecs);
	CVAL(p, 8) = tod.hours;
	CVAL(p, 9) = tod.mins;
	CVAL(p, 10) = tod.secs;
	CVAL(p, 11) = tod.hunds;
	SSVALS(p, 12, tod.zone);	
	SSVAL(p, 14, tod.tintervals);
	CVAL(p, 16) = tod.day;
	CVAL(p, 17) = tod.month;
	SSVAL(p, 18, tod.year);
	CVAL(p, 20) = tod.weekday;

	return (True);
}

/****************************************************************************
  set the user password
  ****************************************************************************/
static BOOL api_SetUserPassword(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{
	char *p = skip_string(param + 2, 2);
	fstring user;
	fstring pass1, pass2;
	uchar pwbuf[516];
	uchar nt_pw[16];
	uchar lm_pw[16];

	fstrcpy(user, p);

	p = skip_string(p, 1);

	memcpy(pass1, p, 16);
	memcpy(pass2, p + 16, 16);

	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_badpass);
	SSVAL(*rparam, 2, 0);	/* converter word */

	DEBUG(3, ("Set password for <%s>\n", user));

	if (strequal(param + 2, "zb16b16WW"))
	{
		/*
		 * attempt the encrypted pw change. NT will generate this
		 * after trying the samr method.
		 */

		if (SVAL(*rparam, 0) != NERR_Success)
		{
			if (make_oem_passwd_hash
			    (pwbuf, pass1, 16, NULL, False)
			    && msrpc_sam_ntpasswd_set("\\\\.", user, NULL,
						      pwbuf, pass2,	/* lm pw */
						      NULL, NULL))	/* nt pw */
			{
				SSVAL(*rparam, 0, NERR_Success);
			}
		}
	}
	else
	{
		/*
		 * Attempt the plaintext password change.
		 * Older versions of Windows seem to do this.
		 */

		nt_lm_owf_gen(pass1, nt_pw, lm_pw);
		if (msrpc_sam_ntchange_pwd("\\\\.", user, global_sam_name,
					   lm_pw, nt_pw, pass2))
		{
			SSVAL(*rparam, 0, NERR_Success);
		}
	}
	ZERO_STRUCT(pwbuf);
	ZERO_STRUCT(pass1);
	ZERO_STRUCT(pass2);

	return (True);
}

/****************************************************************************
  Set the user password (SamOEM version - gets plaintext).
****************************************************************************/

static BOOL api_SamOEMChangePassword(connection_struct * conn, uint16 vuid,
				     char *param, char *data, int mdrcnt,
				     int mprcnt, char **rdata, char **rparam,
				     int *rdata_len, int *rparam_len)
{
	fstring user;
	char *p = param + 2;
	*rparam_len = 2;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_badpass);

	/*
	 * Check the parameter definition is correct.
	 */
	if (!strequal(param + 2, "zsT"))
	{
		DEBUG(0,
		      ("api_SamOEMChangePassword: Invalid parameter string %s\n",
		       param + 2));
		return False;
	}
	p = skip_string(p, 1);

	if (!strequal(p, "B516B16"))
	{
		DEBUG(0,
		      ("api_SamOEMChangePassword: Invalid data parameter string %s\n",
		       p));
		return False;
	}
	p = skip_string(p, 1);

	fstrcpy(user, p);
	p = skip_string(p, 1);

	DEBUG(3,
	      ("api_SamOEMChangePassword: Change password for <%s>\n", user));

	if (msrpc_sam_ntpasswd_set("\\\\.", user, NULL,
				   (uchar *) data, (uchar *) & data[516],	/* lm pw */
				   NULL, NULL))	/* nt pw */
	{
		SSVAL(*rparam, 0, NERR_Success);
	}

	return (True);
}

/****************************************************************************
  delete a print job
  Form: <W> <> 
  ****************************************************************************/
static BOOL api_RDosPrintJobDel(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{
	int function = SVAL(param, 0);
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int jobid, snum;
	int i, count;
	VUSER_KEY;

	printjob_decode(SVAL(p, 0), &snum, &jobid);

	/* check it's a supported variant */
	if (!(strcsequal(str1, "W") && strcsequal(str2, "")))
		return (False);

	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_Success);

	if (snum >= 0 && VALID_SNUM(snum))
	{
		print_queue_struct *queue = NULL;
		lpq_reset(snum);
		count = get_printqueue(snum, conn, &key, &queue, NULL);

		for (i = 0; i < count; i++)
			if ((queue[i].job & 0xFF) == jobid)
			{
				switch (function)
				{
					case 81:	/* delete */
						DEBUG(3,
						      ("Deleting queue entry %d\n",
						       queue[i].job));
						del_printqueue(conn, &key,
							       snum,
							       queue[i].job);
						break;
					case 82:	/* pause */
					case 83:	/* resume */
						DEBUG(3,
						      ("%s queue entry %d\n",
						       (function ==
							82 ? "pausing" :
							"resuming"),
						       queue[i].job));
						status_printjob(conn, &key,
								snum,
								queue[i].job,
								(function ==
								 82 ?
								 LPQ_PAUSED :
								 LPQ_QUEUED));
						break;
				}
				break;
			}

		if (i == count)
			SSVAL(*rparam, 0, NERR_JobNotFound);

		if (queue)
			free(queue);
	}

	SSVAL(*rparam, 2, 0);	/* converter word */

	return (True);
}

/****************************************************************************
  Purge a print queue - or pause or resume it.
  ****************************************************************************/
static BOOL api_WPrintQueuePurge(connection_struct * conn, uint16 vuid,
				 char *param, char *data, int mdrcnt,
				 int mprcnt, char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	int function = SVAL(param, 0);
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *QueueName = skip_string(str2, 1);
	int snum;
	VUSER_KEY;

	/* check it's a supported variant */
	if (!(strcsequal(str1, "z") && strcsequal(str2, "")))
		return (False);

	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */

	snum = lp_servicenumber(QueueName);
	if (snum < 0 && pcap_printername_ok(QueueName, NULL))
	{
		int pnum = lp_servicenumber(PRINTERS_NAME);
		if (pnum >= 0)
		{
			lp_add_printer(QueueName, pnum);
			snum = lp_servicenumber(QueueName);
		}
	}

	if (snum >= 0 && VALID_SNUM(snum))
	{
		lpq_reset(snum);

		switch (function)
		{
			case 74:	/* Pause queue */
			case 75:	/* Resume queue */
			{
				status_printqueue(conn, &key, snum,
						  (function ==
						   74 ? LPSTAT_STOPPED :
						   LPSTAT_OK));
				DEBUG(3,
				      ("Print queue %s, queue=%s\n",
				       (function == 74 ? "pause" : "resume"),
				       QueueName));
				break;
			}
			case 103:	/* Purge */
			{
				print_queue_struct *queue = NULL;
				int i, count;
				count =
					get_printqueue(snum, conn, &key,
						       &queue, NULL);
				for (i = 0; i < count; i++)
					del_printqueue(conn, &key, snum,
						       queue[i].job);

				if (queue)
					free(queue);
				DEBUG(3,
				      ("Print queue purge, queue=%s\n",
				       QueueName));
				break;
			}
		}
	}

	return (True);
}


/****************************************************************************
  set the property of a print job (undocumented?)
  ? function = 0xb -> set name of print job
  ? function = 0x6 -> move print job up/down
  Form: <WWsTP> <WWzWWDDzzzzzzzzzzlz> 
  or   <WWsTP> <WB21BB16B10zWWzDDz> 
****************************************************************************/
static int check_printjob_info(struct pack_desc *desc, int uLevel, char *id)
{
	desc->subformat = NULL;
	switch (uLevel)
	{
		case 0:
			desc->format = "W";
			break;
		case 1:
			desc->format = "WB21BB16B10zWWzDDz";
			break;
		case 2:
			desc->format = "WWzWWDDzz";
			break;
		case 3:
			desc->format = "WWzWWDDzzzzzzzzzzlz";
			break;
		default:
			return False;
	}
	if (strcmp(desc->format, id) != 0)
		return False;
	return True;
}

static BOOL api_PrintJobInfo(connection_struct * conn, uint16 vuid,
			     char *param, char *data, int mdrcnt, int mprcnt,
			     char **rdata, char **rparam, int *rdata_len,
			     int *rparam_len)
{
	struct pack_desc desc;
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int jobid, snum;
	int uLevel = SVAL(p, 2);
	int function = SVAL(p, 4);	/* what is this ?? */
	int i;
	char *s = data;
	files_struct *fsp;
	VUSER_KEY;

	printjob_decode(SVAL(p, 0), &snum, &jobid);

	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	/* check it's a supported variant */
	if ((strcmp(str1, "WWsTP")) ||
	    (!check_printjob_info(&desc, uLevel, str2)))
		return (False);

	switch (function)
	{
		case 0x6:	/* change job place in the queue, 
				   data gives the new place */
			if (snum >= 0 && VALID_SNUM(snum))
			{
				print_queue_struct *queue = NULL;
				int count;

				lpq_reset(snum);
				count =
					get_printqueue(snum, conn, &key,
						       &queue, NULL);
				for (i = 0; i < count; i++)	/* find job */
					if ((queue[i].job & 0xFF) == jobid)
						break;

				if (i == count)
				{
					desc.errcode = NERR_JobNotFound;
					if (queue)
						free(queue);
				}
				else
				{
					desc.errcode = NERR_Success;
					i++;
#if 0
					{
						int place = SVAL(data, 0);
						/* we currently have no way of
						   doing this. Can any unix do it? */
						if (i <
						    place) /* move down */ ;
						else if (i > place)	/* move up */
							;
					}
#endif
					desc.errcode = NERR_notsupported;	/* not yet 
										   supported */
					if (queue)
						free(queue);
				}
			}
			else
			{
				desc.errcode = NERR_JobNotFound;
			}
			break;

		case 0xb:	/* change print job name, data gives the name */
			/* jobid, snum should be zero */
			if (isalpha((int)*s))
			{
				pstring name;
				int l = 0;
				while (l < 64 && *s)
				{
					if (issafe(*s))
						name[l++] = *s;
					s++;
				}
				name[l] = 0;

				DEBUG(3,
				      ("Setting print name to %s\n", name));

				fsp = file_find_print();

				if (fsp)
				{
					pstring zfrom, zto;
					connection_struct *fconn = fsp->conn;
					unbecome_user();

					if (!become_user(fconn, vuid) ||
					    !become_service(fconn, True))
						break;

					pstrcpy(zfrom,
						dos_to_unix(fsp->fsp_name,
							    False));
					pstrcpy(zto,
						dos_to_unix(name, False));

					if (fsp->conn->
					    vfs_ops.rename(zfrom, zto) == 0)
					{
						string_set(&fsp->fsp_name,
							   name);
					}
					break;
				}
			}
			desc.errcode = NERR_Success;
			break;

		default:	/* not implemented */
			return False;
	}

	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);	/* converter word */

	return (True);
}


/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_RNetServerGetInfo(connection_struct * conn, uint16 vuid,
				  char *param, char *data, int mdrcnt,
				  int mprcnt, char **rdata, char **rparam,
				  int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	char *p2;
	int struct_len;
	SRV_INFO_CTR ctr;
	SRV_INFO_102 *sv102 = &ctr.srv.sv102;
	VUSER_KEY;

	DEBUG(4, ("NetServerGetInfo level %d\n", uLevel));

	/* check it's a supported variant */
	if (!prefix_ok(str1, "WrLh"))
		return False;

	switch (uLevel)
	{
		case 0:
			if (strcmp(str2, "B16") != 0)
				return False;
			struct_len = 16;
			break;
		case 1:
			if (strcmp(str2, "B16BBDz") != 0)
				return False;
			struct_len = 26;
			break;
		case 2:
			if (strcmp
			    (str2,
			     "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWz")
			    != 0)
				return False;
			struct_len = 134;
			break;
		case 3:
			if (strcmp
			    (str2,
			     "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWzDWz")
			    != 0)
				return False;
			struct_len = 144;
			break;
		case 20:
			if (strcmp(str2, "DN") != 0)
				return False;
			struct_len = 6;
			break;
		case 50:
			if (strcmp(str2, "B16BBDzWWzzz") != 0)
				return False;
			struct_len = 42;
			break;
		default:
			return False;
	}

	if (uLevel > 1)
	{
		return False;	/* not yet implemented */
	}

	ZERO_STRUCT(ctr);
	if (!srv_net_srv_get_info("\\\\.", 102, &ctr))
	{
		return False;
	}

	*rdata_len = mdrcnt;
	*rdata = REALLOC(*rdata, *rdata_len);

	p = *rdata;
	p2 = p + struct_len;

	if (sv102->ptr_name != 0)
	{
		unistr2_to_ascii(p, &sv102->uni_name, 16 - 1);
		strupper(p);
	}
	else
	{
		memset(p, 0, 16);
	}
	p += 16;

	if (uLevel > 0)
	{
		SCVAL(p, 0, sv102->ver_major);
		SCVAL(p, 1, sv102->ver_minor);
		SIVAL(p, 2, sv102->srv_type);

		if (sv102->ptr_comment != 0 || mdrcnt == struct_len)
		{
			SIVAL(p, 6, PTR_DIFF(p2, *rdata));
			unistr2_to_ascii(p2, &sv102->uni_comment,
					 MAX(mdrcnt - struct_len, 0));
			p2 = skip_string(p2, 1);
		}
		else
		{
			SIVAL(p, 6, 0);
		}
	}

	*rdata_len = PTR_DIFF(p2, *rdata);
	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}


/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_NetWkstaGetInfo(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{

	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *p2;
	extern pstring sesssetup_user; /* want to get rid of this, use vuser */
	int level = SVAL(p, 0);
	int l2;
	int len = 0;
	WKS_INFO_100 ctr;

	ZERO_STRUCT(ctr);

	DEBUG(4, ("NetWkstaGetInfo level %d\n", level));

	/* check it's a supported variant */
	if (!
	    (level == 10 && strcsequal(str1, "WrLh")
	     && strcsequal(str2, "zzzBBzz")))
		return (False);

	if (!wks_query_info( "\\\\.", 100, &ctr))
	{
		return False;
	}

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = mdrcnt + 1024;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */

	p = *rdata;
	p2 = p + 22;
	l2 = *rdata_len;

	len += CopyUnistr2Ptr(*rdata, p, 0,
				      ctr.ptr_compname, &p2,
				      &ctr.uni_compname, &l2);
	p += 4;

	/* session-user's name? */
	SIVAL(p, 0, PTR_DIFF(p2, *rdata));
	pstrcpy(p2, sesssetup_user);
	p2 = skip_string(p2, 1);
	p += 4;

	/* session-user's domain name? */
	len += CopyUnistr2Ptr(*rdata, p, 0,
				      ctr.ptr_lan_grp, &p2,
				      &ctr.uni_lan_grp, &l2);
	p += 4;

	SCVAL(p, 0, ctr.ver_major);
	SCVAL(p, 1, ctr.ver_minor);
	p += 2;

	len += CopyUnistr2Ptr(*rdata, p, 0,
				      ctr.ptr_lan_grp, &p2,
				      &ctr.uni_lan_grp, &l2);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata));	/* don't know */
	pstrcpy(p2, "");
	p2 = skip_string(p2, 1);
	p += 4;

	*rdata_len = PTR_DIFF(p2, *rdata);

	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}

/****************************************************************************
  get info about a user

    struct user_info_11 {
        char                usri11_name[21];  0-20 
        char                usri11_pad;       21 
        char                *usri11_comment;  22-25 
        char            *usri11_usr_comment;  26-29
        unsigned short      usri11_priv;      30-31
        unsigned long       usri11_auth_flags; 32-35
        long                usri11_password_age; 36-39
        char                *usri11_homedir; 40-43
        char            *usri11_parms; 44-47
        long                usri11_last_logon; 48-51
        long                usri11_last_logoff; 52-55
        unsigned short      usri11_bad_pw_count; 56-57
        unsigned short      usri11_num_logons; 58-59
        char                *usri11_logon_server; 60-63
        unsigned short      usri11_country_code; 64-65
        char            *usri11_workstations; 66-69
        unsigned long       usri11_max_storage; 70-73
        unsigned short      usri11_units_per_week; 74-75
        unsigned char       *usri11_logon_hours; 76-79
        unsigned short      usri11_code_page; 80-81
    };

where:

  usri11_name specifies the user name for which information is retireved

  usri11_pad aligns the next data structure element to a word boundary

  usri11_comment is a null terminated ASCII comment

  usri11_user_comment is a null terminated ASCII comment about the user

  usri11_priv specifies the level of the privilege assigned to the user.
       The possible values are:

Name             Value  Description
USER_PRIV_GUEST  0      Guest privilege
USER_PRIV_USER   1      User privilege
USER_PRV_ADMIN   2      Administrator privilege

  usri11_auth_flags specifies the account operator privileges. The
       possible values are:

Name            Value   Description
AF_OP_PRINT     0       Print operator


Leach, Naik                                        [Page 28]


INTERNET-DRAFT   CIFS Remote Admin Protocol     January 10, 1997


AF_OP_COMM      1       Communications operator
AF_OP_SERVER    2       Server operator
AF_OP_ACCOUNTS  3       Accounts operator


  usri11_password_age specifies how many seconds have elapsed since the
       password was last changed.

  usri11_home_dir points to a null terminated ASCII string that contains
       the path name of the user's home directory.

  usri11_parms points to a null terminated ASCII string that is set
       aside for use by applications.

  usri11_last_logon specifies the time when the user last logged on.
       This value is stored as the number of seconds elapsed since
       00:00:00, January 1, 1970.

  usri11_last_logoff specifies the time when the user last logged off.
       This value is stored as the number of seconds elapsed since
       00:00:00, January 1, 1970. A value of 0 means the last logoff
       time is unknown.

  usri11_bad_pw_count specifies the number of incorrect passwords
       entered since the last successful logon.

  usri11_log1_num_logons specifies the number of times this user has
       logged on. A value of -1 means the number of logons is unknown.

  usri11_logon_server points to a null terminated ASCII string that
       contains the name of the server to which logon requests are sent.
       A null string indicates logon requests should be sent to the
       domain controller.

  usri11_country_code specifies the country code for the user's language
       of choice.

  usri11_workstations points to a null terminated ASCII string that
       contains the names of workstations the user may log on from.
       There may be up to 8 workstations, with the names separated by
       commas. A null strings indicates there are no restrictions.

  usri11_max_storage specifies the maximum amount of disk space the user
       can occupy. A value of 0xffffffff indicates there are no
       restrictions.

  usri11_units_per_week specifies the equal number of time units into
       which a week is divided. This value must be equal to 168.

  usri11_logon_hours points to a 21 byte (168 bits) string that
       specifies the time during which the user can log on. Each bit
       represents one unique hour in a week. The first bit (bit 0, word
       0) is Sunday, 0:00 to 0:59, the second bit (bit 1, word 0) is



Leach, Naik                                        [Page 29]


INTERNET-DRAFT   CIFS Remote Admin Protocol     January 10, 1997


       Sunday, 1:00 to 1:59 and so on. A null pointer indicates there
       are no restrictions.

  usri11_code_page specifies the code page for the user's language of
       choice

All of the pointers in this data structure need to be treated
specially. The  pointer is a 32 bit pointer. The higher 16 bits need
to be ignored. The converter word returned in the parameters section
needs to be subtracted from the lower 16 bits to calculate an offset
into the return buffer where this ASCII string resides.

There is no auxilliary data in the response.

  ****************************************************************************/

#define usri11_name           0
#define usri11_pad            21
#define usri11_comment        22
#define usri11_usr_comment    26
#define usri11_full_name      30
#define usri11_priv           34
#define usri11_auth_flags     36
#define usri11_password_age   40
#define usri11_homedir        44
#define usri11_parms          48
#define usri11_last_logon     52
#define usri11_last_logoff    56
#define usri11_bad_pw_count   60
#define usri11_num_logons     62
#define usri11_logon_server   64
#define usri11_country_code   68
#define usri11_workstations   70
#define usri11_max_storage    74
#define usri11_units_per_week 78
#define usri11_logon_hours    80
#define usri11_code_page      84
#define usri11_end            86

#define USER_PRIV_GUEST 0
#define USER_PRIV_USER 1
#define USER_PRIV_ADMIN 2

#define AF_OP_PRINT     0
#define AF_OP_COMM      1
#define AF_OP_SERVER    2
#define AF_OP_ACCOUNTS  3


static BOOL api_RNetUserGetInfo(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *UserName = skip_string(str2, 1);
	char *p = skip_string(UserName, 1);
	int uLevel = SVAL(p, 0);
	char *p2;

	fstring nt_name;
	fstring logon_path;
	fstring full_name;
	fstring home_dir;
	fstring logon_srv;

	/* get NIS home of a previously validated user - simeon */
	/* With share level security vuid will always be zero.
	   Don't depend on vuser being non-null !!. JRA */
	user_struct *vuser = NULL;
	/* moved here due to initialization code (req for IRIX cc) */
	VUSER_KEY;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);

	DEBUG(4, ("RNetUserGetInfo level=%d\n", uLevel));

	/* check it's a supported variant */
	if (strcmp(str1, "zWrLh") != 0)
		return False;
	switch (uLevel)
	{
		case 0:
			p2 = "B21";
			break;
		case 1:
			p2 = "B21BB16DWzzWz";
			break;
		case 2:
			p2 = "B21BB16DWzzWzDzzzzDDDDWb21WWzWW";
			break;
		case 10:
			p2 = "B21Bzzz";
			break;
		case 11:
			p2 = "B21BzzzWDDzzDDWWzWzDWb21W";
			break;
		default:
		{
			vuid_free_user_struct(vuser);
			return False;
		}
	}

	if (strcmp(p2, str2) != 0)
	{
		return False;
	}

	vuser = get_valid_user_struct(&key);
	if (vuser != NULL)
	{
		DEBUG(3,
		      ("  Username of UID %d is %s\n", (int)vuser->uid,
		       vuser->name));
	}
	else
	{
		return False;
	}

	unistr2_to_ascii(full_name, &vuser->usr.uni_full_name,
			 sizeof(full_name) - 1);
	unistr2_to_ascii(home_dir, &vuser->usr.uni_home_dir,
			 sizeof(home_dir) - 1);
	unistr2_to_ascii(nt_name, &vuser->usr.uni_user_name,
			 sizeof(nt_name) - 1);
	unistr2_to_ascii(logon_path, &vuser->usr.uni_logon_script,
			 sizeof(logon_path) - 1);
	fstrcpy(logon_srv, "\\\\");
	unistr2_to_ascii(&logon_srv[2], &vuser->usr.uni_logon_srv,
			 sizeof(logon_srv) - 3);

	*rdata_len = mdrcnt + 1024;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */

	p = *rdata;
	p2 = p + usri11_end;

	memset(p, 0, 21);
	fstrcpy(p + usri11_name, nt_name);	/* 21 bytes - user name */

	if (uLevel > 0)
	{
		SCVAL(p, usri11_pad, 0);	/* padding - 1 byte */
		*p2 = 0;
	}
	if (uLevel >= 10)
	{
		SIVAL(p, usri11_comment, PTR_DIFF(p2, p));	/* comment */
		pstrcpy(p2, "");
		p2 = skip_string(p2, 1);

		SIVAL(p, usri11_usr_comment, PTR_DIFF(p2, p));	/* user_comment */
		pstrcpy(p2, "");
		p2 = skip_string(p2, 1);

		/* EEK! the cifsrap.txt doesn't have this in!!!! */
		SIVAL(p, usri11_full_name, PTR_DIFF(p2, p));	/* full name */
		pstrcpy(p2, full_name);
		p2 = skip_string(p2, 1);
	}

	if (uLevel == 11)	/* modelled after NTAS 3.51 reply */
	{
		SSVAL(p, usri11_priv,
		      conn->admin_user ? USER_PRIV_ADMIN : USER_PRIV_USER);
		SIVAL(p, usri11_auth_flags, AF_OP_PRINT);	/* auth flags */
		SIVALS(p, usri11_password_age, -1);	/* password age */
		SIVAL(p, usri11_homedir, PTR_DIFF(p2, p));	/* home dir */
		pstrcpy(p2, home_dir);
		p2 = skip_string(p2, 1);
		SIVAL(p, usri11_parms, PTR_DIFF(p2, p));	/* parms */
		pstrcpy(p2, "");
		p2 = skip_string(p2, 1);
		SIVAL(p, usri11_last_logon, 0);	/* last logon */
		SIVAL(p, usri11_last_logoff, 0);	/* last logoff */
		SSVALS(p, usri11_bad_pw_count, vuser->usr.bad_pw_count);	/* bad pw counts */
		SSVALS(p, usri11_num_logons, vuser->usr.logon_count);	/* num logons */
		SIVAL(p, usri11_logon_server, PTR_DIFF(p2, p));	/* logon server */
		pstrcpy(p2, logon_srv);
		p2 = skip_string(p2, 1);
		SSVAL(p, usri11_country_code, 0);	/* country code */

		SIVAL(p, usri11_workstations, PTR_DIFF(p2, p));	/* workstations */
		pstrcpy(p2, "");
		p2 = skip_string(p2, 1);

		SIVALS(p, usri11_max_storage, -1);	/* max storage */
		SSVAL(p, usri11_units_per_week, 168);	/* units per week */
		SIVAL(p, usri11_logon_hours, PTR_DIFF(p2, p));	/* logon hours */

		/* a simple way to get logon hours at all times. */
		memset(p2, 0xff, 21);
		SCVAL(p2, 21, 0);	/* fix zero termination */
		p2 = skip_string(p2, 1);

		SSVAL(p, usri11_code_page, 0);	/* code page */
	}
	if (uLevel == 1 || uLevel == 2)
	{
		memset(p + 22, ' ', 16);	/* password */
		SIVALS(p, 38, -1);	/* password age */
		SSVAL(p, 42,
		      conn->admin_user ? USER_PRIV_ADMIN : USER_PRIV_USER);
		SIVAL(p, 44, PTR_DIFF(p2, *rdata));	/* home dir */
		pstrcpy(p2, logon_path);
		p2 = skip_string(p2, 1);
		SIVAL(p, 48, PTR_DIFF(p2, *rdata));	/* comment */
		*p2++ = 0;
		SSVAL(p, 52, 0);	/* flags */
		SIVAL(p, 54, 0);	/* script_path */
		if (uLevel == 2)
		{
			SIVAL(p, 60, 0);	/* auth_flags */
			SIVAL(p, 64, PTR_DIFF(p2, *rdata));	/* full_name */
			pstrcpy(p2, nt_name);
			p2 = skip_string(p2, 1);
			SIVAL(p, 68, 0);	/* urs_comment */
			SIVAL(p, 72, PTR_DIFF(p2, *rdata));	/* parms */
			pstrcpy(p2, "");
			p2 = skip_string(p2, 1);
			SIVAL(p, 76, 0);	/* workstations */
			SIVAL(p, 80, 0);	/* last_logon */
			SIVAL(p, 84, 0);	/* last_logoff */
			SIVALS(p, 88, -1);	/* acct_expires */
			SIVALS(p, 92, -1);	/* max_storage */
			SSVAL(p, 96, 168);	/* units_per_week */
			SIVAL(p, 98, PTR_DIFF(p2, *rdata));	/* logon_hours */
			memset(p2, -1, 21);
			p2 += 21;
			SSVALS(p, 102, vuser->usr.bad_pw_count);	/* bad_pw_count */
			SSVALS(p, 104, vuser->usr.logon_count);	/* num_logons */
			SIVAL(p, 106, PTR_DIFF(p2, *rdata));	/* logon_server */
			pstrcpy(p2, logon_srv);
			p2 = skip_string(p2, 1);
			SSVAL(p, 110, 49);	/* country_code */
			SSVAL(p, 112, 860);	/* code page */
		}
	}

	*rdata_len = PTR_DIFF(p2, *rdata);

	SSVAL(*rparam, 4, *rdata_len);	/* is this right?? */

	vuid_free_user_struct(vuser);

	return (True);
}

/*******************************************************************
  get groups that a user is a member of
  ******************************************************************/
static BOOL api_NetUserGetGroups(connection_struct * conn, uint16 vuid,
				 char *param, char *data, int mdrcnt,
				 int mprcnt, char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *UserName = skip_string(str2, 1);
	char *p = skip_string(UserName, 1);
	int uLevel = SVAL(p, 0);
	char *p2;
	int count = 0;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);

	/* check it's a supported variant */
	if (strcmp(str1, "zWrLeh") != 0)
		return False;
	switch (uLevel)
	{
		case 0:
			p2 = "B21";
			break;
		default:
			return False;
	}
	if (strcmp(p2, str2) != 0)
		return False;

	*rdata_len = mdrcnt + 1024;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);	/* converter word */

	p = *rdata;

	/* XXXX we need a real SAM database some day */
	pstrcpy(p, "Users");
	p += 21;
	count++;
	pstrcpy(p, "Domain Users");
	p += 21;
	count++;
	pstrcpy(p, "Guests");
	p += 21;
	count++;
	pstrcpy(p, "Domain Guests");
	p += 21;
	count++;

	*rdata_len = PTR_DIFF(p, *rdata);

	SSVAL(*rparam, 4, count);	/* is this right?? */
	SSVAL(*rparam, 6, count);	/* is this right?? */

	return (True);
}


static BOOL api_WWkstaUserLogon(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	struct pack_desc desc;
	char *name;
	user_struct *vuser;
	VUSER_KEY;
	vuser = get_valid_user_struct(&key);	/* moved due to VUSER_KEY initialization */

	if (vuser == NULL)
	{
		return False;
	}

	uLevel = SVAL(p, 0);
	name = p + 2;

	ZERO_STRUCT(desc);

	DEBUG(3, ("WWkstaUserLogon uLevel=%d name=%s\n", uLevel, name));

	/* check it's a supported variant */
	if (strcmp(str1, "OOWb54WrLh") != 0)
		return False;
	if (uLevel != 1 || strcmp(str2, "WB21BWDWWDDDDDDDzzzD") != 0)
		return False;
	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	desc.subformat = NULL;
	desc.format = str2;

	if (init_package(&desc, 1, 0))
	{
		fstring nt_name;
		fstring logon_script;
		fstring logon_srv;
		fstring logon_dom;

		unistr2_to_ascii(nt_name, &vuser->usr.uni_user_name,
				 sizeof(nt_name) - 1);
		unistr2_to_ascii(logon_script, &vuser->usr.uni_logon_script,
				 sizeof(logon_script) - 1);
		unistr2_to_ascii(logon_dom, &vuser->usr.uni_logon_dom,
				 sizeof(logon_dom) - 1);
		fstrcpy(logon_srv, "\\\\");
		unistr2_to_ascii(&logon_srv[2], &vuser->usr.uni_logon_srv,
				 sizeof(logon_srv) - 3);

		PACKI(&desc, "W", 0);	/* code */
		PACKS(&desc, "B21", nt_name);	/* eff. name */
		PACKS(&desc, "B", "");	/* pad */
		PACKI(&desc, "W",
		      conn->admin_user ? USER_PRIV_ADMIN : USER_PRIV_USER);
		PACKI(&desc, "D", 0);	/* auth flags XXX */
		PACKI(&desc, "W", 0);	/* num logons */
		PACKI(&desc, "W", 0);	/* bad pw count */
		PACKI(&desc, "D", 0);	/* last logon */
		PACKI(&desc, "D", -1);	/* last logoff */
		PACKI(&desc, "D", -1);	/* logoff time */
		PACKI(&desc, "D", -1);	/* kickoff time */
		PACKI(&desc, "D", 0);	/* password age */
		PACKI(&desc, "D", 0);	/* password can change */
		PACKI(&desc, "D", -1);	/* password must change */
		{
			PACKS(&desc, "z", logon_srv);	/* computer */
		}
		PACKS(&desc, "z", logon_dom);	/* domain */
		PACKS(&desc, "z", logon_script);	/* script path */

		PACKI(&desc, "D", 0x00000000);	/* reserved */
	}

	*rdata_len = desc.usedlen;
	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, desc.neededlen);

	DEBUG(4, ("WWkstaUserLogon: errorcode %d\n", desc.errcode));
	vuid_free_user_struct(vuser);

	return (True);
}


/****************************************************************************
  api_WAccessGetUserPerms
  ****************************************************************************/
static BOOL api_WAccessGetUserPerms(connection_struct * conn, uint16 vuid,
				    char *param, char *data, int mdrcnt,
				    int mprcnt, char **rdata, char **rparam,
				    int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *user = skip_string(str2, 1);
	char *resource = skip_string(user, 1);

	DEBUG(3,
	      ("WAccessGetUserPerms user=%s resource=%s\n", user, resource));

	/* check it's a supported variant */
	if (strcmp(str1, "zzh") != 0)
		return False;
	if (strcmp(str2, "") != 0)
		return False;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, 0);	/* errorcode */
	SSVAL(*rparam, 2, 0);	/* converter word */
	SSVAL(*rparam, 4, 0x7f);	/* permission flags */

	return (True);
}

/****************************************************************************
  api_WPrintJobEnumerate
  ****************************************************************************/
static BOOL api_WPrintJobGetInfo(connection_struct * conn, uint16 vuid,
				 char *param, char *data, int mdrcnt,
				 int mprcnt, char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	int count;
	int i;
	int snum;
	int job;
	struct pack_desc desc;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	VUSER_KEY;

	uLevel = SVAL(p, 2);

	ZERO_STRUCT(desc);
	ZERO_STRUCT(status);

	DEBUG(3,
	      ("WPrintJobGetInfo uLevel=%d uJobId=0x%X\n", uLevel,
	       SVAL(p, 0)));

	/* check it's a supported variant */
	if (strcmp(str1, "WWrLh") != 0)
		return False;
	if (!check_printjob_info(&desc, uLevel, str2))
		return False;

	printjob_decode(SVAL(p, 0), &snum, &job);

	if (snum < 0 || !VALID_SNUM(snum))
		return (False);

	count = get_printqueue(snum, conn, &key, &queue, &status);
	for (i = 0; i < count; i++)
	{
		if ((queue[i].job & 0xFF) == job)
			break;
	}
	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;

	if (init_package(&desc, 1, 0))
	{
		if (i < count)
		{
			fill_printjob_info(conn, snum, uLevel, &desc,
					   &queue[i], i);
			*rdata_len = desc.usedlen;
		}
		else
		{
			desc.errcode = NERR_JobNotFound;
			*rdata_len = 0;
		}
	}

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, desc.neededlen);

	if (queue)
		free(queue);

	DEBUG(4, ("WPrintJobGetInfo: errorcode %d\n", desc.errcode));
	return (True);
}

static BOOL api_WPrintJobEnumerate(connection_struct * conn, uint16 vuid,
				   char *param, char *data, int mdrcnt,
				   int mprcnt, char **rdata, char **rparam,
				   int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *name = p;
	int uLevel;
	int count;
	int i, succnt = 0;
	int snum;
	struct pack_desc desc;
	print_queue_struct *queue = NULL;
	print_status_struct status;
	VUSER_KEY;

	ZERO_STRUCT(desc);
	ZERO_STRUCT(status);

	p = skip_string(p, 1);
	uLevel = SVAL(p, 0);

	DEBUG(3, ("WPrintJobEnumerate uLevel=%d name=%s\n", uLevel, name));

	/* check it's a supported variant */
	if (strcmp(str1, "zWrLeh") != 0)
		return False;
	if (uLevel > 2)
		return False;	/* defined only for uLevel 0,1,2 */
	if (!check_printjob_info(&desc, uLevel, str2))
		return False;

	snum = lp_servicenumber(name);
	if (snum < 0 && pcap_printername_ok(name, NULL))
	{
		int pnum = lp_servicenumber(PRINTERS_NAME);
		if (pnum >= 0)
		{
			lp_add_printer(name, pnum);
			snum = lp_servicenumber(name);
		}
	}

	if (snum < 0 || !VALID_SNUM(snum))
		return (False);

	count = get_printqueue(snum, conn, &key, &queue, &status);
	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;

	if (init_package(&desc, count, 0))
	{
		succnt = 0;
		for (i = 0; i < count; i++)
		{
			fill_printjob_info(conn, snum, uLevel, &desc,
					   &queue[i], i);
			if (desc.errcode == NERR_Success)
				succnt = i + 1;
		}
	}

	*rdata_len = desc.usedlen;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, count);

	if (queue)
		free(queue);

	DEBUG(4, ("WPrintJobEnumerate: errorcode %d\n", desc.errcode));
	return (True);
}

static int check_printdest_info(struct pack_desc *desc, int uLevel, char *id)
{
	desc->subformat = NULL;
	switch (uLevel)
	{
		case 0:
			desc->format = "B9";
			break;
		case 1:
			desc->format = "B9B21WWzW";
			break;
		case 2:
			desc->format = "z";
			break;
		case 3:
			desc->format = "zzzWWzzzWW";
			break;
		default:
			return False;
	}
	if (strcmp(desc->format, id) != 0)
		return False;
	return True;
}

static void fill_printdest_info(connection_struct * conn, int snum,
				int uLevel, struct pack_desc *desc)
{
	char buf[100];
	strncpy(buf, SERVICE(snum), sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;
	strupper(buf);
	if (uLevel <= 1)
	{
		PACKS(desc, "B9", buf);	/* szName */
		if (uLevel == 1)
		{
			PACKS(desc, "B21", "");	/* szUserName */
			PACKI(desc, "W", 0);	/* uJobId */
			PACKI(desc, "W", 0);	/* fsStatus */
			PACKS(desc, "z", "");	/* pszStatus */
			PACKI(desc, "W", 0);	/* time */
		}
	}
	if (uLevel == 2 || uLevel == 3)
	{
		PACKS(desc, "z", buf);	/* pszPrinterName */
		if (uLevel == 3)
		{
			PACKS(desc, "z", "");	/* pszUserName */
			PACKS(desc, "z", "");	/* pszLogAddr */
			PACKI(desc, "W", 0);	/* uJobId */
			PACKI(desc, "W", 0);	/* fsStatus */
			PACKS(desc, "z", "");	/* pszStatus */
			PACKS(desc, "z", "");	/* pszComment */
			PACKS(desc, "z", "NULL");	/* pszDrivers */
			PACKI(desc, "W", 0);	/* time */
			PACKI(desc, "W", 0);	/* pad1 */
		}
	}
}

static BOOL api_WPrintDestGetInfo(connection_struct * conn, uint16 vuid,
				  char *param, char *data, int mdrcnt,
				  int mprcnt, char **rdata, char **rparam,
				  int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *PrinterName = p;
	int uLevel;
	struct pack_desc desc;
	int snum;

	ZERO_STRUCT(desc);

	p = skip_string(p, 1);
	uLevel = SVAL(p, 0);

	DEBUG(3,
	      ("WPrintDestGetInfo uLevel=%d PrinterName=%s\n", uLevel,
	       PrinterName));

	/* check it's a supported variant */
	if (strcmp(str1, "zWrLh") != 0)
		return False;
	if (!check_printdest_info(&desc, uLevel, str2))
		return False;

	snum = lp_servicenumber(PrinterName);
	if (snum < 0 && pcap_printername_ok(PrinterName, NULL))
	{
		int pnum = lp_servicenumber(PRINTERS_NAME);
		if (pnum >= 0)
		{
			lp_add_printer(PrinterName, pnum);
			snum = lp_servicenumber(PrinterName);
		}
	}

	if (snum < 0)
	{
		*rdata_len = 0;
		desc.errcode = NERR_DestNotFound;
		desc.neededlen = 0;
	}
	else
	{
		if (mdrcnt > 0)
			*rdata = REALLOC(*rdata, mdrcnt);
		desc.base = *rdata;
		desc.buflen = mdrcnt;
		if (init_package(&desc, 1, 0))
		{
			fill_printdest_info(conn, snum, uLevel, &desc);
		}
		*rdata_len = desc.usedlen;
	}

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, desc.neededlen);

	DEBUG(4, ("WPrintDestGetInfo: errorcode %d\n", desc.errcode));
	return (True);
}

static BOOL api_WPrintDestEnum(connection_struct * conn, uint16 vuid,
			       char *param, char *data, int mdrcnt,
			       int mprcnt, char **rdata, char **rparam,
			       int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	int queuecnt;
	int i, n, succnt = 0;
	struct pack_desc desc;
	int services = lp_numservices();

	ZERO_STRUCT(desc);

	uLevel = SVAL(p, 0);

	DEBUG(3, ("WPrintDestEnum uLevel=%d\n", uLevel));

	/* check it's a supported variant */
	if (strcmp(str1, "WrLeh") != 0)
		return False;
	if (!check_printdest_info(&desc, uLevel, str2))
		return False;

	queuecnt = 0;
	for (i = 0; i < services; i++)
		if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i))
			queuecnt++;

	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	if (init_package(&desc, queuecnt, 0))
	{
		succnt = 0;
		n = 0;
		for (i = 0; i < services; i++)
		{
			if (lp_snum_ok(i) && lp_print_ok(i)
			    && lp_browseable(i))
			{
				fill_printdest_info(conn, i, uLevel, &desc);
				n++;
				if (desc.errcode == NERR_Success)
					succnt = n;
			}
		}
	}

	*rdata_len = desc.usedlen;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, queuecnt);

	DEBUG(4, ("WPrintDestEnumerate: errorcode %d\n", desc.errcode));
	return (True);
}

static BOOL api_WPrintDriverEnum(connection_struct * conn, uint16 vuid,
				 char *param, char *data, int mdrcnt,
				 int mprcnt, char **rdata, char **rparam,
				 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	int succnt;
	struct pack_desc desc;

	ZERO_STRUCT(desc);

	uLevel = SVAL(p, 0);

	DEBUG(3, ("WPrintDriverEnum uLevel=%d\n", uLevel));

	/* check it's a supported variant */
	if (strcmp(str1, "WrLeh") != 0)
		return False;
	if (uLevel != 0 || strcmp(str2, "B41") != 0)
		return False;

	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	if (init_package(&desc, 1, 0))
	{
		PACKS(&desc, "B41", "NULL");
	}

	succnt = (desc.errcode == NERR_Success ? 1 : 0);

	*rdata_len = desc.usedlen;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, 1);

	DEBUG(4, ("WPrintDriverEnum: errorcode %d\n", desc.errcode));
	return (True);
}

static BOOL api_WPrintQProcEnum(connection_struct * conn, uint16 vuid,
				char *param, char *data, int mdrcnt,
				int mprcnt, char **rdata, char **rparam,
				int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	int succnt;
	struct pack_desc desc;

	ZERO_STRUCT(desc);

	uLevel = SVAL(p, 0);

	DEBUG(3, ("WPrintQProcEnum uLevel=%d\n", uLevel));

	/* check it's a supported variant */
	if (strcmp(str1, "WrLeh") != 0)
		return False;
	if (uLevel != 0 || strcmp(str2, "B13") != 0)
		return False;

	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	desc.format = str2;
	if (init_package(&desc, 1, 0))
	{
		PACKS(&desc, "B13", "lpd");
	}

	succnt = (desc.errcode == NERR_Success ? 1 : 0);

	*rdata_len = desc.usedlen;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, 1);

	DEBUG(4, ("WPrintQProcEnum: errorcode %d\n", desc.errcode));
	return (True);
}

static BOOL api_WPrintPortEnum(connection_struct * conn, uint16 vuid,
			       char *param, char *data, int mdrcnt,
			       int mprcnt, char **rdata, char **rparam,
			       int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel;
	int succnt;
	struct pack_desc desc;

	ZERO_STRUCT(desc);

	uLevel = SVAL(p, 0);

	DEBUG(3, ("WPrintPortEnum uLevel=%d\n", uLevel));

	/* check it's a supported variant */
	if (strcmp(str1, "WrLeh") != 0)
		return False;
	if (uLevel != 0 || strcmp(str2, "B9") != 0)
		return False;

	if (mdrcnt > 0)
		*rdata = REALLOC(*rdata, mdrcnt);
	ZERO_STRUCT(desc);
	desc.base = *rdata;
	desc.buflen = mdrcnt;
	desc.format = str2;
	if (init_package(&desc, 1, 0))
	{
		PACKS(&desc, "B13", "lp0");
	}

	succnt = (desc.errcode == NERR_Success ? 1 : 0);

	*rdata_len = desc.usedlen;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVALS(*rparam, 0, desc.errcode);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, succnt);
	SSVAL(*rparam, 6, 1);

	DEBUG(4, ("WPrintPortEnum: errorcode %d\n", desc.errcode));
	return (True);
}


/****************************************************************************
 The buffer was too small
  ****************************************************************************/
static BOOL api_TooSmall(connection_struct * conn, uint16 vuid, char *param,
			 char *data, int mdrcnt, int mprcnt, char **rdata,
			 char **rparam, int *rdata_len, int *rparam_len)
{
	*rparam_len = MIN(*rparam_len, mprcnt);
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_BufTooSmall);

	DEBUG(3, ("Supplied buffer too small in API command\n"));

	return (True);
}


/****************************************************************************
 The request is not supported
  ****************************************************************************/
static BOOL api_Unsupported(connection_struct * conn, uint16 vuid,
			    char *param, char *data, int mdrcnt, int mprcnt,
			    char **rdata, char **rparam, int *rdata_len,
			    int *rparam_len)
{
	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_notsupported);
	SSVAL(*rparam, 2, 0);	/* converter word */

	DEBUG(3, ("Unsupported API command\n"));

	return (True);
}




struct
{
	char *name;
	int id;
	BOOL (*fn) (connection_struct *, uint16, char *, char *,
		    int, int, char **, char **, int *, int *);
	int flags;
} api_commands[] =
{
	{
	"RNetShareEnum", 0, api_RNetShareEnum, 0}
	,
	{
	"RNetShareGetInfo", 1, api_RNetShareGetInfo, 0}
	,
	{
	"RNetServerGetInfo", 13, api_RNetServerGetInfo, 0}
	,
	{
	"RNetGroupGetUsers", 52, api_RNetGroupGetUsers, 0}
	,
	{
	"RNetUserGetInfo", 56, api_RNetUserGetInfo, 0}
	,
	{
	"NetUserGetGroups", 59, api_NetUserGetGroups, 0}
	,
	{
	"NetWkstaGetInfo", 63, api_NetWkstaGetInfo, 0}
	,
	{
	"DosPrintQEnum", 69, api_DosPrintQEnum, 0}
	,
	{
	"DosPrintQGetInfo", 70, api_DosPrintQGetInfo, 0}
	,
	{
	"WPrintQueuePause", 74, api_WPrintQueuePurge, 0}
	,
	{
	"WPrintQueueResume", 75, api_WPrintQueuePurge, 0}
	,
	{
	"WPrintJobEnumerate", 76, api_WPrintJobEnumerate, 0}
	,
	{
	"WPrintJobGetInfo", 77, api_WPrintJobGetInfo, 0}
	,
	{
	"RDosPrintJobDel", 81, api_RDosPrintJobDel, 0}
	,
	{
	"RDosPrintJobPause", 82, api_RDosPrintJobDel, 0}
	,
	{
	"RDosPrintJobResume", 83, api_RDosPrintJobDel, 0}
	,
	{
	"WPrintDestEnum", 84, api_WPrintDestEnum, 0}
	,
	{
	"WPrintDestGetInfo", 85, api_WPrintDestGetInfo, 0}
	,
	{
	"NetRemoteTOD", 91, api_NetRemoteTOD, 0}
	,
	{
	"WPrintQueuePurge", 103, api_WPrintQueuePurge, 0}
	,
	{
	"NetServerEnum", 104, api_RNetServerEnum, 0}
	,
	{
	"WAccessGetUserPerms", 105, api_WAccessGetUserPerms, 0}
	,
	{
	"SetUserPassword", 115, api_SetUserPassword, 0}
	,
	{
	"WWkstaUserLogon", 132, api_WWkstaUserLogon, 0}
	,
	{
	"PrintJobInfo", 147, api_PrintJobInfo, 0}
	,
	{
	"WPrintDriverEnum", 205, api_WPrintDriverEnum, 0}
	,
	{
	"WPrintQProcEnum", 206, api_WPrintQProcEnum, 0}
	,
	{
	"WPrintPortEnum", 207, api_WPrintPortEnum, 0}
	,
	{
	"SamOEMChangePassword", 214, api_SamOEMChangePassword, 0}
	,
	{
	NULL, -1, api_Unsupported, 0}
};


/****************************************************************************
 Handle remote api calls
  ****************************************************************************/
int api_reply(connection_struct * conn, uint16 vuid, char *outbuf, char *data,
	      char *params, int tdscnt, int tpscnt, int mdrcnt, int mprcnt)
{
	int api_command;
	prs_struct rdata_buf;
	prs_struct rparam_buf;
	char *rdata = NULL;
	char *rparam = NULL;
	int rdata_len = 0;
	int rparam_len = 0;
	BOOL reply = False;
	int i;

	if (params == 0)
	{
		DEBUG(0, ("ERROR: NULL params in api_reply()\n"));
		return 0;
	}

	api_command = SVAL(params, 0);

	DEBUG(3,
	      ("Got API command %d of form <%s> <%s> (tdscnt=%d,tpscnt=%d,mdrcnt=%d,mprcnt=%d)\n",
	       api_command, params + 2, skip_string(params + 2, 1), tdscnt,
	       tpscnt, mdrcnt, mprcnt));

	for (i = 0; api_commands[i].name; i++)
		if (api_commands[i].id == api_command && api_commands[i].fn)
		{
			DEBUG(3, ("Doing %s\n", api_commands[i].name));
			break;
		}

	rdata = (char *)malloc(1024);
	if (rdata)
		memset(rdata, 0, 1024);
	rparam = (char *)malloc(1024);
	if (rparam)
		memset(rparam, 0, 1024);

	if (!rdata || !rparam)
	{
		DEBUG(0, ("api_reply: malloc fail !\n"));
		return -1;
	}

	reply = api_commands[i].fn(conn, vuid, params, data, mdrcnt, mprcnt,
				   &rdata, &rparam, &rdata_len, &rparam_len);


	if (rdata_len > mdrcnt || rparam_len > mprcnt)
	{
		reply = api_TooSmall(conn, vuid, params, data, mdrcnt, mprcnt,
				     &rdata, &rparam, &rdata_len,
				     &rparam_len);
	}


	/* if we get False back then it's actually unsupported */
	if (!reply)
		api_Unsupported(conn, vuid, params, data, mdrcnt, mprcnt,
				&rdata, &rparam, &rdata_len, &rparam_len);

	prs_create(&rdata_buf, rdata, rdata_len, 0, False);
	prs_create(&rparam_buf, rparam, rparam_len, 0, False);

	/* now send the reply */
	send_trans_reply(outbuf, &rdata_buf, &rparam_buf, NULL, 0, 0, False);

	prs_free_data(&rdata_buf);
	prs_free_data(&rparam_buf);

	return (-1);
}
