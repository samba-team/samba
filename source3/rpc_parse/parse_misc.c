/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Gerald (Jerry) Carter             2005
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
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Reads or writes an NTTIME structure.
********************************************************************/

bool smb_io_time(const char *desc, NTTIME *nttime, prs_struct *ps, int depth)
{
	uint32 low, high;
	if (nttime == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_time");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if (MARSHALLING(ps)) {
		low = *nttime & 0xFFFFFFFF;
		high = *nttime >> 32;
	}
	
	if(!prs_uint32("low ", ps, depth, &low)) /* low part */
		return False;
	if(!prs_uint32("high", ps, depth, &high)) /* high part */
		return False;

	if (UNMARSHALLING(ps)) {
		*nttime = (((uint64_t)high << 32) + low);
	}

	return True;
}

/*******************************************************************
********************************************************************/

bool smb_io_system_time(const char *desc, prs_struct *ps, int depth, SYSTEMTIME *systime)
{
	if(!prs_uint16("year", ps, depth, &systime->year))
		return False;
	if(!prs_uint16("month", ps, depth, &systime->month))
		return False;
	if(!prs_uint16("dayofweek", ps, depth, &systime->dayofweek))
		return False;
	if(!prs_uint16("day", ps, depth, &systime->day))
		return False;
	if(!prs_uint16("hour", ps, depth, &systime->hour))
		return False;
	if(!prs_uint16("minute", ps, depth, &systime->minute))
		return False;
	if(!prs_uint16("second", ps, depth, &systime->second))
		return False;
	if(!prs_uint16("milliseconds", ps, depth, &systime->milliseconds))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/

bool make_systemtime(SYSTEMTIME *systime, struct tm *unixtime)
{
	systime->year=unixtime->tm_year+1900;
	systime->month=unixtime->tm_mon+1;
	systime->dayofweek=unixtime->tm_wday;
	systime->day=unixtime->tm_mday;
	systime->hour=unixtime->tm_hour;
	systime->minute=unixtime->tm_min;
	systime->second=unixtime->tm_sec;
	systime->milliseconds=0;

	return True;
}

/*******************************************************************
 Reads or writes a struct GUID
********************************************************************/

bool smb_io_uuid(const char *desc, struct GUID *uuid, 
		 prs_struct *ps, int depth)
{
	if (uuid == NULL)
		return False;

	prs_debug(ps, depth, desc, "smb_io_uuid");
	depth++;

	if(!prs_uint32 ("data   ", ps, depth, &uuid->time_low))
		return False;
	if(!prs_uint16 ("data   ", ps, depth, &uuid->time_mid))
		return False;
	if(!prs_uint16 ("data   ", ps, depth, &uuid->time_hi_and_version))
		return False;

	if(!prs_uint8s (False, "data   ", ps, depth, uuid->clock_seq, sizeof(uuid->clock_seq)))
		return False;
	if(!prs_uint8s (False, "data   ", ps, depth, uuid->node, sizeof(uuid->node)))
		return False;

	return True;
}

/*******************************************************************
 Inits a UNISTR2 structure.
********************************************************************/

void init_unistr2(UNISTR2 *str, const char *buf, enum unistr2_term_codes flags)
{
	size_t len = 0;
	uint32 num_chars = 0;

	if (buf) {
		/* We always null terminate the copy. */
		len = strlen(buf) + 1;
		if ( flags == UNI_STR_DBLTERMINATE )
			len++;
	}

	if (buf == NULL || len == 0) {
		/* no buffer -- nothing to do */
		str->uni_max_len = 0;
		str->offset = 0;
		str->uni_str_len = 0;

		return;
	}
	

	str->buffer = TALLOC_ZERO_ARRAY(talloc_tos(), uint16, len);
	if (str->buffer == NULL) {
		smb_panic("init_unistr2: malloc fail");
		return;
	}

	/* Ensure len is the length in *bytes* */
	len *= sizeof(uint16);

	/*
	 * The UNISTR2 must be initialized !!!
	 * jfm, 7/7/2001.
	 */
	if (buf) {
		rpcstr_push((char *)str->buffer, buf, len, STR_TERMINATE);
		num_chars = strlen_w(str->buffer);
		if (flags == UNI_STR_TERMINATE || flags == UNI_MAXLEN_TERMINATE) {
			num_chars++;
		}
		if ( flags == UNI_STR_DBLTERMINATE )
			num_chars += 2;
	}

	str->uni_max_len = num_chars;
	str->offset = 0;
	str->uni_str_len = num_chars;
	if ( num_chars && ((flags == UNI_MAXLEN_TERMINATE) || (flags == UNI_BROKEN_NON_NULL)) )
		str->uni_max_len++;
}
