/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005.
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
 
#ifndef _RPC_EVENTLOG_H		/* _RPC_EVENTLOG_H */
#define _RPC_EVENTLOG_H

/* opcodes */

#define EVENTLOG_CLEAREVENTLOG		0x00
#define EVENTLOG_CLOSEEVENTLOG		0x02
#define EVENTLOG_GETNUMRECORDS		0x04
#define EVENTLOG_GETOLDESTENTRY		0x05
#define EVENTLOG_OPENEVENTLOG		0x07
#define EVENTLOG_READEVENTLOG		0x0a

/* Eventlog read flags */
/* defined in librpc/gen_ndr/eventlog.h */

/* Event types */
/* defined in librpc/gen_ndr/eventlog.h */

/* Defines for TDB keys */
#define  EVT_OLDEST_ENTRY  "INFO/oldest_entry"
#define  EVT_NEXT_RECORD   "INFO/next_record"
#define  EVT_VERSION       "INFO/version"
#define  EVT_MAXSIZE       "INFO/maxsize"
#define  EVT_RETENTION     "INFO/retention"

#define ELOG_APPL	"Application"
#define ELOG_SYS	"System"
#define ELOG_SEC	"Security"

typedef struct elog_tdb {
	struct elog_tdb *prev, *next;
	char *name;
	TDB_CONTEXT *tdb;
	int ref_count;
} ELOG_TDB;

#define ELOG_TDB_CTX(x) ((x)->tdb)


#define  EVENTLOG_DATABASE_VERSION_V1    1

/***********************************/

typedef struct 
{
	POLICY_HND handle;
	uint32 flags;
	uint32 offset;
	uint32 max_read_size;
} EVENTLOG_Q_READ_EVENTLOG;

typedef struct {
	uint32 length;
	uint32 reserved1;
	uint32 record_number;
	uint32 time_generated;
	uint32 time_written;
	uint32 event_id;
	uint16 event_type;
	uint16 num_strings;
	uint16 event_category;
	uint16 reserved2;
	uint32 closing_record_number;
	uint32 string_offset;
	uint32 user_sid_length;
	uint32 user_sid_offset;
	uint32 data_length;
	uint32 data_offset;
} Eventlog_record;

typedef struct {
	uint32 source_name_len;
	smb_ucs2_t *source_name;
	uint32 computer_name_len;
	smb_ucs2_t *computer_name;
	uint32 sid_padding;
	smb_ucs2_t *sid;
	uint32 strings_len;
	smb_ucs2_t *strings;
	uint32 user_data_len;
	char *user_data;
	uint32 data_padding;
} Eventlog_data_record;

typedef struct eventlog_entry {
	Eventlog_record record;
	Eventlog_data_record data_record;
	uint8 *data;
	uint8 *end_of_data_padding;
	struct eventlog_entry *next;
} Eventlog_entry;
 
typedef struct {
	uint32 num_bytes_in_resp;
	uint32 bytes_in_next_record;
	uint32 num_records;
	Eventlog_entry *entry;
	uint8 *end_of_entries_padding;
	uint32 sent_size;
	uint32 real_size;
	NTSTATUS status;
} EVENTLOG_R_READ_EVENTLOG;

#endif /* _RPC_EVENTLOG_H */
