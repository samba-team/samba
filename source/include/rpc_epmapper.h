/* 
   Unix SMB/CIFS implementation.
   Endpoint mapper data definitions
   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003
   
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

#define EPM_HANDLE_LEN 20

/* ordinal for the mapping interface */

#define EPM_MAP_PIPE_NAME 0x03

/* some of the different connection protocols and their IDs from Windows */

#define EPM_FLOOR_UUID    0x0d   /* floor contains UUID                   */
#define EPM_FLOOR_RPC     0x0b   /* tower is for connection-oriented rpc  */
#define EPM_FLOOR_TCP     0x07   /* floor contains tcp port number        */
#define EPM_FLOOR_IP      0x09   /* floor contains IP address             */
#define EPM_FLOOR_NMPIPES 0x0f   /* floor contains remote named pipe name */
#define EPM_FLOOR_LRPC    0x10   /* floor contains local named pipe name  */
#define EPM_FLOOR_NETBIOS 0x11   /* floor contains netbios address        */
#define EPM_FLOOR_NETBEUI 0x12   /* floor contains netbeui address        */
#define EPM_FLOOR_SOCKET  0x20

#define EPM_PIPE_NM "epmapper"

#define MAX_TOWERS 1

typedef struct
{
	uint8 data[EPM_HANDLE_LEN];
} EPM_HANDLE;

typedef struct 
{
	struct {
		uint16 length;
		uint8 protocol;
		struct {
			RPC_UUID uuid;
			uint16 version;
		} uuid;
	} lhs;
	struct {
		uint16 length;
		uint16 unknown;
		struct {
			uint16 port;
		} tcp;
		struct {
			uint8 addr[4];
		} ip;
		char string[MAXHOSTNAMELEN+3]; /* hostname + \\ + null term */
	} rhs;
} EPM_FLOOR;

typedef struct
{
	uint32 max_length;
	uint32 length;
	uint16 num_floors;
	EPM_FLOOR *floors;
	uint8 unknown;
} EPM_TOWER;

typedef struct
{
	EPM_HANDLE handle;
	uint32 tower_ref_id;
	EPM_TOWER *tower;
	EPM_HANDLE term_handle; /* in/out */       
	uint32 max_towers;  
} EPM_Q_MAP;

typedef struct
{
	uint32 max_count;
	uint32 offset;
	uint32 count;
	uint32 *tower_ref_ids;
	EPM_TOWER *towers;
} EPM_TOWER_ARRAY;

typedef struct
{
	EPM_HANDLE handle;
	uint32 num_results;
	EPM_TOWER_ARRAY *results;
	uint32 status;
} EPM_R_MAP;


/* port mapping entries to be read */

typedef struct _mapper_entries{
	uint8 protocol        ;
 	RPC_IFACE uuid_info   ;  /* needs to be zeroed if no specific uuid */
	uint16 port           ; 
	char pipe_name[40]    ;
	char srv_name[20]     ;  
	uint8 srv_port[4]     ;
	char func_name[16][16];  /* array of up to 16 functions available */
} mapper_entries;

