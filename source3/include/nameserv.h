#ifndef _NAMESERV_H_
#define _NAMESERV_H_
/* 
   Unix SMB/CIFS implementation.
   NBT netbios header - version 2
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

#define MAX_DGRAM_SIZE (576) /* tcp/ip datagram limit is 576 bytes */
#define MIN_DGRAM_SIZE 12

/*********************************************************
 Types of reply packet.
**********************************************************/

enum netbios_reply_type_code { NMB_QUERY, NMB_STATUS, NMB_REG, NMB_REG_REFRESH,
                               NMB_REL, NMB_WAIT_ACK, NMB_MULTIHOMED_REG,
                               WINS_REG, WINS_QUERY };

/* From rfc1002, 4.2.1.2 */
/* Question types. */
#define QUESTION_TYPE_NB_QUERY  0x20
#define QUESTION_TYPE_NB_STATUS 0x21

/* Question class */
#define QUESTION_CLASS_IN  0x1

/* Opcode definitions */
#define NMB_NAME_QUERY_OPCODE       0x0
#define NMB_NAME_REG_OPCODE         0x05 /* see rfc1002.txt 4.2.2,3,5,6,7,8 */
#define NMB_NAME_RELEASE_OPCODE     0x06 /* see rfc1002.txt 4.2.9,10,11 */
#define NMB_WACK_OPCODE             0x07 /* see rfc1002.txt 4.2.16 */
/* Ambiguity in rfc1002 about which of these is correct. */
/* WinNT uses 8 by default but can be made to use 9. */
#define NMB_NAME_REFRESH_OPCODE_8   0x08 /* see rfc1002.txt 4.2.4 */
#define NMB_NAME_REFRESH_OPCODE_9   0x09 /* see rfc1002.txt 4.2.4 */
#define NMB_NAME_MULTIHOMED_REG_OPCODE 0x0F /* Invented by Microsoft. */

/* XXXX what about all the other types?? 0x1, 0x2, 0x3, 0x4, 0x8? */

/* Resource record types. rfc1002 4.2.1.3 */
#define RR_TYPE_A                  0x1
#define RR_TYPE_NS                 0x2
#define RR_TYPE_NULL               0xA
#define RR_TYPE_NB                0x20
#define RR_TYPE_NBSTAT            0x21

/* Resource record class. */
#define RR_CLASS_IN                0x1

/* NetBIOS flags */
#define NB_GROUP  0x80
#define NB_PERM   0x02
#define NB_ACTIVE 0x04
#define NB_CONFL  0x08
#define NB_DEREG  0x10
#define NB_BFLAG  0x00 /* Broadcast node type. */
#define NB_PFLAG  0x20 /* Point-to-point node type. */
#define NB_MFLAG  0x40 /* Mixed bcast & p-p node type. */
#define NB_HFLAG  0x60 /* Microsoft 'hybrid' node type. */
#define NB_NODETYPEMASK 0x60
/* Mask applied to outgoing NetBIOS flags. */
#define NB_FLGMSK 0xE0

/* The wins flags. Looks like the nbflags ! */
#define WINS_UNIQUE	0x00 /* Unique record */
#define WINS_NGROUP	0x01 /* Normal Group eg: 1B */
#define WINS_SGROUP	0x02 /* Special Group eg: 1C */
#define WINS_MHOMED	0x03 /* MultiHomed */

#define WINS_ACTIVE	0x00 /* active record */
#define WINS_RELEASED	0x04 /* released record */
#define WINS_TOMBSTONED 0x08 /* tombstoned record */
#define WINS_DELETED	0x0C /* deleted record */

#define WINS_STATE_MASK	0x0C

#define WINS_LOCAL	0x00 /* local record */
#define WINS_REMOTE	0x10 /* remote record */

#define WINS_BNODE	0x00 /* Broadcast node */
#define WINS_PNODE	0x20 /* PtP node */
#define WINS_MNODE	0x40 /* Mixed node */
#define WINS_HNODE	0x60 /* Hybrid node */

#define WINS_NONSTATIC	0x00 /* dynamic record */
#define WINS_STATIC	0x80 /* static record */

#define WINS_STATE_ACTIVE(p) (((p)->data.wins_flags & WINS_STATE_MASK) == WINS_ACTIVE)


/* NetBIOS flag identifier. */
#define NAME_GROUP(p)  ((p)->data.nb_flags & NB_GROUP)
#define NAME_BFLAG(p) (((p)->data.nb_flags & NB_NODETYPEMASK) == NB_BFLAG)
#define NAME_PFLAG(p) (((p)->data.nb_flags & NB_NODETYPEMASK) == NB_PFLAG)
#define NAME_MFLAG(p) (((p)->data.nb_flags & NB_NODETYPEMASK) == NB_MFLAG)
#define NAME_HFLAG(p) (((p)->data.nb_flags & NB_NODETYPEMASK) == NB_HFLAG)

/* Samba name state for a name in a namelist. */
#define NAME_IS_ACTIVE(p)        ((p)->data.nb_flags & NB_ACTIVE)
#define NAME_IN_CONFLICT(p)      ((p)->data.nb_flags & NB_CONFL)
#define NAME_IS_DEREGISTERING(p) ((p)->data.nb_flags & NB_DEREG)

/* Error codes for NetBIOS requests. */
#define FMT_ERR   0x1       /* Packet format error. */
#define SRV_ERR   0x2       /* Internal server error. */
#define NAM_ERR   0x3       /* Name does not exist. */
#define IMP_ERR   0x4       /* Request not implemented. */
#define RFS_ERR   0x5       /* Request refused. */
#define ACT_ERR   0x6       /* Active error - name owned by another host. */
#define CFT_ERR   0x7       /* Name in conflict error. */

#define REFRESH_TIME (15*60)
#define NAME_POLL_REFRESH_TIME (5*60)
#define NAME_POLL_INTERVAL 15

/* Microsoft browser NetBIOS name. */
#define MSBROWSE "\001\002__MSBROWSE__\002"

/* Mail slots. */
#define BROWSE_MAILSLOT    "\\MAILSLOT\\BROWSE"
#define NET_LOGON_MAILSLOT "\\MAILSLOT\\NET\\NETLOGON"
#define NT_LOGON_MAILSLOT  "\\MAILSLOT\\NET\\NTLOGON"
#define LANMAN_MAILSLOT    "\\MAILSLOT\\LANMAN"

/* Samba definitions for find_name_on_subnet(). */
#define FIND_ANY_NAME   0
#define FIND_SELF_NAME  1

enum node_type {B_NODE=0, P_NODE=1, M_NODE=2, NBDD_NODE=3};
enum packet_type {NMB_PACKET, DGRAM_PACKET};

#define MAX_NETBIOSNAME_LEN 16
/* DOS character, NetBIOS namestring. Type used on the wire. */
typedef char nstring[MAX_NETBIOSNAME_LEN];
/* Unix character, NetBIOS namestring. Type used to manipulate name in nmbd. */
typedef char unstring[MAX_NETBIOSNAME_LEN*4];

/* A netbios name structure. */
struct nmb_name {
	nstring      name;
	char         scope[64];
	unsigned int name_type;
};

/* A netbios node status array element. */
struct node_status {
	nstring name;
	unsigned char type;
	unsigned char flags;
};

/* The extra info from a NetBIOS node status query */
struct node_status_extra {
	unsigned char mac_addr[6];
	/* There really is more here ... */
};

/* A resource record. */
struct res_rec {
	struct nmb_name rr_name;
	int rr_type;
	int rr_class;
	int ttl;
	int rdlength;
	char rdata[MAX_DGRAM_SIZE];
};

/* Define these so we can pass info back to caller of name_query */
#define NM_FLAGS_RS 0x80 /* Response. Cheat     */
#define NM_FLAGS_AA 0x40 /* Authoritative       */
#define NM_FLAGS_TC 0x20 /* Truncated           */
#define NM_FLAGS_RD 0x10 /* Recursion Desired   */
#define NM_FLAGS_RA 0x08 /* Recursion Available */
#define NM_FLAGS_B  0x01 /* Broadcast           */

/* An nmb packet. */
struct nmb_packet {
	struct {
		int name_trn_id;
		int opcode;
		bool response;
		struct {
			bool bcast;
			bool recursion_available;
			bool recursion_desired;
			bool trunc;
			bool authoritative;
		} nm_flags;
		int rcode;
		int qdcount;
		int ancount;
		int nscount;
		int arcount;
	} header;

	struct {
		struct nmb_name question_name;
		int question_type;
		int question_class;
	} question;

	struct res_rec *answers;
	struct res_rec *nsrecs;
	struct res_rec *additional;
};

/* msg_type field options - from rfc1002. */

#define DGRAM_UNIQUE 0x10
#define DGRAM_GROUP 0x11
#define DGRAM_BROADCAST 0x12
/* defined in IDL
#define DGRAM_ERROR 0x13
*/
#define DGRAM_QUERY_REQUEST 0x14
#define DGRAM_POSITIVE_QUERY_RESPONSE 0x15
#define DGRAM_NEGATIVE_QUERT_RESPONSE 0x16

/* A datagram - this normally contains SMB data in the data[] array. */

struct dgram_packet {
	struct {
		int msg_type;
		struct {
			enum node_type node_type;
			bool first;
			bool more;
		} flags;
		int dgm_id;
		struct in_addr source_ip;
		int source_port;
		int dgm_length;
		int packet_offset;
	} header;
	struct nmb_name source_name;
	struct nmb_name dest_name;
	int datasize;
	char data[MAX_DGRAM_SIZE];
};

/* Define a structure used to queue packets. This will be a linked
 list of nmb packets. */

struct packet_struct
{
	struct packet_struct *next;
	struct packet_struct *prev;
	bool locked;
	struct in_addr ip;
	int port;
	int recv_fd;
	int send_fd;
	time_t timestamp;
	enum packet_type packet_type;
	union {
		struct nmb_packet nmb;
		struct dgram_packet dgram;
	} packet;
};

/* Ids for netbios packet types. */

#define ANN_HostAnnouncement         1
#define ANN_AnnouncementRequest      2
#define ANN_Election                 8
#define ANN_GetBackupListReq         9
#define ANN_GetBackupListResp       10
#define ANN_BecomeBackup            11
#define ANN_DomainAnnouncement      12
#define ANN_MasterAnnouncement      13
#define ANN_ResetBrowserState       14
#define ANN_LocalMasterAnnouncement 15

#endif /* _NAMESERV_H_ */
