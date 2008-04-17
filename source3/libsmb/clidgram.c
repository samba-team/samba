/* 
   Unix SMB/CIFS implementation.
   client dgram calls
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Richard Sharpe 2001
   Copyright (C) John Terpstra 2001

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

/*
 * cli_send_mailslot, send a mailslot for client code ...
 */

bool cli_send_mailslot(struct messaging_context *msg_ctx,
		       bool unique, const char *mailslot,
		       uint16 priority,
		       char *buf, int len,
		       const char *srcname, int src_type,
		       const char *dstname, int dest_type,
		       const struct sockaddr_storage *dest_ss)
{
	struct packet_struct p;
	struct dgram_packet *dgram = &p.packet.dgram;
	char *ptr, *p2;
	char tmp[4];
	pid_t nmbd_pid;
	char addr[INET6_ADDRSTRLEN];

	if ((nmbd_pid = pidfile_pid("nmbd")) == 0) {
		DEBUG(3, ("No nmbd found\n"));
		return False;
	}

	if (dest_ss->ss_family != AF_INET) {
		DEBUG(3, ("cli_send_mailslot: can't send to IPv6 address.\n"));
		return false;
	}

	memset((char *)&p, '\0', sizeof(p));

	/*
	 * Next, build the DGRAM ...
	 */

	/* DIRECT GROUP or UNIQUE datagram. */
	dgram->header.msg_type = unique ? 0x10 : 0x11;
	dgram->header.flags.node_type = M_NODE;
	dgram->header.flags.first = True;
	dgram->header.flags.more = False;
	dgram->header.dgm_id = ((unsigned)time(NULL)%(unsigned)0x7FFF) +
		((unsigned)sys_getpid()%(unsigned)100);
	/* source ip is filled by nmbd */
	dgram->header.dgm_length = 0; /* Let build_dgram() handle this. */
	dgram->header.packet_offset = 0;

	make_nmb_name(&dgram->source_name,srcname,src_type);
	make_nmb_name(&dgram->dest_name,dstname,dest_type);

	ptr = &dgram->data[0];

	/* Setup the smb part. */
	ptr -= 4; /* XXX Ugliness because of handling of tcp SMB length. */
	memcpy(tmp,ptr,4);

	if (smb_size + 17*2 + strlen(mailslot) + 1 + len > MAX_DGRAM_SIZE) {
		DEBUG(0, ("cli_send_mailslot: Cannot write beyond end of packet\n"));
		return False;
	}

	cli_set_message(ptr,17,strlen(mailslot) + 1 + len,True);
	memcpy(ptr,tmp,4);

	SCVAL(ptr,smb_com,SMBtrans);
	SSVAL(ptr,smb_vwv1,len);
	SSVAL(ptr,smb_vwv11,len);
	SSVAL(ptr,smb_vwv12,70 + strlen(mailslot));
	SSVAL(ptr,smb_vwv13,3);
	SSVAL(ptr,smb_vwv14,1);
	SSVAL(ptr,smb_vwv15,priority);
	SSVAL(ptr,smb_vwv16,2);
	p2 = smb_buf(ptr);
	fstrcpy(p2,mailslot);
	p2 = skip_string(ptr,MAX_DGRAM_SIZE,p2);
	if (!p2) {
		return False;
	}

	memcpy(p2,buf,len);
	p2 += len;

	dgram->datasize = PTR_DIFF(p2,ptr+4); /* +4 for tcp length. */

	p.packet_type = DGRAM_PACKET;
	p.ip = ((const struct sockaddr_in *)dest_ss)->sin_addr;
	p.timestamp = time(NULL);

	DEBUG(4,("send_mailslot: Sending to mailslot %s from %s ",
		 mailslot, nmb_namestr(&dgram->source_name)));
	print_sockaddr(addr, sizeof(addr), dest_ss);

	DEBUGADD(4,("to %s IP %s\n", nmb_namestr(&dgram->dest_name), addr));

	return NT_STATUS_IS_OK(messaging_send_buf(msg_ctx,
						  pid_to_procid(nmbd_pid),
						  MSG_SEND_PACKET,
						  (uint8 *)&p, sizeof(p)));
}

static void mailslot_name(struct in_addr dc_ip, fstring name)
{
	fstr_sprintf(name, "\\MAILSLOT\\NET\\GETDC%X", dc_ip.s_addr);
}

bool send_getdc_request(struct messaging_context *msg_ctx,
			struct sockaddr_storage *dc_ss,
			const char *domain_name,
			const DOM_SID *sid)
{
	char outbuf[1024];
	struct in_addr dc_ip;
	char *p;
	fstring my_acct_name;
	fstring my_mailslot;
	size_t sid_size;

	if (dc_ss->ss_family != AF_INET) {
		return false;
	}

	dc_ip = ((struct sockaddr_in *)dc_ss)->sin_addr;
	mailslot_name(dc_ip, my_mailslot);

	memset(outbuf, '\0', sizeof(outbuf));

	p = outbuf;

	SCVAL(p, 0, SAMLOGON);
	p++;

	SCVAL(p, 0, 0); /* Count pointer ... */
	p++;

	SIVAL(p, 0, 0); /* The sender's token ... */
	p += 2;

	p += dos_PutUniCode(p, global_myname(),
			sizeof(outbuf) - PTR_DIFF(p, outbuf), True);
	fstr_sprintf(my_acct_name, "%s$", global_myname());
	p += dos_PutUniCode(p, my_acct_name,
			sizeof(outbuf) - PTR_DIFF(p, outbuf), True);

	if (strlen(my_mailslot)+1 > sizeof(outbuf) - PTR_DIFF(p, outbuf)) {
		return false;
	}

	memcpy(p, my_mailslot, strlen(my_mailslot)+1);
	p += strlen(my_mailslot)+1;

	if (sizeof(outbuf) - PTR_DIFF(p, outbuf) < 8) {
		return false;
	}

	SIVAL(p, 0, 0x80);
	p+=4;

	sid_size = ndr_size_dom_sid(sid, 0);

	SIVAL(p, 0, sid_size);
	p+=4;

	p = ALIGN4(p, outbuf);
	if (PTR_DIFF(p, outbuf) > sizeof(outbuf)) {
		return false;
	}

	if (sid_size + 8 > sizeof(outbuf) - PTR_DIFF(p, outbuf)) {
		return false;
	}
	if (sid) {
		sid_linearize(p, sizeof(outbuf) - PTR_DIFF(p, outbuf), sid);
	}

	p += sid_size;

	SIVAL(p, 0, 1);
	SSVAL(p, 4, 0xffff);
	SSVAL(p, 6, 0xffff);
	p+=8;

	return cli_send_mailslot(msg_ctx,
				 False, "\\MAILSLOT\\NET\\NTLOGON", 0,
				 outbuf, PTR_DIFF(p, outbuf),
				 global_myname(), 0, domain_name, 0x1c,
				 dc_ss);
}

bool receive_getdc_response(struct sockaddr_storage *dc_ss,
			    const char *domain_name,
			    fstring dc_name)
{
	struct packet_struct *packet;
	fstring my_mailslot;
	char *buf, *p;
	fstring dcname, user, domain;
	int len;
	struct in_addr dc_ip;

	if (dc_ss->ss_family != AF_INET) {
		return false;
	}
	dc_ip = ((struct sockaddr_in *)dc_ss)->sin_addr;
	mailslot_name(dc_ip, my_mailslot);

	packet = receive_unexpected(DGRAM_PACKET, 0, my_mailslot);

	if (packet == NULL) {
		DEBUG(5, ("Did not receive packet for %s\n", my_mailslot));
		return False;
	}

	DEBUG(5, ("Received packet for %s\n", my_mailslot));

	buf = packet->packet.dgram.data;
	len = packet->packet.dgram.datasize;

	if (len < 70) {
		/* 70 is a completely arbitrary value to make sure
		   the SVAL below does not read uninitialized memory */
		DEBUG(3, ("GetDC got short response\n"));
		return False;
	}

	/* This should be (buf-4)+SVAL(buf-4, smb_vwv12)... */
	p = buf+SVAL(buf, smb_vwv10);

	switch (CVAL(p, 0)) {
	case SAMLOGON_R:
	case SAMLOGON_UNK_R:
		p+=2;
		pull_ucs2(buf, dcname, p, sizeof(dcname), PTR_DIFF(buf+len, p),
			  STR_TERMINATE|STR_NOALIGN);
		p = skip_unibuf(p, PTR_DIFF(buf+len, p));
		pull_ucs2(buf, user, p, sizeof(user), PTR_DIFF(buf+len, p),
			  STR_TERMINATE|STR_NOALIGN);
		p = skip_unibuf(p, PTR_DIFF(buf+len, p));
		pull_ucs2(buf, domain, p, sizeof(domain), PTR_DIFF(buf+len, p),
			  STR_TERMINATE|STR_NOALIGN);
		p = skip_unibuf(p, PTR_DIFF(buf+len, p));

		if (!strequal(domain, domain_name)) {
			DEBUG(3, ("GetDC: Expected domain %s, got %s\n",
				  domain_name, domain));
			return False;
		}
		break;

	default:
		DEBUG(8, ("GetDC got invalid response type %d\n", CVAL(p, 0)));
		return False;
	}
	p = dcname;
	if (*p == '\\')	p += 1;
	if (*p == '\\')	p += 1;

	fstrcpy(dc_name, p);

	DEBUG(10, ("GetDC gave name %s for domain %s\n",
		   dc_name, domain));

	return True;
}

