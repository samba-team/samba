/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client dgram calls
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Richard Sharpe 2001
   Copyright (C) John Terpstra 2001

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

#define NO_SYSLOG

#include "includes.h"

/*
 * cli_send_mailslot, send a mailslot for client code ...
 */

int cli_send_mailslot(int dgram_sock, BOOL unique, const char *mailslot, 
		      char *buf, int len,
		      const char *srcname, int src_type, 
		      const char *dstname, int dest_type,
		      struct in_addr dest_ip, struct in_addr src_ip,
		      int dest_port, int src_port)
{
  struct packet_struct p;
  struct dgram_packet *dgram = &p.packet.dgram;
  char *ptr, *p2;
  char tmp[4];

  memset((char *)&p, '\0', sizeof(p));

  /*
   * Next, build the DGRAM ...
   */

  /* DIRECT GROUP or UNIQUE datagram. */
  dgram->header.msg_type = unique ? 0x10 : 0x11; 
  dgram->header.flags.node_type = M_NODE;
  dgram->header.flags.first = True;
  dgram->header.flags.more = False;
  dgram->header.dgm_id = ((unsigned)time(NULL)%(unsigned)0x7FFF) + ((unsigned)sys_getpid()%(unsigned)100);
  dgram->header.source_ip.s_addr = src_ip.s_addr;
  /*fprintf(stderr, "Source IP = %0X\n", dgram->header.source_ip); */
  dgram->header.source_port = ntohs(src_port);
  fprintf(stderr, "Source Port = %0X\n", dgram->header.source_port);
  dgram->header.dgm_length = 0; /* Let build_dgram() handle this. */
  dgram->header.packet_offset = 0;
  
  make_nmb_name(&dgram->source_name,srcname,src_type);
  make_nmb_name(&dgram->dest_name,dstname,dest_type);

  ptr = &dgram->data[0];

  /* Setup the smb part. */
  ptr -= 4; /* XXX Ugliness because of handling of tcp SMB length. */
  memcpy(tmp,ptr,4);
  set_message(ptr,17,17 + len,True);
  memcpy(ptr,tmp,4);

  SCVAL(ptr,smb_com,SMBtrans);
  SSVAL(ptr,smb_vwv1,len);
  SSVAL(ptr,smb_vwv11,len);
  SSVAL(ptr,smb_vwv12,70 + strlen(mailslot));
  SSVAL(ptr,smb_vwv13,3);
  SSVAL(ptr,smb_vwv14,1);
  SSVAL(ptr,smb_vwv15,1);
  SSVAL(ptr,smb_vwv16,2);
  p2 = smb_buf(ptr);
  pstrcpy(p2,mailslot);
  p2 = skip_string(p2,1);

  memcpy(p2,buf,len);
  p2 += len;

  dgram->datasize = PTR_DIFF(p2,ptr+4); /* +4 for tcp length. */

  p.ip = dest_ip;
  p.port = dest_port;
  p.fd = dgram_sock;
  p.timestamp = time(NULL);
  p.packet_type = DGRAM_PACKET;

  DEBUG(4,("send_mailslot: Sending to mailslot %s from %s IP %s ", mailslot,
                    nmb_namestr(&dgram->source_name), inet_ntoa(src_ip)));
  DEBUG(4,("to %s IP %s\n", nmb_namestr(&dgram->dest_name), inet_ntoa(dest_ip)));

  return send_packet(&p);

}

/*
 * cli_get_response: Get a response ...
 */
int cli_get_response(int dgram_sock, BOOL unique, const char *mailslot, char *buf, int bufsiz)
{
  struct packet_struct *packet;

  packet = receive_dgram_packet(dgram_sock, 5, mailslot);

  if (packet) { /* We got one, pull what we want out of the SMB data ... */

    struct dgram_packet *dgram = &packet->packet.dgram;

    /*
     * We should probably parse the SMB, but for now, we will pull what
     * from fixed, known locations ...
     */

    /* Copy the data to buffer, respecting sizes ... */

    memcpy(buf, &dgram->data[92], MIN(bufsiz, (dgram->datasize - 92)));

  }
  else 
    return -1;

  return 0;

}

/*
 * cli_get_backup_list: Send a get backup list request ...
 */

static char cli_backup_list[1024];

int cli_get_backup_list(const char *myname, const char *send_to_name)
{
  char outbuf[15];
  char *p;
  struct in_addr sendto_ip, my_ip;
  int dgram_sock;
  struct sockaddr_in sock_out;
  socklen_t name_size;

  if (!resolve_name(send_to_name, &sendto_ip, 0x1d)) {

    DEBUG(0, ("Could not resolve name: %s<1D>\n", send_to_name));
    return False;

  }

  my_ip.s_addr = inet_addr("0.0.0.0");
 
  if (!resolve_name(myname, &my_ip, 0x00)) { /* FIXME: Call others here */

    DEBUG(0, ("Could not resolve name: %s<00>\n", myname));

  }

  if ((dgram_sock = open_socket_out(SOCK_DGRAM, &sendto_ip, 138, LONG_CONNECT_TIMEOUT)) < 0) {

    DEBUG(4, ("open_sock_out failed ..."));
    return False;

  }

  /* Make it a broadcast socket ... */

  set_socket_options(dgram_sock, "SO_BROADCAST");

  /* Make it non-blocking??? */

  if (fcntl(dgram_sock, F_SETFL, O_NONBLOCK) < 0) {

    DEBUG(0, ("Unable to set non blocking on dgram sock\n"));

  }

  /* Now, bind a local addr to it ... Try port 138 first ... */

  memset((char *)&sock_out, '\0', sizeof(sock_out));
  sock_out.sin_addr.s_addr = INADDR_ANY;
  sock_out.sin_port = htons(138);
  sock_out.sin_family = AF_INET;

  if (bind(dgram_sock, (struct sockaddr *)&sock_out, sizeof(sock_out)) < 0) {

    /* Try again on any port ... */

    sock_out.sin_port = INADDR_ANY;

    if (bind(dgram_sock, (struct sockaddr *)&sock_out, sizeof(sock_out)) < 0) {

      DEBUG(4, ("failed to bind socket to address ...\n"));
      return False;
	
    }

  }

  /* Now, figure out what socket name we were bound to. We want the port */

  name_size = sizeof(sock_out);

  getsockname(dgram_sock, (struct sockaddr *)&sock_out, &name_size);

  DEBUG(5, ("Socket bound to IP:%s, port: %d\n", inet_ntoa(sock_out.sin_addr), ntohs(sock_out.sin_port)));

  /* Now, build the request */

  memset(cli_backup_list, '\0', sizeof(cli_backup_list));
  memset(outbuf, '\0', sizeof(outbuf));

  p = outbuf;

  SCVAL(p, 0, ANN_GetBackupListReq);
  p++;

  SCVAL(p, 0, 1); /* Count pointer ... */
  p++;

  SIVAL(p, 0, 1); /* The sender's token ... */
  p += 4;

  cli_send_mailslot(dgram_sock, True, "\\MAILSLOT\\BROWSE", outbuf, 
		    PTR_DIFF(p, outbuf), myname, 0, send_to_name, 
		    0x1d, sendto_ip, my_ip, 138, sock_out.sin_port);

  /* We should check the error and return if we got one */

  /* Now, get the response ... */

  cli_get_response(dgram_sock, True, "\\MAILSLOT\\BROWSE", cli_backup_list, sizeof(cli_backup_list));

  /* Should check the response here ... FIXME */

  close(dgram_sock);

  return True;

}

/*
 * cli_get_backup_server: Get the backup list and retrieve a server from it
 */

int cli_get_backup_server(char *my_name, char *target, char *servername, int namesize)
{

  /* Get the backup list first. We could pull this from the cache later */

  cli_get_backup_list(my_name, target);  /* FIXME: Check the response */

  if (!cli_backup_list[0]) { /* Empty list ... try again */

    cli_get_backup_list(my_name, target);

  }

  strncpy(servername, cli_backup_list, MIN(16, namesize));

  return True;

}



