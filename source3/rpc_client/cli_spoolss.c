/*
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000,
 *  Copyright (C) Jean Francois Micouleau      1998-2000,
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "rpc_parse.h"
#include "rpc_client.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
do a SPOOLSS Enum Printers
****************************************************************************/
uint32 spoolss_enum_printers(uint32 flags, fstring srv_name, uint32 level,
                             NEW_BUFFER *buffer, uint32 offered,
                             uint32 *needed, uint32 *returned)
{
        prs_struct rbuf;
        prs_struct buf;
        SPOOL_Q_ENUMPRINTERS q_o;
        SPOOL_R_ENUMPRINTERS r_o;

        struct cli_connection *con = NULL;

        if (!cli_connection_init(srv_name, PIPE_SPOOLSS, &con))
                return False;

        prs_init(&buf , MAX_PDU_FRAG_LEN, 4, MARSHALL);
        prs_init(&rbuf, 0, 4, UNMARSHALL);

        /* create and send a MSRPC command with api SPOOLSS_ENUM_PRINTERS */

        DEBUG(5,("SPOOLSS Enum Printers (Server: %s level: %d)\n", srv_name, level));

        make_spoolss_q_enumprinters(&q_o, flags, "", level, buffer, offered);

        /* turn parameters into data stream */
        if (!spoolss_io_q_enumprinters("", &q_o, &buf, 0) ) {
                prs_free_data(&rbuf);
                prs_free_data(&buf );

                cli_connection_unlink(con);
        }

        if(!rpc_con_pipe_req(con, SPOOLSS_ENUMPRINTERS, &buf, &rbuf)) {
                prs_free_data(&rbuf);
                prs_free_data(&buf );

                cli_connection_unlink(con);
        }

        prs_free_data(&buf );
        ZERO_STRUCT(r_o);

        buffer->prs.io=UNMARSHALL;
        buffer->prs.data_offset=0;
        r_o.buffer=buffer;

        if(!new_spoolss_io_r_enumprinters("", &r_o, &rbuf, 0)) {
                prs_free_data(&rbuf);
                cli_connection_unlink(con);
        }

        *needed=r_o.needed;
        *returned=r_o.returned;

        prs_free_data(&rbuf);
        prs_free_data(&buf );

        cli_connection_unlink(con);

        return r_o.status;
}

