/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
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
#include "../librpc/gen_ndr/srv_spoolss.h"
#include "librpc/gen_ndr/ndr_named_pipe_auth.h"
#include "../libcli/named_pipe_auth/npa_tstream.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/****************************************************************************
 Initialise an outgoing packet.
****************************************************************************/

static bool pipe_init_outgoing_data(pipes_struct *p)
{
	output_data *o_data = &p->out_data;

	/* Reset the offset counters. */
	o_data->data_sent_length = 0;
	o_data->current_pdu_sent = 0;

	prs_mem_free(&o_data->frag);

	/* Free any memory in the current return data buffer. */
	prs_mem_free(&o_data->rdata);

	/*
	 * Initialize the outgoing RPC data buffer.
	 * we will use this as the raw data area for replying to rpc requests.
	 */
	if(!prs_init(&o_data->rdata, 128, p->mem_ctx, MARSHALL)) {
		DEBUG(0,("pipe_init_outgoing_data: malloc fail.\n"));
		return False;
	}

	return True;
}

/****************************************************************************
 Sets the fault state on incoming packets.
****************************************************************************/

static void set_incoming_fault(pipes_struct *p)
{
	prs_mem_free(&p->in_data.data);
	p->in_data.pdu_needed_len = 0;
	p->in_data.pdu_received_len = 0;
	p->fault_state = True;
	DEBUG(10, ("set_incoming_fault: Setting fault state on pipe %s\n",
		   get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
}

/****************************************************************************
 Ensures we have at least RPC_HEADER_LEN amount of data in the incoming buffer.
****************************************************************************/

static ssize_t fill_rpc_header(pipes_struct *p, char *data, size_t data_to_copy)
{
	size_t len_needed_to_complete_hdr =
		MIN(data_to_copy, RPC_HEADER_LEN - p->in_data.pdu_received_len);

	DEBUG(10, ("fill_rpc_header: data_to_copy = %u, "
		   "len_needed_to_complete_hdr = %u, "
		   "receive_len = %u\n",
		   (unsigned int)data_to_copy,
		   (unsigned int)len_needed_to_complete_hdr,
		   (unsigned int)p->in_data.pdu_received_len ));

	if (p->in_data.current_in_pdu == NULL) {
		p->in_data.current_in_pdu = talloc_array(p, uint8_t,
							 RPC_HEADER_LEN);
	}
	if (p->in_data.current_in_pdu == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return -1;
	}

	memcpy((char *)&p->in_data.current_in_pdu[p->in_data.pdu_received_len],
		data, len_needed_to_complete_hdr);
	p->in_data.pdu_received_len += len_needed_to_complete_hdr;

	return (ssize_t)len_needed_to_complete_hdr;
}

/****************************************************************************
 Unmarshalls a new PDU header. Assumes the raw header data is in current_in_pdu.
****************************************************************************/

static ssize_t unmarshall_rpc_header(pipes_struct *p)
{
	/*
	 * Unmarshall the header to determine the needed length.
	 */

	prs_struct rpc_in;

	if(p->in_data.pdu_received_len != RPC_HEADER_LEN) {
		DEBUG(0, ("unmarshall_rpc_header: "
			  "assert on rpc header length failed.\n"));
		set_incoming_fault(p);
		return -1;
	}

	prs_init_empty( &rpc_in, p->mem_ctx, UNMARSHALL);
	prs_set_endian_data( &rpc_in, p->endian);

	prs_give_memory( &rpc_in, (char *)&p->in_data.current_in_pdu[0],
					p->in_data.pdu_received_len, False);

	/*
	 * Unmarshall the header as this will tell us how much
	 * data we need to read to get the complete pdu.
	 * This also sets the endian flag in rpc_in.
	 */

	if(!smb_io_rpc_hdr("", &p->hdr, &rpc_in, 0)) {
		DEBUG(0, ("unmarshall_rpc_header: "
			  "failed to unmarshall RPC_HDR.\n"));
		set_incoming_fault(p);
		prs_mem_free(&rpc_in);
		return -1;
	}

	/*
	 * Validate the RPC header.
	 */

	if(p->hdr.major != 5 && p->hdr.minor != 0) {
		DEBUG(0, ("unmarshall_rpc_header: "
			  "invalid major/minor numbers in RPC_HDR.\n"));
		set_incoming_fault(p);
		prs_mem_free(&rpc_in);
		return -1;
	}

	/*
	 * If there's not data in the incoming buffer this should be the
	 * start of a new RPC.
	 */

	if(prs_offset(&p->in_data.data) == 0) {

		/*
		 * AS/U doesn't set FIRST flag in a BIND packet it seems.
		 */

		if ((p->hdr.pkt_type == DCERPC_PKT_REQUEST) &&
		    !(p->hdr.flags & DCERPC_PFC_FLAG_FIRST)) {
			/*
			 * Ensure that the FIRST flag is set.
			 * If not then we have a stream missmatch.
			 */

			DEBUG(0, ("unmarshall_rpc_header: "
				  "FIRST flag not set in first PDU !\n"));
			set_incoming_fault(p);
			prs_mem_free(&rpc_in);
			return -1;
		}

		/*
		 * If this is the first PDU then set the endianness
		 * flag in the pipe. We will need this when parsing all
		 * data in this RPC.
		 */

		p->endian = rpc_in.bigendian_data;

		DEBUG(5, ("unmarshall_rpc_header: using %sendian RPC\n",
			  p->endian == RPC_LITTLE_ENDIAN ? "little-" : "big-" ));

	} else {

		/*
		 * If this is *NOT* the first PDU then check the endianness
		 * flag in the pipe is the same as that in the PDU.
		 */

		if (p->endian != rpc_in.bigendian_data) {
			DEBUG(0, ("unmarshall_rpc_header: FIRST endianness "
				  "flag (%d) different in next PDU !\n",
				  (int)p->endian));
			set_incoming_fault(p);
			prs_mem_free(&rpc_in);
			return -1;
		}
	}

	/*
	 * Ensure that the pdu length is sane.
	 */

	if ((p->hdr.frag_len < RPC_HEADER_LEN) ||
	    (p->hdr.frag_len > RPC_MAX_PDU_FRAG_LEN)) {
		DEBUG(0,("unmarshall_rpc_header: assert on frag length failed.\n"));
		set_incoming_fault(p);
		prs_mem_free(&rpc_in);
		return -1;
	}

	DEBUG(10, ("unmarshall_rpc_header: type = %u, flags = %u\n",
		   (unsigned int)p->hdr.pkt_type, (unsigned int)p->hdr.flags));

	p->in_data.pdu_needed_len = (uint32)p->hdr.frag_len - RPC_HEADER_LEN;

	prs_mem_free(&rpc_in);

	p->in_data.current_in_pdu = TALLOC_REALLOC_ARRAY(
		p, p->in_data.current_in_pdu, uint8_t, p->hdr.frag_len);
	if (p->in_data.current_in_pdu == NULL) {
		DEBUG(0, ("talloc failed\n"));
		set_incoming_fault(p);
		return -1;
	}

	return 0; /* No extra data processed. */
}

/****************************************************************************
  Call this to free any talloc'ed memory. Do this after processing
  a complete incoming and outgoing request (multiple incoming/outgoing
  PDU's).
****************************************************************************/

static void free_pipe_context(pipes_struct *p)
{
	prs_mem_free(&p->out_data.frag);
	prs_mem_free(&p->out_data.rdata);
	prs_mem_free(&p->in_data.data);

	DEBUG(3, ("free_pipe_context: "
		"destroying talloc pool of size %lu\n",
		(unsigned long)talloc_total_size(p->mem_ctx)));
	talloc_free_children(p->mem_ctx);
	/*
	 * Re-initialize to set back to marshalling and set the
	 * offset back to the start of the buffer.
	 */
	if(!prs_init(&p->in_data.data, 128, p->mem_ctx, MARSHALL)) {
		DEBUG(0, ("free_pipe_context: "
			  "rps_init failed!\n"));
		p->fault_state = True;
	}
}

/****************************************************************************
 Processes a request pdu. This will do auth processing if needed, and
 appends the data into the complete stream if the LAST flag is not set.
****************************************************************************/

static bool process_request_pdu(pipes_struct *p, prs_struct *rpc_in_p)
{
	uint32 ss_padding_len = 0;
	size_t data_len = p->hdr.frag_len
				- RPC_HEADER_LEN
				- RPC_HDR_REQ_LEN
				- (p->hdr.auth_len ? RPC_HDR_AUTH_LEN : 0)
				- p->hdr.auth_len;

	if(!p->pipe_bound) {
		DEBUG(0,("process_request_pdu: rpc request with no bind.\n"));
		set_incoming_fault(p);
		return False;
	}

	/*
	 * Check if we need to do authentication processing.
	 * This is only done on requests, not binds.
	 */

	/*
	 * Read the RPC request header.
	 */

	if(!smb_io_rpc_hdr_req("req", &p->hdr_req, rpc_in_p, 0)) {
		DEBUG(0,("process_request_pdu: failed to unmarshall RPC_HDR_REQ.\n"));
		set_incoming_fault(p);
		return False;
	}

	switch(p->auth.auth_type) {
		case PIPE_AUTH_TYPE_NONE:
			break;

		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
		case PIPE_AUTH_TYPE_NTLMSSP:
		{
			NTSTATUS status;
			if (!api_pipe_ntlmssp_auth_process(p, rpc_in_p,
							   &ss_padding_len,
							   &status)) {
				DEBUG(0, ("process_request_pdu: "
					  "failed to do auth processing.\n"));
				DEBUG(0, ("process_request_pdu: error is %s\n",
					  nt_errstr(status)));
				set_incoming_fault(p);
				return False;
			}
			break;
		}

		case PIPE_AUTH_TYPE_SCHANNEL:
			if (!api_pipe_schannel_process(p, rpc_in_p,
							&ss_padding_len)) {
				DEBUG(3, ("process_request_pdu: "
					  "failed to do schannel processing.\n"));
				set_incoming_fault(p);
				return False;
			}
			break;

		default:
			DEBUG(0, ("process_request_pdu: "
				  "unknown auth type %u set.\n",
				  (unsigned int)p->auth.auth_type));
			set_incoming_fault(p);
			return False;
	}

	/* Now we've done the sign/seal we can remove any padding data. */
	if (data_len > ss_padding_len) {
		data_len -= ss_padding_len;
	}

	/*
	 * Check the data length doesn't go over the 15Mb limit.
	 * increased after observing a bug in the Windows NT 4.0 SP6a
	 * spoolsv.exe when the response to a GETPRINTERDRIVER2 RPC
	 * will not fit in the initial buffer of size 0x1068   --jerry 22/01/2002
	 */

	if(prs_offset(&p->in_data.data) + data_len > MAX_RPC_DATA_SIZE) {
		DEBUG(0, ("process_request_pdu: "
			  "rpc data buffer too large (%u) + (%u)\n",
			  (unsigned int)prs_data_size(&p->in_data.data),
			  (unsigned int)data_len ));
		set_incoming_fault(p);
		return False;
	}

	/*
	 * Append the data portion into the buffer and return.
	 */

	if (!prs_append_some_prs_data(&p->in_data.data, rpc_in_p,
				      prs_offset(rpc_in_p), data_len)) {
		DEBUG(0, ("process_request_pdu: Unable to append data size %u "
			  "to parse buffer of size %u.\n",
			  (unsigned int)data_len,
			  (unsigned int)prs_data_size(&p->in_data.data)));
		set_incoming_fault(p);
		return False;
	}

	if(p->hdr.flags & DCERPC_PFC_FLAG_LAST) {
		bool ret = False;
		/*
		 * Ok - we finally have a complete RPC stream.
		 * Call the rpc command to process it.
		 */

		/*
		 * Ensure the internal prs buffer size is *exactly* the same
		 * size as the current offset.
		 */

 		if (!prs_set_buffer_size(&p->in_data.data,
					 prs_offset(&p->in_data.data))) {
			DEBUG(0, ("process_request_pdu: "
				  "Call to prs_set_buffer_size failed!\n"));
			set_incoming_fault(p);
			return False;
		}

		/*
		 * Set the parse offset to the start of the data and set the
		 * prs_struct to UNMARSHALL.
		 */

		prs_set_offset(&p->in_data.data, 0);
		prs_switch_type(&p->in_data.data, UNMARSHALL);

		/*
		 * Process the complete data stream here.
		 */

		if(pipe_init_outgoing_data(p)) {
			ret = api_pipe_request(p);
		}

		return ret;
	}

	return True;
}

/****************************************************************************
 Processes a finished PDU stored in current_in_pdu. The RPC_HEADER has
 already been parsed and stored in p->hdr.
****************************************************************************/

static void process_complete_pdu(pipes_struct *p)
{
	prs_struct rpc_in;
	size_t data_len = p->in_data.pdu_received_len - RPC_HEADER_LEN;
	char *data_p = (char *)&p->in_data.current_in_pdu[RPC_HEADER_LEN];
	bool reply = False;

	if(p->fault_state) {
		DEBUG(10,("process_complete_pdu: pipe %s in fault state.\n",
			  get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
		set_incoming_fault(p);
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		return;
	}

	prs_init_empty( &rpc_in, p->mem_ctx, UNMARSHALL);

	/*
	 * Ensure we're using the corrent endianness for both the
	 * RPC header flags and the raw data we will be reading from.
	 */

	prs_set_endian_data( &rpc_in, p->endian);
	prs_set_endian_data( &p->in_data.data, p->endian);

	prs_give_memory( &rpc_in, data_p, (uint32)data_len, False);

	DEBUG(10,("process_complete_pdu: processing packet type %u\n",
			(unsigned int)p->hdr.pkt_type ));

	switch (p->hdr.pkt_type) {
		case DCERPC_PKT_REQUEST:
			reply = process_request_pdu(p, &rpc_in);
			break;

		case DCERPC_PKT_PING: /* CL request - ignore... */
			DEBUG(0, ("process_complete_pdu: Error. "
				  "Connectionless packet type %u received on "
				  "pipe %s.\n", (unsigned int)p->hdr.pkt_type,
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;

		case DCERPC_PKT_RESPONSE: /* No responses here. */
			DEBUG(0, ("process_complete_pdu: Error. "
				  "DCERPC_PKT_RESPONSE received from client "
				  "on pipe %s.\n",
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;

		case DCERPC_PKT_FAULT:
		case DCERPC_PKT_WORKING:
			/* CL request - reply to a ping when a call in process. */
		case DCERPC_PKT_NOCALL:
			/* CL - server reply to a ping call. */
		case DCERPC_PKT_REJECT:
		case DCERPC_PKT_ACK:
		case DCERPC_PKT_CL_CANCEL:
		case DCERPC_PKT_FACK:
		case DCERPC_PKT_CANCEL_ACK:
			DEBUG(0, ("process_complete_pdu: Error. "
				  "Connectionless packet type %u received on "
				  "pipe %s.\n", (unsigned int)p->hdr.pkt_type,
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;

		case DCERPC_PKT_BIND:
			/*
			 * We assume that a pipe bind is only in one pdu.
			 */
			if(pipe_init_outgoing_data(p)) {
				reply = api_pipe_bind_req(p, &rpc_in);
			}
			break;

		case DCERPC_PKT_BIND_ACK:
		case DCERPC_PKT_BIND_NAK:
			DEBUG(0, ("process_complete_pdu: Error. "
				  "DCERPC_PKT_BINDACK/DCERPC_PKT_BINDNACK "
				  "packet type %u received on pipe %s.\n",
				  (unsigned int)p->hdr.pkt_type,
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;


		case DCERPC_PKT_ALTER:
			/*
			 * We assume that a pipe bind is only in one pdu.
			 */
			if(pipe_init_outgoing_data(p)) {
				reply = api_pipe_alter_context(p, &rpc_in);
			}
			break;

		case DCERPC_PKT_ALTER_RESP:
			DEBUG(0, ("process_complete_pdu: Error. "
				  "DCERPC_PKT_ALTER_RESP on pipe %s: "
				  "Should only be server -> client.\n",
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;

		case DCERPC_PKT_AUTH3:
			/*
			 * The third packet in an NTLMSSP auth exchange.
			 */
			if(pipe_init_outgoing_data(p)) {
				reply = api_pipe_bind_auth3(p, &rpc_in);
			}
			break;

		case DCERPC_PKT_SHUTDOWN:
			DEBUG(0, ("process_complete_pdu: Error. "
				  "DCERPC_PKT_SHUTDOWN on pipe %s: "
				  "Should only be server -> client.\n",
				 get_pipe_name_from_syntax(talloc_tos(),
							   &p->syntax)));
			break;

		case DCERPC_PKT_CO_CANCEL:
			/* For now just free all client data and continue
			 * processing. */
			DEBUG(3,("process_complete_pdu: DCERPC_PKT_CO_CANCEL."
				 " Abandoning rpc call.\n"));
			/* As we never do asynchronous RPC serving, we can
			 * never cancel a call (as far as I know).
			 * If we ever did we'd have to send a cancel_ack reply.
			 * For now, just free all client data and continue
			 * processing. */
			reply = True;
			break;
#if 0
			/* Enable this if we're doing async rpc. */
			/* We must check the outstanding callid matches. */
			if(pipe_init_outgoing_data(p)) {
				/* Send a cancel_ack PDU reply. */
				/* We should probably check the auth-verifier here. */
				reply = setup_cancel_ack_reply(p, &rpc_in);
			}
			break;
#endif

		case DCERPC_PKT_ORPHANED:
			/* We should probably check the auth-verifier here.
			 * For now just free all client data and continue
			 * processing. */
			DEBUG(3, ("process_complete_pdu: DCERPC_PKT_ORPHANED."
				  " Abandoning rpc call.\n"));
			reply = True;
			break;

		default:
			DEBUG(0, ("process_complete_pdu: "
				  "Unknown rpc type = %u received.\n",
				  (unsigned int)p->hdr.pkt_type));
			break;
	}

	/* Reset to little endian.
	 * Probably don't need this but it won't hurt. */
	prs_set_endian_data( &p->in_data.data, RPC_LITTLE_ENDIAN);

	if (!reply) {
		DEBUG(3,("process_complete_pdu: DCE/RPC fault sent on "
			 "pipe %s\n", get_pipe_name_from_syntax(talloc_tos(),
								&p->syntax)));
		set_incoming_fault(p);
		setup_fault_pdu(p, NT_STATUS(DCERPC_FAULT_OP_RNG_ERROR));
		prs_mem_free(&rpc_in);
	} else {
		/*
		 * Reset the lengths. We're ready for a new pdu.
		 */
		TALLOC_FREE(p->in_data.current_in_pdu);
		p->in_data.pdu_needed_len = 0;
		p->in_data.pdu_received_len = 0;
	}

	prs_mem_free(&rpc_in);
}

/****************************************************************************
 Accepts incoming data on an rpc pipe. Processes the data in pdu sized units.
****************************************************************************/

static ssize_t process_incoming_data(pipes_struct *p, char *data, size_t n)
{
	size_t data_to_copy = MIN(n, RPC_MAX_PDU_FRAG_LEN
					- p->in_data.pdu_received_len);

	DEBUG(10, ("process_incoming_data: Start: pdu_received_len = %u, "
		   "pdu_needed_len = %u, incoming data = %u\n",
		   (unsigned int)p->in_data.pdu_received_len,
		   (unsigned int)p->in_data.pdu_needed_len,
		   (unsigned int)n ));

	if(data_to_copy == 0) {
		/*
		 * This is an error - data is being received and there is no
		 * space in the PDU. Free the received data and go into the
		 * fault state.
		 */
		DEBUG(0, ("process_incoming_data: "
			  "No space in incoming pdu buffer. "
			  "Current size = %u incoming data size = %u\n",
			  (unsigned int)p->in_data.pdu_received_len,
			  (unsigned int)n));
		set_incoming_fault(p);
		return -1;
	}

	/*
	 * If we have no data already, wait until we get at least
	 * a RPC_HEADER_LEN * number of bytes before we can do anything.
	 */

	if ((p->in_data.pdu_needed_len == 0) &&
	    (p->in_data.pdu_received_len < RPC_HEADER_LEN)) {
		/*
		 * Always return here. If we have more data then the RPC_HEADER
		 * will be processed the next time around the loop.
		 */
		return fill_rpc_header(p, data, data_to_copy);
	}

	/*
	 * At this point we know we have at least an RPC_HEADER_LEN amount of
	 * data * stored in current_in_pdu.
	 */

	/*
	 * If pdu_needed_len is zero this is a new pdu.
	 * Unmarshall the header so we know how much more
	 * data we need, then loop again.
	 */

	if(p->in_data.pdu_needed_len == 0) {
		ssize_t rret = unmarshall_rpc_header(p);
		if (rret == -1 || p->in_data.pdu_needed_len > 0) {
			return rret;
		}
		/* If rret == 0 and pdu_needed_len == 0 here we have a PDU
		 * that consists of an RPC_HEADER only. This is a
		 * DCERPC_PKT_SHUTDOWN, DCERPC_PKT_CO_CANCEL or
		 * DCERPC_PKT_ORPHANED pdu type.
		 * Deal with this in process_complete_pdu(). */
	}

	/*
	 * Ok - at this point we have a valid RPC_HEADER in p->hdr.
	 * Keep reading until we have a full pdu.
	 */

	data_to_copy = MIN(data_to_copy, p->in_data.pdu_needed_len);

	/*
	 * Copy as much of the data as we need into the current_in_pdu buffer.
	 * pdu_needed_len becomes zero when we have a complete pdu.
	 */

	memcpy((char *)&p->in_data.current_in_pdu[p->in_data.pdu_received_len],
		data, data_to_copy);
	p->in_data.pdu_received_len += data_to_copy;
	p->in_data.pdu_needed_len -= data_to_copy;

	/*
	 * Do we have a complete PDU ?
	 * (return the number of bytes handled in the call)
	 */

	if(p->in_data.pdu_needed_len == 0) {
		process_complete_pdu(p);
		return data_to_copy;
	}

	DEBUG(10, ("process_incoming_data: not a complete PDU yet. "
		   "pdu_received_len = %u, pdu_needed_len = %u\n",
		   (unsigned int)p->in_data.pdu_received_len,
		   (unsigned int)p->in_data.pdu_needed_len));

	return (ssize_t)data_to_copy;
}

/****************************************************************************
 Accepts incoming data on an internal rpc pipe.
****************************************************************************/

static ssize_t write_to_internal_pipe(struct pipes_struct *p, char *data, size_t n)
{
	size_t data_left = n;

	while(data_left) {
		ssize_t data_used;

		DEBUG(10, ("write_to_pipe: data_left = %u\n",
			  (unsigned int)data_left));

		data_used = process_incoming_data(p, data, data_left);

		DEBUG(10, ("write_to_pipe: data_used = %d\n",
			   (int)data_used));

		if(data_used < 0) {
			return -1;
		}

		data_left -= data_used;
		data += data_used;
	}

	return n;
}

/****************************************************************************
 Replies to a request to read data from a pipe.

 Headers are interspersed with the data at PDU intervals. By the time
 this function is called, the start of the data could possibly have been
 read by an SMBtrans (file_offset != 0).

 Calling create_rpc_reply() here is a hack. The data should already
 have been prepared into arrays of headers + data stream sections.
****************************************************************************/

static ssize_t read_from_internal_pipe(struct pipes_struct *p, char *data,
				       size_t n, bool *is_data_outstanding)
{
	uint32 pdu_remaining = 0;
	ssize_t data_returned = 0;

	if (!p) {
		DEBUG(0,("read_from_pipe: pipe not open\n"));
		return -1;
	}

	DEBUG(6,(" name: %s len: %u\n",
		 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
		 (unsigned int)n));

	/*
	 * We cannot return more than one PDU length per
	 * read request.
	 */

	/*
	 * This condition should result in the connection being closed.
	 * Netapp filers seem to set it to 0xffff which results in domain
	 * authentications failing.  Just ignore it so things work.
	 */

	if(n > RPC_MAX_PDU_FRAG_LEN) {
                DEBUG(5,("read_from_pipe: too large read (%u) requested on "
			 "pipe %s. We can only service %d sized reads.\n",
			 (unsigned int)n,
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
			 RPC_MAX_PDU_FRAG_LEN ));
		n = RPC_MAX_PDU_FRAG_LEN;
	}

	/*
 	 * Determine if there is still data to send in the
	 * pipe PDU buffer. Always send this first. Never
	 * send more than is left in the current PDU. The
	 * client should send a new read request for a new
	 * PDU.
	 */

	pdu_remaining = prs_offset(&p->out_data.frag)
		- p->out_data.current_pdu_sent;

	if (pdu_remaining > 0) {
		data_returned = (ssize_t)MIN(n, pdu_remaining);

		DEBUG(10,("read_from_pipe: %s: current_pdu_len = %u, "
			  "current_pdu_sent = %u returning %d bytes.\n",
			  get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
			  (unsigned int)prs_offset(&p->out_data.frag),
			  (unsigned int)p->out_data.current_pdu_sent,
			  (int)data_returned));

		memcpy(data,
		       prs_data_p(&p->out_data.frag)
		       + p->out_data.current_pdu_sent,
		       data_returned);

		p->out_data.current_pdu_sent += (uint32)data_returned;
		goto out;
	}

	/*
	 * At this point p->current_pdu_len == p->current_pdu_sent (which
	 * may of course be zero if this is the first return fragment.
	 */

	DEBUG(10,("read_from_pipe: %s: fault_state = %d : data_sent_length "
		  "= %u, prs_offset(&p->out_data.rdata) = %u.\n",
		  get_pipe_name_from_syntax(talloc_tos(), &p->syntax),
		  (int)p->fault_state,
		  (unsigned int)p->out_data.data_sent_length,
		  (unsigned int)prs_offset(&p->out_data.rdata) ));

	if(p->out_data.data_sent_length >= prs_offset(&p->out_data.rdata)) {
		/*
		 * We have sent all possible data, return 0.
		 */
		data_returned = 0;
		goto out;
	}

	/*
	 * We need to create a new PDU from the data left in p->rdata.
	 * Create the header/data/footers. This also sets up the fields
	 * p->current_pdu_len, p->current_pdu_sent, p->data_sent_length
	 * and stores the outgoing PDU in p->current_pdu.
	 */

	if(!create_next_pdu(p)) {
		DEBUG(0,("read_from_pipe: %s: create_next_pdu failed.\n",
			 get_pipe_name_from_syntax(talloc_tos(), &p->syntax)));
		return -1;
	}

	data_returned = MIN(n, prs_offset(&p->out_data.frag));

	memcpy( data, prs_data_p(&p->out_data.frag), (size_t)data_returned);
	p->out_data.current_pdu_sent += (uint32)data_returned;

  out:
	(*is_data_outstanding) = prs_offset(&p->out_data.frag) > n;

	if (p->out_data.current_pdu_sent == prs_offset(&p->out_data.frag)) {
		/* We've returned everything in the out_data.frag
		 * so we're done with this pdu. Free it and reset
		 * current_pdu_sent. */
		p->out_data.current_pdu_sent = 0;
		prs_mem_free(&p->out_data.frag);

		if (p->out_data.data_sent_length
		    >= prs_offset(&p->out_data.rdata)) {
			/*
			 * We're completely finished with both outgoing and
			 * incoming data streams. It's safe to free all
			 * temporary data from this request.
			 */
			free_pipe_context(p);
		}
	}

	return data_returned;
}

bool fsp_is_np(struct files_struct *fsp)
{
	enum FAKE_FILE_TYPE type;

	if ((fsp == NULL) || (fsp->fake_file_handle == NULL)) {
		return false;
	}

	type = fsp->fake_file_handle->type;

	return ((type == FAKE_FILE_TYPE_NAMED_PIPE)
		|| (type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY));
}

struct np_proxy_state {
	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;
	struct tstream_context *npipe;
	struct tevent_queue *read_queue;
	struct tevent_queue *write_queue;
};

static struct np_proxy_state *make_external_rpc_pipe_p(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *local_address,
				const struct tsocket_address *remote_address,
				struct auth_serversupplied_info *server_info)
{
	struct np_proxy_state *result;
	char *socket_np_dir;
	const char *socket_dir;
	struct tevent_context *ev;
	struct tevent_req *subreq;
	struct netr_SamInfo3 *info3;
	NTSTATUS status;
	bool ok;
	int ret;
	int sys_errno;

	result = talloc(mem_ctx, struct np_proxy_state);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	result->read_queue = tevent_queue_create(result, "np_read");
	if (result->read_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	result->write_queue = tevent_queue_create(result, "np_write");
	if (result->write_queue == NULL) {
		DEBUG(0, ("tevent_queue_create failed\n"));
		goto fail;
	}

	ev = s3_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		DEBUG(0, ("s3_tevent_context_init failed\n"));
		goto fail;
	}

	socket_dir = lp_parm_const_string(
		GLOBAL_SECTION_SNUM, "external_rpc_pipe", "socket_dir",
		get_dyn_NCALRPCDIR());
	if (socket_dir == NULL) {
		DEBUG(0, ("externan_rpc_pipe:socket_dir not set\n"));
		goto fail;
	}
	socket_np_dir = talloc_asprintf(talloc_tos(), "%s/np", socket_dir);
	if (socket_np_dir == NULL) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		goto fail;
	}

	info3 = talloc_zero(talloc_tos(), struct netr_SamInfo3);
	if (info3 == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	status = serverinfo_to_SamInfo3(server_info, NULL, 0, info3);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		DEBUG(0, ("serverinfo_to_SamInfo3 failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	become_root();
	subreq = tstream_npa_connect_send(talloc_tos(), ev,
					  socket_np_dir,
					  pipe_name,
					  remote_address, /* client_addr */
					  NULL, /* client_name */
					  local_address, /* server_addr */
					  NULL, /* server_name */
					  info3,
					  server_info->user_session_key,
					  data_blob_null /* delegated_creds */);
	if (subreq == NULL) {
		unbecome_root();
		DEBUG(0, ("tstream_npa_connect_send to %s for pipe %s and "
			  "user %s\\%s failed\n",
			  socket_np_dir, pipe_name, info3->base.domain.string,
			  info3->base.account_name.string));
		goto fail;
	}
	ok = tevent_req_poll(subreq, ev);
	unbecome_root();
	if (!ok) {
		DEBUG(0, ("tevent_req_poll to %s for pipe %s and user %s\\%s "
			  "failed for tstream_npa_connect: %s\n",
			  socket_np_dir, pipe_name, info3->base.domain.string,
			  info3->base.account_name.string,
			  strerror(errno)));
		goto fail;

	}
	ret = tstream_npa_connect_recv(subreq, &sys_errno,
				       result,
				       &result->npipe,
				       &result->file_type,
				       &result->device_state,
				       &result->allocation_size);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DEBUG(0, ("tstream_npa_connect_recv  to %s for pipe %s and "
			  "user %s\\%s failed: %s\n",
			  socket_np_dir, pipe_name, info3->base.domain.string,
			  info3->base.account_name.string,
			  strerror(sys_errno)));
		goto fail;
	}

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

NTSTATUS np_open(TALLOC_CTX *mem_ctx, const char *name,
		 const struct tsocket_address *local_address,
		 const struct tsocket_address *remote_address,
		 struct auth_serversupplied_info *server_info,
		 struct fake_file_handle **phandle)
{
	const char **proxy_list;
	struct fake_file_handle *handle;

	proxy_list = lp_parm_string_list(-1, "np", "proxy", NULL);

	handle = talloc(mem_ctx, struct fake_file_handle);
	if (handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if ((proxy_list != NULL) && str_list_check_ci(proxy_list, name)) {
		struct np_proxy_state *p;

		p = make_external_rpc_pipe_p(handle, name,
					     local_address,
					     remote_address,
					     server_info);

		handle->type = FAKE_FILE_TYPE_NAMED_PIPE_PROXY;
		handle->private_data = p;
	} else {
		struct pipes_struct *p;
		struct ndr_syntax_id syntax;
		const char *client_address;

		if (!is_known_pipename(name, &syntax)) {
			TALLOC_FREE(handle);
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}

		if (tsocket_address_is_inet(remote_address, "ip")) {
			client_address = tsocket_address_inet_addr_string(
						remote_address,
						talloc_tos());
			if (client_address == NULL) {
				TALLOC_FREE(handle);
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			client_address = "";
		}

		p = make_internal_rpc_pipe_p(handle, &syntax, client_address,
					     server_info);

		handle->type = FAKE_FILE_TYPE_NAMED_PIPE;
		handle->private_data = p;
	}

	if (handle->private_data == NULL) {
		TALLOC_FREE(handle);
		return NT_STATUS_PIPE_NOT_AVAILABLE;
	}

	*phandle = handle;

	return NT_STATUS_OK;
}

bool np_read_in_progress(struct fake_file_handle *handle)
{
	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE) {
		return false;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct np_proxy_state *p = talloc_get_type_abort(
			handle->private_data, struct np_proxy_state);
		size_t read_count;

		read_count = tevent_queue_length(p->read_queue);
		if (read_count > 0) {
			return true;
		}

		return false;
	}

	return false;
}

struct np_write_state {
	struct event_context *ev;
	struct np_proxy_state *p;
	struct iovec iov;
	ssize_t nwritten;
};

static void np_write_done(struct tevent_req *subreq);

struct tevent_req *np_write_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct fake_file_handle *handle,
				 const uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_write_state *state;
	NTSTATUS status;

	DEBUG(6, ("np_write_send: len: %d\n", (int)len));
	dump_data(50, data, len);

	req = tevent_req_create(mem_ctx, &state, struct np_write_state);
	if (req == NULL) {
		return NULL;
	}

	if (len == 0) {
		state->nwritten = 0;
		status = NT_STATUS_OK;
		goto post_status;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE) {
		struct pipes_struct *p = talloc_get_type_abort(
			handle->private_data, struct pipes_struct);

		state->nwritten = write_to_internal_pipe(p, (char *)data, len);

		status = (state->nwritten >= 0)
			? NT_STATUS_OK : NT_STATUS_UNEXPECTED_IO_ERROR;
		goto post_status;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct np_proxy_state *p = talloc_get_type_abort(
			handle->private_data, struct np_proxy_state);
		struct tevent_req *subreq;

		state->ev = ev;
		state->p = p;
		state->iov.iov_base = CONST_DISCARD(void *, data);
		state->iov.iov_len = len;

		subreq = tstream_writev_queue_send(state, ev,
						   p->npipe,
						   p->write_queue,
						   &state->iov, 1);
		if (subreq == NULL) {
			goto fail;
		}
		tevent_req_set_callback(subreq, np_write_done, req);
		return req;
	}

	status = NT_STATUS_INVALID_HANDLE;
 post_status:
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
	} else {
		tevent_req_nterror(req, status);
	}
	return tevent_req_post(req, ev);
 fail:
	TALLOC_FREE(req);
	return NULL;
}

static void np_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	ssize_t received;
	int err;

	received = tstream_writev_queue_recv(subreq, &err);
	if (received < 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	state->nwritten = received;
	tevent_req_done(req);
}

NTSTATUS np_write_recv(struct tevent_req *req, ssize_t *pnwritten)
{
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pnwritten = state->nwritten;
	return NT_STATUS_OK;
}

struct np_ipc_readv_next_vector_state {
	uint8_t *buf;
	size_t len;
	off_t ofs;
	size_t remaining;
};

static void np_ipc_readv_next_vector_init(struct np_ipc_readv_next_vector_state *s,
					  uint8_t *buf, size_t len)
{
	ZERO_STRUCTP(s);

	s->buf = buf;
	s->len = MIN(len, UINT16_MAX);
}

static int np_ipc_readv_next_vector(struct tstream_context *stream,
				    void *private_data,
				    TALLOC_CTX *mem_ctx,
				    struct iovec **_vector,
				    size_t *count)
{
	struct np_ipc_readv_next_vector_state *state =
		(struct np_ipc_readv_next_vector_state *)private_data;
	struct iovec *vector;
	ssize_t pending;
	size_t wanted;

	if (state->ofs == state->len) {
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	pending = tstream_pending_bytes(stream);
	if (pending == -1) {
		return -1;
	}

	if (pending == 0 && state->ofs != 0) {
		/* return a short read */
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	if (pending == 0) {
		/* we want at least one byte and recheck again */
		wanted = 1;
	} else {
		size_t missing = state->len - state->ofs;
		if (pending > missing) {
			/* there's more available */
			state->remaining = pending - missing;
			wanted = missing;
		} else {
			/* read what we can get and recheck in the next cycle */
			wanted = pending;
		}
	}

	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		return -1;
	}

	vector[0].iov_base = state->buf + state->ofs;
	vector[0].iov_len = wanted;

	state->ofs += wanted;

	*_vector = vector;
	*count = 1;
	return 0;
}

struct np_read_state {
	struct np_proxy_state *p;
	struct np_ipc_readv_next_vector_state next_vector;

	size_t nread;
	bool is_data_outstanding;
};

static void np_read_done(struct tevent_req *subreq);

struct tevent_req *np_read_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				struct fake_file_handle *handle,
				uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_read_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct np_read_state);
	if (req == NULL) {
		return NULL;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE) {
		struct pipes_struct *p = talloc_get_type_abort(
			handle->private_data, struct pipes_struct);

		state->nread = read_from_internal_pipe(
			p, (char *)data, len, &state->is_data_outstanding);

		status = (state->nread >= 0)
			? NT_STATUS_OK : NT_STATUS_UNEXPECTED_IO_ERROR;
		goto post_status;
	}

	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct np_proxy_state *p = talloc_get_type_abort(
			handle->private_data, struct np_proxy_state);
		struct tevent_req *subreq;

		np_ipc_readv_next_vector_init(&state->next_vector,
					      data, len);

		subreq = tstream_readv_pdu_queue_send(state,
						      ev,
						      p->npipe,
						      p->read_queue,
						      np_ipc_readv_next_vector,
						      &state->next_vector);
		if (subreq == NULL) {

		}
		tevent_req_set_callback(subreq, np_read_done, req);
		return req;
	}

	status = NT_STATUS_INVALID_HANDLE;
 post_status:
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
	} else {
		tevent_req_nterror(req, status);
	}
	return tevent_req_post(req, ev);
}

static void np_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	ssize_t ret;
	int err;

	ret = tstream_readv_pdu_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	state->nread = ret;
	state->is_data_outstanding = (state->next_vector.remaining > 0);

	tevent_req_done(req);
	return;
}

NTSTATUS np_read_recv(struct tevent_req *req, ssize_t *nread,
		      bool *is_data_outstanding)
{
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*nread = state->nread;
	*is_data_outstanding = state->is_data_outstanding;
	return NT_STATUS_OK;
}

/**
 * @brief Create a new RPC client context which uses a local dispatch function.
 *
 * @param[in]  conn  The connection struct that will hold the pipe
 *
 * @param[out] spoolss_pipe  A pointer to the connected rpc client pipe.
 *
 * @return              NT_STATUS_OK on success, a corresponding NT status if an
 *                      error occured.
 */
NTSTATUS rpc_connect_spoolss_pipe(connection_struct *conn,
				  struct rpc_pipe_client **spoolss_pipe)
{
	NTSTATUS status;

	/* TODO: check and handle disconnections */

	if (!conn->spoolss_pipe) {
		status = rpc_pipe_open_internal(conn,
						&ndr_table_spoolss.syntax_id,
						conn->server_info,
						&conn->spoolss_pipe);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	*spoolss_pipe = conn->spoolss_pipe;
	return NT_STATUS_OK;
}
