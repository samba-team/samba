#ifndef __DEFAULT_LIBRPC_RPCCOMMON_H__
#define __DEFAULT_LIBRPC_RPCCOMMON_H__

/* The following definitions come from ../librpc/rpc/dcerpc_error.c  */


/* The following definitions come from ../librpc/rpc/binding.c  */

const char *epm_floor_string(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
const char *dcerpc_floor_get_rhs_data(TALLOC_CTX *mem_ctx, struct epm_floor *epm_floor);
enum dcerpc_transport_t dcerpc_transport_by_endpoint_protocol(int prot);

/* The following definitions come from ../librpc/rpc/dcerpc_util.c  */

void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v);
uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob);
void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v);
uint8_t dcerpc_get_endian_flag(DATA_BLOB *blob);

/**
* @brief	Pull a dcerpc_auth structure, taking account of any auth
*		padding in the blob. For request/response packets we pass
*		the whole data blob, so auth_data_only must be set to false
*		as the blob contains data+pad+auth and no just pad+auth.
*
* @param pkt		- The ncacn_packet strcuture
* @param mem_ctx	- The mem_ctx used to allocate dcerpc_auth elements
* @param pkt_trailer	- The packet trailer data, usually the trailing
*			  auth_info blob, but in the request/response case
*			  this is the stub_and_verifier blob.
* @param auth		- A preallocated dcerpc_auth *empty* structure
* @param auth_length	- The length of the auth trail, sum of auth header
*			  lenght and pkt->auth_length
* @param auth_data_only	- Whether the pkt_trailer includes only the auth_blob
*			  (+ padding) or also other data.
*
* @return		- A NTSTATUS error code.
*/
NTSTATUS dcerpc_pull_auth_trailer(struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *pkt_trailer,
				  struct dcerpc_auth *auth,
				  uint32_t *auth_length,
				  bool auth_data_only);
struct tevent_req *dcerpc_read_ncacn_packet_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tstream_context *stream);
NTSTATUS dcerpc_read_ncacn_packet_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct ncacn_packet **pkt,
				       DATA_BLOB *buffer);

/* The following definitions come from ../librpc/rpc/binding_handle.c  */

struct dcerpc_binding_handle *_dcerpc_binding_handle_create(TALLOC_CTX *mem_ctx,
					const struct dcerpc_binding_handle_ops *ops,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location);
void *_dcerpc_binding_handle_data(struct dcerpc_binding_handle *h);
void dcerpc_binding_handle_set_sync_ev(struct dcerpc_binding_handle *h,
				       struct tevent_context *ev);
bool dcerpc_binding_handle_is_connected(struct dcerpc_binding_handle *h);
uint32_t dcerpc_binding_handle_set_timeout(struct dcerpc_binding_handle *h,
					   uint32_t timeout);
struct tevent_req *dcerpc_binding_handle_raw_call_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h,
						const struct GUID *object,
						uint32_t opnum,
						uint32_t in_flags,
						const uint8_t *in_data,
						size_t in_length);
NTSTATUS dcerpc_binding_handle_raw_call_recv(struct tevent_req *req,
					     TALLOC_CTX *mem_ctx,
					     uint8_t **out_data,
					     size_t *out_length,
					     uint32_t *out_flags);
struct tevent_req *dcerpc_binding_handle_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct dcerpc_binding_handle *h);
NTSTATUS dcerpc_binding_handle_disconnect_recv(struct tevent_req *req);
struct tevent_req *dcerpc_binding_handle_call_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct dcerpc_binding_handle *h,
					const struct GUID *object,
					const struct ndr_interface_table *table,
					uint32_t opnum,
					TALLOC_CTX *r_mem,
					void *r_ptr);
NTSTATUS dcerpc_binding_handle_call_recv(struct tevent_req *req);
NTSTATUS dcerpc_binding_handle_call(struct dcerpc_binding_handle *h,
				    const struct GUID *object,
				    const struct ndr_interface_table *table,
				    uint32_t opnum,
				    TALLOC_CTX *r_mem,
				    void *r_ptr);
#endif /* __DEFAULT_LIBRPC_RPCCOMMON_H__ */
