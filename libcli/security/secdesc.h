#ifndef _SECDESC_H_
#define _SECDESC_H_

/* The following definitions come from libcli/security/secdesc.c  */
#include "librpc/gen_ndr/security.h"

/*******************************************************************
 Given a security_descriptor return the sec_info.
********************************************************************/
uint32_t get_sec_info(const struct security_descriptor *sd);

/*******************************************************************
 Merge part of security descriptor old_sec in to the empty sections of
 security descriptor new_sec.
********************************************************************/
struct sec_desc_buf *sec_desc_merge_buf(TALLOC_CTX *ctx, struct sec_desc_buf *new_sdb, struct sec_desc_buf *old_sdb);
struct security_descriptor *sec_desc_merge(TALLOC_CTX *ctx, struct security_descriptor *new_sdb, struct security_descriptor *old_sdb);

/*******************************************************************
 Creates a struct security_descriptor structure
********************************************************************/
struct security_descriptor *make_sec_desc(TALLOC_CTX *ctx,
			enum security_descriptor_revision revision,
			uint16_t type,
			const struct dom_sid *owner_sid, const struct dom_sid *grp_sid,
			struct security_acl *sacl, struct security_acl *dacl, size_t *sd_size);

/*******************************************************************
 Duplicate a struct security_descriptor structure.
********************************************************************/
struct security_descriptor *dup_sec_desc(TALLOC_CTX *ctx, const struct security_descriptor *src);

/*******************************************************************
 Convert a secdesc into a byte stream
********************************************************************/
NTSTATUS marshall_sec_desc(TALLOC_CTX *mem_ctx,
			   struct security_descriptor *secdesc,
			   uint8_t **data, size_t *len);

/*******************************************************************
 Convert a secdesc_buf into a byte stream
********************************************************************/
NTSTATUS marshall_sec_desc_buf(TALLOC_CTX *mem_ctx,
			       struct sec_desc_buf *secdesc_buf,
			       uint8_t **data, size_t *len);

/*******************************************************************
 Parse a byte stream into a secdesc
********************************************************************/
NTSTATUS unmarshall_sec_desc(TALLOC_CTX *mem_ctx, uint8_t *data, size_t len,
			     struct security_descriptor **psecdesc);

/*******************************************************************
 Parse a byte stream into a sec_desc_buf
********************************************************************/
NTSTATUS unmarshall_sec_desc_buf(TALLOC_CTX *mem_ctx, uint8_t *data, size_t len,
				 struct sec_desc_buf **psecdesc_buf);

/*******************************************************************
 Creates a struct security_descriptor structure with typical defaults.
********************************************************************/
struct security_descriptor *make_standard_sec_desc(TALLOC_CTX *ctx, const struct dom_sid *owner_sid, const struct dom_sid *grp_sid,
				 struct security_acl *dacl, size_t *sd_size);

/*******************************************************************
 Creates a struct sec_desc_buf structure.
********************************************************************/
struct sec_desc_buf *make_sec_desc_buf(TALLOC_CTX *ctx, size_t len, struct security_descriptor *sec_desc);

/*******************************************************************
 Duplicates a struct sec_desc_buf structure.
********************************************************************/
struct sec_desc_buf *dup_sec_desc_buf(TALLOC_CTX *ctx, struct sec_desc_buf *src);

/*******************************************************************
 Add a new SID with its permissions to struct security_descriptor.
********************************************************************/
NTSTATUS sec_desc_add_sid(TALLOC_CTX *ctx, struct security_descriptor **psd, const struct dom_sid *sid, uint32_t mask, size_t *sd_size);

/*******************************************************************
 Modify a SID's permissions in a struct security_descriptor.
********************************************************************/
NTSTATUS sec_desc_mod_sid(struct security_descriptor *sd, struct dom_sid *sid, uint32_t mask);

/*******************************************************************
 Delete a SID from a struct security_descriptor.
********************************************************************/
NTSTATUS sec_desc_del_sid(TALLOC_CTX *ctx, struct security_descriptor **psd, struct dom_sid *sid, size_t *sd_size);
bool sd_has_inheritable_components(const struct security_descriptor *parent_ctr, bool container);
NTSTATUS se_create_child_secdesc(TALLOC_CTX *ctx,
					struct security_descriptor **ppsd,
					size_t *psize,
					const struct security_descriptor *parent_ctr,
					const struct dom_sid *owner_sid,
					const struct dom_sid *group_sid,
					bool container);
NTSTATUS se_create_child_secdesc_buf(TALLOC_CTX *ctx,
					struct sec_desc_buf **ppsdb,
					const struct security_descriptor *parent_ctr,
					bool container);

#endif /* _SECDESC_H_ */
