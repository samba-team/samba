#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-eparser.h"

/* Create a ndr_pull structure from data stored in a tvb at a given offset. */

struct e_ndr_pull *ndr_pull_init(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, guint8 *drep)
{
	struct e_ndr_pull *ndr;

	ndr = (struct e_ndr_pull *)g_malloc(sizeof(*ndr));
	
	ndr->tvb = tvb;
	ndr->offset = offset;
	ndr->pinfo = pinfo;
	ndr->tree = tree;
	ndr->drep = drep;

	return ndr;
}

/* Dispose of a dynamically allocated ndr_pull structure */

void ndr_pull_free(struct e_ndr_pull *ndr)
{
	g_free(ndr);
}

void ndr_pull_ptr(struct e_ndr_pull *e_ndr, int hf, guint32 *ptr)
{
	e_ndr->offset = dissect_ndr_uint32(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, ptr);
}

void ndr_pull_level(struct e_ndr_pull *e_ndr, int hf, int *ptr)
{
	e_ndr->offset = dissect_ndr_uint16(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, ptr);
}

void ndr_pull_NTSTATUS(struct e_ndr_pull *e_ndr, int hf)
{
	e_ndr->offset = dissect_ntstatus(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, NULL);
}

void ndr_pull_uint8(struct e_ndr_pull *e_ndr, int hf)
{
	e_ndr->offset = dissect_ndr_uint8(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, NULL);
}

void ndr_pull_uint16(struct e_ndr_pull *e_ndr, int hf)
{
	e_ndr->offset = dissect_ndr_uint16(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, NULL);
}

void ndr_pull_uint32(struct e_ndr_pull *e_ndr, int hf)
{
	e_ndr->offset = dissect_ndr_uint32(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo,
		e_ndr->tree, e_ndr->drep, hf, NULL);
}

void ndr_pull_int64(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_uint64(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_string(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_NTTIME(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_HYPER_T(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_dom_sid2(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_security_descriptor(struct e_ndr_pull *e_ndr, int hf)
{
}

void ndr_pull_policy_handle(struct e_ndr_pull *e_ndr, int hf)
{
	e_ndr->offset = dissect_nt_policy_hnd(
		e_ndr->tvb, e_ndr->offset, e_ndr->pinfo, e_ndr->tree, 
		e_ndr->drep, hf, NULL, NULL, 0, 0);
}

void ndr_pull_advance(struct e_ndr_pull *e_ndr, int offset)
{
	e_ndr->offset += offset;
}

void ndr_pull_align(struct e_ndr_pull *ndr, int size)
{
	if (!(ndr->flags & LIBNDR_FLAG_NOALIGN)) {
		ndr->offset = (ndr->offset + (size-1)) & ~(size-1);
	}
}

void ndr_pull_subcontext_flags_fn(struct e_ndr_pull *ndr, size_t sub_size,
				  void (*fn)(struct e_ndr_pull *, 
					     int ndr_flags))
{
	struct e_ndr_pull ndr2;

	ndr_pull_subcontext_header(ndr, sub_size, &ndr2);
	fn(&ndr2, NDR_SCALARS|NDR_BUFFERS);
	if (sub_size) {
//		ndr_pull_advance(ndr, ndr2.data_size);
	} else {
		ndr_pull_advance(ndr, ndr2.offset);
	}
}

/*
  mark the start of a structure
*/
void ndr_pull_struct_start(struct e_ndr_pull *ndr)
{
	struct ndr_ofs_list *ofs;
	ofs = g_malloc(sizeof(*ofs));
	ofs->offset = ndr->offset;
	ofs->next = ndr->ofs_list;
	ndr->ofs_list = ofs;
}

/*
  mark the end of a structure
*/
void ndr_pull_struct_end(struct e_ndr_pull *ndr)
{
	struct ndr_ofs_list *ofs = ndr->ofs_list->next;
	g_free(ndr->ofs_list);
	ndr->ofs_list = ofs;
}

void ndr_pull_subcontext_header(struct e_ndr_pull *ndr, 
				size_t sub_size,
				struct e_ndr_pull *ndr2)
{
}

void ndr_pull_lsa_SidArray(struct e_ndr_pull *ndr, int ndr_flags)
{
}

void ndr_pull_samr_LogonHours(struct e_ndr_pull *ndr, int ndr_flags)
{
}

void ndr_pull_samr_Password(struct e_ndr_pull *ndr, int ndr_flags)
{
}

