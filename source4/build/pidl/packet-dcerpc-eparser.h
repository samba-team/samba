#define NDR_SCALARS 1
#define NDR_BUFFERS 2

/* Ethereal version of struct ndr_pull */

struct e_ndr_pull {
	tvbuff_t *tvb;
	int offset;
	packet_info *pinfo;
	proto_tree *tree;
	guint8 *drep;
};

/* Create a ndr_pull structure from data stored in a tvb at a given offset. */

struct e_ndr_pull *ndr_pull_init(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, guint8 *drep);
void ndr_pull_free(struct e_ndr_pull *ndr);
void ndr_pull_ptr(struct e_ndr_pull *ndr, int hf, guint32 *ptr);
void ndr_pull_NTSTATUS(struct e_ndr_pull *ndr, int hf);
void ndr_pull_uint16(struct e_ndr_pull *ndr, int hf);
void ndr_pull_uint32(struct e_ndr_pull *ndr, int hf);
void ndr_pull_policy_handle(struct e_ndr_pull *e_ndr, int hf);
