#include "eparser.h"
#include <string.h>

static gint ett_array = -1;

struct ndr_pull *ndr_pull_init(tvbuff_t *tvb, int offset, packet_info *pinfo,
			       guint8 *drep)
{
	struct ndr_pull *ndr;

	ndr = (struct ndr_pull *)g_malloc(sizeof(*ndr));
	
	ndr->tvb = tvb_new_subset(tvb, offset, -1, -1);
	ndr->offset = 0;
	ndr->pinfo = pinfo;
	ndr->drep = drep;
	ndr->flags = NDR_SCALARS|NDR_BUFFERS|LIBNDR_FLAG_REF_ALLOC;
	return ndr;
}

/*
  mark the start of a structure
*/
void ndr_pull_struct_start(struct ndr_pull *ndr)
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
void ndr_pull_struct_end(struct ndr_pull *ndr)
{
	ndr->ofs_list = ndr->ofs_list->next;
}

void ndr_pull_align(struct ndr_pull *ndr, int size)
{
       	if (!(ndr->flags & LIBNDR_FLAG_NOALIGN)) {
		ndr->offset = (ndr->offset + (size-1)) & ~(size-1);
	}
}

void ndr_pull_ptr(struct ndr_pull *ndr, proto_tree *tree, int hf, guint32 *ptr)
{
	ndr_pull_uint32(ndr, tree, hf, ptr);
}

static int hf_string4_len = -1;
static int hf_string4_offset = -1;
static int hf_string4_len2 = -1;
static int hf_string_data = -1;

void ndr_pull_string(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, 
		     char **s)
{
	guint32 len1, ofs, len2;
	char *data;

	if (!(ndr_flags & NDR_SCALARS)) {
		return;
	}
	
	switch (ndr->flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:

		ndr_pull_uint32(ndr, tree, hf_string4_len, &len1);
		ndr_pull_uint32(ndr, tree, hf_string4_offset, &ofs);
		ndr_pull_uint32(ndr, tree, hf_string4_len2, &len2);

		if (len2 > 65535)
			return;

		data = g_malloc(len2*2);

		proto_tree_add_bytes(tree, hf_string_data, ndr->tvb,
				     ndr->offset, len2 * 2, data);

		g_free(data);

		ndr->offset += len2 * 2;

#if 0

		ndr_pull_uint32(ndr, &len1));
		ndr_pull_uint32(ndr, &ofs);
		ndr_pull_uint32(ndr, &len2);
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, 
					      "Bad string lengths len1=%u ofs=%u len2=%u\n", 
					      len1, ofs, len2);
		}
		if (len2 == 0) {
			*s = talloc_strdup(ndr->mem_ctx, "");
			break;
		}
		NDR_PULL_NEED_BYTES(ndr, len2*2);
		ret = convert_string_talloc(ndr->mem_ctx, chset, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len2*2,
					    (const void **)&as);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr_pull_advance(ndr, len2*2);

		/* this is a way of detecting if a string is sent with the wrong
		   termination */
		if (ndr->flags & LIBNDR_FLAG_STR_NOTERM) {
			if (strlen(as) < len2) {
				DEBUG(6,("short string '%s'\n", as));
			}
		} else {
			if (strlen(as) == len2) {
				DEBUG(6,("long string '%s'\n", as));
			}
		}
		*s = as;

#endif

		break;

	case LIBNDR_FLAG_STR_SIZE4:

#if 0

		ndr_pull_uint32(ndr, &len1);
		NDR_PULL_NEED_BYTES(ndr, len1*2);
		if (len1 == 0) {
			*s = talloc_strdup(ndr->mem_ctx, "");
			break;
		}
		ret = convert_string_talloc(ndr->mem_ctx, chset, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len1*2,
					    (const void **)&as);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr_pull_advance(ndr, len1*2);
		*s = as;

#endif

		break;

	case LIBNDR_FLAG_STR_NULLTERM:

#if 0

		len1 = strnlen_w(ndr->data+ndr->offset, 
				 (ndr->data_size - ndr->offset)/2);
		if (len1*2+2 <= ndr->data_size - ndr->offset) {
			len1++;
		}
		ret = convert_string_talloc(ndr->mem_ctx, chset, CH_UNIX, 
					    ndr->data+ndr->offset, 
					    len1*2,
					    (const void **)s);
		if (ret == -1) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
					      "Bad character conversion");
		}
		ndr_pull_advance(ndr, len1*2);

#endif

		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:

#if 0

		ndr_pull_uint32(ndr, &len1);
		ndr_pull_uint32(ndr, &ofs);
		ndr_pull_uint32(ndr, &len2);
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, 
					      "Bad ascii string lengths len1=%u ofs=%u len2=%u\n", 
					      len1, ofs, len2);
		}
		NDR_ALLOC_N(ndr, as, (len2+1));
		ndr_pull_bytes(ndr, as, len2);
		as[len2] = 0;
		(*s) = as;

#endif

		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_LEN4:

#if 0
		ndr_pull_uint32(ndr, &ofs);
		ndr_pull_uint32(ndr, &len2);
		NDR_ALLOC_N(ndr, as, (len2+1));
		ndr_pull_bytes(ndr, as, len2);
		as[len2] = 0;
		(*s) = as;

#endif

		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_SIZE2:

#if 0

		ndr_pull_uint16(ndr, &len3);
		NDR_ALLOC_N(ndr, as, (len3+1));
		ndr_pull_bytes(ndr, as, len3);
		as[len3] = 0;
		(*s) = as;

#endif

		break;

	case LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_NULLTERM:

#if 0

		len1 = strnlen(ndr->data+ndr->offset, (ndr->data_size - ndr->offset));
		if (len1+1 <= ndr->data_size - ndr->offset) {
			len1++;
		}
		NDR_ALLOC_N(ndr, as, (len1+1));
		ndr_pull_bytes(ndr, as, len1);
		as[len1] = 0;
		(*s) = as;

#endif

		break;

	default:

#if 0

		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);

#endif

	}	
}

void ndr_pull_array_uint32(struct ndr_pull *ndr, int ndr_flags, 
			   proto_tree *tree, char *name, int hf, void *data, 
			   int count)
{
	int i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return;
	}
	for (i=0;i<count;i++) {
		ndr_pull_uint32(ndr, tree, hf, NULL);
	}
}

void ndr_pull_array_uint16(struct ndr_pull *ndr, int ndr_flags, 
			   proto_tree *tree, char *name, int hf, void *data, 
			   int count)
{
	int i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return;
	}
	for (i=0;i<count;i++) {
		ndr_pull_uint16(ndr, tree, hf, NULL);
	}
}

void ndr_pull_array_uint8(struct ndr_pull *ndr, int ndr_flags, 
			  proto_tree *tree, char *name, int hf, void *data, 
			  int count)
{
	int i;
	if (!(ndr_flags & NDR_SCALARS)) {
		return;
	}
	for (i=0;i<count;i++) {
		ndr_pull_uint8(ndr, tree, hf, NULL);
	}	
}

void ndr_pull_array(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree,
		    char *name, void *data, int size, int count, 
		    void (*pull_fn)(struct ndr_pull *, int ndr_flags, 
				    proto_tree *tree, void *fn_data))
{
	proto_tree **subtrees;
	int i;

	subtrees = (proto_tree **)g_malloc(sizeof(proto_tree **) * count);

	if (!(ndr_flags & NDR_SCALARS)) goto buffers;
	for (i=0;i<count;i++) {
		proto_item *item;
		item = proto_tree_add_text(tree, ndr->tvb, ndr->offset, 0, "Array entry");
		subtrees[i] = proto_item_add_subtree(item, ett_array);

		if ((ndr_flags & (NDR_SCALARS|NDR_BUFFERS)) == (NDR_SCALARS|NDR_BUFFERS))
			pull_fn(ndr, NDR_SCALARS, subtrees[i], data);
		else
			pull_fn(ndr, NDR_SCALARS, tree, data);

	}
	if (!(ndr_flags & NDR_BUFFERS)) goto done;
buffers:
	for (i=0;i<count;i++) {
		if ((ndr_flags & (NDR_SCALARS|NDR_BUFFERS)) == (NDR_SCALARS|NDR_BUFFERS))
			pull_fn(ndr, NDR_BUFFERS, subtrees[i], data);
		else
			pull_fn(ndr, NDR_BUFFERS, tree, data);
	}
 done: 
	g_free(subtrees);
}

void ndr_pull_relative(struct ndr_pull *ndr, void *data, int size,
		       void (*fn)(struct ndr_pull *, int ndr_flags, 
				  char *name))
{
}

void ndr_pull_uint8(struct ndr_pull *ndr, proto_tree *tree, int hf, uint8 *data)
{
        ndr->offset = dissect_ndr_uint8(
                ndr->tvb, ndr->offset, ndr->pinfo,
                tree, ndr->drep, hf, data);
}

void ndr_pull_uint16(struct ndr_pull *ndr, proto_tree *tree, int hf, uint16 *data)
{
        ndr->offset = dissect_ndr_uint16(
                ndr->tvb, ndr->offset, ndr->pinfo,
                tree, ndr->drep, hf, data);
}

void ndr_pull_uint32(struct ndr_pull *ndr, proto_tree *tree, int hf, uint32 *data)
{
	ndr->offset = dissect_ndr_uint32(
                ndr->tvb, ndr->offset, ndr->pinfo,
                tree, ndr->drep, hf, data);
}

void ndr_pull_uint64(struct ndr_pull *ndr, proto_tree *tree, int hf, uint64 *data)
{
        ndr->offset = dissect_ndr_uint64(
                ndr->tvb, ndr->offset, ndr->pinfo,
                tree, ndr->drep, hf, data);
}

void ndr_pull_int8(struct ndr_pull *ndr, proto_tree *tree, int hf, int8 *data)
{
}

void ndr_pull_int16(struct ndr_pull *ndr, proto_tree *tree, int hf, int16 *data)
{
}

void ndr_pull_int32(struct ndr_pull *ndr, proto_tree *tree, int hf, int32 *data)
{
}

void ndr_pull_int64(struct ndr_pull *ndr, proto_tree *tree, int hf, int64 *data)
{
}

void ndr_pull_NTTIME(struct ndr_pull *ndr, proto_tree *tree, int hf, NTTIME *data)
{
}

void ndr_pull_NTSTATUS(struct ndr_pull *ndr, proto_tree *tree, int hf, NTSTATUS *data)
{
	ndr->offset = dissect_ntstatus(
		ndr->tvb, ndr->offset, ndr->pinfo,
		tree, ndr->drep, hf, data);
}

void ndr_pull_HYPER_T(struct ndr_pull *ndr, proto_tree *tree, int hf, HYPER_T *data)
{
}

void ndr_pull_dom_sid2(struct ndr_pull *ndr, int ndr_flags, proto_tree *tree, struct dom_sid2 *data)
{
}

void ndr_pull_subcontext_flags_fn(struct ndr_pull *ndr, proto_tree *tree,
				  size_t sub_size, void *data,
				  void (*fn)(struct ndr_pull *, int ndr_flags,
					     proto_tree *tree, void *data))
{
	struct ndr_pull ndr2;

	ndr_pull_subcontext_header(ndr, tree, sub_size, &ndr2);
	fn(&ndr2, NDR_SCALARS|NDR_BUFFERS, tree, data);
	if (sub_size) {
		ndr_pull_advance(ndr, tvb_length(ndr2.tvb));
	} else {
		ndr_pull_advance(ndr, ndr2.offset);
	}
}

void ndr_pull_subcontext(struct ndr_pull *ndr, struct ndr_pull *ndr2, 
			 guint32 size)
{
	ndr2->tvb = tvb_new_subset(
		ndr->tvb, ndr->offset, 
		(tvb_length_remaining(ndr->tvb, ndr->offset) > size) ? size :
		tvb_length_remaining(ndr->tvb, ndr->offset),
		(tvb_reported_length_remaining(ndr->tvb, ndr->offset) > size) ? size :
		tvb_reported_length_remaining(ndr->tvb, ndr->offset));

	ndr2->offset = 0;
	ndr2->flags = ndr->flags;

	ndr2->pinfo = ndr->pinfo;
	ndr2->drep = ndr->drep;
	ndr2->ofs_list = ndr->ofs_list;
}

static int hf_subcontext_size_2 = -1;
static int hf_subcontext_size_4 = -1;

void ndr_pull_subcontext_header(struct ndr_pull *ndr, proto_tree *tree,
				size_t sub_size, struct ndr_pull *ndr2)
{
	switch (sub_size) {
	case 0: {
		guint32 size = tvb_length(ndr->tvb) - ndr->offset;
		if (size == 0) return;
		ndr_pull_subcontext(ndr, ndr2, size);
		break;
	}

	case 2: {
		guint16 size;
		ndr_pull_uint16(ndr, tree, hf_subcontext_size_2, &size);
		if (size == 0) return;
		ndr_pull_subcontext(ndr, ndr2, size);
		break;
	}

	case 4: {
		guint32 size;
		ndr_pull_uint32(ndr, tree, hf_subcontext_size_4, &size);
		if (size == 0) return;
		ndr_pull_subcontext(ndr, ndr2, size);
		break;
	}
	default: ;
//		return ndr_pull_error(ndr, NDR_ERR_SUBCONTEXT, "Bad subcontext size %d", sub_size);
	}
}

void ndr_pull_advance(struct ndr_pull *ndr, int offset)
{
	ndr->offset += offset;
}

struct subtree_info {
	char *name;
	proto_tree *subtree;
};

proto_tree *get_subtree(proto_tree *tree, char *name, struct ndr_pull *ndr,
			gint ett)
{
	GSList *list, *l;
	proto_item *item;
	struct subtree_info *info;

	/* Get current list value */

	if (!tree)
		return NULL;

	list = (GSList *)tree->user_data;

	/* Look for name */

	for (l = list; l; l = g_slist_next(l)) {
		info = l->data;
		
		if (strcmp(name, info->name) == 0)
			return info->subtree;
	}
	
	/* Create new subtree entry */
	
	info = (struct subtree_info *)g_malloc(sizeof(struct subtree_info));
	
	info->name = g_strdup(name);
	item = proto_tree_add_text(tree, ndr->tvb, ndr->offset, 0, name);
	info->subtree = proto_item_add_subtree(item, ett);

	/* Don't forget to add new list head */

	list = g_slist_append(list, info);

	tree->user_data = list;

	return info->subtree;
}

void proto_register_eparser(void)
{
        static hf_register_info hf[] = {
        { &hf_string4_len, { "String4 length", "eparser.string4_length", FT_UINT32, BASE_DEC, NULL, 0x0, "String4 length", HFILL }},
        { &hf_string4_offset, { "String4 offset", "eparser.string4_offset", FT_UINT32, BASE_DEC, NULL, 0x0, "String4 offset", HFILL }},
        { &hf_string4_len2, { "String4 length2", "eparser.string4_length2", FT_UINT32, BASE_DEC, NULL, 0x0, "String4 length2", HFILL }},
        { &hf_string_data, { "String data", "eparser.string_data", FT_BYTES, BASE_NONE, NULL, 0x0, "String data", HFILL }},
        { &hf_subcontext_size_2, { "Subcontext size2", "eparser.subcontext_size2", FT_UINT16, BASE_DEC, NULL, 0x0, "Subcontext size2", HFILL }},
        { &hf_subcontext_size_4, { "Subcontext size4", "eparser.subcontext_size4", FT_UINT16, BASE_DEC, NULL, 0x0, "Subcontext size4", HFILL }},
//        { &hf_relative_ofs, { "Relative offset", "eparser.relative_offset", FT_UINT32, BASE_DEC, NULL, 0x0, "Relative offset", HFILL }},
//        { &hf_subtree_list, { "Subtree list", "", FT_UINT64, BASE_DEC, NULL, 0,"", HFILL }},
        };

        static gint *ett[] = {
                &ett_array,
        };

        int proto_dcerpc;

        proto_dcerpc = proto_get_id_by_filter_name("dcerpc");
        proto_register_field_array(proto_dcerpc, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}
