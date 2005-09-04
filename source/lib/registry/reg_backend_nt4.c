/*
   Samba CIFS implementation
   Registry backend for REGF files
   Copyright (C) 2005 Jelmer Vernooij, jelmer@samba.org

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "registry.h"
#include "system/filesys.h"
#include "system/time.h"
#include "lib/registry/tdr_regf.h"
#include "librpc/gen_ndr/ndr_security.h"

/*
 * Read HBIN blocks into memory
 */

struct regf_data {
	DATA_BLOB data;
	struct hbin_block **hbins;
};

static struct hbin_block *hbin_by_offset (const struct regf_data *data, uint32_t offset, uint32_t *rel_offset)
{
	int i;

	for (i = 0; data->hbins[i]; i++) {
		if (offset >= data->hbins[i]->offset_from_first && 
			offset < data->hbins[i]->offset_from_first+
					 data->hbins[i]->offset_to_next) {
			if (rel_offset)
				*rel_offset = offset - data->hbins[i]->offset_from_first - 0x20;
			return data->hbins[i];
		}
	}

	return NULL;
}

/*
 * Validate a regf header
 * For now, do nothing, but we should check the checksum
 */
static uint32_t regf_hdr_checksum(const uint8_t *buffer)
{
	uint32_t checksum = 0, x;
	int i;
	
	for (i = 0; i < 0x01FB; i+= 4) {
		x = IVAL(buffer, i);
		checksum ^= x;
	}

	return checksum;
}

static DATA_BLOB hbin_get_data(const struct regf_data *data, uint32_t offset)
{
	DATA_BLOB ret;
	struct hbin_block *hbin;
	uint32_t rel_offset;
	ret.data = NULL;
	ret.length = 0;

	hbin = hbin_by_offset(data, offset, &rel_offset);

	if (hbin == NULL) {
		DEBUG(1, ("Can't find HBIN containing 0x%4x\n", offset));
		return ret;
	}

	ret.length = IVAL(hbin->data, rel_offset);
	if (ret.length & 0x80000000) {
		/* absolute value */
		ret.length = (ret.length ^ 0xffffffff) + 1;
	}
	ret.length -= 4; /* 4 bytes for the length... */
	ret.data = hbin->data + 
		(offset - hbin->offset_from_first - 0x20) + 4;
	
	return ret;
}

/* Allocate some new data */
static DATA_BLOB hbin_alloc (struct regf_data *data, uint32_t size, uint32_t *offset)
{
	DATA_BLOB ret;
	uint32_t rel_offset = -1; /* Relative offset ! */
	struct hbin_block *hbin = NULL;
	int i;

	size += 4; /* Need to include uint32 for the length */

	/* Allocate as a multiple of 8 */
	size = (size + 7) & ~7;

	ret.data = NULL;
	ret.length = 0;

	if (size == 0)
		return ret;

	for (i = 0; (hbin = data->hbins[i]); i++) {
		int j;
		uint32_t my_size;
		for (j = 0; j < hbin->offset_to_next-0x20; j+= my_size) {
			my_size = IVAL(hbin->data, j);
			uint32_t header = IVAL(hbin->data, j + 4);

			if (my_size % 8 != 0) {
				DEBUG(0, ("Encountered non-aligned block!\n"));
			}

			if (my_size & 0x80000000) { /* Used... */
				my_size = (my_size ^ 0xffffffff) + 1;
			} else if (my_size == size) { /* exact match */
				rel_offset = j;
				break;
			} else if (my_size > size) { /* data will remain */
				rel_offset = j;
				SIVAL(hbin->data, rel_offset+size, my_size-size); 
				break;
			}

			if (header == 0xffffffff &&
				hbin->offset_to_next-rel_offset >= size)  {
				rel_offset = j;
				/* Mark new free block size */
				SIVAL(hbin->data, rel_offset+size,hbin->offset_to_next - rel_offset - size - 0x20);
				SIVAL(hbin->data, rel_offset+size+0x4, 0xffffffff);
				break;
			}

			if (header == 0xffffffff)  {
				break;
			}
		}

		if (rel_offset != -1)
			break;
	}
	
	/* No space available in previous hbins, 
	 * allocate new one */
	if (data->hbins[i] == NULL) { 
		data->hbins = talloc_realloc(data, data->hbins, struct hbin_block *, i+2);
		hbin = talloc(data->hbins, struct hbin_block);
		data->hbins[i] = hbin;
		data->hbins[i+1] = NULL;

		hbin->HBIN_ID = talloc_strdup(hbin, "hbin");
		hbin->offset_from_first = (i == 0?0:data->hbins[i-1]->offset_from_first+data->hbins[i-1]->offset_to_next);
		hbin->offset_to_next = 0x1000;
		hbin->unknown[0] = 0;
		hbin->unknown[0] = 0;
		unix_to_nt_time(&hbin->last_change, time(NULL));
		hbin->block_size = hbin->offset_to_next;
		hbin->data = talloc_zero_array(hbin, uint8_t, hbin->block_size - 0x20);

		rel_offset = 0x0;
		SIVAL(hbin->data, size, hbin->block_size - size - 0x20);
		SIVAL(hbin->data, size + 0x4, 0xffffffff);
	}

	/* Set size and mark as used */
	SIVAL(hbin->data, rel_offset, size & 0x80000000);

	ret.data = hbin->data + rel_offset + 0x4; /* Skip past length */
	ret.length = size - 0x4;
	if (offset)
		*offset = hbin->offset_from_first + rel_offset + 0x20;

	return ret;
}

/* Store a data blob. Return the offset at which it was stored */
static uint32_t hbin_store (struct regf_data *data, DATA_BLOB blob)
{
	uint32_t ret;
	DATA_BLOB dest = hbin_alloc(data, blob.length, &ret);

	memcpy(dest.data, blob.data, blob.length);

	return ret;
}


/* Free existing data */
static void hbin_free (struct regf_data *data, uint32_t offset)
{
	uint32_t size;
	uint32_t rel_offset;
	struct hbin_block *hbin = hbin_by_offset(data, offset, &rel_offset);

	if (hbin == NULL)
		return;
	
	/* Get original size */
	size = IVAL(hbin->data, rel_offset);

	if (!(size & 0x80000000)) {
		DEBUG(1, ("Trying to free already freed block\n"));
		return;
	}

	/* Mark block as free */
	SIVAL(hbin->data, rel_offset, (size ^ 0xffffffff) + 1);
}

/* Store a data blob data was already stored, but hsa changed in size
 * Will try to save it at the current location if possible, otherwise 
 * does a free + store */
static uint32_t hbin_store_resize (struct regf_data *data, uint32_t orig_offset, DATA_BLOB blob)
{
	uint32_t rel_offset;
	struct hbin_block *hbin = hbin_by_offset(data, orig_offset, &rel_offset);
	uint32_t orig_size;
	uint32_t needed_size;
	uint32_t possible_size;
	int i;

	if (!hbin)
		return hbin_store(data, blob);

	/* Get original size */
	orig_size = IVAL(hbin->data, rel_offset);

	/* Fits into current allocated block */
	if (orig_size - 4 >= blob.length) {
		memcpy(hbin->data + rel_offset + 0x4, blob.data, blob.length);
		return orig_offset;
	}

	needed_size = blob.length + 4; /* Add uint32 containing length */
	needed_size = (needed_size + 7) & ~7; /* Align */

	possible_size = orig_size;

	/* Check if it can be combined with the next few free records */
	for (i = rel_offset; 
		 i < hbin->offset_to_next - 0x20; 
		 i = rel_offset + possible_size) {
		uint32_t header;
		if (IVAL(hbin->data, i) & 0x80000000) /* Used */
			break;

		header = IVAL(hbin->data, i + 4);
		if (header == 0xffffffff) {
			possible_size = hbin->offset_to_next - 0x20 - rel_offset;
		} else {
			possible_size += IVAL(hbin->data, i);
		}

		if (possible_size >= blob.length) {
			SIVAL(hbin->data, rel_offset, possible_size);
			memcpy(hbin->data + rel_offset + 0x4, blob.data, blob.length);
			return orig_offset;
		}

		if (header == 0xffffffff) 
			break;
	}

	hbin_free(data, orig_offset);
	return hbin_store(data, blob);
}

static WERROR regf_num_subkeys (struct registry_key *key, uint32_t *count)
{
	struct nk_block *nk = key->backend_data;

	*count = nk->num_subkeys;
	
	return WERR_OK;
}

static WERROR regf_num_values (struct registry_key *key, uint32_t *count)
{
	struct nk_block *nk = key->backend_data;

	*count = nk->num_values;

	return WERR_OK;
}

static struct registry_key *regf_get_key (TALLOC_CTX *ctx, struct regf_data *regf, uint32_t offset)
{
	DATA_BLOB data = hbin_get_data(regf, offset);
	struct tdr_pull *pull;
	struct registry_key *ret;
	struct nk_block *nk;

	if (data.data == NULL) {
		DEBUG(0, ("Unable to find HBIN data for offset %d\n", offset));
		return NULL;
	}

	ret = talloc_zero(ctx, struct registry_key);
	pull = talloc_zero(ret, struct tdr_pull);
	pull->data = data;
	nk = talloc(ret, struct nk_block);

	if (NT_STATUS_IS_ERR(tdr_pull_nk_block(pull, nk))) {
		DEBUG(1, ("Error parsing 'nk' record\n"));
		talloc_free(ret);
		return NULL;
	}

	if (strcmp(nk->header, "nk") != 0) {
		DEBUG(0, ("Expected nk record, got %s\n", nk->header));
		talloc_free(ret);
		return NULL;
	}

	ret->name = talloc_steal(ret, nk->key_name);
	ret->last_mod = nk->last_change;
	ret->class_name = NULL; /* FIXME: get somehow using clsname_offset */
	ret->backend_data = nk;

	return ret;
}

static WERROR regf_get_value (TALLOC_CTX *ctx, struct registry_key *key, int idx, struct registry_value **ret)
{
	struct nk_block *nk = key->backend_data;
	struct vk_block *vk;
	struct tdr_pull *pull;
	uint32_t vk_offset;
	DATA_BLOB data;

	if (idx >= nk->num_values)
		return WERR_NO_MORE_ITEMS;

	data = hbin_get_data(key->hive->backend_data, nk->values_offset);
	if (!data.data) {
		DEBUG(0, ("Unable to find value list\n"));
		return WERR_GENERAL_FAILURE;
	}

	if (data.length < nk->num_values * 4) {
		DEBUG(1, ("Value counts mismatch\n"));
	}

	vk_offset = IVAL(data.data, idx * 4);

	data = hbin_get_data(key->hive->backend_data, vk_offset);
	if (!data.data) {
		DEBUG(0, ("Unable to find value\n"));
		return WERR_GENERAL_FAILURE;
	}

	*ret = talloc_zero(ctx, struct registry_value);
	if (!(*ret)) 
		return WERR_NOMEM;

	vk = talloc(*ret, struct vk_block);
	if (!vk)
		return WERR_NOMEM;
	
	pull = talloc_zero(*ret, struct tdr_pull);
	pull->data = data;

	if (NT_STATUS_IS_ERR(tdr_pull_vk_block(pull, vk))) {
		DEBUG(0, ("Error parsing vk block\n"));
		return WERR_GENERAL_FAILURE;
	}

	(*ret)->name = talloc_steal(*ret, vk->data_name);
	(*ret)->data_type = vk->data_type;
	if (vk->data_length & 0x80000000) { 
		vk->data_length &= ~0x80000000;
		(*ret)->data.data = (uint8_t *)&vk->data_offset;
		(*ret)->data.length = vk->data_length;
	} else {
		(*ret)->data = hbin_get_data(key->hive->backend_data, vk->data_offset);
	}

	if ((*ret)->data.length < vk->data_length) {
		DEBUG(1, ("Read data less then indicated data length!\n"));
	}
	
	return WERR_OK;
}

static WERROR regf_get_subkey (TALLOC_CTX *ctx, struct registry_key *key, int idx, struct registry_key **ret)
{
	DATA_BLOB data;
	struct nk_block *nk = key->backend_data;
	uint32_t key_off;

	if (idx >= nk->num_subkeys)
		return WERR_NO_MORE_ITEMS;

	data = hbin_get_data(key->hive->backend_data, nk->subkeys_offset);
	if (!data.data) {
		DEBUG(0, ("Unable to find subkey list\n"));
		return WERR_GENERAL_FAILURE;
	}

	if (!strncmp((char *)data.data, "li", 2)) {
		DEBUG(4, ("Subkeys in LI list\n"));
		SMB_ASSERT(0);
	} else if (!strncmp((char *)data.data, "lf", 2)) {
		struct lf_block lf;
		struct tdr_pull *pull = talloc_zero(ctx, struct tdr_pull);

		DEBUG(10, ("Subkeys in LF list\n"));
		pull->data = data;

		if (NT_STATUS_IS_ERR(tdr_pull_lf_block(pull, &lf))) {
			DEBUG(0, ("Error parsing LF list\n"));
			return WERR_GENERAL_FAILURE;
		}

		if (lf.key_count != nk->num_subkeys) {
			DEBUG(0, ("Subkey counts don't match\n"));
			return WERR_GENERAL_FAILURE;
		}

		key_off = lf.hr[idx].nk_off;
		
		talloc_free(pull);
	} else if (!strncmp((char *)data.data, "ri", 2)) {
		DEBUG(4, ("Subkeys in RI list\n"));
		SMB_ASSERT(0);
	} else if (!strncmp((char *)data.data, "lh", 2)) {
		DEBUG(4, ("Subkeys in LH list\n"));
		SMB_ASSERT(0);
	} else {
		DEBUG(0, ("Unknown type for subkey list (0x%04x): %c%c\n", nk->subkeys_offset, data.data[0], data.data[1]));
		return WERR_GENERAL_FAILURE;
	}

	*ret = regf_get_key (ctx, key->hive->backend_data, key_off);

	return WERR_OK;
}

static WERROR regf_get_sec_desc(TALLOC_CTX *ctx, struct registry_key *key, struct security_descriptor **sd)
{
	struct nk_block *nk = key->backend_data;
	struct tdr_pull *tdr;
	struct sk_block sk;
	DATA_BLOB data;

	data = hbin_get_data(key->hive->backend_data, nk->sk_offset);
	if (!data.data) {
		DEBUG(0, ("Unable to find security descriptor\n"));
		return WERR_GENERAL_FAILURE;
	}

	tdr = talloc_zero(ctx, struct tdr_pull);
	if (!tdr)
		return WERR_NOMEM;

	tdr->data = data;

	if (NT_STATUS_IS_ERR(tdr_pull_sk_block(tdr, &sk))) {
		DEBUG(0, ("Error parsing SK block\n"));
		return WERR_GENERAL_FAILURE;
	}

	if (strcmp(sk.header, "sk") != 0) {
		DEBUG(0, ("Expected 'sk', got '%s'\n", sk.header));
		return WERR_GENERAL_FAILURE;
	}

	*sd = talloc(ctx, struct security_descriptor);
	if (!*sd)
		return WERR_NOMEM;

	data.data = sk.sec_desc;
	data.length = sk.rec_size;
	if (NT_STATUS_IS_ERR(ndr_pull_struct_blob(&data, ctx, *sd, (ndr_pull_flags_fn_t)ndr_pull_security_descriptor))) {
		DEBUG(0, ("Error parsing security descriptor\n"));
		return WERR_GENERAL_FAILURE;
	}

	talloc_free(tdr);

	return WERR_OK;
}

static uint32_t lf_add_entry (struct regf_data *regf, uint32_t list_offset, const char *name, uint32_t key_offset)
{
	uint32_t ret;
	struct lf_block lf;
	struct tdr_pull *pull = NULL;
	struct tdr_push *push;

	/* Add to subkeys list */
	if (list_offset == -1) { /* Need to create subkeys list */
		lf.header = "lf";
		lf.key_count = 0;
		lf.hr = NULL;
	} else {
		DATA_BLOB data;
		pull = talloc(regf, struct tdr_pull);

		data = hbin_get_data(regf, list_offset);
		if (!data.data) {
			DEBUG(0, ("Can't get subkeys list\n"));
			talloc_free(pull);
			return -1;
		}

		if (NT_STATUS_IS_ERR(tdr_pull_lf_block(pull, &lf))) {
			DEBUG(0, ("Unable to parse lf list\n"));
			talloc_free(pull);
			return -1;
		}
	}

	lf.hr = talloc_realloc(pull, lf.hr, struct hash_record, lf.key_count+1);
	lf.hr[lf.key_count].nk_off = key_offset;
	lf.hr[lf.key_count].hash = name;

	push = talloc_zero(regf, struct tdr_push);

	if (NT_STATUS_IS_ERR(tdr_push_lf_block(push, &lf))) {
		DEBUG(0, ("Error storing lf block\n"));
		return -1;
	}

	ret = hbin_store_resize (regf, list_offset, push->data);

	talloc_free(push);
	talloc_free(pull);
	
	return ret;
}

static WERROR regf_add_key (TALLOC_CTX *ctx, struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *sec_desc, struct registry_key **ret)
{
	struct nk_block *parent_nk = parent->backend_data, nk;
	DATA_BLOB data;
	struct tdr_push *push;
	uint32_t offset;

	nk.header = "nk";
	nk.type = REG_SUB_KEY;
	unix_to_nt_time(&nk.last_change, time(NULL));
	nk.uk1 = 0;
	nk.parent_offset = 0; /* FIXME */
	nk.num_subkeys = 0;
	nk.uk2 = 0;
	nk.subkeys_offset = -1;
	nk.unknown_offset = -1;
	nk.num_values = 0;
	nk.sk_offset = 0;
	memset(nk.unk3, 0, 5);
	nk.clsname_offset = -1;
	nk.clsname_length = 0;
	nk.key_name = name;
	
	push = talloc_zero(ctx, struct tdr_push);
	if (NT_STATUS_IS_ERR(tdr_push_nk_block(push, &nk))) {
		DEBUG(0, ("Error storing 'nk' block\n"));
		return WERR_GENERAL_FAILURE;
	}

	offset = hbin_store(parent->hive->backend_data, push->data);

	parent_nk->subkeys_offset = lf_add_entry(parent->hive->backend_data, parent_nk->subkeys_offset, name, nk.parent_offset);

	parent_nk->num_subkeys++;

	ZERO_STRUCTP(push);

	if (NT_STATUS_IS_ERR(tdr_push_nk_block(push, parent_nk))) {
		DEBUG(0, ("Error storing parent 'nk' block\n"));
		return WERR_GENERAL_FAILURE;
	}

	data = hbin_get_data(parent->hive->backend_data, nk.parent_offset);
	memcpy(data.data, push->data.data, push->data.length);

	talloc_free(push);

	/* FIXME: Set sec desc ! */

	*ret = regf_get_key(ctx, parent->hive->backend_data, offset);
	return WERR_OK;
}

static WERROR nt_open_hive (struct registry_hive *h, struct registry_key **key)
{
	struct regf_data *regf;
	struct regf_hdr *regf_hdr;
	struct tdr_pull *pull;
	int i;

	regf = (struct regf_data *)talloc_zero(h, struct regf_data);
	h->backend_data = regf;

	DEBUG(5, ("Attempting to load registry file\n"));

	/* Get the header */

	regf->data.data = (uint8_t *)file_load(h->location, &regf->data.length, regf);
	if (regf->data.data == NULL) {
		DEBUG(0,("Could not load file: %s, %s\n", h->location,
				 strerror(errno)));
		return WERR_GENERAL_FAILURE;
	}

	pull = talloc_zero(regf, struct tdr_pull);
	if (!pull)
		return WERR_NOMEM;

	pull->data = regf->data;

	regf_hdr = talloc(regf, struct regf_hdr);
	if (NT_STATUS_IS_ERR(tdr_pull_regf_hdr(pull, regf_hdr))) {
		return WERR_GENERAL_FAILURE;
	}

	if (strcmp(regf_hdr->REGF_ID, "regf") != 0) {
		DEBUG(0, ("Unrecognized NT registry header id: %s, %s\n",
				  regf_hdr->REGF_ID, h->location));
	}

	DEBUG(1, ("Registry '%s' read. Version %d.%d.%d.%d\n", 
			  regf_hdr->description, regf_hdr->version.major,
			  regf_hdr->version.minor, regf_hdr->version.release,
			  regf_hdr->version.build));

	/*
	 * Validate the header ...
	 */
	if (regf_hdr_checksum(regf->data.data) != regf_hdr->chksum) {
		DEBUG(0, ("Registry file checksum error: %s: %d,%d\n",
				  h->location, regf_hdr->chksum, regf_hdr_checksum(regf->data.data)));
		return WERR_GENERAL_FAILURE;
	}

	pull->offset = 0x1000;

	i = 0;
	/* Read in all hbin blocks */
	regf->hbins = talloc_array(regf, struct hbin_block *, 1);
	regf->hbins[0] = NULL;

	while (pull->offset < pull->data.length) {
		struct hbin_block *hbin = talloc(regf->hbins, struct hbin_block);

		if (NT_STATUS_IS_ERR(tdr_pull_hbin_block(pull, hbin))) {
			DEBUG(0, ("[%d] Error parsing HBIN block\n", i));
			return WERR_FOOBAR;
		}

		if (strcmp(hbin->HBIN_ID, "hbin") != 0) {
			DEBUG(0, ("[%d] Expected 'hbin', got '%s'\n", i, hbin->HBIN_ID));
			return WERR_FOOBAR;
		}

		regf->hbins[i] = hbin;
		i++;
		regf->hbins = talloc_realloc(regf, regf->hbins, struct hbin_block *, i+2);
		regf->hbins[i] = NULL;
	} 

	DEBUG(1, ("%d HBIN blocks read\n", i));

	*key = regf_get_key(h, regf, 0x20);

	return WERR_OK;
}

static struct hive_operations reg_backend_nt4 = {
	.name = "nt4",
	.open_hive = nt_open_hive,
	.num_subkeys = regf_num_subkeys,
	.num_values = regf_num_values,
	.get_subkey_by_index = regf_get_subkey,
	.get_value_by_index = regf_get_value,
	.key_get_sec_desc = regf_get_sec_desc,
	.add_key = regf_add_key,
};

NTSTATUS registry_nt4_init(void)
{
	return registry_register(&reg_backend_nt4);
}
