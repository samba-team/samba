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
#include "lib/registry/tdr_regf.h"

/*
 * Read HBIN blocks into memory
 */

struct regf_data {
	DATA_BLOB data;
	struct hbin_block **hbins;
};

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

static DATA_BLOB regf_get_data(const struct regf_data *data, uint32_t offset)
{
	int i;
	DATA_BLOB ret;
	ret.data = NULL;
	ret.length = 0;
	
	for (i = 0; data->hbins[i]; i++) {
		if (offset >= data->hbins[i]->offset_from_first && 
			offset < data->hbins[i]->offset_from_first+
					 data->hbins[i]->offset_to_next)
			break;
	}

	if (data->hbins[i] == NULL) {
		DEBUG(1, ("Can't find HBIN containing 0x%4x\n", offset));
		return ret;
	}

	ret.length = IVAL(data->hbins[i]->data, 
			offset - data->hbins[i]->offset_from_first - 0x20);
	if (ret.length & 0x80000000) {
		/* absolute value */
		ret.length = (ret.length ^ 0xffffffff) + 1;
	}
	ret.data = data->hbins[i]->data + 
		(offset - data->hbins[i]->offset_from_first - 0x20) + 4;
	
	return ret;
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
	DATA_BLOB data = regf_get_data(regf, offset);
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

	data = regf_get_data(key->hive->backend_data, nk->values_offset);
	if (!data.data) {
		DEBUG(0, ("Unable to find value list\n"));
		return WERR_GENERAL_FAILURE;
	}

	if (data.length < nk->num_values * 4) {
		DEBUG(1, ("Value counts mismatch\n"));
	}

	vk_offset = IVAL(data.data, idx * 4);

	data = regf_get_data(key->hive->backend_data, vk_offset);
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
		(*ret)->data = regf_get_data(key->hive->backend_data, vk->data_offset);
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

	data = regf_get_data(key->hive->backend_data, nk->subkeys_offset);
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
};

NTSTATUS registry_nt4_init(void)
{
	return registry_register(&reg_backend_nt4);
}
