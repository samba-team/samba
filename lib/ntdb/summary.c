 /*
   Trivial Database 2: human-readable summary code
   Copyright (C) Rusty Russell 2010

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "private.h"
#include <assert.h>
#include <ccan/tally/tally.h>

#define SUMMARY_FORMAT \
	"Size of file/data: %zu/%zu\n" \
	"Number of records: %zu\n" \
	"Smallest/average/largest keys: %zu/%zu/%zu\n%s" \
	"Smallest/average/largest data: %zu/%zu/%zu\n%s" \
	"Smallest/average/largest padding: %zu/%zu/%zu\n%s" \
	"Number of free records: %zu\n" \
	"Smallest/average/largest free records: %zu/%zu/%zu\n%s" \
	"Number of uncoalesced records: %zu\n" \
	"Smallest/average/largest uncoalesced runs: %zu/%zu/%zu\n%s" \
	"Toplevel hash used: %u of %u\n" \
	"Number of chains: %zu\n" \
	"Number of subhashes: %zu\n" \
	"Smallest/average/largest subhash entries: %zu/%zu/%zu\n%s" \
	"Percentage keys/data/padding/free/rechdrs/freehdrs/hashes: %.0f/%.0f/%.0f/%.0f/%.0f/%.0f/%.0f\n"

#define BUCKET_SUMMARY_FORMAT_A					\
	"Free bucket %zu: total entries %zu.\n"			\
	"Smallest/average/largest length: %zu/%zu/%zu\n%s"
#define BUCKET_SUMMARY_FORMAT_B					\
	"Free bucket %zu-%zu: total entries %zu.\n"		\
	"Smallest/average/largest length: %zu/%zu/%zu\n%s"
#define CAPABILITY_FORMAT					\
	"Capability %llu%s\n"

#define HISTO_WIDTH 70
#define HISTO_HEIGHT 20

static ntdb_off_t count_hash(struct ntdb_context *ntdb,
			    ntdb_off_t hash_off, unsigned bits)
{
	const ntdb_off_t *h;
	ntdb_off_t count = 0;
	unsigned int i;

	h = ntdb_access_read(ntdb, hash_off, sizeof(*h) << bits, true);
	if (NTDB_PTR_IS_ERR(h)) {
		return NTDB_ERR_TO_OFF(NTDB_PTR_ERR(h));
	}
	for (i = 0; i < (1 << bits); i++)
		count += (h[i] != 0);

	ntdb_access_release(ntdb, h);
	return count;
}

static enum NTDB_ERROR summarize(struct ntdb_context *ntdb,
				struct tally *hashes,
				struct tally *ftables,
				struct tally *fr,
				struct tally *keys,
				struct tally *data,
				struct tally *extra,
				struct tally *uncoal,
				struct tally *chains,
				size_t *num_caps)
{
	ntdb_off_t off;
	ntdb_len_t len;
	ntdb_len_t unc = 0;

	for (off = sizeof(struct ntdb_header);
	     off < ntdb->file->map_size;
	     off += len) {
		const union {
			struct ntdb_used_record u;
			struct ntdb_free_record f;
			struct ntdb_recovery_record r;
		} *p;
		/* We might not be able to get the whole thing. */
		p = ntdb_access_read(ntdb, off, sizeof(p->f), true);
		if (NTDB_PTR_IS_ERR(p)) {
			return NTDB_PTR_ERR(p);
		}
		if (frec_magic(&p->f) != NTDB_FREE_MAGIC) {
			if (unc > 1) {
				tally_add(uncoal, unc);
				unc = 0;
			}
		}

		if (p->r.magic == NTDB_RECOVERY_INVALID_MAGIC
		    || p->r.magic == NTDB_RECOVERY_MAGIC) {
			len = sizeof(p->r) + p->r.max_len;
		} else if (frec_magic(&p->f) == NTDB_FREE_MAGIC) {
			len = frec_len(&p->f);
			tally_add(fr, len);
			len += sizeof(p->u);
			unc++;
		} else if (rec_magic(&p->u) == NTDB_USED_MAGIC) {
			len = sizeof(p->u)
				+ rec_key_length(&p->u)
				+ rec_data_length(&p->u)
				+ rec_extra_padding(&p->u);

			tally_add(keys, rec_key_length(&p->u));
			tally_add(data, rec_data_length(&p->u));
			tally_add(extra, rec_extra_padding(&p->u));
		} else if (rec_magic(&p->u) == NTDB_HTABLE_MAGIC) {
			ntdb_off_t count = count_hash(ntdb,
						     off + sizeof(p->u),
						     NTDB_SUBLEVEL_HASH_BITS);
			if (NTDB_OFF_IS_ERR(count)) {
				return NTDB_OFF_TO_ERR(count);
			}
			tally_add(hashes, count);
			tally_add(extra, rec_extra_padding(&p->u));
			len = sizeof(p->u)
				+ rec_data_length(&p->u)
				+ rec_extra_padding(&p->u);
		} else if (rec_magic(&p->u) == NTDB_FTABLE_MAGIC) {
			len = sizeof(p->u)
				+ rec_data_length(&p->u)
				+ rec_extra_padding(&p->u);
			tally_add(ftables, rec_data_length(&p->u));
			tally_add(extra, rec_extra_padding(&p->u));
		} else if (rec_magic(&p->u) == NTDB_CHAIN_MAGIC) {
			len = sizeof(p->u)
				+ rec_data_length(&p->u)
				+ rec_extra_padding(&p->u);
			tally_add(chains, 1);
			tally_add(extra, rec_extra_padding(&p->u));
		} else if (rec_magic(&p->u) == NTDB_CAP_MAGIC) {
			len = sizeof(p->u)
				+ rec_data_length(&p->u)
				+ rec_extra_padding(&p->u);
			(*num_caps)++;
		} else {
			len = dead_space(ntdb, off);
			if (NTDB_OFF_IS_ERR(len)) {
				return NTDB_OFF_TO_ERR(len);
			}
		}
		ntdb_access_release(ntdb, p);
	}
	if (unc)
		tally_add(uncoal, unc);
	return NTDB_SUCCESS;
}

static void add_capabilities(struct ntdb_context *ntdb, char *summary)
{
	ntdb_off_t off, next;
	const struct ntdb_capability *cap;
	size_t count = 0;

	/* Append to summary. */
	summary += strlen(summary);

	off = ntdb_read_off(ntdb, offsetof(struct ntdb_header, capabilities));
	if (NTDB_OFF_IS_ERR(off))
		return;

	/* Walk capability list. */
	for (; off; off = next) {
		cap = ntdb_access_read(ntdb, off, sizeof(*cap), true);
		if (NTDB_PTR_IS_ERR(cap)) {
			break;
		}
		count++;
		sprintf(summary, CAPABILITY_FORMAT,
			cap->type & NTDB_CAP_TYPE_MASK,
			/* Noopen?  How did we get here? */
			(cap->type & NTDB_CAP_NOOPEN) ? " (unopenable)"
			: ((cap->type & NTDB_CAP_NOWRITE)
			   && (cap->type & NTDB_CAP_NOCHECK)) ? " (uncheckable,read-only)"
			: (cap->type & NTDB_CAP_NOWRITE) ? " (read-only)"
			: (cap->type & NTDB_CAP_NOCHECK) ? " (uncheckable)"
			: "");
		summary += strlen(summary);
		next = cap->next;
		ntdb_access_release(ntdb, cap);
	}
}

_PUBLIC_ enum NTDB_ERROR ntdb_summary(struct ntdb_context *ntdb,
			   enum ntdb_summary_flags flags,
			   char **summary)
{
	ntdb_len_t len;
	size_t num_caps = 0;
	struct tally *ftables, *hashes, *freet, *keys, *data, *extra, *uncoal,
		*chains;
	char *hashesg, *freeg, *keysg, *datag, *extrag, *uncoalg;
	enum NTDB_ERROR ecode;

	hashesg = freeg = keysg = datag = extrag = uncoalg = NULL;

	ecode = ntdb_allrecord_lock(ntdb, F_RDLCK, NTDB_LOCK_WAIT, false);
	if (ecode != NTDB_SUCCESS) {
		return ecode;
	}

	ecode = ntdb_lock_expand(ntdb, F_RDLCK);
	if (ecode != NTDB_SUCCESS) {
		ntdb_allrecord_unlock(ntdb, F_RDLCK);
		return ecode;
	}

	/* Start stats off empty. */
	ftables = tally_new(HISTO_HEIGHT);
	hashes = tally_new(HISTO_HEIGHT);
	freet = tally_new(HISTO_HEIGHT);
	keys = tally_new(HISTO_HEIGHT);
	data = tally_new(HISTO_HEIGHT);
	extra = tally_new(HISTO_HEIGHT);
	uncoal = tally_new(HISTO_HEIGHT);
	chains = tally_new(HISTO_HEIGHT);
	if (!ftables || !hashes || !freet || !keys || !data || !extra
	    || !uncoal || !chains) {
		ecode = ntdb_logerr(ntdb, NTDB_ERR_OOM, NTDB_LOG_ERROR,
				   "ntdb_summary: failed to allocate"
				   " tally structures");
		goto unlock;
	}

	ecode = summarize(ntdb, hashes, ftables, freet, keys, data, extra,
			  uncoal, chains, &num_caps);
	if (ecode != NTDB_SUCCESS) {
		goto unlock;
	}

	if (flags & NTDB_SUMMARY_HISTOGRAMS) {
		hashesg = tally_histogram(hashes, HISTO_WIDTH, HISTO_HEIGHT);
		freeg = tally_histogram(freet, HISTO_WIDTH, HISTO_HEIGHT);
		keysg = tally_histogram(keys, HISTO_WIDTH, HISTO_HEIGHT);
		datag = tally_histogram(data, HISTO_WIDTH, HISTO_HEIGHT);
		extrag = tally_histogram(extra, HISTO_WIDTH, HISTO_HEIGHT);
		uncoalg = tally_histogram(uncoal, HISTO_WIDTH, HISTO_HEIGHT);
	}

	/* 20 is max length of a %llu. */
	len = strlen(SUMMARY_FORMAT) + 33*20 + 1
		+ (hashesg ? strlen(hashesg) : 0)
		+ (freeg ? strlen(freeg) : 0)
		+ (keysg ? strlen(keysg) : 0)
		+ (datag ? strlen(datag) : 0)
		+ (extrag ? strlen(extrag) : 0)
		+ (uncoalg ? strlen(uncoalg) : 0)
		+ num_caps * (strlen(CAPABILITY_FORMAT) + 20
			      + strlen(" (uncheckable,read-only)"));

	*summary = malloc(len);
	if (!*summary) {
		ecode = ntdb_logerr(ntdb, NTDB_ERR_OOM, NTDB_LOG_ERROR,
				   "ntdb_summary: failed to allocate string");
		goto unlock;
	}

	sprintf(*summary, SUMMARY_FORMAT,
		(size_t)ntdb->file->map_size,
		tally_total(keys, NULL) + tally_total(data, NULL),
		tally_num(keys),
		tally_min(keys), tally_mean(keys), tally_max(keys),
		keysg ? keysg : "",
		tally_min(data), tally_mean(data), tally_max(data),
		datag ? datag : "",
		tally_min(extra), tally_mean(extra), tally_max(extra),
		extrag ? extrag : "",
		tally_num(freet),
		tally_min(freet), tally_mean(freet), tally_max(freet),
		freeg ? freeg : "",
		tally_total(uncoal, NULL),
		tally_min(uncoal), tally_mean(uncoal), tally_max(uncoal),
		uncoalg ? uncoalg : "",
		(unsigned)count_hash(ntdb, offsetof(struct ntdb_header,
						   hashtable),
				     NTDB_TOPLEVEL_HASH_BITS),
		1 << NTDB_TOPLEVEL_HASH_BITS,
		tally_num(chains),
		tally_num(hashes),
		tally_min(hashes), tally_mean(hashes), tally_max(hashes),
		hashesg ? hashesg : "",
		tally_total(keys, NULL) * 100.0 / ntdb->file->map_size,
		tally_total(data, NULL) * 100.0 / ntdb->file->map_size,
		tally_total(extra, NULL) * 100.0 / ntdb->file->map_size,
		tally_total(freet, NULL) * 100.0 / ntdb->file->map_size,
		(tally_num(keys) + tally_num(freet) + tally_num(hashes))
		* sizeof(struct ntdb_used_record) * 100.0 / ntdb->file->map_size,
		tally_num(ftables) * sizeof(struct ntdb_freetable)
		* 100.0 / ntdb->file->map_size,
		(tally_num(hashes)
		 * (sizeof(ntdb_off_t) << NTDB_SUBLEVEL_HASH_BITS)
		 + (sizeof(ntdb_off_t) << NTDB_TOPLEVEL_HASH_BITS)
		 + sizeof(struct ntdb_chain) * tally_num(chains))
		* 100.0 / ntdb->file->map_size);

	add_capabilities(ntdb, *summary);

unlock:
	free(hashesg);
	free(freeg);
	free(keysg);
	free(datag);
	free(extrag);
	free(uncoalg);
	free(hashes);
	free(freet);
	free(keys);
	free(data);
	free(extra);
	free(uncoal);
	free(ftables);
	free(chains);

	ntdb_allrecord_unlock(ntdb, F_RDLCK);
	ntdb_unlock_expand(ntdb, F_RDLCK);
	return ecode;
}
