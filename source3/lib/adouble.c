/*
 * Samba AppleDouble helpers
 *
 * Copyright (C) Ralph Boehme, 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "adouble.h"
#include "MacExtensions.h"
#include "string_replace.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "libcli/security/security.h"
#include "lib/util_macstreams.h"
#include "auth.h"

/*
   "._" AppleDouble Header File Layout:

         MAGIC          0x00051607
         VERSION        0x00020000
         FILLER         0
         COUNT          2
     .-- AD ENTRY[0]    Finder Info Entry (must be first)
  .--+-- AD ENTRY[1]    Resource Fork Entry (must be last)
  |  |   /////////////
  |  '-> FINDER INFO    Fixed Size Data (32 Bytes)
  |      ~~~~~~~~~~~~~  2 Bytes Padding
  |      EXT ATTR HDR   Fixed Size Data (36 Bytes)
  |      /////////////
  |      ATTR ENTRY[0] --.
  |      ATTR ENTRY[1] --+--.
  |      ATTR ENTRY[2] --+--+--.
  |         ...          |  |  |
  |      ATTR ENTRY[N] --+--+--+--.
  |      ATTR DATA 0   <-'  |  |  |
  |      ////////////       |  |  |
  |      ATTR DATA 1   <----'  |  |
  |      /////////////         |  |
  |      ATTR DATA 2   <-------'  |
  |      /////////////            |
  |         ...                   |
  |      ATTR DATA N   <----------'
  |      /////////////
  |         ...          Attribute Free Space
  |
  '----> RESOURCE FORK
            ...          Variable Sized Data
            ...
*/

/* Number of actually used entries */
#define ADEID_NUM_XATTR      8
#define ADEID_NUM_DOT_UND    2
#define ADEID_NUM_RSRC_XATTR 1

/* Sizes of relevant entry bits */
#define ADEDLEN_MAGIC       4
#define ADEDLEN_VERSION     4
#define ADEDLEN_FILLER      16
#define AD_FILLER_TAG       "Netatalk        " /* should be 16 bytes */
#define AD_FILLER_TAG_OSX   "Mac OS X        " /* should be 16 bytes */
#define ADEDLEN_NENTRIES    2
#define AD_HEADER_LEN       (ADEDLEN_MAGIC + ADEDLEN_VERSION + \
			     ADEDLEN_FILLER + ADEDLEN_NENTRIES) /* 26 */
#define AD_ENTRY_LEN_EID    4
#define AD_ENTRY_LEN_OFF    4
#define AD_ENTRY_LEN_LEN    4
#define AD_ENTRY_LEN (AD_ENTRY_LEN_EID + AD_ENTRY_LEN_OFF + AD_ENTRY_LEN_LEN)

/* Offsets */
#define ADEDOFF_MAGIC         0
#define ADEDOFF_VERSION       (ADEDOFF_MAGIC + ADEDLEN_MAGIC)
#define ADEDOFF_FILLER        (ADEDOFF_VERSION + ADEDLEN_VERSION)
#define ADEDOFF_NENTRIES      (ADEDOFF_FILLER + ADEDLEN_FILLER)

#define ADEDOFF_FINDERI_XATTR    (AD_HEADER_LEN + \
				  (ADEID_NUM_XATTR * AD_ENTRY_LEN))
#define ADEDOFF_COMMENT_XATTR    (ADEDOFF_FINDERI_XATTR    + ADEDLEN_FINDERI)
#define ADEDOFF_FILEDATESI_XATTR (ADEDOFF_COMMENT_XATTR    + ADEDLEN_COMMENT)
#define ADEDOFF_AFPFILEI_XATTR   (ADEDOFF_FILEDATESI_XATTR + \
				  ADEDLEN_FILEDATESI)
#define ADEDOFF_PRIVDEV_XATTR    (ADEDOFF_AFPFILEI_XATTR   + ADEDLEN_AFPFILEI)
#define ADEDOFF_PRIVINO_XATTR    (ADEDOFF_PRIVDEV_XATTR    + ADEDLEN_PRIVDEV)
#define ADEDOFF_PRIVSYN_XATTR    (ADEDOFF_PRIVINO_XATTR    + ADEDLEN_PRIVINO)
#define ADEDOFF_PRIVID_XATTR     (ADEDOFF_PRIVSYN_XATTR    + ADEDLEN_PRIVSYN)

#define ADEDOFF_FINDERI_DOT_UND  (AD_HEADER_LEN + \
				  (ADEID_NUM_DOT_UND * AD_ENTRY_LEN))
#define ADEDOFF_RFORK_DOT_UND    (ADEDOFF_FINDERI_DOT_UND + ADEDLEN_FINDERI)

#define AD_DATASZ_XATTR (AD_HEADER_LEN + \
			 (ADEID_NUM_XATTR * AD_ENTRY_LEN) + \
			 ADEDLEN_FINDERI + ADEDLEN_COMMENT + \
			 ADEDLEN_FILEDATESI + ADEDLEN_AFPFILEI + \
			 ADEDLEN_PRIVDEV + ADEDLEN_PRIVINO + \
			 ADEDLEN_PRIVSYN + ADEDLEN_PRIVID)

#if AD_DATASZ_XATTR != 402
#error bad size for AD_DATASZ_XATTR
#endif

#define AD_DATASZ_DOT_UND (AD_HEADER_LEN + \
			   (ADEID_NUM_DOT_UND * AD_ENTRY_LEN) + \
			   ADEDLEN_FINDERI)
#if AD_DATASZ_DOT_UND != 82
#error bad size for AD_DATASZ_DOT_UND
#endif

#define AD_XATTR_HDR_MAGIC    0x41545452 /* 'ATTR' */
#define AD_XATTR_MAX_ENTRIES  1024 /* Some arbitrarily enforced limit */
#define AD_XATTR_HDR_SIZE     36
#define AD_XATTR_MAX_HDR_SIZE 65536
#define ADX_ENTRY_FIXED_SIZE  (4+4+2+1)

/*
 * Both struct ad_xattr_header and struct ad_xattr_entry describe the in memory
 * representation as well as the on-disk format.
 *
 * The ad_xattr_header follows the FinderInfo data in the FinderInfo entry if
 * the length of the FinderInfo entry is larger then 32 bytes. It is then
 * preceeded with 2 bytes padding.
 *
 * Cf: https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/vfs/vfs_xattr.c
 */

struct ad_xattr_header {
	uint32_t adx_magic;        /* ATTR_HDR_MAGIC */
	uint32_t adx_debug_tag;    /* for debugging == file id of owning file */
	uint32_t adx_total_size;   /* file offset of end of attribute header + entries + data */
	uint32_t adx_data_start;   /* file offset to attribute data area */
	uint32_t adx_data_length;  /* length of attribute data area */
	uint32_t adx_reserved[3];
	uint16_t adx_flags;
	uint16_t adx_num_attrs;
};

/* On-disk entries are aligned on 4 byte boundaries */
struct ad_xattr_entry {
	uint32_t adx_offset;    /* file offset to data */
	uint32_t adx_length;    /* size of attribute data */
	uint16_t adx_flags;
	uint8_t  adx_namelen;	/* included the NULL terminator */
	char    *adx_name;      /* NULL-terminated UTF-8 name */
};

struct ad_entry {
	size_t ade_off;
	size_t ade_len;
};

struct adouble {
	files_struct             *ad_fsp;
	bool                      ad_opened;
	adouble_type_t            ad_type;
	uint32_t                  ad_magic;
	uint32_t                  ad_version;
	uint8_t                   ad_filler[ADEDLEN_FILLER];
	struct ad_entry           ad_eid[ADEID_MAX];
	char                     *ad_data;
	char                     *ad_rsrc_data;
	struct ad_xattr_header    adx_header;
	struct ad_xattr_entry    *adx_entries;
	char                     *adx_data;
};

struct ad_entry_order {
	uint32_t id, offset, len;
};

/* Netatalk AppleDouble metadata xattr */
static const
struct ad_entry_order entry_order_meta_xattr[ADEID_NUM_XATTR + 1] = {
	{ADEID_FINDERI,    ADEDOFF_FINDERI_XATTR,    ADEDLEN_FINDERI},
	{ADEID_COMMENT,    ADEDOFF_COMMENT_XATTR,    0},
	{ADEID_FILEDATESI, ADEDOFF_FILEDATESI_XATTR, ADEDLEN_FILEDATESI},
	{ADEID_AFPFILEI,   ADEDOFF_AFPFILEI_XATTR,   ADEDLEN_AFPFILEI},
	{ADEID_PRIVDEV,    ADEDOFF_PRIVDEV_XATTR,    0},
	{ADEID_PRIVINO,    ADEDOFF_PRIVINO_XATTR,    0},
	{ADEID_PRIVSYN,    ADEDOFF_PRIVSYN_XATTR,    0},
	{ADEID_PRIVID,     ADEDOFF_PRIVID_XATTR,     0},
	{0, 0, 0}
};

/* AppleDouble resource fork file (the ones prefixed by "._") */
static const
struct ad_entry_order entry_order_dot_und[ADEID_NUM_DOT_UND + 1] = {
	{ADEID_FINDERI,    ADEDOFF_FINDERI_DOT_UND,  ADEDLEN_FINDERI},
	{ADEID_RFORK,      ADEDOFF_RFORK_DOT_UND,    0},
	{0, 0, 0}
};

/* Conversion from enumerated id to on-disk AppleDouble id */
#define AD_EID_DISK(a) (set_eid[a])
static const uint32_t set_eid[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	AD_DEV, AD_INO, AD_SYN, AD_ID
};

static char empty_resourcefork[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E,
	0x54, 0x68, 0x69, 0x73, 0x20, 0x72, 0x65, 0x73,
	0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x66, 0x6F,
	0x72, 0x6B, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6E,
	0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x6C, 0x79,
	0x20, 0x6C, 0x65, 0x66, 0x74, 0x20, 0x62, 0x6C,
	0x61, 0x6E, 0x6B, 0x20, 0x20, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1E,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x1C, 0x00, 0x1E, 0xFF, 0xFF
};

size_t ad_getentrylen(const struct adouble *ad, int eid)
{
	return ad->ad_eid[eid].ade_len;
}

size_t ad_getentryoff(const struct adouble *ad, int eid)
{
	return ad->ad_eid[eid].ade_off;
}

size_t ad_setentrylen(struct adouble *ad, int eid, size_t len)
{
	return ad->ad_eid[eid].ade_len = len;
}

size_t ad_setentryoff(struct adouble *ad, int eid, size_t off)
{
	return ad->ad_eid[eid].ade_off = off;
}

/*
 * All entries besides FinderInfo and resource fork must fit into the
 * buffer. FinderInfo is special as it may be larger then the default 32 bytes
 * if it contains marshalled xattrs, which we will fixup that in
 * ad_convert(). The first 32 bytes however must also be part of the buffer.
 *
 * The resource fork is never accessed directly by the ad_data buf.
 */
static bool ad_entry_check_size(uint32_t eid,
				size_t bufsize,
				uint32_t off,
				uint32_t got_len)
{
	struct {
		off_t expected_len;
		bool fixed_size;
		bool minimum_size;
	} ad_checks[] = {
		[ADEID_DFORK] = {-1, false, false}, /* not applicable */
		[ADEID_RFORK] = {-1, false, false}, /* no limit */
		[ADEID_NAME] = {ADEDLEN_NAME, false, false},
		[ADEID_COMMENT] = {ADEDLEN_COMMENT, false, false},
		[ADEID_ICONBW] = {ADEDLEN_ICONBW, true, false},
		[ADEID_ICONCOL] = {ADEDLEN_ICONCOL, false, false},
		[ADEID_FILEI] = {ADEDLEN_FILEI, true, false},
		[ADEID_FILEDATESI] = {ADEDLEN_FILEDATESI, true, false},
		[ADEID_FINDERI] = {ADEDLEN_FINDERI, false, true},
		[ADEID_MACFILEI] = {ADEDLEN_MACFILEI, true, false},
		[ADEID_PRODOSFILEI] = {ADEDLEN_PRODOSFILEI, true, false},
		[ADEID_MSDOSFILEI] = {ADEDLEN_MSDOSFILEI, true, false},
		[ADEID_SHORTNAME] = {ADEDLEN_SHORTNAME, false, false},
		[ADEID_AFPFILEI] = {ADEDLEN_AFPFILEI, true, false},
		[ADEID_DID] = {ADEDLEN_DID, true, false},
		[ADEID_PRIVDEV] = {ADEDLEN_PRIVDEV, true, false},
		[ADEID_PRIVINO] = {ADEDLEN_PRIVINO, true, false},
		[ADEID_PRIVSYN] = {ADEDLEN_PRIVSYN, true, false},
		[ADEID_PRIVID] = {ADEDLEN_PRIVID, true, false},
	};

	if (eid >= ADEID_MAX) {
		return false;
	}
	if (got_len == 0) {
		/* Entry present, but empty, allow */
		return true;
	}
	if (ad_checks[eid].expected_len == 0) {
		/*
		 * Shouldn't happen: implicitly initialized to zero because
		 * explicit initializer missing.
		 */
		return false;
	}
	if (ad_checks[eid].expected_len == -1) {
		/* Unused or no limit */
		return true;
	}
	if (ad_checks[eid].fixed_size) {
		if (ad_checks[eid].expected_len != got_len) {
			/* Wrong size fo fixed size entry. */
			return false;
		}
	} else {
		if (ad_checks[eid].minimum_size) {
			if (got_len < ad_checks[eid].expected_len) {
				/*
				 * Too small for variable sized entry with
				 * minimum size.
				 */
				return false;
			}
		} else {
			if (got_len > ad_checks[eid].expected_len) {
				/* Too big for variable sized entry. */
				return false;
			}
		}
	}
	if (off + got_len < off) {
		/* wrap around */
		return false;
	}
	if (off + got_len > bufsize) {
		/* overflow */
		return false;
	}
	return true;
}

/**
 * Return a pointer to an AppleDouble entry
 *
 * Returns NULL if the entry is not present
 **/
char *ad_get_entry(const struct adouble *ad, int eid)
{
	size_t bufsize = talloc_get_size(ad->ad_data);
	off_t off = ad_getentryoff(ad, eid);
	size_t len = ad_getentrylen(ad, eid);
	bool valid;

	valid = ad_entry_check_size(eid, bufsize, off, len);
	if (!valid) {
		return NULL;
	}

	if (off == 0 || len == 0) {
		return NULL;
	}

	return ad->ad_data + off;
}

/**
 * Get a date
 **/
int ad_getdate(const struct adouble *ad, unsigned int dateoff, uint32_t *date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);
	char *p = NULL;

	dateoff &= AD_DATE_MASK;
	p = ad_get_entry(ad, ADEID_FILEDATESI);
	if (p == NULL) {
		return -1;
	}

	if (dateoff > AD_DATE_ACCESS) {
	    return -1;
	}

	memcpy(date, p + dateoff, sizeof(uint32_t));

	if (xlate) {
		*date = AD_DATE_TO_UNIX(*date);
	}
	return 0;
}

/**
 * Set a date
 **/
int ad_setdate(struct adouble *ad, unsigned int dateoff, uint32_t date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);
	char *p = NULL;

	p = ad_get_entry(ad, ADEID_FILEDATESI);
	if (p == NULL) {
		return -1;
	}

	dateoff &= AD_DATE_MASK;
	if (xlate) {
		date = AD_DATE_FROM_UNIX(date);
	}

	if (dateoff > AD_DATE_ACCESS) {
		return -1;
	}

	memcpy(p + dateoff, &date, sizeof(date));

	return 0;
}


/**
 * Map on-disk AppleDouble id to enumerated id
 **/
static uint32_t get_eid(uint32_t eid)
{
	if (eid <= 15) {
		return eid;
	}

	switch (eid) {
	case AD_DEV:
		return ADEID_PRIVDEV;
	case AD_INO:
		return ADEID_PRIVINO;
	case AD_SYN:
		return ADEID_PRIVSYN;
	case AD_ID:
		return ADEID_PRIVID;
	default:
		break;
	}

	return 0;
}

/*
 * Move resourcefork data in an AppleDouble file
 *
 * This is supposed to make room in an AppleDouble file by moving the
 * resourcefork data behind the space required for packing additional xattr data
 * in the extended FinderInfo entry.
 *
 * When we're called we're expecting an AppleDouble file with just two entries
 * (FinderInfo an Resourcefork) and the resourcefork is expected at a fixed
 * offset of ADEDOFF_RFORK_DOT_UND.
 */
static bool ad_pack_move_reso(struct vfs_handle_struct *handle,
			      struct adouble *ad,
			      files_struct *fsp)
{
	size_t reso_len;
	size_t reso_off;
	size_t n;
	bool ok;

	reso_len = ad_getentrylen(ad, ADEID_RFORK);
	reso_off = ad_getentryoff(ad, ADEID_RFORK);

	if (reso_len == 0) {
		return true;
	}

	if (ad->ad_rsrc_data == NULL) {
		/*
		 * This buffer is already set when converting a resourcefork
		 * stream from vfs_streams_depot backend via ad_unconvert(). It
		 * is NULL with vfs_streams_xattr where the resourcefork stream
		 * is stored in an AppleDouble sidecar file vy vfs_fruit.
		 */
		ad->ad_rsrc_data = talloc_size(ad, reso_len);
		if (ad->ad_rsrc_data == NULL) {
			return false;
		}

		n = SMB_VFS_NEXT_PREAD(handle,
				       fsp,
				       ad->ad_rsrc_data,
				       reso_len,
				       ADEDOFF_RFORK_DOT_UND);
		if (n != reso_len) {
			DBG_ERR("Read on [%s] failed\n",
				fsp_str_dbg(fsp));
			ok = false;
			goto out;
		}
	}

	n = SMB_VFS_NEXT_PWRITE(handle,
				fsp,
				ad->ad_rsrc_data,
				reso_len,
				reso_off);
	if (n != reso_len) {
		DBG_ERR("Write on [%s] failed\n",
			fsp_str_dbg(fsp));
		ok = false;
		goto out;
	}

	ok = true;
out:
	return ok;
}

static bool ad_pack_xattrs(struct vfs_handle_struct *handle,
			   struct adouble *ad,
			   files_struct *fsp)
{
	struct ad_xattr_header *h = &ad->adx_header;
	size_t oldsize;
	uint32_t off;
	uint32_t data_off;
	uint16_t i;
	bool ok;

	if (ad->adx_entries == NULL) {
		/* No xattrs, nothing to pack */
		return true;
	}

	if (fsp == NULL) {
		DBG_ERR("fsp unexpectedly NULL\n");
		return false;
	}

	oldsize = talloc_get_size(ad->ad_data);
	if (oldsize < AD_XATTR_MAX_HDR_SIZE) {
		ad->ad_data = talloc_realloc(ad,
					     ad->ad_data,
					     char,
					     AD_XATTR_MAX_HDR_SIZE);
		if (ad->ad_data == NULL) {
			return false;
		}
		memset(ad->ad_data + oldsize,
		       0,
		       AD_XATTR_MAX_HDR_SIZE - oldsize);
	}

	/*
	 * First, let's calculate the start of the xattr data area which will be
	 * after the xattr header + header entries.
	 */

	data_off = ad_getentryoff(ad, ADEID_FINDERI);
	data_off += ADEDLEN_FINDERI + AD_XATTR_HDR_SIZE;
	/* 2 bytes padding */
	data_off += 2;

	for (i = 0; i < h->adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];

		/* Align on 4 byte boundary */
		data_off = (data_off + 3) & ~3;

		data_off += e->adx_namelen + ADX_ENTRY_FIXED_SIZE;
		if (data_off >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
	}

	off = ad_getentryoff(ad, ADEID_FINDERI);
	off +=  ADEDLEN_FINDERI + AD_XATTR_HDR_SIZE;
	/* 2 bytes padding */
	off += 2;

	for (i = 0; i < h->adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];

		/* Align on 4 byte boundary */
		off = (off + 3) & ~3;

		e->adx_offset = data_off;
		data_off += e->adx_length;

		DBG_DEBUG("%zu(%s){%zu}: off [%zu] adx_length [%zu] "
			  "adx_data_off [%zu]\n",
			  (size_t)i,
			  e->adx_name,
			  (size_t)e->adx_namelen,
			  (size_t)off,
			  (size_t)e->adx_length,
			  (size_t)e->adx_offset);

		if (off + 4 >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
		RSIVAL(ad->ad_data, off, e->adx_offset);
		off += 4;

		if (off + 4 >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
		RSIVAL(ad->ad_data, off, e->adx_length);
		off += 4;

		if (off + 2 >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
		RSSVAL(ad->ad_data, off, e->adx_flags);
		off += 2;

		if (off + 1 >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
		SCVAL(ad->ad_data, off, e->adx_namelen);
		off += 1;

		if (off + e->adx_namelen >= AD_XATTR_MAX_HDR_SIZE) {
			return false;
		}
		memcpy(ad->ad_data + off, e->adx_name, e->adx_namelen);
		off += e->adx_namelen;
	}

	h->adx_data_start = off;
	h->adx_data_length = talloc_get_size(ad->adx_data);
	h->adx_total_size = h->adx_data_start + h->adx_data_length;

	if (talloc_get_size(ad->ad_data) < h->adx_total_size) {
		ad->ad_data = talloc_realloc(ad,
					     ad->ad_data,
					     char,
					     h->adx_total_size);
		if (ad->ad_data == NULL) {
			return false;
		}
	}

	memcpy(ad->ad_data + h->adx_data_start,
	       ad->adx_data,
	       h->adx_data_length);

	ad_setentrylen(ad,
		       ADEID_FINDERI,
		       h->adx_total_size - ad_getentryoff(ad, ADEID_FINDERI));

	ad_setentryoff(ad,
		       ADEID_RFORK,
		       ad_getentryoff(ad, ADEID_FINDERI) +
		       ad_getentrylen(ad, ADEID_FINDERI));

	memcpy(ad->ad_data + ADEDOFF_FILLER, AD_FILLER_TAG_OSX, ADEDLEN_FILLER);

	/*
	 * Rewind, then update the header fields.
	 */

	off = ad_getentryoff(ad, ADEID_FINDERI) + ADEDLEN_FINDERI;
	/* 2 bytes padding */
	off += 2;

	RSIVAL(ad->ad_data, off, AD_XATTR_HDR_MAGIC);
	off += 4;
	RSIVAL(ad->ad_data, off, 0);
	off += 4;
	RSIVAL(ad->ad_data, off, h->adx_total_size);
	off += 4;
	RSIVAL(ad->ad_data, off, h->adx_data_start);
	off += 4;
	RSIVAL(ad->ad_data, off, h->adx_data_length);
	off += 4;

	/* adx_reserved and adx_flags */
	memset(ad->ad_data + off, 0, 3 * 4 + 2);
	off += 3 * 4 + 2;

	RSSVAL(ad->ad_data, off, h->adx_num_attrs);
	off += 2;

	ok = ad_pack_move_reso(handle, ad, fsp);
	if (!ok) {
		DBG_ERR("Moving resourcefork of [%s] failed\n",
			fsp_str_dbg(fsp));
		return false;
	}

	return true;
}

/**
 * Pack AppleDouble structure into data buffer
 **/
static bool ad_pack(struct vfs_handle_struct *handle,
		    struct adouble *ad,
		    files_struct *fsp)
{
	uint32_t       eid;
	uint16_t       nent;
	uint32_t       bufsize;
	uint32_t       offset = 0;
	bool ok;

	bufsize = talloc_get_size(ad->ad_data);
	if (bufsize < AD_DATASZ_DOT_UND) {
		DBG_ERR("bad buffer size [0x%" PRIx32 "]\n", bufsize);
		return false;
	}

	if (offset + ADEDLEN_MAGIC < offset ||
			offset + ADEDLEN_MAGIC >= bufsize) {
		return false;
	}
	RSIVAL(ad->ad_data, offset, ad->ad_magic);
	offset += ADEDLEN_MAGIC;

	if (offset + ADEDLEN_VERSION < offset ||
			offset + ADEDLEN_VERSION >= bufsize) {
		return false;
	}
	RSIVAL(ad->ad_data, offset, ad->ad_version);
	offset += ADEDLEN_VERSION;

	if (offset + ADEDLEN_FILLER < offset ||
			offset + ADEDLEN_FILLER >= bufsize) {
		return false;
	}
	if (ad->ad_type == ADOUBLE_RSRC) {
		memcpy(ad->ad_data + offset, AD_FILLER_TAG, ADEDLEN_FILLER);
	}
	offset += ADEDLEN_FILLER;

	if (offset + ADEDLEN_NENTRIES < offset ||
			offset + ADEDLEN_NENTRIES >= bufsize) {
		return false;
	}
	offset += ADEDLEN_NENTRIES;

	ok = ad_pack_xattrs(handle, ad, fsp);
	if (!ok) {
		return false;
	}

	for (eid = 0, nent = 0; eid < ADEID_MAX; eid++) {
		if (ad->ad_eid[eid].ade_off == 0) {
			/*
			 * ade_off is also used as indicator whether a
			 * specific entry is used or not
			 */
			continue;
		}

		if (offset + AD_ENTRY_LEN_EID < offset ||
				offset + AD_ENTRY_LEN_EID >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, AD_EID_DISK(eid));
		offset += AD_ENTRY_LEN_EID;

		if (offset + AD_ENTRY_LEN_OFF < offset ||
				offset + AD_ENTRY_LEN_OFF >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, ad->ad_eid[eid].ade_off);
		offset += AD_ENTRY_LEN_OFF;

		if (offset + AD_ENTRY_LEN_LEN < offset ||
				offset + AD_ENTRY_LEN_LEN >= bufsize) {
			return false;
		}
		RSIVAL(ad->ad_data, offset, ad->ad_eid[eid].ade_len);
		offset += AD_ENTRY_LEN_LEN;

		nent++;
	}

	if (ADEDOFF_NENTRIES + 2 >= bufsize) {
		return false;
	}
	RSSVAL(ad->ad_data, ADEDOFF_NENTRIES, nent);

	return true;
}

static bool ad_unpack_xattrs(struct adouble *ad)
{
	struct ad_xattr_header *h = &ad->adx_header;
	size_t bufsize = talloc_get_size(ad->ad_data);
	const char *p = ad->ad_data;
	uint32_t hoff;
	uint32_t i;

	if (ad->ad_type != ADOUBLE_RSRC) {
		return false;
	}

	if (ad_getentrylen(ad, ADEID_FINDERI) <= ADEDLEN_FINDERI) {
		return true;
	}

	/*
	 * Ensure the buffer ad->ad_data was allocated by ad_alloc() for an
	 * ADOUBLE_RSRC type (._ AppleDouble file on-disk).
	 */
	if (bufsize != AD_XATTR_MAX_HDR_SIZE) {
		return false;
	}

	/* 2 bytes padding */
	hoff = ad_getentryoff(ad, ADEID_FINDERI) + ADEDLEN_FINDERI + 2;

	h->adx_magic       = RIVAL(p, hoff + 0);
	h->adx_debug_tag   = RIVAL(p, hoff + 4); /* Not used -> not checked */
	h->adx_total_size  = RIVAL(p, hoff + 8);
	h->adx_data_start  = RIVAL(p, hoff + 12);
	h->adx_data_length = RIVAL(p, hoff + 16);
	h->adx_flags       = RSVAL(p, hoff + 32); /* Not used -> not checked */
	h->adx_num_attrs   = RSVAL(p, hoff + 34);

	if (h->adx_magic != AD_XATTR_HDR_MAGIC) {
		DBG_ERR("Bad magic: 0x%" PRIx32 "\n", h->adx_magic);
		return false;
	}

	if (h->adx_total_size > ad_getentryoff(ad, ADEID_RFORK)) {
		DBG_ERR("Bad total size: 0x%" PRIx32 "\n", h->adx_total_size);
		return false;
	}
	if (h->adx_total_size > AD_XATTR_MAX_HDR_SIZE) {
		DBG_ERR("Bad total size: 0x%" PRIx32 "\n", h->adx_total_size);
		return false;
	}

	if (h->adx_data_start < (hoff + AD_XATTR_HDR_SIZE)) {
		DBG_ERR("Bad start: 0x%" PRIx32 "\n", h->adx_data_start);
		return false;
	}

	if ((h->adx_data_start + h->adx_data_length) < h->adx_data_start) {
		DBG_ERR("Bad length: %" PRIu32 "\n", h->adx_data_length);
		return false;
	}
	if ((h->adx_data_start + h->adx_data_length) >
	    ad->adx_header.adx_total_size)
	{
		DBG_ERR("Bad length: %" PRIu32 "\n", h->adx_data_length);
		return false;
	}

	if (h->adx_num_attrs > AD_XATTR_MAX_ENTRIES) {
		DBG_ERR("Bad num xattrs: %" PRIu16 "\n", h->adx_num_attrs);
		return false;
	}

	if (h->adx_num_attrs == 0) {
		return true;
	}

	ad->adx_entries = talloc_zero_array(
		ad, struct ad_xattr_entry, h->adx_num_attrs);
	if (ad->adx_entries == NULL) {
		return false;
	}

	hoff += AD_XATTR_HDR_SIZE;

	for (i = 0; i < h->adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];

		hoff = (hoff + 3) & ~3;

		e->adx_offset  = RIVAL(p, hoff + 0);
		e->adx_length  = RIVAL(p, hoff + 4);
		e->adx_flags   = RSVAL(p, hoff + 8);
		e->adx_namelen = *(p + hoff + 10);

		if (e->adx_offset >= ad->adx_header.adx_total_size) {
			DBG_ERR("Bad adx_offset: %" PRIx32 "\n",
				e->adx_offset);
			return false;
		}

		if ((e->adx_offset + e->adx_length) < e->adx_offset) {
			DBG_ERR("Bad adx_length: %" PRIx32 "\n",
				e->adx_length);
			return false;
		}

		if ((e->adx_offset + e->adx_length) >
		    ad->adx_header.adx_total_size)
		{
			DBG_ERR("Bad adx_length: %" PRIx32 "\n",
				e->adx_length);
			return false;
		}

		if (e->adx_namelen == 0) {
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}
		if ((hoff + 11 + e->adx_namelen) < hoff + 11) {
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}
		if ((hoff + 11 + e->adx_namelen) >
		    ad->adx_header.adx_data_start)
		{
			DBG_ERR("Bad adx_namelen: %" PRIx32 "\n",
				e->adx_namelen);
			return false;
		}

		e->adx_name = talloc_strndup(ad->adx_entries,
					     p + hoff + 11,
					     e->adx_namelen);
		if (e->adx_name == NULL) {
			return false;
		}

		DBG_DEBUG("xattr [%s] offset [0x%x] size [0x%x]\n",
			  e->adx_name, e->adx_offset, e->adx_length);
		dump_data(10, (uint8_t *)(ad->ad_data + e->adx_offset),
			  e->adx_length);

		hoff += 11 + e->adx_namelen;
	}

	return true;
}

/**
 * Unpack an AppleDouble blob into a struct adoble
 **/
static bool ad_unpack(struct adouble *ad, const size_t nentries,
		      size_t filesize)
{
	size_t bufsize = talloc_get_size(ad->ad_data);
	size_t adentries, i;
	uint32_t eid, len, off;
	bool ok;

	/*
	 * The size of the buffer ad->ad_data is checked when read, so
	 * we wouldn't have to check our own offsets, a few extra
	 * checks won't hurt though. We have to check the offsets we
	 * read from the buffer anyway.
	 */

	if (bufsize < (AD_HEADER_LEN + (AD_ENTRY_LEN * nentries))) {
		DEBUG(1, ("bad size\n"));
		return false;
	}

	ad->ad_magic = RIVAL(ad->ad_data, 0);
	ad->ad_version = RIVAL(ad->ad_data, ADEDOFF_VERSION);
	if ((ad->ad_magic != AD_MAGIC) || (ad->ad_version != AD_VERSION)) {
		DEBUG(1, ("wrong magic or version\n"));
		return false;
	}

	memcpy(ad->ad_filler, ad->ad_data + ADEDOFF_FILLER, ADEDLEN_FILLER);

	adentries = RSVAL(ad->ad_data, ADEDOFF_NENTRIES);
	if (adentries != nentries) {
		DEBUG(1, ("invalid number of entries: %zu\n",
			  adentries));
		return false;
	}

	/* now, read in the entry bits */
	for (i = 0; i < adentries; i++) {
		eid = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN));
		eid = get_eid(eid);
		off = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 4);
		len = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 8);

		if (!eid || eid >= ADEID_MAX) {
			DEBUG(1, ("bogus eid %d\n", eid));
			return false;
		}

		/*
		 * All entries other than the resource fork are
		 * expected to be read into the ad_data buffer, so
		 * ensure the specified offset is within that bound
		 */
		if ((off > bufsize) && (eid != ADEID_RFORK)) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		ok = ad_entry_check_size(eid, bufsize, off, len);
		if (!ok) {
			DBG_ERR("bogus eid [%"PRIu32"] bufsize [%zu] "
				"off [%"PRIu32"] len [%"PRIu32"]\n",
				eid, bufsize, off, len);
			return false;
		}

		/*
		 * That would be obviously broken
		 */
		if (off > filesize) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		/*
		 * Check for any entry that has its end beyond the
		 * filesize.
		 */
		if (off + len < off) {
			DEBUG(1, ("offset wrap in eid %d: off: %" PRIu32
				  ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;

		}
		if (off + len > filesize) {
			/*
			 * If this is the resource fork entry, we fix
			 * up the length, for any other entry we bail
			 * out.
			 */
			if (eid != ADEID_RFORK) {
				DEBUG(1, ("bogus eid %d: off: %" PRIu32
					  ", len: %" PRIu32 "\n",
					  eid, off, len));
				return false;
			}

			/*
			 * Fixup the resource fork entry by limiting
			 * the size to entryoffset - filesize.
			 */
			len = filesize - off;
			DEBUG(1, ("Limiting ADEID_RFORK: off: %" PRIu32
				  ", len: %" PRIu32 "\n", off, len));
		}

		ad->ad_eid[eid].ade_off = off;
		ad->ad_eid[eid].ade_len = len;
	}

	if (ad->ad_type == ADOUBLE_RSRC) {
		ok = ad_unpack_xattrs(ad);
		if (!ok) {
			return false;
		}
	}

	return true;
}

static bool ad_convert_move_reso(vfs_handle_struct *handle,
				 struct adouble *ad,
				 const struct smb_filename *smb_fname)
{
	char *buf = NULL;
	size_t rforklen;
	size_t rforkoff;
	ssize_t n;
	int ret;

	rforklen = ad_getentrylen(ad, ADEID_RFORK);
	if (rforklen == 0) {
		return true;
	}

	buf = talloc_size(ad, rforklen);
	if (buf == NULL) {
		/*
		 * This allocates a buffer for reading the resource fork data in
		 * one big swoop. Resource forks won't be larger then, say, 64
		 * MB, I swear, so just doing the allocation with the talloc
		 * limit as safeguard seems safe.
		 */
		DBG_ERR("Failed to allocate %zu bytes for rfork\n",
			rforklen);
		return false;
	}

	rforkoff = ad_getentryoff(ad, ADEID_RFORK);

	n = SMB_VFS_PREAD(ad->ad_fsp, buf, rforklen, rforkoff);
	if (n != rforklen) {
		DBG_ERR("Reading %zu bytes from rfork [%s] failed: %s\n",
			rforklen, fsp_str_dbg(ad->ad_fsp), strerror(errno));
		return false;
	}

	rforkoff = ADEDOFF_RFORK_DOT_UND;

	n = SMB_VFS_PWRITE(ad->ad_fsp, buf, rforklen, rforkoff);
	if (n != rforklen) {
		DBG_ERR("Writing %zu bytes to rfork [%s] failed: %s\n",
			rforklen, fsp_str_dbg(ad->ad_fsp), strerror(errno));
		return false;
	}

	ad_setentryoff(ad, ADEID_RFORK, ADEDOFF_RFORK_DOT_UND);

	ret = ad_fset(handle, ad, ad->ad_fsp);
	if (ret != 0) {
		DBG_ERR("ad_fset on [%s] failed\n", fsp_str_dbg(ad->ad_fsp));
		return false;
	}

	return true;
}

static bool ad_convert_xattr(vfs_handle_struct *handle,
			     struct adouble *ad,
			     const struct smb_filename *smb_fname,
			     const char *catia_mappings,
			     bool *converted_xattr)
{
	static struct char_mappings **string_replace_cmaps = NULL;
	uint16_t i;
	int saved_errno = 0;
	NTSTATUS status;
	int rc;
	bool ok;

	*converted_xattr = false;

	if (ad_getentrylen(ad, ADEID_FINDERI) == ADEDLEN_FINDERI) {
		return true;
	}

	if (string_replace_cmaps == NULL) {
		const char **mappings = NULL;

		mappings = str_list_make_v3_const(
			talloc_tos(), catia_mappings, NULL);
		if (mappings == NULL) {
			return false;
		}
		string_replace_cmaps = string_replace_init_map(
			handle->conn->sconn, mappings);
		TALLOC_FREE(mappings);
	}

	for (i = 0; i < ad->adx_header.adx_num_attrs; i++) {
		struct ad_xattr_entry *e = &ad->adx_entries[i];
		char *mapped_name = NULL;
		char *tmp = NULL;
		struct smb_filename *stream_name = NULL;
		files_struct *fsp = NULL;
		ssize_t nwritten;

		status = string_replace_allocate(handle->conn,
						 e->adx_name,
						 string_replace_cmaps,
						 talloc_tos(),
						 &mapped_name,
						 vfs_translate_to_windows);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED))
		{
			DBG_ERR("string_replace_allocate failed\n");
			ok = false;
			goto fail;
		}

		tmp = mapped_name;
		mapped_name = talloc_asprintf(talloc_tos(), ":%s", tmp);
		TALLOC_FREE(tmp);
		if (mapped_name == NULL) {
			ok = false;
			goto fail;
		}

		stream_name = synthetic_smb_fname(talloc_tos(),
						  smb_fname->base_name,
						  mapped_name,
						  NULL,
						  smb_fname->twrp,
						  smb_fname->flags);
		TALLOC_FREE(mapped_name);
		if (stream_name == NULL) {
			DBG_ERR("synthetic_smb_fname failed\n");
			ok = false;
			goto fail;
		}

		DBG_DEBUG("stream_name: %s\n", smb_fname_str_dbg(stream_name));

		status = SMB_VFS_CREATE_FILE(
			handle->conn,			/* conn */
			NULL,				/* req */
			&handle->conn->cwd_fsp,		/* dirfsp */
			stream_name,			/* fname */
			FILE_GENERIC_WRITE,		/* access_mask */
			FILE_SHARE_READ | FILE_SHARE_WRITE, /* share_access */
			FILE_OPEN_IF,			/* create_disposition */
			0,				/* create_options */
			0,				/* file_attributes */
			INTERNAL_OPEN_ONLY,		/* oplock_request */
			NULL,				/* lease */
			0,				/* allocation_size */
			0,				/* private_flags */
			NULL,				/* sd */
			NULL,				/* ea_list */
			&fsp,				/* result */
			NULL,				/* psbuf */
			NULL, NULL);			/* create context */
		TALLOC_FREE(stream_name);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("SMB_VFS_CREATE_FILE failed\n");
			ok = false;
			goto fail;
		}

		nwritten = SMB_VFS_PWRITE(fsp,
					  ad->ad_data + e->adx_offset,
					  e->adx_length,
					  0);
		if (nwritten == -1) {
			DBG_ERR("SMB_VFS_PWRITE failed\n");
			saved_errno = errno;
			close_file(NULL, fsp, ERROR_CLOSE);
			errno = saved_errno;
			ok = false;
			goto fail;
		}

		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			ok = false;
			goto fail;
		}
		fsp = NULL;
	}

	ad->adx_header.adx_num_attrs = 0;
	TALLOC_FREE(ad->adx_entries);

	ad_setentrylen(ad, ADEID_FINDERI, ADEDLEN_FINDERI);

	rc = ad_fset(handle, ad, ad->ad_fsp);
	if (rc != 0) {
		DBG_ERR("ad_fset on [%s] failed: %s\n",
			fsp_str_dbg(ad->ad_fsp), strerror(errno));
		ok = false;
		goto fail;
	}

	ok = ad_convert_move_reso(handle, ad, smb_fname);
	if (!ok) {
		goto fail;
	}

	*converted_xattr = true;
	ok = true;

fail:
	return ok;
}

static bool ad_convert_finderinfo(vfs_handle_struct *handle,
				  struct adouble *ad,
				  const struct smb_filename *smb_fname)
{
	char *p_ad = NULL;
	AfpInfo *ai = NULL;
	DATA_BLOB aiblob;
	struct smb_filename *stream_name = NULL;
	files_struct *fsp = NULL;
	size_t size;
	ssize_t nwritten;
	NTSTATUS status;
	int saved_errno = 0;
	int cmp;

	cmp = memcmp(ad->ad_filler, AD_FILLER_TAG_OSX, ADEDLEN_FILLER);
	if (cmp != 0) {
		return true;
	}

	p_ad = ad_get_entry(ad, ADEID_FINDERI);
	if (p_ad == NULL) {
		return false;
	}

	ai = afpinfo_new(talloc_tos());
	if (ai == NULL) {
		return false;
	}

	memcpy(ai->afpi_FinderInfo, p_ad, ADEDLEN_FINDERI);

	aiblob = data_blob_talloc(talloc_tos(), NULL, AFP_INFO_SIZE);
	if (aiblob.data == NULL) {
		TALLOC_FREE(ai);
		return false;
	}

	size = afpinfo_pack(ai, (char *)aiblob.data);
	TALLOC_FREE(ai);
	if (size != AFP_INFO_SIZE) {
		return false;
	}

	stream_name = synthetic_smb_fname(talloc_tos(),
					  smb_fname->base_name,
					  AFPINFO_STREAM,
					  NULL,
					  smb_fname->twrp,
					  smb_fname->flags);
	if (stream_name == NULL) {
		data_blob_free(&aiblob);
		DBG_ERR("synthetic_smb_fname failed\n");
		return false;
	}

	DBG_DEBUG("stream_name: %s\n", smb_fname_str_dbg(stream_name));

	status = SMB_VFS_CREATE_FILE(
		handle->conn,			/* conn */
		NULL,				/* req */
		&handle->conn->cwd_fsp,		/* dirfsp */
		stream_name,			/* fname */
		FILE_GENERIC_WRITE,		/* access_mask */
		FILE_SHARE_READ | FILE_SHARE_WRITE, /* share_access */
		FILE_OPEN_IF,			/* create_disposition */
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,				/* result */
		NULL,				/* psbuf */
		NULL, NULL);			/* create context */
	TALLOC_FREE(stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE failed\n");
		return false;
	}

	nwritten = SMB_VFS_PWRITE(fsp,
				  aiblob.data,
				  aiblob.length,
				  0);
	if (nwritten == -1) {
		DBG_ERR("SMB_VFS_PWRITE failed\n");
		saved_errno = errno;
		close_file(NULL, fsp, ERROR_CLOSE);
		errno = saved_errno;
		return false;
	}

	status = close_file(NULL, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	fsp = NULL;

	return true;
}

static bool ad_convert_truncate(vfs_handle_struct *handle,
				struct adouble *ad,
				const struct smb_filename *smb_fname)
{
	int rc;
	off_t newlen;

	newlen = ADEDOFF_RFORK_DOT_UND + ad_getentrylen(ad, ADEID_RFORK);

	rc = SMB_VFS_FTRUNCATE(ad->ad_fsp, newlen);
	if (rc != 0) {
		return false;
	}

	return true;
}

static bool ad_convert_blank_rfork(vfs_handle_struct *handle,
				   struct adouble *ad,
				   uint32_t flags,
				   bool *blank)
{
	size_t rforklen = sizeof(empty_resourcefork);
	char buf[rforklen];
	ssize_t nread;
	int cmp;
	int rc;

	*blank = false;

	if (!(flags & AD_CONV_WIPE_BLANK)) {
		return true;
	}

	if (ad_getentrylen(ad, ADEID_RFORK) != rforklen) {
		return true;
	}

	nread = SMB_VFS_PREAD(ad->ad_fsp, buf, rforklen, ADEDOFF_RFORK_DOT_UND);
	if (nread != rforklen) {
		DBG_ERR("Reading %zu bytes from rfork [%s] failed: %s\n",
			rforklen, fsp_str_dbg(ad->ad_fsp), strerror(errno));
		return false;
	}

	cmp = memcmp(buf, empty_resourcefork, rforklen);
	if (cmp != 0) {
		return true;
	}

	ad_setentrylen(ad, ADEID_RFORK, 0);

	rc = ad_fset(handle, ad, ad->ad_fsp);
	if (rc != 0) {
		DBG_ERR("ad_fset on [%s] failed\n", fsp_str_dbg(ad->ad_fsp));
		return false;
	}

	*blank = true;
	return true;
}

static bool ad_convert_delete_adfile(vfs_handle_struct *handle,
				struct adouble *ad,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t flags)
{
	struct smb_filename *ad_name = NULL;
	int rc;

	if (ad_getentrylen(ad, ADEID_RFORK) > 0) {
		return true;
	}

	if (!(flags & AD_CONV_DELETE)) {
		return true;
	}

	rc = adouble_path(talloc_tos(), smb_fname, &ad_name);
	if (rc != 0) {
		return false;
	}

	rc = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			ad_name,
			0);
	if (rc != 0) {
		DBG_ERR("Unlinking [%s] failed: %s\n",
			smb_fname_str_dbg(ad_name), strerror(errno));
		TALLOC_FREE(ad_name);
		return false;
	}

	DBG_WARNING("Unlinked [%s] after conversion\n", smb_fname_str_dbg(ad_name));
	TALLOC_FREE(ad_name);

	return true;
}

/**
 * Convert from Apple's ._ file to Netatalk
 *
 * Apple's AppleDouble may contain a FinderInfo entry longer then 32
 * bytes containing packed xattrs.
 *
 * @return -1 in case an error occurred, 0 if no conversion was done, 1
 * otherwise
 **/
int ad_convert(struct vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		const char *catia_mappings,
		uint32_t flags)
{
	struct adouble *ad = NULL;
	bool ok;
	bool converted_xattr = false;
	bool blank;
	int ret;

	ad = ad_get(talloc_tos(), handle, smb_fname, ADOUBLE_RSRC);
	if (ad == NULL) {
		return 0;
	}

	ok = ad_convert_xattr(handle,
			      ad,
			      smb_fname,
			      catia_mappings,
			      &converted_xattr);
	if (!ok) {
		ret = -1;
		goto done;
	}

	ok = ad_convert_blank_rfork(handle, ad, flags, &blank);
	if (!ok) {
		ret = -1;
		goto done;
	}

	if (converted_xattr || blank) {
		ok = ad_convert_truncate(handle, ad, smb_fname);
		if (!ok) {
			ret = -1;
			goto done;
		}
	}

	ok = ad_convert_finderinfo(handle, ad, smb_fname);
	if (!ok) {
		DBG_ERR("Failed to convert [%s]\n",
			smb_fname_str_dbg(smb_fname));
		ret = -1;
		goto done;
	}

	ok = ad_convert_delete_adfile(handle,
			ad,
			dirfsp,
			smb_fname,
			flags);
	if (!ok) {
		ret = -1;
		goto done;
	}

	ret = 0;
done:
	TALLOC_FREE(ad);
	return ret;
}

static bool ad_unconvert_open_ad(TALLOC_CTX *mem_ctx,
				 struct vfs_handle_struct *handle,
				 struct smb_filename *smb_fname,
				 struct smb_filename *adpath,
				 files_struct **_fsp)
{
	files_struct *fsp = NULL;
	NTSTATUS status;
	int ret;

	status = SMB_VFS_CREATE_FILE(
		handle->conn,
		NULL,				/* req */
		&handle->conn->cwd_fsp,		/* dirfsp */
		adpath,
		FILE_READ_DATA|FILE_WRITE_DATA,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,
		NULL,				/* info */
		NULL, NULL);			/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE [%s] failed: %s\n",
			smb_fname_str_dbg(adpath), nt_errstr(status));
		return false;
	}

	if (fsp->fsp_name->st.st_ex_uid != smb_fname->st.st_ex_uid ||
	    fsp->fsp_name->st.st_ex_gid != smb_fname->st.st_ex_gid)
	{
		ret = SMB_VFS_FCHOWN(fsp,
				     smb_fname->st.st_ex_uid,
				     smb_fname->st.st_ex_gid);
		if (ret != 0) {
			DBG_ERR("SMB_VFS_FCHOWN [%s] failed: %s\n",
				fsp_str_dbg(fsp), nt_errstr(status));
			close_file(NULL, fsp, NORMAL_CLOSE);
			return false;
		}
	}

	*_fsp = fsp;
	return true;
}

static bool ad_unconvert_get_streams(struct vfs_handle_struct *handle,
				     struct smb_filename *smb_fname,
				     TALLOC_CTX *mem_ctx,
				     unsigned int *num_streams,
				     struct stream_struct **streams)
{
	files_struct *fsp = NULL;
	NTSTATUS status;

	status = SMB_VFS_CREATE_FILE(
		handle->conn,				/* conn */
		NULL,					/* req */
		&handle->conn->cwd_fsp,			/* dirfsp */
		smb_fname,				/* fname */
		FILE_READ_ATTRIBUTES,			/* access_mask */
		(FILE_SHARE_READ | FILE_SHARE_WRITE |	/* share_access */
			FILE_SHARE_DELETE),
		FILE_OPEN,				/* create_disposition*/
		0,					/* create_options */
		0,					/* file_attributes */
		INTERNAL_OPEN_ONLY,			/* oplock_request */
		NULL,					/* lease */
		0,					/* allocation_size */
		0,					/* private_flags */
		NULL,					/* sd */
		NULL,					/* ea_list */
		&fsp,					/* result */
		NULL,					/* pinfo */
		NULL, NULL);				/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Opening [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		return false;
	}

	status = vfs_streaminfo(handle->conn,
				fsp,
				fsp->fsp_name,
				mem_ctx,
				num_streams,
				streams);
	if (!NT_STATUS_IS_OK(status)) {
		close_file(NULL, fsp, NORMAL_CLOSE);
		DBG_ERR("streaminfo on [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		return false;
	}

	status = close_file(NULL, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("close_file [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		return false;
	}

	return true;
}

struct ad_collect_state {
	bool have_adfile;
	size_t adx_data_off;
	char *rsrc_data_buf;
};

static bool ad_collect_one_stream(struct vfs_handle_struct *handle,
				  struct char_mappings **cmaps,
				  struct smb_filename *smb_fname,
				  const struct stream_struct *stream,
				  struct adouble *ad,
				  struct ad_collect_state *state)
{
	struct smb_filename *sname = NULL;
	files_struct *fsp = NULL;
	struct ad_xattr_entry *e = NULL;
	char *mapped_name = NULL;
	char *p = NULL;
	size_t needed_size;
	ssize_t nread;
	NTSTATUS status;
	int ret;
	bool ok;

	sname = synthetic_smb_fname(ad,
				    smb_fname->base_name,
				    stream->name,
				    NULL,
				    smb_fname->twrp,
				    0);
	if (sname == NULL) {
		return false;
	}

	if (is_ntfs_default_stream_smb_fname(sname)) {
		TALLOC_FREE(sname);
		return true;
	}

	DBG_DEBUG("Collecting stream [%s]\n", smb_fname_str_dbg(sname));

	ret = SMB_VFS_STAT(handle->conn, sname);
	if (ret != 0) {
		DBG_ERR("SMB_VFS_STAT [%s] failed\n", smb_fname_str_dbg(sname));
		ok = false;
		goto out;
	}

	status = SMB_VFS_CREATE_FILE(
		handle->conn,
		NULL,				/* req */
		&handle->conn->cwd_fsp,		/* dirfsp */
		sname,
		FILE_READ_DATA|DELETE_ACCESS,
		FILE_SHARE_READ,
		FILE_OPEN,
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,
		NULL,				/* info */
		NULL, NULL);			/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE [%s] failed\n",
			smb_fname_str_dbg(sname));
		ok = false;
		goto out;
	}

	if (is_afpinfo_stream(stream->name)) {
		char buf[AFP_INFO_SIZE];

		if (stream->size != AFP_INFO_SIZE) {
			DBG_ERR("Bad size [%zd] on [%s]\n",
				(ssize_t)stream->size,
				smb_fname_str_dbg(sname));
			ok = false;
			goto out;
		}

		nread = SMB_VFS_PREAD(fsp, buf, stream->size, 0);
		if (nread != AFP_INFO_SIZE) {
			DBG_ERR("Bad size [%zd] on [%s]\n",
				(ssize_t)stream->size,
				smb_fname_str_dbg(sname));
			ok = false;
			goto out;
		}

		memcpy(ad->ad_data + ADEDOFF_FINDERI_DOT_UND,
		       buf + AFP_OFF_FinderInfo,
		       AFP_FinderSize);

		ok = set_delete_on_close(fsp,
					 true,
					 fsp->conn->session_info->security_token,
					 fsp->conn->session_info->unix_token);
		if (!ok) {
			DBG_ERR("Deleting [%s] failed\n",
				smb_fname_str_dbg(sname));
			ok = false;
			goto out;
		}
		ok = true;
		goto out;
	}

	if (is_afpresource_stream(stream->name)) {
		ad->ad_rsrc_data = talloc_size(ad, stream->size);
		if (ad->ad_rsrc_data == NULL) {
			ok = false;
			goto out;
		}

		nread = SMB_VFS_PREAD(fsp,
				      ad->ad_rsrc_data,
				      stream->size,
				      0);
		if (nread != stream->size) {
			DBG_ERR("Bad size [%zd] on [%s]\n",
				(ssize_t)stream->size,
				smb_fname_str_dbg(sname));
			ok = false;
			goto out;
		}

		ad_setentrylen(ad, ADEID_RFORK, stream->size);

		if (!state->have_adfile) {
			/*
			 * We have a resource *stream* but no AppleDouble
			 * sidecar file, this means the share is configured with
			 * fruit:resource=stream. So we should delete the
			 * resource stream.
			 */
			ok = set_delete_on_close(
				fsp,
				true,
				fsp->conn->session_info->security_token,
				fsp->conn->session_info->unix_token);
			if (!ok) {
				DBG_ERR("Deleting [%s] failed\n",
					smb_fname_str_dbg(sname));
				ok = false;
				goto out;
			}
		}
		ok = true;
		goto out;
	}

	ad->adx_entries = talloc_realloc(ad,
					 ad->adx_entries,
					 struct ad_xattr_entry,
					 ad->adx_header.adx_num_attrs + 1);
	if (ad->adx_entries == NULL) {
		ok = false;
		goto out;
	}

	e = &ad->adx_entries[ad->adx_header.adx_num_attrs];
	*e = (struct ad_xattr_entry) {
		.adx_length = stream->size,
	};
	e->adx_name = talloc_strdup(ad, stream->name + 1);
	if (e->adx_name == NULL) {
		ok = false;
		goto out;
	}
	p = strchr(e->adx_name, ':');
	if (p != NULL) {
		*p = '\0';
	}

	status = string_replace_allocate(handle->conn,
					 e->adx_name,
					 cmaps,
					 ad,
					 &mapped_name,
					 vfs_translate_to_unix);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED))
	{
		DBG_ERR("string_replace_allocate failed\n");
		ok = false;
		goto out;
	}

	e->adx_name = mapped_name;
	e->adx_namelen = strlen(e->adx_name) + 1,

	DBG_DEBUG("%u: name (%s) size (%zu)\n",
		  ad->adx_header.adx_num_attrs,
		  e->adx_name,
		  (size_t)e->adx_length);

	ad->adx_header.adx_num_attrs++;

	needed_size = state->adx_data_off + stream->size;
	if (needed_size > talloc_get_size(ad->adx_data)) {
		ad->adx_data = talloc_realloc(ad,
					      ad->adx_data,
					      char,
					      needed_size);
		if (ad->adx_data == NULL) {
			ok = false;
			goto out;
		}
	}

	nread = SMB_VFS_PREAD(fsp,
			      ad->adx_data + state->adx_data_off,
			      stream->size,
			      0);
	if (nread != stream->size) {
		DBG_ERR("Bad size [%zd] on [%s]\n",
			(ssize_t)stream->size,
			smb_fname_str_dbg(sname));
		ok = false;
		goto out;
	}
	state->adx_data_off += nread;

	ok = set_delete_on_close(fsp,
				 true,
				 fsp->conn->session_info->security_token,
				 fsp->conn->session_info->unix_token);
	if (!ok) {
		DBG_ERR("Deleting [%s] failed\n",
			smb_fname_str_dbg(sname));
		ok = false;
		goto out;
	}

out:
	TALLOC_FREE(sname);
	if (fsp != NULL) {
		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("close_file [%s] failed: %s\n",
				smb_fname_str_dbg(smb_fname),
				nt_errstr(status));
			ok = false;
		}
	}

	return ok;
}

/**
 * Convert filesystem metadata to AppleDouble file
 **/
bool ad_unconvert(TALLOC_CTX *mem_ctx,
		  struct vfs_handle_struct *handle,
		  const char *catia_mappings,
		  struct smb_filename *smb_fname,
		  bool *converted)
{
	static struct char_mappings **cmaps = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	struct ad_collect_state state;
	struct stream_struct *streams = NULL;
	struct smb_filename *adpath = NULL;
	struct adouble *ad = NULL;
	unsigned int num_streams = 0;
	size_t to_convert = 0;
	bool have_rsrc = false;
	files_struct *fsp = NULL;
	size_t i;
	NTSTATUS status;
	int ret;
	bool ok;

	*converted = false;

	if (cmaps == NULL) {
		const char **mappings = NULL;

		mappings = str_list_make_v3_const(
			frame, catia_mappings, NULL);
		if (mappings == NULL) {
			ok = false;
			goto out;
		}
		cmaps = string_replace_init_map(mem_ctx, mappings);
		TALLOC_FREE(mappings);
	}

	ok = ad_unconvert_get_streams(handle,
				      smb_fname,
				      frame,
				      &num_streams,
				      &streams);
	if (!ok) {
		goto out;
	}

	for (i = 0; i < num_streams; i++) {
		if (strcasecmp_m(streams[i].name, "::$DATA") == 0) {
			continue;
		}
		to_convert++;
		if (is_afpresource_stream(streams[i].name)) {
			have_rsrc = true;
		}
	}

	if (to_convert == 0) {
		ok = true;
		goto out;
	}

	state = (struct ad_collect_state) {
		.adx_data_off = 0,
	};

	ret = adouble_path(frame, smb_fname, &adpath);
	if (ret != 0) {
		ok = false;
		goto out;
	}

	ret = SMB_VFS_STAT(handle->conn, adpath);
	if (ret == 0) {
		state.have_adfile = true;
	} else {
		if (errno != ENOENT) {
			ok = false;
			goto out;
		}
		state.have_adfile = false;
	}

	if (to_convert == 1 && have_rsrc && state.have_adfile) {
		/*
		 * So we have just a single stream, the resource fork stream
		 * from an AppleDouble file. Fine, that means there's nothing to
		 * convert.
		 */
		ok = true;
		goto out;
	}

	ad = ad_init(frame, ADOUBLE_RSRC);
	if (ad == NULL) {
		ok = false;
		goto out;
	}

	for (i = 0; i < num_streams; i++) {
		ok = ad_collect_one_stream(handle,
					   cmaps,
					   smb_fname,
					   &streams[i],
					   ad,
					   &state);
		if (!ok) {
			goto out;
		}
	}

	ok = ad_unconvert_open_ad(frame, handle, smb_fname, adpath, &fsp);
	if (!ok) {
		DBG_ERR("Failed to open adfile [%s]\n",
			smb_fname_str_dbg(smb_fname));
		goto out;
	}

	ret = ad_fset(handle, ad, fsp);
	if (ret != 0) {
		ok = false;
		goto out;
	}

	*converted = true;
	ok = true;

out:
	if (fsp != NULL) {
		status = close_file(NULL, fsp, NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("close_file [%s] failed: %s\n",
				smb_fname_str_dbg(smb_fname),
				nt_errstr(status));
			ok = false;
		}
	}
	TALLOC_FREE(frame);
	return ok;
}

/**
 * Read and parse Netatalk AppleDouble metadata xattr
 **/
static ssize_t ad_read_meta(vfs_handle_struct *handle,
			    struct adouble *ad,
			    const struct smb_filename *smb_fname)
{
	int      rc = 0;
	ssize_t  ealen;
	bool     ok;

	DEBUG(10, ("reading meta xattr for %s\n", smb_fname->base_name));

	ealen = SMB_VFS_GETXATTR(handle->conn, smb_fname,
				 AFPINFO_EA_NETATALK, ad->ad_data,
				 AD_DATASZ_XATTR);
	if (ealen == -1) {
		switch (errno) {
		case ENOATTR:
		case ENOENT:
			if (errno == ENOATTR) {
				errno = ENOENT;
			}
			rc = -1;
			goto exit;
		default:
			DEBUG(2, ("error reading meta xattr: %s\n",
				  strerror(errno)));
			rc = -1;
			goto exit;
		}
	}
	if (ealen != AD_DATASZ_XATTR) {
		DEBUG(2, ("bad size %zd\n", ealen));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

	/* Now parse entries */
	ok = ad_unpack(ad, ADEID_NUM_XATTR, AD_DATASZ_XATTR);
	if (!ok) {
		DEBUG(2, ("invalid AppleDouble metadata xattr\n"));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

	if (!ad_getentryoff(ad, ADEID_FINDERI)
	    || !ad_getentryoff(ad, ADEID_COMMENT)
	    || !ad_getentryoff(ad, ADEID_FILEDATESI)
	    || !ad_getentryoff(ad, ADEID_AFPFILEI)
	    || !ad_getentryoff(ad, ADEID_PRIVDEV)
	    || !ad_getentryoff(ad, ADEID_PRIVINO)
	    || !ad_getentryoff(ad, ADEID_PRIVSYN)
	    || !ad_getentryoff(ad, ADEID_PRIVID)) {
		DEBUG(2, ("invalid AppleDouble metadata xattr\n"));
		errno = EINVAL;
		rc = -1;
		goto exit;
	}

exit:
	DEBUG(10, ("reading meta xattr for %s, rc: %d\n",
		smb_fname->base_name, rc));

	if (rc != 0) {
		ealen = -1;
		if (errno == EINVAL) {
			become_root();
			(void)SMB_VFS_REMOVEXATTR(handle->conn,
						  smb_fname,
						  AFPINFO_EA_NETATALK);
			unbecome_root();
			errno = ENOENT;
		}
	}
	return ealen;
}

static int ad_open_rsrc(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			int flags,
			mode_t mode,
			files_struct **_fsp)
{
	int ret;
	struct smb_filename *adp_smb_fname = NULL;
	files_struct *fsp = NULL;
	uint32_t access_mask;
	uint32_t share_access;
	uint32_t create_disposition;
	NTSTATUS status;

	ret = adouble_path(talloc_tos(), smb_fname, &adp_smb_fname);
	if (ret != 0) {
		return -1;
	}

	ret = SMB_VFS_STAT(handle->conn, adp_smb_fname);
	if (ret != 0) {
		TALLOC_FREE(adp_smb_fname);
		return -1;
	}

	access_mask = FILE_GENERIC_READ;
	share_access = FILE_SHARE_READ | FILE_SHARE_WRITE;
	create_disposition = FILE_OPEN;

	if (flags & O_RDWR) {
		access_mask |= FILE_GENERIC_WRITE;
		share_access &= ~FILE_SHARE_WRITE;
	}

	status = SMB_VFS_CREATE_FILE(
		handle->conn,			/* conn */
		NULL,				/* req */
		&handle->conn->cwd_fsp,		/* dirfsp */
		adp_smb_fname,
		access_mask,
		share_access,
		create_disposition,
		0,				/* create_options */
		0,				/* file_attributes */
		INTERNAL_OPEN_ONLY,		/* oplock_request */
		NULL,				/* lease */
		0,				/* allocation_size */
		0,				/* private_flags */
		NULL,				/* sd */
		NULL,				/* ea_list */
		&fsp,
		NULL,				/* psbuf */
		NULL, NULL);			/* create context */
	TALLOC_FREE(adp_smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("SMB_VFS_CREATE_FILE failed\n");
		return -1;
	}

	*_fsp = fsp;
	return 0;
}

/*
 * Here's the deal: for ADOUBLE_META we can do without an fd as we can issue
 * path based xattr calls. For ADOUBLE_RSRC however we need a full-fledged fd
 * for file IO on the ._ file.
 */
static int ad_open(vfs_handle_struct *handle,
		   struct adouble *ad,
		   files_struct *fsp,
		   const struct smb_filename *smb_fname,
		   int flags,
		   mode_t mode)
{
	int ret;

	DBG_DEBUG("Path [%s] type [%s]\n", smb_fname->base_name,
		  ad->ad_type == ADOUBLE_META ? "meta" : "rsrc");

	if (ad->ad_type == ADOUBLE_META) {
		return 0;
	}

	if (fsp != NULL) {
		ad->ad_fsp = fsp;
		ad->ad_opened = false;
		return 0;
	}

	ret = ad_open_rsrc(handle, smb_fname, flags, mode, &ad->ad_fsp);
	if (ret != 0) {
		return -1;
	}
	ad->ad_opened = true;

	DBG_DEBUG("Path [%s] type [%s]\n",
		  smb_fname->base_name,
		  ad->ad_type == ADOUBLE_META ? "meta" : "rsrc");

	return 0;
}

static ssize_t ad_read_rsrc_adouble(vfs_handle_struct *handle,
				    struct adouble *ad,
				    const struct smb_filename *smb_fname)
{
	size_t to_read;
	ssize_t len;
	int ret;
	bool ok;

	ret = SMB_VFS_NEXT_FSTAT(handle, ad->ad_fsp, &ad->ad_fsp->fsp_name->st);
	if (ret != 0) {
		DBG_ERR("fstat [%s] failed: %s\n",
			fsp_str_dbg(ad->ad_fsp), strerror(errno));
		return -1;
	}

	to_read = ad->ad_fsp->fsp_name->st.st_ex_size;
	if (to_read > AD_XATTR_MAX_HDR_SIZE) {
		to_read = AD_XATTR_MAX_HDR_SIZE;
	}

	len = SMB_VFS_NEXT_PREAD(handle,
				 ad->ad_fsp,
				 ad->ad_data,
				 to_read,
				 0);
	if (len != to_read)  {
		DBG_NOTICE("%s %s: bad size: %zd\n",
			   smb_fname->base_name, strerror(errno), len);
		return -1;
	}

	/* Now parse entries */
	ok = ad_unpack(ad,
		       ADEID_NUM_DOT_UND,
		       ad->ad_fsp->fsp_name->st.st_ex_size);
	if (!ok) {
		DBG_ERR("invalid AppleDouble resource %s\n",
			smb_fname->base_name);
		errno = EINVAL;
		return -1;
	}

	if ((ad_getentryoff(ad, ADEID_FINDERI) != ADEDOFF_FINDERI_DOT_UND)
	    || (ad_getentrylen(ad, ADEID_FINDERI) < ADEDLEN_FINDERI)
	    || (ad_getentryoff(ad, ADEID_RFORK) < ADEDOFF_RFORK_DOT_UND))
	{
		DBG_ERR("invalid AppleDouble resource %s\n",
			smb_fname->base_name);
		errno = EINVAL;
		return -1;
	}

	return len;
}

/**
 * Read and parse resource fork, either ._ AppleDouble file or xattr
 **/
static ssize_t ad_read_rsrc(vfs_handle_struct *handle,
			    struct adouble *ad,
			    const struct smb_filename *smb_fname)
{
	return ad_read_rsrc_adouble(handle, ad, smb_fname);
}

/**
 * Read and unpack an AppleDouble metadata xattr or resource
 **/
static ssize_t ad_read(vfs_handle_struct *handle,
		       struct adouble *ad,
		       const struct smb_filename *smb_fname)
{
	switch (ad->ad_type) {
	case ADOUBLE_META:
		return ad_read_meta(handle, ad, smb_fname);
	case ADOUBLE_RSRC:
		return ad_read_rsrc(handle, ad, smb_fname);
	default:
		return -1;
	}
}

static int adouble_destructor(struct adouble *ad)
{
	NTSTATUS status;

	if (!ad->ad_opened) {
		return 0;
	}

	SMB_ASSERT(ad->ad_fsp != NULL);

	status = close_file(NULL, ad->ad_fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Closing [%s] failed: %s\n",
			fsp_str_dbg(ad->ad_fsp), nt_errstr(status));
	}

	return 0;
}

/**
 * Allocate a struct adouble without initialiing it
 *
 * The struct is either hang of the fsp extension context or if fsp is
 * NULL from ctx.
 *
 * @param[in] ctx        talloc context
 * @param[in] handle     vfs handle
 * @param[in] type       type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return               adouble handle
 **/
static struct adouble *ad_alloc(TALLOC_CTX *ctx,
				adouble_type_t type)
{
	int rc = 0;
	size_t adsize = 0;
	struct adouble *ad;

	switch (type) {
	case ADOUBLE_META:
		adsize = AD_DATASZ_XATTR;
		break;
	case ADOUBLE_RSRC:
		/*
		 * AppleDouble ._ file case, optimize for fewer (but larger)
		 * IOs. Two cases:
		 *
		 * - without xattrs size of the header is exactly
		 *   AD_DATASZ_DOT_UND (82) bytes
		 *
		 * - with embedded xattrs it can be larger, up to
		 *   AD_XATTR_MAX_HDR_SIZE
		 *
		 * Larger headers are not supported, but this is a reasonable
		 * limit that is also employed by the macOS client.
		 *
		 * We used the largest possible size to be able to read the full
		 * header with one IO.
		 */
		adsize = AD_XATTR_MAX_HDR_SIZE;
		break;
	default:
		return NULL;
	}

	ad = talloc_zero(ctx, struct adouble);
	if (ad == NULL) {
		rc = -1;
		goto exit;
	}

	if (adsize) {
		ad->ad_data = talloc_zero_array(ad, char, adsize);
		if (ad->ad_data == NULL) {
			rc = -1;
			goto exit;
		}
	}

	ad->ad_type = type;
	ad->ad_magic = AD_MAGIC;
	ad->ad_version = AD_VERSION;

	talloc_set_destructor(ad, adouble_destructor);

exit:
	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

/**
 * Allocate and initialize a new struct adouble
 *
 * @param[in] ctx        talloc context
 * @param[in] type       type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return               adouble handle, initialized
 **/
struct adouble *ad_init(TALLOC_CTX *ctx, adouble_type_t type)
{
	int rc = 0;
	const struct ad_entry_order  *eid;
	struct adouble *ad = NULL;
	time_t t = time(NULL);

	switch (type) {
	case ADOUBLE_META:
		eid = entry_order_meta_xattr;
		break;
	case ADOUBLE_RSRC:
		eid = entry_order_dot_und;
		break;
	default:
		return NULL;
	}

	ad = ad_alloc(ctx, type);
	if (ad == NULL) {
		return NULL;
	}

	while (eid->id) {
		ad->ad_eid[eid->id].ade_off = eid->offset;
		ad->ad_eid[eid->id].ade_len = eid->len;
		eid++;
	}

	/* put something sane in the date fields */
	ad_setdate(ad, AD_DATE_CREATE | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_MODIFY | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_ACCESS | AD_DATE_UNIX, t);
	ad_setdate(ad, AD_DATE_BACKUP, htonl(AD_DATE_START));

	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

static struct adouble *ad_get_internal(TALLOC_CTX *ctx,
				       vfs_handle_struct *handle,
				       files_struct *fsp,
				       const struct smb_filename *smb_fname,
				       adouble_type_t type)
{
	int rc = 0;
	ssize_t len;
	struct adouble *ad = NULL;
	int mode;

	if (fsp != NULL) {
		smb_fname = fsp->base_fsp->fsp_name;
	}

	DEBUG(10, ("ad_get(%s) called for %s\n",
		   type == ADOUBLE_META ? "meta" : "rsrc",
		   smb_fname != NULL ? smb_fname->base_name : "???"));

	ad = ad_alloc(ctx, type);
	if (ad == NULL) {
		rc = -1;
		goto exit;
	}

	/* Try rw first so we can use the fd in ad_convert() */
	mode = O_RDWR;

	rc = ad_open(handle, ad, fsp, smb_fname, mode, 0);
	if (rc == -1 && ((errno == EROFS) || (errno == EACCES))) {
		mode = O_RDONLY;
		rc = ad_open(handle, ad, fsp, smb_fname, mode, 0);
	}
	if (rc == -1) {
		DBG_DEBUG("ad_open [%s] error [%s]\n",
			  smb_fname->base_name, strerror(errno));
		goto exit;

	}

	len = ad_read(handle, ad, smb_fname);
	if (len == -1) {
		DEBUG(10, ("error reading AppleDouble for %s\n",
			smb_fname->base_name));
		rc = -1;
		goto exit;
	}

exit:
	DEBUG(10, ("ad_get(%s) for %s returning %d\n",
		  type == ADOUBLE_META ? "meta" : "rsrc",
		  smb_fname->base_name, rc));

	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

/**
 * Return AppleDouble data for a file
 *
 * @param[in] ctx      talloc context
 * @param[in] handle   vfs handle
 * @param[in] smb_fname pathname to file or directory
 * @param[in] type     type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return             talloced struct adouble or NULL on error
 **/
struct adouble *ad_get(TALLOC_CTX *ctx,
			      vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      adouble_type_t type)
{
	return ad_get_internal(ctx, handle, NULL, smb_fname, type);
}

/**
 * Return AppleDouble data for a file
 *
 * @param[in] ctx      talloc context
 * @param[in] handle   vfs handle
 * @param[in] fsp      fsp to use for IO
 * @param[in] type     type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return             talloced struct adouble or NULL on error
 **/
struct adouble *ad_fget(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			files_struct *fsp, adouble_type_t type)
{
	return ad_get_internal(ctx, handle, fsp, NULL, type);
}

/**
 * Set AppleDouble metadata on a file or directory
 *
 * @param[in] ad      adouble handle
 *
 * @param[in] smb_fname    pathname to file or directory
 *
 * @return            status code, 0 means success
 **/
int ad_set(vfs_handle_struct *handle,
	   struct adouble *ad,
	   const struct smb_filename *smb_fname)
{
	bool ok;
	int ret;

	DBG_DEBUG("Path [%s]\n", smb_fname->base_name);

	if (ad->ad_type != ADOUBLE_META) {
		DBG_ERR("ad_set on [%s] used with ADOUBLE_RSRC\n",
			smb_fname->base_name);
		return -1;
	}

	ok = ad_pack(handle, ad, NULL);
	if (!ok) {
		return -1;
	}

	ret = SMB_VFS_SETXATTR(handle->conn,
			       smb_fname,
			       AFPINFO_EA_NETATALK,
			       ad->ad_data,
			       AD_DATASZ_XATTR, 0);

	DBG_DEBUG("Path [%s] ret [%d]\n", smb_fname->base_name, ret);

	return ret;
}

/**
 * Set AppleDouble metadata on a file or directory
 *
 * @param[in] ad      adouble handle
 * @param[in] fsp     file handle
 *
 * @return            status code, 0 means success
 **/
int ad_fset(struct vfs_handle_struct *handle,
	    struct adouble *ad,
	    files_struct *fsp)
{
	int rc = -1;
	ssize_t len;
	bool ok;

	DBG_DEBUG("Path [%s]\n", fsp_str_dbg(fsp));

	if ((fsp == NULL)
	    || (fsp->fh == NULL)
	    || (fsp->fh->fd == -1))
	{
		smb_panic("bad fsp");
	}

	ok = ad_pack(handle, ad, fsp);
	if (!ok) {
		return -1;
	}

	switch (ad->ad_type) {
	case ADOUBLE_META:
		rc = SMB_VFS_NEXT_SETXATTR(handle,
					   fsp->fsp_name,
					   AFPINFO_EA_NETATALK,
					   ad->ad_data,
					   AD_DATASZ_XATTR, 0);
		break;

	case ADOUBLE_RSRC:
		len = SMB_VFS_NEXT_PWRITE(handle,
					  fsp,
					  ad->ad_data,
					  ad_getentryoff(ad, ADEID_RFORK),
					  0);
		if (len != ad_getentryoff(ad, ADEID_RFORK)) {
			DBG_ERR("short write on %s: %zd", fsp_str_dbg(fsp), len);
			return -1;
		}
		rc = 0;
		break;

	default:
		return -1;
	}

	DBG_DEBUG("Path [%s] rc [%d]\n", fsp_str_dbg(fsp), rc);

	return rc;
}

bool is_adouble_file(const char *path)
{
	const char *p = NULL;
	int match;

	p = strrchr(path, '/');
	if (p == NULL) {
		p = path;
	} else {
		p++;
	}

	match = strncmp(p,
			ADOUBLE_NAME_PREFIX,
			strlen(ADOUBLE_NAME_PREFIX));
	if (match != 0) {
		return false;
	}
	return true;
}

/**
 * Prepend "._" to a basename
 * Return a new struct smb_filename with stream_name == NULL.
 **/
int adouble_path(TALLOC_CTX *ctx,
		 const struct smb_filename *smb_fname_in,
		 struct smb_filename **pp_smb_fname_out)
{
	char *parent;
	const char *base;
	struct smb_filename *smb_fname = cp_smb_filename(ctx,
						smb_fname_in);

	if (smb_fname == NULL) {
		return -1;
	}

	/* We need streamname to be NULL */
	TALLOC_FREE(smb_fname->stream_name);

	/* And we're replacing base_name. */
	TALLOC_FREE(smb_fname->base_name);

	SET_STAT_INVALID(smb_fname->st);

	if (!parent_dirname(smb_fname, smb_fname_in->base_name,
				&parent, &base)) {
		TALLOC_FREE(smb_fname);
		return -1;
	}

	smb_fname->base_name = talloc_asprintf(smb_fname,
					"%s/._%s", parent, base);
	if (smb_fname->base_name == NULL) {
		TALLOC_FREE(smb_fname);
		return -1;
	}

	*pp_smb_fname_out = smb_fname;

	return 0;
}

/**
 * Allocate and initialize an AfpInfo struct
 **/
AfpInfo *afpinfo_new(TALLOC_CTX *ctx)
{
	AfpInfo *ai = talloc_zero(ctx, AfpInfo);
	if (ai == NULL) {
		return NULL;
	}
	ai->afpi_Signature = AFP_Signature;
	ai->afpi_Version = AFP_Version;
	ai->afpi_BackupTime = AD_DATE_START;
	return ai;
}

/**
 * Pack an AfpInfo struct into a buffer
 *
 * Buffer size must be at least AFP_INFO_SIZE
 * Returns size of packed buffer
 **/
ssize_t afpinfo_pack(const AfpInfo *ai, char *buf)
{
	memset(buf, 0, AFP_INFO_SIZE);

	RSIVAL(buf, 0, ai->afpi_Signature);
	RSIVAL(buf, 4, ai->afpi_Version);
	RSIVAL(buf, 12, ai->afpi_BackupTime);
	memcpy(buf + 16, ai->afpi_FinderInfo, sizeof(ai->afpi_FinderInfo));

	return AFP_INFO_SIZE;
}

/**
 * Unpack a buffer into a AfpInfo structure
 *
 * Buffer size must be at least AFP_INFO_SIZE
 * Returns allocated AfpInfo struct
 **/
AfpInfo *afpinfo_unpack(TALLOC_CTX *ctx, const void *data)
{
	AfpInfo *ai = talloc_zero(ctx, AfpInfo);
	if (ai == NULL) {
		return NULL;
	}

	ai->afpi_Signature = RIVAL(data, 0);
	ai->afpi_Version = RIVAL(data, 4);
	ai->afpi_BackupTime = RIVAL(data, 12);
	memcpy(ai->afpi_FinderInfo, (const char *)data + 16,
	       sizeof(ai->afpi_FinderInfo));

	if (ai->afpi_Signature != AFP_Signature
	    || ai->afpi_Version != AFP_Version) {
		DEBUG(1, ("Bad AfpInfo signature or version\n"));
		TALLOC_FREE(ai);
	}

	return ai;
}
