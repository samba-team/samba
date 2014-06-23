/*
 * OS X and Netatalk interoperability VFS module for Samba-3.x
 *
 * Copyright (C) Ralph Boehme, 2013, 2014
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
#include "MacExtensions.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "lib/util/time.h"
#include "../lib/crypto/md5.h"
#include "system/shmem.h"
#include "locking/proto.h"
#include "smbd/globals.h"
#include "messages.h"
#include "libcli/security/security.h"

/*
 * Enhanced OS X and Netatalk compatibility
 * ========================================
 *
 * This modules takes advantage of vfs_streams_xattr and
 * vfs_catia. VFS modules vfs_fruit and vfs_streams_xattr must be
 * loaded in the correct order:
 *
 *   vfs modules = catia fruit streams_xattr
 *
 * The module intercepts the OS X special streams "AFP_AfpInfo" and
 * "AFP_Resource" and handles them in a special way. All other named
 * streams are deferred to vfs_streams_xattr.
 *
 * The OS X client maps all NTFS illegal characters to the Unicode
 * private range. This module optionally stores the charcters using
 * their native ASCII encoding using vfs_catia. If you're not enabling
 * this feature, you can skip catia from vfs modules.
 *
 * Finally, open modes are optionally checked against Netatalk AFP
 * share modes.
 *
 * The "AFP_AfpInfo" named stream is a binary blob containing OS X
 * extended metadata for files and directories. This module optionally
 * reads and stores this metadata in a way compatible with Netatalk 3
 * which stores the metadata in an EA "org.netatalk.metadata". Cf
 * source3/include/MacExtensions.h for a description of the binary
 * blobs content.
 *
 * The "AFP_Resource" named stream may be arbitrarily large, thus it
 * can't be stored in an xattr on most filesystem. ZFS on Solaris is
 * the only available filesystem where xattrs can be of any size and
 * the OS supports using the file APIs for xattrs.
 *
 * The AFP_Resource stream is stored in an AppleDouble file prepending
 * "._" to the filename. On Solaris with ZFS the stream is optionally
 * stored in an EA "org.netatalk.ressource".
 *
 *
 * Extended Attributes
 * ===================
 *
 * The OS X SMB client sends xattrs as ADS too. For xattr interop with
 * other protocols you may want to adjust the xattr names the VFS
 * module vfs_streams_xattr uses for storing ADS's. This defaults to
 * user.DosStream.ADS_NAME:$DATA and can be changed by specifying
 * these module parameters:
 *
 *   streams_xattr:prefix = user.
 *   streams_xattr:store_stream_type = false
 *
 *
 * TODO
 * ====
 *
 * - log diagnostic if any needed VFS module is not loaded
 *   (eg with lp_vfs_objects())
 * - add tests
 */

static int vfs_fruit_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_fruit_debug_level

#define FRUIT_PARAM_TYPE_NAME "fruit"
#define ADOUBLE_NAME_PREFIX "._"

/*
 * REVIEW:
 * This is hokey, but what else can we do?
 */
#if defined(HAVE_ATTROPEN) || defined(FREEBSD)
#define AFPINFO_EA_NETATALK "org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "org.netatalk.ResourceFork"
#else
#define AFPINFO_EA_NETATALK "user.org.netatalk.Metadata"
#define AFPRESOURCE_EA_NETATALK "user.org.netatalk.ResourceFork"
#endif

enum apple_fork {APPLE_FORK_DATA, APPLE_FORK_RSRC};

enum fruit_rsrc {FRUIT_RSRC_STREAM, FRUIT_RSRC_ADFILE, FRUIT_RSRC_XATTR};
enum fruit_meta {FRUIT_META_STREAM, FRUIT_META_NETATALK};
enum fruit_locking {FRUIT_LOCKING_NETATALK, FRUIT_LOCKING_NONE};
enum fruit_encoding {FRUIT_ENC_NATIVE, FRUIT_ENC_PRIVATE};

struct fruit_config_data {
	enum fruit_rsrc rsrc;
	enum fruit_meta meta;
	enum fruit_locking locking;
	enum fruit_encoding encoding;
};

static const struct enum_list fruit_rsrc[] = {
	{FRUIT_RSRC_STREAM, "stream"}, /* pass on to vfs_streams_xattr */
	{FRUIT_RSRC_ADFILE, "file"}, /* ._ AppleDouble file */
	{FRUIT_RSRC_XATTR, "xattr"}, /* Netatalk compatible xattr (ZFS only) */
	{ -1, NULL}
};

static const struct enum_list fruit_meta[] = {
	{FRUIT_META_STREAM, "stream"}, /* pass on to vfs_streams_xattr */
	{FRUIT_META_NETATALK, "netatalk"}, /* Netatalk compatible xattr */
	{ -1, NULL}
};

static const struct enum_list fruit_locking[] = {
	{FRUIT_LOCKING_NETATALK, "netatalk"}, /* synchronize locks with Netatalk */
	{FRUIT_LOCKING_NONE, "none"},
	{ -1, NULL}
};

static const struct enum_list fruit_encoding[] = {
	{FRUIT_ENC_NATIVE, "native"}, /* map unicode private chars to ASCII */
	{FRUIT_ENC_PRIVATE, "private"}, /* keep unicode private chars */
	{ -1, NULL}
};

/*****************************************************************************
 * Defines, functions and data structures that deal with AppleDouble
 *****************************************************************************/

/*
 * There are two AppleDouble blobs we deal with:
 *
 * - ADOUBLE_META - AppleDouble blob used by Netatalk for storing
 *   metadata in an xattr
 *
 * - ADOUBLE_RSRC - AppleDouble blob used by OS X and Netatalk in
 *   ._ files
 */
typedef enum {ADOUBLE_META, ADOUBLE_RSRC} adouble_type_t;

/* Version info */
#define AD_VERSION2     0x00020000
#define AD_VERSION      AD_VERSION2

/*
 * AppleDouble entry IDs.
 */
#define ADEID_DFORK         1
#define ADEID_RFORK         2
#define ADEID_NAME          3
#define ADEID_COMMENT       4
#define ADEID_ICONBW        5
#define ADEID_ICONCOL       6
#define ADEID_FILEI         7
#define ADEID_FILEDATESI    8
#define ADEID_FINDERI       9
#define ADEID_MACFILEI      10
#define ADEID_PRODOSFILEI   11
#define ADEID_MSDOSFILEI    12
#define ADEID_SHORTNAME     13
#define ADEID_AFPFILEI      14
#define ADEID_DID           15

/* Private Netatalk entries */
#define ADEID_PRIVDEV       16
#define ADEID_PRIVINO       17
#define ADEID_PRIVSYN       18
#define ADEID_PRIVID        19
#define ADEID_MAX           (ADEID_PRIVID + 1)

/*
 * These are the real ids for the private entries,
 * as stored in the adouble file
 */
#define AD_DEV              0x80444556
#define AD_INO              0x80494E4F
#define AD_SYN              0x8053594E
#define AD_ID               0x8053567E

/* Number of actually used entries */
#define ADEID_NUM_XATTR      8
#define ADEID_NUM_DOT_UND    2
#define ADEID_NUM_RSRC_XATTR 1

/* AppleDouble magic */
#define AD_APPLESINGLE_MAGIC 0x00051600
#define AD_APPLEDOUBLE_MAGIC 0x00051607
#define AD_MAGIC             AD_APPLEDOUBLE_MAGIC

/* Sizes of relevant entry bits */
#define ADEDLEN_MAGIC       4
#define ADEDLEN_VERSION     4
#define ADEDLEN_FILLER      16
#define AD_FILLER_TAG       "Netatalk        " /* should be 16 bytes */
#define ADEDLEN_NENTRIES    2
#define AD_HEADER_LEN       (ADEDLEN_MAGIC + ADEDLEN_VERSION + \
			     ADEDLEN_FILLER + ADEDLEN_NENTRIES) /* 26 */
#define AD_ENTRY_LEN_EID    4
#define AD_ENTRY_LEN_OFF    4
#define AD_ENTRY_LEN_LEN    4
#define AD_ENTRY_LEN (AD_ENTRY_LEN_EID + AD_ENTRY_LEN_OFF + AD_ENTRY_LEN_LEN)

/* Field widths */
#define ADEDLEN_NAME            255
#define ADEDLEN_COMMENT         200
#define ADEDLEN_FILEI           16
#define ADEDLEN_FINDERI         32
#define ADEDLEN_FILEDATESI      16
#define ADEDLEN_SHORTNAME       12 /* length up to 8.3 */
#define ADEDLEN_AFPFILEI        4
#define ADEDLEN_MACFILEI        4
#define ADEDLEN_PRODOSFILEI     8
#define ADEDLEN_MSDOSFILEI      2
#define ADEDLEN_DID             4
#define ADEDLEN_PRIVDEV         8
#define ADEDLEN_PRIVINO         8
#define ADEDLEN_PRIVSYN         8
#define ADEDLEN_PRIVID          4

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

/*
 * Sharemode locks fcntl() offsets
 */
#if _FILE_OFFSET_BITS == 64 || defined(HAVE_LARGEFILE)
#define AD_FILELOCK_BASE (UINT64_C(0x7FFFFFFFFFFFFFFF) - 9)
#else
#define AD_FILELOCK_BASE (UINT32_C(0x7FFFFFFF) - 9)
#endif
#define BYTELOCK_MAX (AD_FILELOCK_BASE - 1)

#define AD_FILELOCK_OPEN_WR        (AD_FILELOCK_BASE + 0)
#define AD_FILELOCK_OPEN_RD        (AD_FILELOCK_BASE + 1)
#define AD_FILELOCK_RSRC_OPEN_WR   (AD_FILELOCK_BASE + 2)
#define AD_FILELOCK_RSRC_OPEN_RD   (AD_FILELOCK_BASE + 3)
#define AD_FILELOCK_DENY_WR        (AD_FILELOCK_BASE + 4)
#define AD_FILELOCK_DENY_RD        (AD_FILELOCK_BASE + 5)
#define AD_FILELOCK_RSRC_DENY_WR   (AD_FILELOCK_BASE + 6)
#define AD_FILELOCK_RSRC_DENY_RD   (AD_FILELOCK_BASE + 7)
#define AD_FILELOCK_OPEN_NONE      (AD_FILELOCK_BASE + 8)
#define AD_FILELOCK_RSRC_OPEN_NONE (AD_FILELOCK_BASE + 9)

/* Time stuff we overload the bits a little */
#define AD_DATE_CREATE         0
#define AD_DATE_MODIFY         4
#define AD_DATE_BACKUP         8
#define AD_DATE_ACCESS        12
#define AD_DATE_MASK          (AD_DATE_CREATE | AD_DATE_MODIFY | \
                               AD_DATE_BACKUP | AD_DATE_ACCESS)
#define AD_DATE_UNIX          (1 << 10)
#define AD_DATE_START         0x80000000
#define AD_DATE_DELTA         946684800
#define AD_DATE_FROM_UNIX(x)  (htonl((x) - AD_DATE_DELTA))
#define AD_DATE_TO_UNIX(x)    (ntohl(x) + AD_DATE_DELTA)

/* Accessor macros */
#define ad_getentrylen(ad,eid)     ((ad)->ad_eid[(eid)].ade_len)
#define ad_getentryoff(ad,eid)     ((ad)->ad_eid[(eid)].ade_off)
#define ad_setentrylen(ad,eid,len) ((ad)->ad_eid[(eid)].ade_len = (len))
#define ad_setentryoff(ad,eid,off) ((ad)->ad_eid[(eid)].ade_off = (off))
#define ad_entry(ad,eid)           ((ad)->ad_data + ad_getentryoff((ad),(eid)))

struct ad_entry {
	size_t ade_off;
	size_t ade_len;
};

struct adouble {
	vfs_handle_struct        *ad_handle;
	files_struct             *ad_fsp;
	adouble_type_t            ad_type;
	uint32_t                  ad_magic;
	uint32_t                  ad_version;
	struct ad_entry           ad_eid[ADEID_MAX];
	char                     *ad_data;
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

/* AppleDouble ressource fork file (the ones prefixed by "._") */
static const
struct ad_entry_order entry_order_dot_und[ADEID_NUM_DOT_UND + 1] = {
	{ADEID_FINDERI,    ADEDOFF_FINDERI_DOT_UND,  ADEDLEN_FINDERI},
	{ADEID_RFORK,      ADEDOFF_RFORK_DOT_UND,    0},
	{0, 0, 0}
};

/*
 * Fake AppleDouble entry oder for ressource fork xattr.  The xattr
 * isn't an AppleDouble file, it simply contains the ressource data,
 * but in order to be able to use some API calls like ad_getentryoff()
 * we build a fake/helper struct adouble with this entry order struct.
 */
static const
struct ad_entry_order entry_order_rsrc_xattr[ADEID_NUM_RSRC_XATTR + 1] = {
	{ADEID_RFORK, 0, 0},
	{0, 0, 0}
};

/* Conversion from enumerated id to on-disk AppleDouble id */
#define AD_EID_DISK(a) (set_eid[a])
static const uint32_t set_eid[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	AD_DEV, AD_INO, AD_SYN, AD_ID
};

/*
 * Forward declarations
 */
static struct adouble *ad_init(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			       adouble_type_t type, files_struct *fsp);
static int ad_write(struct adouble *ad, const char *path);
static int adouble_path(TALLOC_CTX *ctx, const char *path_in, char **path_out);

/**
 * Get a date
 **/
static int ad_getdate(const struct adouble *ad,
		      unsigned int dateoff,
		      uint32_t *date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);

	dateoff &= AD_DATE_MASK;
	if (!ad_getentryoff(ad, ADEID_FILEDATESI)) {
		return -1;
	}

	if (dateoff > AD_DATE_ACCESS) {
	    return -1;
	}
	memcpy(date,
	       ad_entry(ad, ADEID_FILEDATESI) + dateoff,
	       sizeof(uint32_t));

	if (xlate) {
		*date = AD_DATE_TO_UNIX(*date);
	}
	return 0;
}

/**
 * Set a date
 **/
static int ad_setdate(struct adouble *ad, unsigned int dateoff, uint32_t date)
{
	bool xlate = (dateoff & AD_DATE_UNIX);

	if (!ad_getentryoff(ad, ADEID_FILEDATESI)) {
		return 0;
	}

	dateoff &= AD_DATE_MASK;
	if (xlate) {
		date = AD_DATE_FROM_UNIX(date);
	}

	if (dateoff > AD_DATE_ACCESS) {
		return -1;
	}

	memcpy(ad_entry(ad, ADEID_FILEDATESI) + dateoff, &date, sizeof(date));

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

/**
 * Pack AppleDouble structure into data buffer
 **/
static bool ad_pack(struct adouble *ad)
{
	uint32_t       eid;
	uint16_t       nent;
	uint32_t       bufsize;
	uint32_t       offset = 0;

	bufsize = talloc_get_size(ad->ad_data);

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

	for (eid = 0, nent = 0; eid < ADEID_MAX; eid++) {
		if ((ad->ad_eid[eid].ade_off == 0)) {
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

	return 0;
}

/**
 * Unpack an AppleDouble blob into a struct adoble
 **/
static bool ad_unpack(struct adouble *ad, const int nentries)
{
	size_t bufsize = talloc_get_size(ad->ad_data);
	int adentries, i;
	uint32_t eid, len, off;

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

	adentries = RSVAL(ad->ad_data, ADEDOFF_NENTRIES);
	if (adentries != nentries) {
		DEBUG(1, ("invalid number of entries: %d\n", adentries));
		return false;
	}

	/* now, read in the entry bits */
	for (i = 0; i < adentries; i++) {
		eid = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN));
		eid = get_eid(eid);
		off = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 4);
		len = RIVAL(ad->ad_data, AD_HEADER_LEN + (i * AD_ENTRY_LEN) + 8);

		if (!eid || eid > ADEID_MAX) {
			DEBUG(1, ("bogus eid %d\n", eid));
			return false;
		}

		if (off > bufsize) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}
		if ((eid != ADEID_RFORK) && ((off + len) > bufsize)) {
			DEBUG(1, ("bogus eid %d: off: %" PRIu32 ", len: %" PRIu32 "\n",
				  eid, off, len));
			return false;
		}

		ad->ad_eid[eid].ade_off = off;
		ad->ad_eid[eid].ade_len = len;
	}

	return true;
}

/**
 * Convert from Apple's ._ file to Netatalk
 *
 * Apple's AppleDouble may contain a FinderInfo entry longer then 32
 * bytes containing packed xattrs. Netatalk can't deal with that, so
 * we simply discard the packed xattrs.
 *
 * @return -1 in case an error occured, 0 if no conversion was done, 1
 * otherwise
 **/
static int ad_convert(struct adouble *ad, int fd)
{
	int rc = 0;
	char *map = MAP_FAILED;
	size_t origlen;

	origlen = ad_getentryoff(ad, ADEID_RFORK) +
		ad_getentrylen(ad, ADEID_RFORK);

	/* FIXME: direct use of mmap(), vfs_aio_fork does it too */
	map = mmap(NULL, origlen, PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		DEBUG(2, ("mmap AppleDouble: %s\n", strerror(errno)));
		rc = -1;
		goto exit;
	}

	memmove(map + ad_getentryoff(ad, ADEID_FINDERI) + ADEDLEN_FINDERI,
		map + ad_getentryoff(ad, ADEID_RFORK),
		ad_getentrylen(ad, ADEID_RFORK));

	ad_setentrylen(ad, ADEID_FINDERI, ADEDLEN_FINDERI);
	ad_setentryoff(ad, ADEID_RFORK,
		       ad_getentryoff(ad, ADEID_FINDERI) + ADEDLEN_FINDERI);

	/*
	 * FIXME: direct ftruncate(), but we don't have a fsp for the
	 * VFS call
	 */
	rc = ftruncate(fd, ad_getentryoff(ad, ADEID_RFORK)
		       + ad_getentrylen(ad, ADEID_RFORK));

exit:
	if (map != MAP_FAILED) {
		munmap(map, origlen);
	}
	return rc;
}

/**
 * Read and parse Netatalk AppleDouble metadata xattr
 **/
static ssize_t ad_header_read_meta(struct adouble *ad, const char *path)
{
	int      rc = 0;
	ssize_t  ealen;
	bool     ok;

	DEBUG(10, ("reading meta xattr for %s\n", path));

	ealen = SMB_VFS_GETXATTR(ad->ad_handle->conn, path,
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
	ok = ad_unpack(ad, ADEID_NUM_XATTR);
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
	DEBUG(10, ("reading meta xattr for %s, rc: %d\n", path, rc));

	if (rc != 0) {
		ealen = -1;
		if (errno == EINVAL) {
			become_root();
			removexattr(path, AFPINFO_EA_NETATALK);
			unbecome_root();
			errno = ENOENT;
		}
	}
	return ealen;
}

/**
 * Read and parse resource fork, either ._ AppleDouble file or xattr
 **/
static ssize_t ad_header_read_rsrc(struct adouble *ad, const char *path)
{
	struct fruit_config_data *config = NULL;
	int fd = -1;
	int rc = 0;
	ssize_t len;
	char *adpath = NULL;
	bool opened = false;
	int mode;
	struct adouble *meta_ad = NULL;
	SMB_STRUCT_STAT sbuf;
	bool ok;
	int saved_errno;

	SMB_VFS_HANDLE_GET_DATA(ad->ad_handle, config,
				struct fruit_config_data, return -1);

	if (ad->ad_fsp && ad->ad_fsp->fh && (ad->ad_fsp->fh->fd != -1)) {
		fd = ad->ad_fsp->fh->fd;
	} else {
		if (config->rsrc == FRUIT_RSRC_XATTR) {
			adpath = talloc_strdup(talloc_tos(), path);
		} else {
			rc = adouble_path(talloc_tos(), path, &adpath);
			if (rc != 0) {
				goto exit;
			}
		}

		/* Try rw first so we can use the fd in ad_convert() */
		mode = O_RDWR;

	retry:
		if (config->rsrc == FRUIT_RSRC_XATTR) {
#ifndef HAVE_ATTROPEN
			errno = ENOSYS;
			rc = -1;
			goto exit;
#else
			/* FIXME: direct Solaris xattr syscall */
			fd = attropen(adpath, AFPRESOURCE_EA_NETATALK,
				      mode, 0);
#endif
		} else {
			/* FIXME: direct open(), don't have an fsp */
			fd = open(adpath, mode);
		}

		if (fd == -1) {
			switch (errno) {
			case EROFS:
			case EACCES:
				if (mode == O_RDWR) {
					mode = O_RDONLY;
					goto retry;
				}
				/* fall through ... */
			default:
				DEBUG(2, ("open AppleDouble: %s, %s\n",
					  adpath, strerror(errno)));
				rc = -1;
				goto exit;
			}
		}
		opened = true;
	}

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		/* FIXME: direct sys_fstat(), don't have an fsp */
		rc = sys_fstat(
			fd, &sbuf,
			lp_fake_directory_create_times(
				SNUM(ad->ad_handle->conn)));
		if (rc != 0) {
			rc = -1;
			goto exit;
		}
		ad_setentrylen(ad, ADEID_RFORK, sbuf.st_ex_size);
	} else {
		/* FIXME: direct sys_pread(), don't have an fsp */
		len = sys_pread(fd, ad->ad_data, AD_DATASZ_DOT_UND, 0);
		if (len != AD_DATASZ_DOT_UND) {
			DEBUG(2, ("%s: bad size: %zd\n",
				  strerror(errno), len));
			rc = -1;
			goto exit;
		}

		/* Now parse entries */
		ok = ad_unpack(ad, ADEID_NUM_DOT_UND);
		if (!ok) {
			DEBUG(1, ("invalid AppleDouble ressource %s\n", path));
			errno = EINVAL;
			rc = -1;
			goto exit;
		}

		if ((ad_getentryoff(ad, ADEID_FINDERI)
		     != ADEDOFF_FINDERI_DOT_UND)
		    || (ad_getentrylen(ad, ADEID_FINDERI)
			< ADEDLEN_FINDERI)
		    || (ad_getentryoff(ad, ADEID_RFORK)
			< ADEDOFF_RFORK_DOT_UND)) {
			DEBUG(2, ("invalid AppleDouble ressource %s\n", path));
			errno = EINVAL;
			rc = -1;
			goto exit;
		}

		if ((mode == O_RDWR)
		    && (ad_getentrylen(ad, ADEID_FINDERI) > ADEDLEN_FINDERI)) {
			rc = ad_convert(ad, fd);
			if (rc != 0) {
				rc = -1;
				goto exit;
			}
			/*
			 * Can't use ad_write() because we might not have a fsp
			 */
			rc = ad_pack(ad);
			if (rc != 0) {
				goto exit;
			}
			/* FIXME: direct sys_pwrite(), don't have an fsp */
			len = sys_pwrite(fd, ad->ad_data,
					 AD_DATASZ_DOT_UND, 0);
			if (len != AD_DATASZ_DOT_UND) {
				DEBUG(2, ("%s: bad size: %zd\n", adpath, len));
				rc = -1;
				goto exit;
			}

			meta_ad = ad_init(talloc_tos(), ad->ad_handle,
					  ADOUBLE_META, NULL);
			if (meta_ad == NULL) {
				rc = -1;
				goto exit;
			}

			memcpy(ad_entry(meta_ad, ADEID_FINDERI),
			       ad_entry(ad, ADEID_FINDERI),
			       ADEDLEN_FINDERI);

			rc = ad_write(meta_ad, path);
			if (rc != 0) {
				rc = -1;
				goto exit;
			}
		}
	}

	DEBUG(10, ("opened AppleDouble: %s\n", path));

exit:
	if (rc != 0) {
		saved_errno = errno;
		len = -1;
	}
	if (opened && fd != -1) {
		close(fd);
	}
	TALLOC_FREE(adpath);
	TALLOC_FREE(meta_ad);
	if (rc != 0) {
		errno = saved_errno;
	}
	return len;
}

/**
 * Read and unpack an AppleDouble metadata xattr or resource
 **/
static ssize_t ad_read(struct adouble *ad, const char *path)
{
	switch (ad->ad_type) {
	case ADOUBLE_META:
		return ad_header_read_meta(ad, path);
	case ADOUBLE_RSRC:
		return ad_header_read_rsrc(ad, path);
	default:
		return -1;
	}
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

 * @param[in] fsp        if not NULL (for stream IO), the adouble handle is
 *                       added as an fsp extension
 *
 * @return               adouble handle
 **/
static struct adouble *ad_alloc(TALLOC_CTX *ctx, vfs_handle_struct *handle,
				adouble_type_t type, files_struct *fsp)
{
	int rc = 0;
	size_t adsize = 0;
	struct adouble *ad;
	struct fruit_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return NULL);

	switch (type) {
	case ADOUBLE_META:
		adsize = AD_DATASZ_XATTR;
		break;
	case ADOUBLE_RSRC:
		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			adsize = AD_DATASZ_DOT_UND;
		}
		break;
	default:
		return NULL;
	}

	if (!fsp) {
		ad = talloc_zero(ctx, struct adouble);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		if (adsize) {
			ad->ad_data = talloc_zero_array(ad, char, adsize);
		}
	} else {
		ad = (struct adouble *)VFS_ADD_FSP_EXTENSION(handle, fsp,
							     struct adouble,
							     NULL);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		if (adsize) {
			ad->ad_data = talloc_zero_array(
				VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
				char, adsize);
		}
		ad->ad_fsp = fsp;
	}

	if (adsize && ad->ad_data == NULL) {
		rc = -1;
		goto exit;
	}
	ad->ad_handle = handle;
	ad->ad_type = type;
	ad->ad_magic = AD_MAGIC;
	ad->ad_version = AD_VERSION;

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
 * @param[in] handle     vfs handle
 * @param[in] type       type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 * @param[in] fsp        file handle, may be NULL for a type of e_ad_meta
 *
 * @return               adouble handle, initialized
 **/
static struct adouble *ad_init(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			       adouble_type_t type, files_struct *fsp)
{
	int rc = 0;
	const struct ad_entry_order  *eid;
	struct adouble *ad = NULL;
	struct fruit_config_data *config;
	time_t t = time(NULL);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return NULL);

	switch (type) {
	case ADOUBLE_META:
		eid = entry_order_meta_xattr;
		break;
	case ADOUBLE_RSRC:
		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			eid = entry_order_dot_und;
		} else {
			eid = entry_order_rsrc_xattr;
		}
		break;
	default:
		return NULL;
	}

	ad = ad_alloc(ctx, handle, type, fsp);
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

/**
 * Return AppleDouble data for a file
 *
 * @param[in] ctx      talloc context
 * @param[in] handle   vfs handle
 * @param[in] path     pathname to file or directory
 * @param[in] type     type of AppleDouble, ADOUBLE_META or ADOUBLE_RSRC
 *
 * @return             talloced struct adouble or NULL on error
 **/
static struct adouble *ad_get(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			      const char *path, adouble_type_t type)
{
	int rc = 0;
	ssize_t len;
	struct adouble *ad = NULL;

	DEBUG(10, ("ad_get(%s) called for %s\n",
		   type == ADOUBLE_META ? "meta" : "rsrc", path));

	ad = ad_alloc(ctx, handle, type, NULL);
	if (ad == NULL) {
		rc = -1;
		goto exit;
	}

	len = ad_read(ad, path);
	if (len == -1) {
		DEBUG(10, ("error reading AppleDouble for %s\n", path));
		rc = -1;
		goto exit;
	}

exit:
	DEBUG(10, ("ad_get(%s) for %s returning %d\n",
		  type == ADOUBLE_META ? "meta" : "rsrc", path, rc));

	if (rc != 0) {
		TALLOC_FREE(ad);
	}
	return ad;
}

/**
 * Set AppleDouble metadata on a file or directory
 *
 * @param[in] ad      adouble handle
 * @param[in] path    pathname to file or directory
 *
 * @return            status code, 0 means success
 **/
static int ad_write(struct adouble *ad, const char *path)
{
	int rc = 0;
	ssize_t len;

	rc = ad_pack(ad);
	if (rc != 0) {
		goto exit;
	}

	switch (ad->ad_type) {
	case ADOUBLE_META:
		rc = SMB_VFS_SETXATTR(ad->ad_handle->conn, path,
				      AFPINFO_EA_NETATALK, ad->ad_data,
				      AD_DATASZ_XATTR, 0);
		break;
	case ADOUBLE_RSRC:
		if ((ad->ad_fsp == NULL)
		    || (ad->ad_fsp->fh == NULL)
		    || (ad->ad_fsp->fh->fd == -1)) {
			rc = -1;
			goto exit;
		}
		/* FIXME: direct sys_pwrite(), don't have an fsp */
		len = sys_pwrite(ad->ad_fsp->fh->fd, ad->ad_data,
				 talloc_get_size(ad->ad_data), 0);
		if (len != talloc_get_size(ad->ad_data)) {
			DEBUG(1, ("short write on %s: %zd", path, len));
			rc = -1;
			goto exit;
		}
		break;
	default:
		return -1;
	}
exit:
	return rc;
}

/*****************************************************************************
 * Helper functions
 *****************************************************************************/

static bool is_afpinfo_stream(const struct smb_filename *smb_fname)
{
	if (strncasecmp_m(smb_fname->stream_name,
			  AFPINFO_STREAM_NAME,
			  strlen(AFPINFO_STREAM_NAME)) == 0) {
		return true;
	}
	return false;
}

static bool is_afpresource_stream(const struct smb_filename *smb_fname)
{
	if (strncasecmp_m(smb_fname->stream_name,
			  AFPRESOURCE_STREAM_NAME,
			  strlen(AFPRESOURCE_STREAM_NAME)) == 0) {
		return true;
	}
	return false;
}

/**
 * Test whether stream is an Apple stream, not used atm
 **/
#if 0
static bool is_apple_stream(const struct smb_filename *smb_fname)
{
	if (is_afpinfo_stream(smb_fname)) {
		return true;
	}
	if (is_afpresource_stream(smb_fname)) {
		return true;
	}
	return false;
}
#endif

/**
 * Initialize config struct from our smb.conf config parameters
 **/
static int init_fruit_config(vfs_handle_struct *handle)
{
	struct fruit_config_data *config;
	int enumval;

	config = talloc_zero(handle->conn, struct fruit_config_data);
	if (!config) {
		DEBUG(1, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "ressource", fruit_rsrc, FRUIT_RSRC_ADFILE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: ressource type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->rsrc = (enum fruit_rsrc)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "metadata", fruit_meta, FRUIT_META_NETATALK);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: metadata type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->meta = (enum fruit_meta)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "locking", fruit_locking, FRUIT_LOCKING_NONE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: locking type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->locking = (enum fruit_locking)enumval;

	enumval = lp_parm_enum(SNUM(handle->conn), FRUIT_PARAM_TYPE_NAME,
			       "encoding", fruit_encoding, FRUIT_ENC_PRIVATE);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: encoding type unknown\n",
			  FRUIT_PARAM_TYPE_NAME));
		return -1;
	}
	config->encoding = (enum fruit_encoding)enumval;

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct fruit_config_data,
				return -1);

	return 0;
}

/**
 * Prepend "._" to a basename
 **/
static int adouble_path(TALLOC_CTX *ctx, const char *path_in, char **path_out)
{
	char *parent;
	const char *basename;

	if (!parent_dirname(ctx, path_in, &parent, &basename)) {
		return -1;
	}

	*path_out = talloc_asprintf(ctx, "%s/._%s", parent, basename);
	if (*path_out == NULL) {
		return -1;
	}

	return 0;
}

/**
 * Allocate and initialize an AfpInfo struct
 **/
static AfpInfo *afpinfo_new(TALLOC_CTX *ctx)
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
static ssize_t afpinfo_pack(const AfpInfo *ai, char *buf)
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
static AfpInfo *afpinfo_unpack(TALLOC_CTX *ctx, const void *data)
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

/**
 * Fake an inode number from the md5 hash of the (xattr) name
 **/
static SMB_INO_T fruit_inode(const SMB_STRUCT_STAT *sbuf, const char *sname)
{
	MD5_CTX ctx;
	unsigned char hash[16];
	SMB_INO_T result;
	char *upper_sname;

	upper_sname = talloc_strdup_upper(talloc_tos(), sname);
	SMB_ASSERT(upper_sname != NULL);

	MD5Init(&ctx);
	MD5Update(&ctx, (const unsigned char *)&(sbuf->st_ex_dev),
		  sizeof(sbuf->st_ex_dev));
	MD5Update(&ctx, (const unsigned char *)&(sbuf->st_ex_ino),
		  sizeof(sbuf->st_ex_ino));
	MD5Update(&ctx, (unsigned char *)upper_sname,
		  talloc_get_size(upper_sname)-1);
	MD5Final(hash, &ctx);

	TALLOC_FREE(upper_sname);

	/* Hopefully all the variation is in the lower 4 (or 8) bytes! */
	memcpy(&result, hash, sizeof(result));

	DEBUG(10, ("fruit_inode \"%s\": ino=0x%llu\n",
		   sname, (unsigned long long)result));

	return result;
}

/**
 * Ensure ad_fsp is still valid
 **/
static bool fruit_fsp_recheck(struct adouble *ad, files_struct *fsp)
{
	if (ad->ad_fsp == fsp) {
		return true;
	}
	ad->ad_fsp = fsp;

	return true;
}

static bool add_fruit_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			     struct stream_struct **streams,
			     const char *name, off_t size,
			     off_t alloc_size)
{
	struct stream_struct *tmp;

	tmp = talloc_realloc(mem_ctx, *streams, struct stream_struct,
			     (*num_streams)+1);
	if (tmp == NULL) {
		return false;
	}

	tmp[*num_streams].name = talloc_asprintf(tmp, "%s:$DATA", name);
	if (tmp[*num_streams].name == NULL) {
		return false;
	}

	tmp[*num_streams].size = size;
	tmp[*num_streams].alloc_size = alloc_size;

	*streams = tmp;
	*num_streams += 1;
	return true;
}

static bool empty_finderinfo(const struct adouble *ad)
{

	char emptybuf[ADEDLEN_FINDERI] = {0};
	if (memcmp(emptybuf,
		   ad_entry(ad, ADEID_FINDERI),
		   ADEDLEN_FINDERI) == 0) {
		return true;
	}
	return false;
}

/**
 * Update btime with btime from Netatalk
 **/
static void update_btime(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	uint32_t t;
	struct timespec creation_time = {0};
	struct adouble *ad;

	ad = ad_get(talloc_tos(), handle, smb_fname->base_name, ADOUBLE_META);
	if (ad == NULL) {
		return;
	}
	if (ad_getdate(ad, AD_DATE_UNIX | AD_DATE_CREATE, &t) != 0) {
		TALLOC_FREE(ad);
		return;
	}
	TALLOC_FREE(ad);

	creation_time.tv_sec = convert_uint32_t_to_time_t(t);
	update_stat_ex_create_time(&smb_fname->st, creation_time);

	return;
}

/**
 * Map an access mask to a Netatalk single byte byte range lock
 **/
static off_t access_to_netatalk_brl(enum apple_fork fork,
				    uint32_t access_mask)
{
	off_t offset;

	switch (access_mask) {
	case FILE_READ_DATA:
		offset = AD_FILELOCK_OPEN_RD;
		break;

	case FILE_WRITE_DATA:
	case FILE_APPEND_DATA:
		offset = AD_FILELOCK_OPEN_WR;
		break;

	default:
		offset = AD_FILELOCK_OPEN_NONE;
		break;
	}

	if (fork == APPLE_FORK_RSRC) {
		if (offset == AD_FILELOCK_OPEN_NONE) {
			offset = AD_FILELOCK_RSRC_OPEN_NONE;
		} else {
			offset += 2;
		}
	}

	return offset;
}

/**
 * Map a deny mode to a Netatalk brl
 **/
static off_t denymode_to_netatalk_brl(enum apple_fork fork,
				      uint32_t deny_mode)
{
	off_t offset;

	switch (deny_mode) {
	case DENY_READ:
		offset = AD_FILELOCK_DENY_RD;
		break;

	case DENY_WRITE:
		offset = AD_FILELOCK_DENY_WR;
		break;

	default:
		smb_panic("denymode_to_netatalk_brl: bad deny mode\n");
	}

	if (fork == APPLE_FORK_RSRC) {
		offset += 2;
	}

	return offset;
}

/**
 * Call fcntl() with an exclusive F_GETLK request in order to
 * determine if there's an exisiting shared lock
 *
 * @return true if the requested lock was found or any error occured
 *         false if the lock was not found
 **/
static bool test_netatalk_lock(files_struct *fsp, off_t in_offset)
{
	bool result;
	off_t offset = in_offset;
	off_t len = 1;
	int type = F_WRLCK;
	pid_t pid;

	result = SMB_VFS_GETLOCK(fsp, &offset, &len, &type, &pid);
	if (result == false) {
		return true;
	}

	if (type != F_UNLCK) {
		return true;
	}

	return false;
}

static NTSTATUS fruit_check_access(vfs_handle_struct *handle,
				   files_struct *fsp,
				   uint32_t access_mask,
				   uint32_t deny_mode)
{
	NTSTATUS status = NT_STATUS_OK;
	struct byte_range_lock *br_lck = NULL;
	bool open_for_reading, open_for_writing, deny_read, deny_write;
	off_t off;

	/* FIXME: hardcoded data fork, add resource fork */
	enum apple_fork fork = APPLE_FORK_DATA;

	DEBUG(10, ("fruit_check_access: %s, am: %s/%s, dm: %s/%s\n",
		  fsp_str_dbg(fsp),
		  access_mask & FILE_READ_DATA ? "READ" :"-",
		  access_mask & FILE_WRITE_DATA ? "WRITE" : "-",
		  deny_mode & DENY_READ ? "DENY_READ" : "-",
		  deny_mode & DENY_WRITE ? "DENY_WRITE" : "-"));

	/*
	 * Check read access and deny read mode
	 */
	if ((access_mask & FILE_READ_DATA) || (deny_mode & DENY_READ)) {
		/* Check access */
		open_for_reading = test_netatalk_lock(
			fsp, access_to_netatalk_brl(fork, FILE_READ_DATA));

		deny_read = test_netatalk_lock(
			fsp, denymode_to_netatalk_brl(fork, DENY_READ));

		DEBUG(10, ("read: %s, deny_write: %s\n",
			  open_for_reading == true ? "yes" : "no",
			  deny_read == true ? "yes" : "no"));

		if (((access_mask & FILE_READ_DATA) && deny_read)
		    || ((deny_mode & DENY_READ) && open_for_reading)) {
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* Set locks */
		if (access_mask & FILE_READ_DATA) {
			off = access_to_netatalk_brl(fork, FILE_READ_DATA);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			if (!NT_STATUS_IS_OK(status))  {
				return status;
			}
			TALLOC_FREE(br_lck);
		}

		if (deny_mode & DENY_READ) {
			off = denymode_to_netatalk_brl(fork, DENY_READ);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			TALLOC_FREE(br_lck);
		}
	}

	/*
	 * Check write access and deny write mode
	 */
	if ((access_mask & FILE_WRITE_DATA) || (deny_mode & DENY_WRITE)) {
		/* Check access */
		open_for_writing = test_netatalk_lock(
			fsp, access_to_netatalk_brl(fork, FILE_WRITE_DATA));

		deny_write = test_netatalk_lock(
			fsp, denymode_to_netatalk_brl(fork, DENY_WRITE));

		DEBUG(10, ("write: %s, deny_write: %s\n",
			  open_for_writing == true ? "yes" : "no",
			  deny_write == true ? "yes" : "no"));

		if (((access_mask & FILE_WRITE_DATA) && deny_write)
		    || ((deny_mode & DENY_WRITE) && open_for_writing)) {
			return NT_STATUS_SHARING_VIOLATION;
		}

		/* Set locks */
		if (access_mask & FILE_WRITE_DATA) {
			off = access_to_netatalk_brl(fork, FILE_WRITE_DATA);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			TALLOC_FREE(br_lck);

		}
		if (deny_mode & DENY_WRITE) {
			off = denymode_to_netatalk_brl(fork, DENY_WRITE);
			br_lck = do_lock(
				handle->conn->sconn->msg_ctx, fsp,
				fsp->op->global->open_persistent_id, 1, off,
				READ_LOCK, POSIX_LOCK, false,
				&status, NULL);

			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			TALLOC_FREE(br_lck);
		}
	}

	TALLOC_FREE(br_lck);

	return status;
}

/****************************************************************************
 * VFS ops
 ****************************************************************************/

static int fruit_connect(vfs_handle_struct *handle,
			 const char *service,
			 const char *user)
{
	int rc;
	char *list = NULL, *newlist = NULL;
	struct fruit_config_data *config;

	DEBUG(10, ("fruit_connect\n"));

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc < 0) {
		return rc;
	}

	list = lp_veto_files(talloc_tos(), SNUM(handle->conn));

	if (list) {
		if (strstr(list, "/" ADOUBLE_NAME_PREFIX "*/") == NULL) {
			newlist = talloc_asprintf(
				list,
				"%s/" ADOUBLE_NAME_PREFIX "*/",
				list);
			lp_do_parameter(SNUM(handle->conn),
					"veto files",
					newlist);
		}
	} else {
		lp_do_parameter(SNUM(handle->conn),
				"veto files",
				"/" ADOUBLE_NAME_PREFIX "*/");
	}

	TALLOC_FREE(list);

	rc = init_fruit_config(handle);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->encoding == FRUIT_ENC_NATIVE) {
		lp_do_parameter(
			SNUM(handle->conn),
			"catia:mappings",
			"0x22:0xf020,0x2a:0xf021,0x3a:0xf022,0x3c:0xf023,"
			"0x3e:0xf024,0x3f:0xf025,0x5c:0xf026,0x7c:0xf027,"
			"0x0d:0xf00d");
	}

	return rc;
}

static int fruit_open_meta(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   files_struct *fsp, int flags, mode_t mode)
{
	int rc = 0;
	struct fruit_config_data *config = NULL;
	struct smb_filename *smb_fname_base = NULL;
	int baseflags;
	int hostfd = -1;
	struct adouble *ad = NULL;

	DEBUG(10, ("fruit_open_meta for %s\n", smb_fname_str_dbg(smb_fname)));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->meta == FRUIT_META_STREAM) {
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	/* Create an smb_filename with stream_name == NULL. */
	smb_fname_base = synthetic_smb_fname(talloc_tos(),
					     smb_fname->base_name, NULL, NULL);

	if (smb_fname_base == NULL) {
		errno = ENOMEM;
		rc = -1;
		goto exit;
	}

	/*
	 * We use baseflags to turn off nasty side-effects when opening the
	 * underlying file.
	 */
	baseflags = flags;
	baseflags &= ~O_TRUNC;
	baseflags &= ~O_EXCL;
	baseflags &= ~O_CREAT;

	hostfd = SMB_VFS_OPEN(handle->conn, smb_fname_base, fsp,
			      baseflags, mode);

	/*
	 * It is legit to open a stream on a directory, but the base
	 * fd has to be read-only.
	 */
	if ((hostfd == -1) && (errno == EISDIR)) {
		baseflags &= ~O_ACCMODE;
		baseflags |= O_RDONLY;
		hostfd = SMB_VFS_OPEN(handle->conn, smb_fname_base, fsp,
				      baseflags, mode);
	}

	TALLOC_FREE(smb_fname_base);

	if (hostfd == -1) {
		rc = -1;
		goto exit;
	}

	if (flags & (O_CREAT | O_TRUNC)) {
		/*
		 * The attribute does not exist or needs to be truncated,
		 * create an AppleDouble EA
		 */
		ad = ad_init(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
			     handle, ADOUBLE_META, fsp);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}

		rc = ad_write(ad, smb_fname->base_name);
		if (rc != 0) {
			rc = -1;
			goto exit;
		}
	} else {
		ad = ad_alloc(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
			      handle, ADOUBLE_META, fsp);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		if (ad_read(ad, smb_fname->base_name) == -1) {
			rc = -1;
			goto exit;
		}
	}

exit:
	DEBUG(10, ("fruit_open meta rc=%d, fd=%d\n", rc, hostfd));
	if (rc != 0) {
		int saved_errno = errno;
		if (hostfd >= 0) {
			/*
			 * BUGBUGBUG -- we would need to call
			 * fd_close_posix here, but we don't have a
			 * full fsp yet
			 */
			fsp->fh->fd = hostfd;
			SMB_VFS_CLOSE(fsp);
		}
		hostfd = -1;
		errno = saved_errno;
	}
	return hostfd;
}

static int fruit_open_rsrc(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   files_struct *fsp, int flags, mode_t mode)
{
	int rc = 0;
	struct fruit_config_data *config = NULL;
	struct adouble *ad = NULL;
	struct smb_filename *smb_fname_base = NULL;
	char *adpath = NULL;
	int hostfd = -1;

	DEBUG(10, ("fruit_open_rsrc for %s\n", smb_fname_str_dbg(smb_fname)));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (config->rsrc) {
	case FRUIT_RSRC_STREAM:
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	case FRUIT_RSRC_XATTR:
#ifdef HAVE_ATTROPEN
		hostfd = attropen(smb_fname->base_name,
				  AFPRESOURCE_EA_NETATALK, flags, mode);
		if (hostfd == -1) {
			return -1;
		}
		ad = ad_init(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
			     handle, ADOUBLE_RSRC, fsp);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		goto exit;
#else
		errno = ENOTSUP;
		return -1;
#endif
	default:
		break;
	}

	if (!(flags & O_CREAT) && !VALID_STAT(smb_fname->st)) {
		rc = SMB_VFS_NEXT_STAT(handle, smb_fname);
		if (rc != 0) {
			rc = -1;
			goto exit;
		}
	}

	if (VALID_STAT(smb_fname->st) && S_ISDIR(smb_fname->st.st_ex_mode)) {
		/* sorry, but directories don't habe a resource fork */
		rc = -1;
		goto exit;
	}

	rc = adouble_path(talloc_tos(), smb_fname->base_name, &adpath);
	if (rc != 0) {
		goto exit;
	}

	/* Create an smb_filename with stream_name == NULL. */
	smb_fname_base = synthetic_smb_fname(talloc_tos(),
					     adpath, NULL, NULL);
	if (smb_fname_base == NULL) {
		errno = ENOMEM;
		rc = -1;
		goto exit;
	}

	/* Sanitize flags */
	if (flags & O_WRONLY) {
		/* We always need read access for the metadata header too */
		flags &= ~O_WRONLY;
		flags |= O_RDWR;
	}

	hostfd = SMB_VFS_OPEN(handle->conn, smb_fname_base, fsp,
			      flags, mode);
	if (hostfd == -1) {
		rc = -1;
		goto exit;
	}

	/* REVIEW: we need this in ad_write() */
	fsp->fh->fd = hostfd;

	if (flags & (O_CREAT | O_TRUNC)) {
		ad = ad_init(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
			     handle, ADOUBLE_RSRC, fsp);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		rc = ad_write(ad, smb_fname->base_name);
		if (rc != 0) {
			rc = -1;
			goto exit;
		}
	} else {
		ad = ad_alloc(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
			      handle, ADOUBLE_RSRC, fsp);
		if (ad == NULL) {
			rc = -1;
			goto exit;
		}
		if (ad_read(ad, smb_fname->base_name) == -1) {
			rc = -1;
			goto exit;
		}
	}

exit:

	TALLOC_FREE(adpath);
	TALLOC_FREE(smb_fname_base);

	DEBUG(10, ("fruit_open resource fork: rc=%d, fd=%d\n", rc, hostfd));
	if (rc != 0) {
		int saved_errno = errno;
		if (hostfd >= 0) {
			/*
			 * BUGBUGBUG -- we would need to call
			 * fd_close_posix here, but we don't have a
			 * full fsp yet
			 */
			fsp->fh->fd = hostfd;
			SMB_VFS_CLOSE(fsp);
		}
		hostfd = -1;
		errno = saved_errno;
	}
	return hostfd;
}

static int fruit_open(vfs_handle_struct *handle,
                      struct smb_filename *smb_fname,
                      files_struct *fsp, int flags, mode_t mode)
{
	DEBUG(10, ("fruit_open called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	if (!is_ntfs_stream_smb_fname(smb_fname)) {
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	if (is_afpinfo_stream(smb_fname)) {
		return fruit_open_meta(handle, smb_fname, fsp, flags, mode);
	} else if (is_afpresource_stream(smb_fname)) {
		return fruit_open_rsrc(handle, smb_fname, fsp, flags, mode);
	}

	return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
}

static int fruit_rename(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_src,
			const struct smb_filename *smb_fname_dst)
{
	int rc = -1;
	char *src_adouble_path = NULL;
	char *dst_adouble_path = NULL;
	struct fruit_config_data *config = NULL;

	rc = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);

	if (!VALID_STAT(smb_fname_src->st)
	    || !S_ISREG(smb_fname_src->st.st_ex_mode)) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		return rc;
	}

	rc = adouble_path(talloc_tos(), smb_fname_src->base_name,
			  &src_adouble_path);
	if (rc != 0) {
		goto done;
	}
	rc = adouble_path(talloc_tos(), smb_fname_dst->base_name,
			  &dst_adouble_path);
	if (rc != 0) {
		goto done;
	}

	DEBUG(10, ("fruit_rename: %s -> %s\n",
		   src_adouble_path, dst_adouble_path));

	rc = rename(src_adouble_path, dst_adouble_path);
	if (errno == ENOENT) {
		rc = 0;
	}

	TALLOC_FREE(src_adouble_path);
	TALLOC_FREE(dst_adouble_path);

done:
	return rc;
}

static int fruit_unlink(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int rc = -1;
	struct fruit_config_data *config = NULL;
	char *adp = NULL;

	if (!is_ntfs_stream_smb_fname(smb_fname)) {
		return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (is_afpinfo_stream(smb_fname)) {
		if (config->meta == FRUIT_META_STREAM) {
			rc = SMB_VFS_NEXT_UNLINK(handle, smb_fname);
		} else {
			rc = SMB_VFS_REMOVEXATTR(handle->conn,
						 smb_fname->base_name,
						 AFPINFO_EA_NETATALK);
		}
	} else if (is_afpresource_stream(smb_fname)) {
		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			rc = adouble_path(talloc_tos(),
					  smb_fname->base_name, &adp);
			if (rc != 0) {
				return -1;
			}
			/* FIXME: direct unlink(), missing smb_fname */
			rc = unlink(adp);
			if ((rc == -1) && (errno == ENOENT)) {
				rc = 0;
			}
		} else {
			rc = SMB_VFS_REMOVEXATTR(handle->conn,
                                     smb_fname->base_name,
                                     AFPRESOURCE_EA_NETATALK);
		}
	} else {
		rc = SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	}

	TALLOC_FREE(adp);
	return rc;
}

static int fruit_chmod(vfs_handle_struct *handle,
		       const char *path,
		       mode_t mode)
{
	int rc = -1;
	char *adp = NULL;
	struct fruit_config_data *config = NULL;
	SMB_STRUCT_STAT sb;

	rc = SMB_VFS_NEXT_CHMOD(handle, path, mode);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		return 0;
	}

	/* FIXME: direct sys_lstat(), missing smb_fname */
	rc = sys_lstat(path, &sb, false);
	if (rc != 0 || !S_ISREG(sb.st_ex_mode)) {
		return rc;
	}

	rc = adouble_path(talloc_tos(), path, &adp);
	if (rc != 0) {
		return -1;
	}

	DEBUG(10, ("fruit_chmod: %s\n", adp));

	rc = SMB_VFS_NEXT_CHMOD(handle, adp, mode);
	if (errno == ENOENT) {
		rc = 0;
	}

	TALLOC_FREE(adp);
	return rc;
}

static int fruit_chown(vfs_handle_struct *handle,
		       const char *path,
		       uid_t uid,
		       gid_t gid)
{
	int rc = -1;
	char *adp = NULL;
	struct fruit_config_data *config = NULL;
	SMB_STRUCT_STAT sb;

	rc = SMB_VFS_NEXT_CHOWN(handle, path, uid, gid);
	if (rc != 0) {
		return rc;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_XATTR) {
		return rc;
	}

	/* FIXME: direct sys_lstat(), missing smb_fname */
	rc = sys_lstat(path, &sb, false);
	if (rc != 0 || !S_ISREG(sb.st_ex_mode)) {
		return rc;
	}

	rc = adouble_path(talloc_tos(), path, &adp);
	if (rc != 0) {
		goto done;
	}

	DEBUG(10, ("fruit_chown: %s\n", adp));

	rc = SMB_VFS_NEXT_CHOWN(handle, adp, uid, gid);
	if (errno == ENOENT) {
		rc = 0;
	}

 done:
	TALLOC_FREE(adp);
	return rc;
}

static int fruit_rmdir(struct vfs_handle_struct *handle, const char *path)
{
	DIR *dh = NULL;
	struct dirent *de;
	struct fruit_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (!handle->conn->cwd || !path || (config->rsrc == FRUIT_RSRC_XATTR)) {
		goto exit_rmdir;
	}

	/*
	 * Due to there is no way to change bDeleteVetoFiles variable
	 * from this module, need to clean up ourselves
	 */
	dh = opendir(path);
	if (dh == NULL) {
		goto exit_rmdir;
	}

	while ((de = readdir(dh)) != NULL) {
		if ((strncmp(de->d_name,
			     ADOUBLE_NAME_PREFIX,
			     strlen(ADOUBLE_NAME_PREFIX))) == 0) {
			char *p = talloc_asprintf(talloc_tos(),
						  "%s/%s",
						  path, de->d_name);
			if (p == NULL) {
				goto exit_rmdir;
			}
			DEBUG(10, ("fruit_rmdir: delete %s\n", p));
			(void)unlink(p);
			TALLOC_FREE(p);
		}
	}

exit_rmdir:
	if (dh) {
		closedir(dh);
	}
	return SMB_VFS_NEXT_RMDIR(handle, path);
}

static ssize_t fruit_pread(vfs_handle_struct *handle,
			   files_struct *fsp, void *data,
			   size_t n, off_t offset)
{
	int rc = 0;
        struct adouble *ad = (struct adouble *)VFS_FETCH_FSP_EXTENSION(
		handle, fsp);
	struct fruit_config_data *config = NULL;
	AfpInfo *ai = NULL;
	ssize_t len;
	char *name = NULL;
	char *tmp_base_name = NULL;
	NTSTATUS status;

	DEBUG(10, ("fruit_pread: offset=%d, size=%d\n", (int)offset, (int)n));

	if (!fsp->base_fsp) {
		return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	/* fsp_name is not converted with vfs_catia */
	tmp_base_name = fsp->base_fsp->fsp_name->base_name;
	status = SMB_VFS_TRANSLATE_NAME(handle->conn,
					fsp->base_fsp->fsp_name->base_name,
					vfs_translate_to_unix,
					talloc_tos(), &name);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		rc = -1;
		goto exit;
	}
	fsp->base_fsp->fsp_name->base_name = name;

	if (ad == NULL) {
		len = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
		if (len == -1) {
			rc = -1;
			goto exit;
		}
		goto exit;
	}

	if (!fruit_fsp_recheck(ad, fsp)) {
		rc = -1;
		goto exit;
	}

	if (ad->ad_type == ADOUBLE_META) {
		ai = afpinfo_new(talloc_tos());
		if (ai == NULL) {
			rc = -1;
			goto exit;
		}

		len = ad_read(ad, fsp->base_fsp->fsp_name->base_name);
		if (len == -1) {
			rc = -1;
			goto exit;
		}

		memcpy(&ai->afpi_FinderInfo[0],
		       ad_entry(ad, ADEID_FINDERI),
		       ADEDLEN_FINDERI);
		len = afpinfo_pack(ai, data);
		if (len != AFP_INFO_SIZE) {
			rc = -1;
			goto exit;
		}
	} else {
		len = SMB_VFS_NEXT_PREAD(
			handle, fsp, data, n,
			offset + ad_getentryoff(ad, ADEID_RFORK));
		if (len == -1) {
			rc = -1;
			goto exit;
		}
	}
exit:
	fsp->base_fsp->fsp_name->base_name = tmp_base_name;
	TALLOC_FREE(name);
	TALLOC_FREE(ai);
	if (rc != 0) {
		len = -1;
	}
	DEBUG(10, ("fruit_pread: rc=%d, len=%zd\n", rc, len));
	return len;
}

static ssize_t fruit_pwrite(vfs_handle_struct *handle,
			    files_struct *fsp, const void *data,
			    size_t n, off_t offset)
{
	int rc = 0;
	struct adouble *ad = (struct adouble *)VFS_FETCH_FSP_EXTENSION(
		handle, fsp);
	struct fruit_config_data *config = NULL;
	AfpInfo *ai = NULL;
	ssize_t len, new_rfork_size;
	char *name = NULL;
	char *tmp_base_name = NULL;
	NTSTATUS status;

	DEBUG(10, ("fruit_pwrite: offset=%d, size=%d\n", (int)offset, (int)n));

	if (!fsp->base_fsp) {
		return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	tmp_base_name = fsp->base_fsp->fsp_name->base_name;
	status = SMB_VFS_TRANSLATE_NAME(handle->conn,
					fsp->base_fsp->fsp_name->base_name,
					vfs_translate_to_unix,
					talloc_tos(), &name);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		rc = -1;
		goto exit;
	}
	fsp->base_fsp->fsp_name->base_name = name;

	if (ad == NULL) {
		len = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
		if (len != n) {
			rc = -1;
			goto exit;
		}
		goto exit;
	}

	if (!fruit_fsp_recheck(ad, fsp)) {
		rc = -1;
		goto exit;
	}

	if (ad->ad_type == ADOUBLE_META) {
		if (n != AFP_INFO_SIZE || offset != 0) {
			DEBUG(1, ("unexpected offset=%jd or size=%jd\n",
				  (intmax_t)offset, (intmax_t)n));
			rc = -1;
			goto exit;
		}
		ai = afpinfo_unpack(talloc_tos(), data);
		if (ai == NULL) {
			rc = -1;
			goto exit;
		}
		memcpy(ad_entry(ad, ADEID_FINDERI),
		       &ai->afpi_FinderInfo[0], ADEDLEN_FINDERI);
		rc = ad_write(ad, name);
	} else {
		len = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n,
                                   offset + ad_getentryoff(ad, ADEID_RFORK));
		if (len != n) {
			rc = -1;
			goto exit;
		}

		if (config->rsrc == FRUIT_RSRC_ADFILE) {
			rc = ad_read(ad, name);
			if (rc == -1) {
				rc = -1;
				goto exit;
			}
			rc = 0;

			new_rfork_size = len + offset
				+ ad_getentryoff(ad, ADEID_RFORK);
			if (new_rfork_size > ad_getentrylen(ad, ADEID_RFORK)) {
				ad_setentrylen(ad, ADEID_RFORK,
					       new_rfork_size);
				rc = ad_write(ad, name);
			}
		}
	}

exit:
	fsp->base_fsp->fsp_name->base_name = tmp_base_name;
	TALLOC_FREE(name);
	TALLOC_FREE(ai);
	if (rc != 0) {
		return -1;
	}
	return n;
}

/**
 * Helper to stat/lstat the base file of an smb_fname.
 */
static int fruit_stat_base(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)
{
	char *tmp_stream_name;
	int rc;

	tmp_stream_name = smb_fname->stream_name;
	smb_fname->stream_name = NULL;
	if (follow_links) {
		rc = SMB_VFS_NEXT_STAT(handle, smb_fname);
	} else {
		rc = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}
	smb_fname->stream_name = tmp_stream_name;
	return rc;
}

static int fruit_stat_meta(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)
{
	/* Populate the stat struct with info from the base file. */
	if (fruit_stat_base(handle, smb_fname, follow_links) == -1) {
		return -1;
	}
	smb_fname->st.st_ex_size = AFP_INFO_SIZE;
	smb_fname->st.st_ex_ino = fruit_inode(&smb_fname->st,
					      smb_fname->stream_name);
	return 0;
}

static int fruit_stat_rsrc(vfs_handle_struct *handle,
			   struct smb_filename *smb_fname,
			   bool follow_links)

{
	struct adouble *ad = NULL;

	DEBUG(10, ("fruit_stat_rsrc called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	ad = ad_get(talloc_tos(), handle, smb_fname->base_name, ADOUBLE_RSRC);
	if (ad == NULL) {
		errno = ENOENT;
		return -1;
	}

	/* Populate the stat struct with info from the base file. */
	if (fruit_stat_base(handle, smb_fname, follow_links) == -1) {
		TALLOC_FREE(ad);
		return -1;
	}

	smb_fname->st.st_ex_size = ad_getentrylen(ad, ADEID_RFORK);
	smb_fname->st.st_ex_ino = fruit_inode(&smb_fname->st,
					      smb_fname->stream_name);
	TALLOC_FREE(ad);
	return 0;
}

static int fruit_stat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	int rc = -1;

	DEBUG(10, ("fruit_stat called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	if (!is_ntfs_stream_smb_fname(smb_fname)
	    || is_ntfs_default_stream_smb_fname(smb_fname)) {
		rc = SMB_VFS_NEXT_STAT(handle, smb_fname);
		if (rc == 0) {
			update_btime(handle, smb_fname);
		}
		return rc;
	}

	/*
	 * Note if lp_posix_paths() is true, we can never
	 * get here as is_ntfs_stream_smb_fname() is
	 * always false. So we never need worry about
	 * not following links here.
	 */

	if (is_afpinfo_stream(smb_fname)) {
		rc = fruit_stat_meta(handle, smb_fname, true);
	} else if (is_afpresource_stream(smb_fname)) {
		rc = fruit_stat_rsrc(handle, smb_fname, true);
	} else {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	if (rc == 0) {
		update_btime(handle, smb_fname);
		smb_fname->st.st_ex_mode &= ~S_IFMT;
		smb_fname->st.st_ex_mode |= S_IFREG;
		smb_fname->st.st_ex_blocks =
			smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}
	return rc;
}

static int fruit_lstat(vfs_handle_struct *handle,
		       struct smb_filename *smb_fname)
{
	int rc = -1;

	DEBUG(10, ("fruit_lstat called for %s\n",
		   smb_fname_str_dbg(smb_fname)));

	if (!is_ntfs_stream_smb_fname(smb_fname)
	    || is_ntfs_default_stream_smb_fname(smb_fname)) {
		rc = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
		if (rc == 0) {
			update_btime(handle, smb_fname);
		}
		return rc;
	}

	if (is_afpinfo_stream(smb_fname)) {
		rc = fruit_stat_meta(handle, smb_fname, false);
	} else if (is_afpresource_stream(smb_fname)) {
		rc = fruit_stat_rsrc(handle, smb_fname, false);
	} else {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	if (rc == 0) {
		update_btime(handle, smb_fname);
		smb_fname->st.st_ex_mode &= ~S_IFMT;
		smb_fname->st.st_ex_mode |= S_IFREG;
		smb_fname->st.st_ex_blocks =
			smb_fname->st.st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}
	return rc;
}

static int fruit_fstat_meta(vfs_handle_struct *handle,
			    files_struct *fsp,
			    SMB_STRUCT_STAT *sbuf)
{
	DEBUG(10, ("fruit_fstat_meta called for %s\n",
		   smb_fname_str_dbg(fsp->base_fsp->fsp_name)));

	/* Populate the stat struct with info from the base file. */
	if (fruit_stat_base(handle, fsp->base_fsp->fsp_name, false) == -1) {
		return -1;
	}
	*sbuf = fsp->base_fsp->fsp_name->st;
	sbuf->st_ex_size = AFP_INFO_SIZE;
	sbuf->st_ex_ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);

	return 0;
}

static int fruit_fstat_rsrc(vfs_handle_struct *handle, files_struct *fsp,
			    SMB_STRUCT_STAT *sbuf)
{
	struct fruit_config_data *config;
	struct adouble *ad = (struct adouble *)VFS_FETCH_FSP_EXTENSION(
		handle, fsp);

	DEBUG(10, ("fruit_fstat_rsrc called for %s\n",
		   smb_fname_str_dbg(fsp->base_fsp->fsp_name)));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	if (config->rsrc == FRUIT_RSRC_STREAM) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	/* Populate the stat struct with info from the base file. */
	if (fruit_stat_base(handle, fsp->base_fsp->fsp_name, false) == -1) {
		return -1;
	}
	*sbuf = fsp->base_fsp->fsp_name->st;
	sbuf->st_ex_size = ad_getentrylen(ad, ADEID_RFORK);
	sbuf->st_ex_ino = fruit_inode(sbuf, fsp->fsp_name->stream_name);

	DEBUG(10, ("fruit_fstat_rsrc %s, size: %zd\n",
		   smb_fname_str_dbg(fsp->fsp_name),
		   (ssize_t)sbuf->st_ex_size));

	return 0;
}

static int fruit_fstat(vfs_handle_struct *handle, files_struct *fsp,
		       SMB_STRUCT_STAT *sbuf)
{
	int rc;
	char *name = NULL;
	char *tmp_base_name = NULL;
	NTSTATUS status;
	struct adouble *ad = (struct adouble *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);

	DEBUG(10, ("fruit_fstat called for %s\n",
		   smb_fname_str_dbg(fsp->fsp_name)));

	if (fsp->base_fsp) {
		tmp_base_name = fsp->fsp_name->base_name;
		/* fsp_name is not converted with vfs_catia */
		status = SMB_VFS_TRANSLATE_NAME(
			handle->conn,
			fsp->base_fsp->fsp_name->base_name,
			vfs_translate_to_unix,
			talloc_tos(), &name);

		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			rc = -1;
			goto exit;
		}
		fsp->base_fsp->fsp_name->base_name = name;
	}

	if (ad == NULL || fsp->base_fsp == NULL) {
		rc = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
		goto exit;
	}

	if (!fruit_fsp_recheck(ad, fsp)) {
		rc = -1;
		goto exit;
	}

	switch (ad->ad_type) {
	case ADOUBLE_META:
		rc = fruit_fstat_meta(handle, fsp, sbuf);
		break;
	case ADOUBLE_RSRC:
		rc = fruit_fstat_rsrc(handle, fsp, sbuf);
		break;
	default:
		DEBUG(10, ("fruit_fstat %s: bad type\n",
			   smb_fname_str_dbg(fsp->fsp_name)));
		rc = -1;
		goto exit;
	}

	if (rc == 0) {
		sbuf->st_ex_mode &= ~S_IFMT;
		sbuf->st_ex_mode |= S_IFREG;
		sbuf->st_ex_blocks = sbuf->st_ex_size / STAT_ST_BLOCKSIZE + 1;
	}

exit:
	DEBUG(10, ("fruit_fstat %s, size: %zd\n",
		   smb_fname_str_dbg(fsp->fsp_name),
		   (ssize_t)sbuf->st_ex_size));
	if (tmp_base_name) {
		fsp->base_fsp->fsp_name->base_name = tmp_base_name;
	}
	TALLOC_FREE(name);
	return rc;
}

static NTSTATUS fruit_streaminfo(vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *fname,
				 TALLOC_CTX *mem_ctx,
				 unsigned int *pnum_streams,
				 struct stream_struct **pstreams)
{
	struct fruit_config_data *config = NULL;
	struct smb_filename *smb_fname = NULL;
	struct adouble *ad = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);
	DEBUG(10, ("fruit_streaminfo called for %s\n", fname));

	smb_fname = synthetic_smb_fname(talloc_tos(), fname, NULL, NULL);
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (config->meta == FRUIT_META_NETATALK) {
		ad = ad_get(talloc_tos(), handle,
			    smb_fname->base_name, ADOUBLE_META);
		if (ad && !empty_finderinfo(ad)) {
			if (!add_fruit_stream(
				    mem_ctx, pnum_streams, pstreams,
				    AFPINFO_STREAM_NAME, AFP_INFO_SIZE,
				    smb_roundup(handle->conn,
						AFP_INFO_SIZE))) {
				TALLOC_FREE(ad);
				TALLOC_FREE(smb_fname);
				return NT_STATUS_NO_MEMORY;
			}
		}
		TALLOC_FREE(ad);
	}

	if (config->rsrc != FRUIT_RSRC_STREAM) {
		ad = ad_get(talloc_tos(), handle, smb_fname->base_name,
			    ADOUBLE_RSRC);
		if (ad) {
			if (!add_fruit_stream(
				    mem_ctx, pnum_streams, pstreams,
				    AFPRESOURCE_STREAM_NAME,
				    ad_getentrylen(ad, ADEID_RFORK),
				    smb_roundup(handle->conn,
						ad_getentrylen(
							ad, ADEID_RFORK)))) {
				TALLOC_FREE(ad);
				TALLOC_FREE(smb_fname);
				return NT_STATUS_NO_MEMORY;
			}
		}
		TALLOC_FREE(ad);
	}

	TALLOC_FREE(smb_fname);

	return SMB_VFS_NEXT_STREAMINFO(handle, fsp, fname, mem_ctx,
				       pnum_streams, pstreams);
}

static int fruit_ntimes(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct smb_file_time *ft)
{
	int rc = 0;
	struct adouble *ad = NULL;

	if (null_timespec(ft->create_time)) {
		goto exit;
	}

	DEBUG(10,("set btime for %s to %s\n", smb_fname_str_dbg(smb_fname),
		 time_to_asc(convert_timespec_to_time_t(ft->create_time))));

	ad = ad_get(talloc_tos(), handle, smb_fname->base_name, ADOUBLE_META);
	if (ad == NULL) {
		goto exit;
	}

	ad_setdate(ad, AD_DATE_CREATE | AD_DATE_UNIX,
		   convert_time_t_to_uint32_t(ft->create_time.tv_sec));

	rc = ad_write(ad, smb_fname->base_name);

exit:

	TALLOC_FREE(ad);
	if (rc != 0) {
		DEBUG(1, ("fruit_ntimes: %s\n", smb_fname_str_dbg(smb_fname)));
		return -1;
	}
	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int fruit_fallocate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   enum vfs_fallocate_mode mode,
			   off_t offset,
			   off_t len)
{
        struct adouble *ad =
		(struct adouble *)VFS_FETCH_FSP_EXTENSION(handle, fsp);

	if (ad == NULL) {
		return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	}

	if (!fruit_fsp_recheck(ad, fsp)) {
		return errno;
	}

	/* Let the pwrite code path handle it. */
	return ENOSYS;
}

static int fruit_ftruncate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   off_t offset)
{
	int rc = 0;
        struct adouble *ad =
		(struct adouble *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	struct fruit_config_data *config;

	DEBUG(10, ("streams_xattr_ftruncate called for file %s offset %.0f\n",
		   fsp_str_dbg(fsp), (double)offset));

	if (ad == NULL) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
	}

	if (!fruit_fsp_recheck(ad, fsp)) {
		return -1;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct fruit_config_data, return -1);

	switch (ad->ad_type) {
	case ADOUBLE_META:
		/*
		 * As this request hasn't been seen in the wild,
		 * the only sensible use I can imagine is the client
		 * truncating the stream to 0 bytes size.
		 * We simply remove the metadata on such a request.
		 */
		if (offset == 0) {
			rc = SMB_VFS_FREMOVEXATTR(fsp,
						  AFPRESOURCE_EA_NETATALK);
		}
		break;
	case ADOUBLE_RSRC:
		if (config->rsrc == FRUIT_RSRC_XATTR && offset == 0) {
			rc = SMB_VFS_FREMOVEXATTR(fsp,
						  AFPRESOURCE_EA_NETATALK);
		} else {
			rc = SMB_VFS_NEXT_FTRUNCATE(
				handle, fsp,
				offset + ad_getentryoff(ad, ADEID_RFORK));
		}
		break;
	default:
		return -1;
	}

	return rc;
}

static NTSTATUS fruit_create_file(vfs_handle_struct *handle,
				  struct smb_request *req,
				  uint16_t root_dir_fid,
				  struct smb_filename *smb_fname,
				  uint32_t access_mask,
				  uint32_t share_access,
				  uint32_t create_disposition,
				  uint32_t create_options,
				  uint32_t file_attributes,
				  uint32_t oplock_request,
				  struct smb2_lease *lease,
				  uint64_t allocation_size,
				  uint32_t private_flags,
				  struct security_descriptor *sd,
				  struct ea_list *ea_list,
				  files_struct **result,
				  int *pinfo)
{
	NTSTATUS status;
	struct fruit_config_data *config = NULL;

	status = SMB_VFS_NEXT_CREATE_FILE(
		handle, req, root_dir_fid, smb_fname,
		access_mask, share_access,
		create_disposition, create_options,
		file_attributes, oplock_request,
		lease,
		allocation_size, private_flags,
		sd, ea_list, result,
		pinfo);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (is_ntfs_stream_smb_fname(smb_fname)
	    || (*result == NULL)
	    || ((*result)->is_directory)) {
		return status;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct fruit_config_data,
				return NT_STATUS_UNSUCCESSFUL);

	if (config->locking == FRUIT_LOCKING_NETATALK) {
		status = fruit_check_access(
			handle, *result,
			access_mask,
			map_share_mode_to_deny_mode(share_access, 0));
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	return status;

fail:
	DEBUG(1, ("fruit_create_file: %s\n", nt_errstr(status)));

	if (*result) {
		close_file(req, *result, ERROR_CLOSE);
		*result = NULL;
	}

	return status;
}

static struct vfs_fn_pointers vfs_fruit_fns = {
	.connect_fn = fruit_connect,

	/* File operations */
	.chmod_fn = fruit_chmod,
	.chown_fn = fruit_chown,
	.unlink_fn = fruit_unlink,
	.rename_fn = fruit_rename,
	.rmdir_fn = fruit_rmdir,
	.open_fn = fruit_open,
	.pread_fn = fruit_pread,
	.pwrite_fn = fruit_pwrite,
	.stat_fn = fruit_stat,
	.lstat_fn = fruit_lstat,
	.fstat_fn = fruit_fstat,
	.streaminfo_fn = fruit_streaminfo,
	.ntimes_fn = fruit_ntimes,
	.unlink_fn = fruit_unlink,
	.ftruncate_fn = fruit_ftruncate,
	.fallocate_fn = fruit_fallocate,
	.create_file_fn = fruit_create_file,
};

NTSTATUS vfs_fruit_init(void);
NTSTATUS vfs_fruit_init(void)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "fruit",
					&vfs_fruit_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_fruit_debug_level = debug_add_class("fruit");
	if (vfs_fruit_debug_level == -1) {
		vfs_fruit_debug_level = DBGC_VFS;
		DEBUG(0, ("%s: Couldn't register custom debugging class!\n",
			  "vfs_fruit_init"));
	} else {
		DEBUG(10, ("%s: Debug class number of '%s': %d\n",
			   "vfs_fruit_init","fruit",vfs_fruit_debug_level));
	}

	return ret;
}
