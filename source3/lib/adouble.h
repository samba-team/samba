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

#ifndef _ADOUBLE_H_
#define _ADOUBLE_H_

#include "MacExtensions.h"

#define ADOUBLE_NAME_PREFIX "._"

#define NETATALK_META_XATTR "org.netatalk.Metadata"
#define NETATALK_RSRC_XATTR "org.netatalk.ResourceFork"

#if defined(HAVE_ATTROPEN)
#define AFPINFO_EA_NETATALK NETATALK_META_XATTR
#define AFPRESOURCE_EA_NETATALK NETATALK_RSRC_XATTR
#else
#define AFPINFO_EA_NETATALK "user." NETATALK_META_XATTR
#define AFPRESOURCE_EA_NETATALK "user." NETATALK_RSRC_XATTR
#endif

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

/* AppleDouble magic */
#define AD_APPLESINGLE_MAGIC 0x00051600
#define AD_APPLEDOUBLE_MAGIC 0x00051607
#define AD_MAGIC             AD_APPLEDOUBLE_MAGIC

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
#define ADEDLEN_ICONBW          128
#define ADEDLEN_ICONCOL         1024
#define ADEDLEN_DID             4
#define ADEDLEN_PRIVDEV         8
#define ADEDLEN_PRIVINO         8
#define ADEDLEN_PRIVSYN         8
#define ADEDLEN_PRIVID          4

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

#define AD_CONV_WIPE_BLANK	(1<<0)
#define AD_CONV_DELETE		(1<<1)

struct adouble;

size_t ad_getentrylen(const struct adouble *ad, int eid);
size_t ad_getentryoff(const struct adouble *ad, int eid);
size_t ad_setentrylen(struct adouble *ad, int eid, size_t len);
size_t ad_setentryoff(struct adouble *ad, int eid, size_t off);
char *ad_get_entry(const struct adouble *ad, int eid);
int ad_getdate(const struct adouble *ad, unsigned int dateoff, uint32_t *date);
int ad_setdate(struct adouble *ad, unsigned int dateoff, uint32_t date);
int ad_convert(struct vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		const char *catia_mappings,
		uint32_t flags);
bool ad_unconvert(TALLOC_CTX *mem_ctx,
		  struct vfs_handle_struct *handle,
		  const char *catia_mappings,
		  struct smb_filename *smb_fname,
		  bool *converted);
struct adouble *ad_init(TALLOC_CTX *ctx, adouble_type_t type);
struct adouble *ad_get(TALLOC_CTX *ctx,
		       vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       adouble_type_t type);
struct adouble *ad_fget(TALLOC_CTX *ctx, vfs_handle_struct *handle,
			files_struct *fsp, adouble_type_t type);
int ad_set(vfs_handle_struct *handle,
	   struct adouble *ad,
	   const struct smb_filename *smb_fname);
int ad_fset(struct vfs_handle_struct *handle,
	    struct adouble *ad,
	    files_struct *fsp);
bool is_adouble_file(const char *path);
int adouble_path(TALLOC_CTX *ctx,
		 const struct smb_filename *smb_fname_in,
		 struct smb_filename **pp_smb_fname_out);

AfpInfo *afpinfo_new(TALLOC_CTX *ctx);
ssize_t afpinfo_pack(const AfpInfo *ai, char *buf);
AfpInfo *afpinfo_unpack(TALLOC_CTX *ctx, const void *data);

#endif
