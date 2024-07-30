/*
    SSSD

    ID-mapping library - private headers

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SSS_IDMAP_PRIVATE_H_
#define SSS_IDMAP_PRIVATE_H_

#define SSS_IDMAP_DEFAULT_LOWER 200000
#define SSS_IDMAP_DEFAULT_UPPER 2000200000
#define SSS_IDMAP_DEFAULT_RANGESIZE 200000
#define SSS_IDMAP_DEFAULT_AUTORID false
#define SSS_IDMAP_DEFAULT_EXTRA_SLICE_INIT 10

#define CHECK_IDMAP_CTX(ctx, ret) do { \
    if (ctx == NULL || ctx->alloc_func == NULL || ctx->free_func == NULL) { \
        return ret; \
    } \
} while(0)

struct sss_idmap_opts {
    /* true if autorid compatibility mode is used */
    bool autorid_mode;

    /* smallest available id (for all domains) */
    id_t idmap_lower;

    /* highest available id (for all domains) */
    id_t idmap_upper;

    /* number of available UIDs (for single domain) */
    id_t rangesize;

    /* maximal number of secondary slices */
    int extra_slice_init;
};

struct sss_idmap_ctx {
    idmap_alloc_func *alloc_func;
    void *alloc_pvt;
    idmap_free_func *free_func;
    struct sss_idmap_opts idmap_opts;
    struct idmap_domain_info *idmap_domain_info;
};

/* This is a copy of the definition in the samba gen_ndr/security.h header
 * file. We use it here to be able to offer conversions form struct dom_sid to
 * string or binary representation since those are not made available by
 * public samba libraries.
 *
 * If the definition ever changes on the samba side we have to adopt the
 * change. But chances are very low that this will ever happen since e.g. this
 * struct is also defined in public documentation from Microsoft. See e.g.
 * section 2.4.2.3 of "[MS-DTYP]: Windows Data Types"
 * http://msdn.microsoft.com/en-us/library/cc230364(v=prot.10)
 */

struct dom_sid {
        uint8_t sid_rev_num;
        int8_t num_auths;
        uint8_t id_auth[6];
        uint32_t sub_auths[15];
};

#endif /* SSS_IDMAP_PRIVATE_H_ */
