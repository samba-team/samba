/*
    SSSD

    ID-mapping library - conversion utilities

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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "sss_idmap.h"
#include "sss_idmap_private.h"
//#include "util/util.h"
//#include "util/sss_endian.h"
#include "util.h"

#define SID_ID_AUTHS 6
#define SID_SUB_AUTHS 15
struct sss_dom_sid {
        uint8_t sid_rev_num;
        int8_t num_auths;                  /* [range(0,15)] */
        uint8_t id_auth[SID_ID_AUTHS];     /* highest order byte has index 0 */
        uint32_t sub_auths[SID_SUB_AUTHS]; /* host byte-order */
};

enum idmap_error_code sss_idmap_bin_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct sss_dom_sid **_dom_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid;
    size_t i = 0;
    size_t p = 0;
    uint32_t val;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (length > sizeof(struct sss_dom_sid)) return IDMAP_SID_INVALID;

    dom_sid = ctx->alloc_func(sizeof(struct sss_dom_sid), ctx->alloc_pvt);
    if (dom_sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom_sid, 0, sizeof(struct sss_dom_sid));

    /* Safely copy in the SID revision number */
    dom_sid->sid_rev_num = (uint8_t) *(bin_sid + p);
    p++;

    /* Safely copy in the number of sub auth values */
    dom_sid->num_auths = (uint8_t) *(bin_sid + p);
    p++;

    /* Make sure we aren't being told to read more bin_sid
     * than can fit in the structure
     */
    if (dom_sid->num_auths > SID_SUB_AUTHS) {
        err = IDMAP_SID_INVALID;
        goto done;
    }

    /* Safely copy in the id_auth values */
    for (i = 0; i < SID_ID_AUTHS; i++) {
        dom_sid->id_auth[i] = (uint8_t) *(bin_sid + p);
        p++;
    }

    /* Safely copy in the sub_auths values */
    for (i = 0; i < dom_sid->num_auths; i++) {
        /* SID sub auth values in Active Directory are stored little-endian,
         * we store them in host order */
        SAFEALIGN_COPY_UINT32(&val, bin_sid + p, &p);
        dom_sid->sub_auths[i] = le32toh(val);
    }

    *_dom_sid = dom_sid;
    err = IDMAP_SUCCESS;

done:
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(dom_sid, ctx->alloc_pvt);
    }
    return err;
}

enum idmap_error_code sss_idmap_dom_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   uint8_t **_bin_sid,
                                                   size_t *_length)
{
    enum idmap_error_code err;
    uint8_t *bin_sid;
    size_t length;
    size_t i = 0;
    size_t p = 0;
    uint32_t val;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (dom_sid->num_auths > SID_SUB_AUTHS) {
        return IDMAP_SID_INVALID;
    }

    length = 2 + SID_ID_AUTHS + dom_sid->num_auths * 4;

    bin_sid = ctx->alloc_func(length, ctx->alloc_pvt);
    if (bin_sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }

    bin_sid[p] = dom_sid->sid_rev_num;
    p++;

    bin_sid[p] = dom_sid->num_auths;
    p++;

    for (i = 0; i < SID_ID_AUTHS; i++) {
        bin_sid[p] = dom_sid->id_auth[i];
        p++;
    }

    for (i = 0; i < dom_sid->num_auths; i++) {
        if (p + sizeof(uint32_t) > length) {
            err = IDMAP_SID_INVALID;
            goto done;
        }
        val = htole32(dom_sid->sub_auths[i]);
        SAFEALIGN_COPY_UINT32(bin_sid + p, &val, &p);
    }

    *_bin_sid = bin_sid;
    *_length = length;

    err = IDMAP_SUCCESS;
done:
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(bin_sid, ctx->alloc_pvt);
    }
    return err;
}

enum idmap_error_code sss_idmap_dom_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct sss_dom_sid *dom_sid,
                                               char **_sid)
{
    enum idmap_error_code err;
    char *sid_buf;
    size_t sid_buf_len;
    char *p;
    int nc;
    int8_t i;
    uint32_t id_auth_val = 0;

    if (dom_sid->num_auths > SID_SUB_AUTHS) {
        return IDMAP_SID_INVALID;
    }

    sid_buf_len = 25 + dom_sid->num_auths * 11;
    sid_buf = ctx->alloc_func(sid_buf_len, ctx->alloc_pvt);
    if (sid_buf == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(sid_buf, 0, sid_buf_len);

    /* Only 32bits are used for the string representation */
    id_auth_val = (dom_sid->id_auth[2] << 24) +
                  (dom_sid->id_auth[3] << 16) +
                  (dom_sid->id_auth[4] << 8) +
                  (dom_sid->id_auth[5]);

    nc = snprintf(sid_buf, sid_buf_len, "S-%u-%lu", dom_sid->sid_rev_num,
                                                    (unsigned long) id_auth_val);
    if (nc < 0 || nc >= sid_buf_len) {
        err = IDMAP_SID_INVALID;
        goto done;
    }


    /* Loop through the sub-auths, if any, prepending a hyphen
     * for each one.
     */
    p = sid_buf;
    for (i = 0; i < dom_sid->num_auths ; i++) {
        p += nc;
        sid_buf_len -= nc;

        nc = snprintf(p, sid_buf_len, "-%lu",
                                      (unsigned long) dom_sid->sub_auths[i]);
        if (nc < 0 || nc >= sid_buf_len) {
            err = IDMAP_SID_INVALID;
            goto done;
        }
    }

    *_sid = sid_buf;
    err = IDMAP_SUCCESS;

done:
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(sid_buf, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct sss_dom_sid **_dom_sid)
{
    enum idmap_error_code err;
    unsigned long ul;
    char *r;
    char *end;
    struct sss_dom_sid *dom_sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (sid == NULL || (sid[0] != 'S' && sid[0] != 's') || sid[1] != '-') {
            return IDMAP_SID_INVALID;
    }

    dom_sid = ctx->alloc_func(sizeof(struct sss_dom_sid), ctx->alloc_pvt);
    if (dom_sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom_sid, 0, sizeof(struct sss_dom_sid));


    if (!isdigit(sid[2])) {
        err = IDMAP_SID_INVALID;
        goto done;
    }
    errno = 0;
    ul = strtoul(sid + 2, &r, 10);
    if (errno != 0 || r == NULL || *r != '-' || ul > UINT8_MAX) {
        err = IDMAP_SID_INVALID;
        goto done;
    }
    dom_sid->sid_rev_num = (uint8_t) ul;
    r++;

    if (!isdigit(*r)) {
        err = IDMAP_SID_INVALID;
        goto done;
    }
    errno = 0;
    ul = strtoul(r, &r, 10);
    if (errno != 0 || r == NULL || ul > UINT32_MAX) {
        err = IDMAP_SID_INVALID;
        goto done;
    }

    /* id_auth in the string should always be <2^32 in decimal */
    /* store values in the same order as the binary representation */
    dom_sid->id_auth[0] = 0;
    dom_sid->id_auth[1] = 0;
    dom_sid->id_auth[2] = (ul & 0xff000000) >> 24;
    dom_sid->id_auth[3] = (ul & 0x00ff0000) >> 16;
    dom_sid->id_auth[4] = (ul & 0x0000ff00) >> 8;
    dom_sid->id_auth[5] = (ul & 0x000000ff);

    if (*r == '\0') {
        /* no sub auths given */
        err = IDMAP_SUCCESS;
        goto done;
    }

    if (*r != '-') {
        err = IDMAP_SID_INVALID;
        goto done;
    }

    do {
        if (dom_sid->num_auths >= SID_SUB_AUTHS) {
            err = IDMAP_SID_INVALID;
            goto done;
        }

        r++;
        if (!isdigit(*r)) {
            err = IDMAP_SID_INVALID;
            goto done;
        }

        errno = 0;
        ul = strtoul(r, &end, 10);
        if (errno != 0 || ul > UINT32_MAX || end == NULL ||
            (*end != '\0' && *end != '-')) {
            err = IDMAP_SID_INVALID;
            goto done;
        }

        dom_sid->sub_auths[dom_sid->num_auths++] = ul;

        r = end;
    } while (*r != '\0');

    err = IDMAP_SUCCESS;

done:
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(dom_sid, ctx->alloc_pvt);
    } else {
        *_dom_sid = dom_sid;
    }

    return err;
}

enum idmap_error_code sss_idmap_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint8_t **_bin_sid,
                                               size_t *_length)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    size_t length;
    uint8_t *bin_sid = NULL;

    err = sss_idmap_sid_to_dom_sid(ctx, sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_bin_sid(ctx, dom_sid, &bin_sid, &length);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_length = length;
    *_bin_sid = bin_sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(bin_sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_bin_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               const uint8_t *bin_sid,
                                               size_t length,
                                               char **_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    char *sid = NULL;

    err = sss_idmap_bin_sid_to_dom_sid(ctx, bin_sid, length, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_sid = sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct dom_sid **_smb_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    struct dom_sid *smb_sid = NULL;

    err = sss_idmap_sid_to_dom_sid(ctx, sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_smb_sid(ctx, dom_sid, &smb_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_smb_sid = smb_sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(smb_sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_smb_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct dom_sid *smb_sid,
                                               char **_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    char *sid = NULL;

    err = sss_idmap_smb_sid_to_dom_sid(ctx, smb_sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_sid = sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_dom_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   struct dom_sid **_smb_sid)
{
    struct dom_sid *smb_sid;
    size_t c;

    smb_sid = ctx->alloc_func(sizeof(struct dom_sid), ctx->alloc_pvt);
    if (smb_sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(smb_sid, 0, sizeof(struct dom_sid));

    smb_sid->sid_rev_num = dom_sid->sid_rev_num;
    smb_sid->num_auths = dom_sid->num_auths;
    for (c = 0; c < SID_ID_AUTHS; c++) {
        smb_sid->id_auth[c] = dom_sid->id_auth[c];
    }
    for (c = 0; c < SID_SUB_AUTHS; c++) {
        smb_sid->sub_auths[c] = dom_sid->sub_auths[c];
    }

    *_smb_sid = smb_sid;

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_smb_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   struct sss_dom_sid **_dom_sid)
{
    struct sss_dom_sid *dom_sid;
    size_t c;

    dom_sid = ctx->alloc_func(sizeof(struct sss_dom_sid), ctx->alloc_pvt);
    if (dom_sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom_sid, 0, sizeof(struct sss_dom_sid));

    dom_sid->sid_rev_num = smb_sid->sid_rev_num;
    dom_sid->num_auths = smb_sid->num_auths;
    for (c = 0; c < SID_ID_AUTHS; c++) {
        dom_sid->id_auth[c] = smb_sid->id_auth[c];
    }
    for (c = 0; c < SID_SUB_AUTHS; c++) {
        dom_sid->sub_auths[c] = smb_sid->sub_auths[c];
    }

    *_dom_sid = dom_sid;

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_bin_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct dom_sid **_smb_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    struct dom_sid *smb_sid = NULL;

    err = sss_idmap_bin_sid_to_dom_sid(ctx, bin_sid, length, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_smb_sid(ctx, dom_sid, &smb_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_smb_sid = smb_sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(smb_sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_smb_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint8_t **_bin_sid,
                                                   size_t *_length)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    uint8_t *bin_sid = NULL;
    size_t length;

    err = sss_idmap_smb_sid_to_dom_sid(ctx, smb_sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_dom_sid_to_bin_sid(ctx, dom_sid, &bin_sid, &length);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_bin_sid = bin_sid;
    *_length = length;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(dom_sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(bin_sid, ctx->alloc_pvt);
    }

    return err;
}
