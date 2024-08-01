/*
    SSSD

    ID-mapping library

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
#include <inttypes.h>
#include <utf8proc.h>

#include "sss_idmap.h"
#include "sss_idmap_private.h"
#include "murmurhash3.h"

#define SID_FMT "%s-%"PRIu32
#define SID_STR_MAX_LEN 1024

/* Hold all parameters for unix<->sid mapping relevant for
 * given slice. */
struct idmap_range_params {
    uint32_t min_id;
    uint32_t max_id;
    char *range_id;

    uint32_t first_rid;
    struct idmap_range_params *next;
};

struct idmap_domain_info {
    char *name;
    char *sid;
    struct idmap_range_params range_params;
    struct idmap_domain_info *next;
    bool external_mapping;

    struct idmap_range_params *helpers;
    bool auto_add_ranges;
    bool helpers_owner;

    idmap_offset_func *offset_func;
    idmap_rev_offset_func *rev_offset_func;
    void *offset_func_pvt;

    idmap_store_cb cb;
    void *pvt;
};

static void *default_alloc(size_t size, void *pvt)
{
    return malloc(size);
}

static void default_free(void *ptr, void *pvt)
{
    free(ptr);
}

static char *idmap_strdup(struct sss_idmap_ctx *ctx, const char *str)
{
    char *new = NULL;
    size_t len;

    CHECK_IDMAP_CTX(ctx, NULL);

    len = strlen(str) + 1;

    new = ctx->alloc_func(len, ctx->alloc_pvt);
    if (new == NULL) {
        return NULL;
    }

    memcpy(new, str, len);

    return new;
}

static bool ranges_eq(const struct idmap_range_params *a,
                      const struct idmap_range_params *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }

    if (a->first_rid == b->first_rid
            && a->min_id == b->min_id
            && a->max_id == b->max_id) {
        return true;
    }

    return false;
}

static enum idmap_error_code
construct_range(struct sss_idmap_ctx *ctx,
                const struct idmap_range_params *src,
                char *id,
                struct idmap_range_params **_dst)
{
    struct idmap_range_params *dst;

    if (src == NULL || id == NULL || _dst == NULL) {
        return IDMAP_ERROR;
    }

    dst = ctx->alloc_func(sizeof(struct idmap_range_params), ctx->alloc_pvt);
    if (dst == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }

    dst->min_id = src->min_id;
    dst->max_id = src->max_id;
    dst->first_rid = src->first_rid;
    dst->next = NULL;
    dst->range_id = id;

    *_dst = dst;
    return IDMAP_SUCCESS;
}

static bool id_is_in_range(uint32_t id,
                           struct idmap_range_params *rp,
                           uint32_t *rid)
{
    if (id == 0 || rp == NULL) {
        return false;
    }

    if (id >= rp->min_id && id <= rp->max_id) {
        if (rid != NULL) {
            *rid = rp->first_rid + (id - rp->min_id);
        }

        return true;
    }

    return false;
}

const char *idmap_error_string(enum idmap_error_code err)
{
    switch (err) {
        case IDMAP_SUCCESS:
            return "IDMAP operation successful";
            break;
        case IDMAP_NOT_IMPLEMENTED:
            return "IDMAP Function is not yet implemented";
            break;
        case IDMAP_ERROR:
            return "IDMAP general error";
            break;
        case IDMAP_OUT_OF_MEMORY:
            return "IDMAP operation ran out of memory";
            break;
        case IDMAP_NO_DOMAIN:
            return "IDMAP domain not found";
            break;
        case IDMAP_CONTEXT_INVALID:
            return "IDMAP context is invalid";
            break;
        case IDMAP_SID_INVALID:
            return "IDMAP SID is invalid";
            break;
        case IDMAP_SID_UNKNOWN:
            return "IDMAP SID not found";
            break;
        case IDMAP_NO_RANGE:
            return "IDMAP range not found";
            break;
        case IDMAP_BUILTIN_SID:
            return "IDMAP SID from BUILTIN domain";
            break;
        case IDMAP_OUT_OF_SLICES:
            return "IDMAP not more free slices";
            break;
        case IDMAP_COLLISION:
            return "IDMAP new range collides with existing one";
            break;
        case IDMAP_EXTERNAL:
            return "IDMAP ID managed externally";
            break;
        case IDMAP_NAME_UNKNOWN:
            return "IDMAP domain with the given name not found";
            break;
        case IDMAP_NO_REVERSE:
            return "IDMAP cannot revert id to original source";
            break;
        case IDMAP_UTF8_ERROR:
            return "IDMAP failed to modify UTF8 string";
            break;
        default:
            return "IDMAP unknown error code";
    }
}

bool is_domain_sid(const char *sid)
{
    const char *p;
    long long a;
    char *endptr;
    size_t c;

    if (sid == NULL || strncmp(sid, DOM_SID_PREFIX, DOM_SID_PREFIX_LEN) != 0) {
        return false;
    }

    p = sid + DOM_SID_PREFIX_LEN;
    c = 0;

    do {
        errno = 0;
        a = strtoull(p, &endptr, 10);
        if (errno != 0 || a > UINT32_MAX) {
            return false;
        }

        if (*endptr == '-') {
            p = endptr + 1;
        } else if (*endptr != '\0') {
            return false;
        }
        c++;
    } while(c < 3 && *endptr != '\0');

    if (c != 3 || *endptr != '\0') {
        return false;
    }

    return true;
}

enum idmap_error_code sss_idmap_init(idmap_alloc_func *alloc_func,
                                     void *alloc_pvt,
                                     idmap_free_func *free_func,
                                     struct sss_idmap_ctx **_ctx)
{
    struct sss_idmap_ctx *ctx;

    if (alloc_func == NULL) {
        alloc_func = default_alloc;
    }

    ctx = alloc_func(sizeof(struct sss_idmap_ctx), alloc_pvt);
    if (ctx == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(ctx, 0, sizeof(struct sss_idmap_ctx));

    ctx->alloc_func = alloc_func;
    ctx->alloc_pvt = alloc_pvt;
    ctx->free_func = (free_func == NULL) ? default_free : free_func;

    /* Set default values. */
    ctx->idmap_opts.autorid_mode = SSS_IDMAP_DEFAULT_AUTORID;
    ctx->idmap_opts.idmap_lower = SSS_IDMAP_DEFAULT_LOWER;
    ctx->idmap_opts.idmap_upper = SSS_IDMAP_DEFAULT_UPPER;
    ctx->idmap_opts.rangesize = SSS_IDMAP_DEFAULT_RANGESIZE;
    ctx->idmap_opts.extra_slice_init = SSS_IDMAP_DEFAULT_EXTRA_SLICE_INIT;

    *_ctx = ctx;

    return IDMAP_SUCCESS;
}

static void free_helpers(struct sss_idmap_ctx *ctx,
                         struct idmap_range_params *helpers,
                         bool helpers_owner)
{
    struct idmap_range_params *it = helpers;
    struct idmap_range_params *tmp;

    if (helpers_owner == false) {
        return;
    }

    while (it != NULL) {
        tmp = it->next;

        ctx->free_func(it->range_id, ctx->alloc_pvt);
        ctx->free_func(it, ctx->alloc_pvt);

        it = tmp;
    }
}

static struct idmap_range_params*
get_helper_by_id(struct idmap_range_params *helpers, const char *id)
{
    struct idmap_range_params *it;

    for (it = helpers; it != NULL; it = it->next) {
        if (strcmp(it->range_id, id) == 0) {
            return it;
        }
    }

    return NULL;
}

static void sss_idmap_free_domain(struct sss_idmap_ctx *ctx,
                                  struct idmap_domain_info *dom)
{
    if (ctx == NULL || dom == NULL) {
        return;
    }

    ctx->free_func(dom->range_params.range_id, ctx->alloc_pvt);

    free_helpers(ctx, dom->helpers, dom->helpers_owner);

    ctx->free_func(dom->name, ctx->alloc_pvt);
    ctx->free_func(dom->sid, ctx->alloc_pvt);
    ctx->free_func(dom, ctx->alloc_pvt);
}

enum idmap_error_code sss_idmap_free(struct sss_idmap_ctx *ctx)
{
    struct idmap_domain_info *dom;
    struct idmap_domain_info *next;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    next = ctx->idmap_domain_info;
    while (next) {
        dom = next;
        next = dom->next;
        sss_idmap_free_domain(ctx, dom);
    }

    ctx->free_func(ctx, ctx->alloc_pvt);

    return IDMAP_SUCCESS;
}

static enum idmap_error_code sss_idmap_free_ptr(struct sss_idmap_ctx *ctx,
                                                void *ptr)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ptr != NULL) {
        ctx->free_func(ptr, ctx->alloc_pvt);
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_free_sid(struct sss_idmap_ctx *ctx,
                                         char *sid)
{
    return sss_idmap_free_ptr(ctx, sid);
}

enum idmap_error_code sss_idmap_free_dom_sid(struct sss_idmap_ctx *ctx,
                                             struct sss_dom_sid *dom_sid)
{
    return sss_idmap_free_ptr(ctx, dom_sid);
}

enum idmap_error_code sss_idmap_free_smb_sid(struct sss_idmap_ctx *ctx,
                                             struct dom_sid *smb_sid)
{
    return sss_idmap_free_ptr(ctx, smb_sid);
}

enum idmap_error_code sss_idmap_free_bin_sid(struct sss_idmap_ctx *ctx,
                                             uint8_t *bin_sid)
{
    return sss_idmap_free_ptr(ctx, bin_sid);
}

static bool check_overlap(struct idmap_range_params *range,
                          id_t min, id_t max)
{
    return ((range->min_id <= min && range->max_id >= max)
                || (range->min_id >= min && range->min_id <= max)
                || (range->max_id >= min && range->max_id <= max));
}

static bool check_dom_overlap(struct idmap_range_params *prim_range,
                              /* struct idmap_range_params *sec_ranges, */
                              id_t min,
                              id_t max)
{
    return check_overlap(prim_range, min, max);
}

enum idmap_error_code sss_idmap_calculate_range(struct sss_idmap_ctx *ctx,
                                                const char *range_id,
                                                id_t *slice_num,
                                                struct sss_idmap_range *_range)
{
    id_t max_slices;
    id_t orig_slice;
    id_t new_slice = 0;
    id_t min;
    id_t max;
    id_t idmap_lower;
    id_t idmap_upper;
    id_t rangesize;
    bool autorid_mode;
    uint32_t hash_val;
    struct idmap_domain_info *dom;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_lower = ctx->idmap_opts.idmap_lower;
    idmap_upper = ctx->idmap_opts.idmap_upper;
    rangesize = ctx->idmap_opts.rangesize;
    autorid_mode = ctx->idmap_opts.autorid_mode;

    max_slices = (idmap_upper - idmap_lower) / rangesize;

    if (slice_num && *slice_num != -1) {
        /* The slice is being set explicitly.
         * This may happen at system startup when we're loading
         * previously-determined slices. In the future, we may also
         * permit configuration to select the slice for a domain
         * explicitly.
         */
        new_slice = *slice_num;
        min = (rangesize * new_slice) + idmap_lower;
        max = min + rangesize - 1;
        for (dom = ctx->idmap_domain_info; dom != NULL; dom = dom->next) {
                if (check_dom_overlap(&dom->range_params,min, max)) {
                    /* This range overlaps one already registered
                     * Fail, because the slice was manually configured
                     */
                    return IDMAP_COLLISION;
                }
        }
    } else {
        /* If slice is -1, we're being asked to pick a new slice */

        if (autorid_mode) {
            /* In autorid compatibility mode, always start at 0 and find the
             * first free value.
             */
            orig_slice = 0;
        } else {
            /* Hash the range identifier string */
            hash_val = murmurhash3(range_id, strlen(range_id), 0xdeadbeef);

            /* Now get take the modulus of the hash val and the max_slices
             * to determine its optimal position in the range.
             */
            new_slice = hash_val % max_slices;
            orig_slice = new_slice;
        }

        min = (rangesize * new_slice) + idmap_lower;
        max = min + rangesize - 1;
        /* Verify that this slice is not already in use */
        do {
            for (dom = ctx->idmap_domain_info; dom != NULL; dom = dom->next) {

                if (check_dom_overlap(&dom->range_params,
                                      min, max)) {
                    /* This range overlaps one already registered
                     * We'll try the next available slot
                     */
                    new_slice++;
                    if (new_slice >= max_slices) {
                        /* loop around to the beginning if necessary */
                        new_slice = 0;
                    }

                    min = (rangesize * new_slice) + idmap_lower;
                    max = min + rangesize - 1;
                    break;
                }
            }

            /* Keep trying until dom is NULL (meaning we got to the end
             * without matching) or we have run out of slices and gotten
             * back to the first one we tried.
             */
        } while (dom && new_slice != orig_slice);

        if (dom) {
            /* We looped all the way through and found no empty slots */
            return IDMAP_OUT_OF_SLICES;
        }
    }

    _range->min = (rangesize * new_slice) + idmap_lower;
    _range->max = _range->min + rangesize - 1;

    if (slice_num) {
        *slice_num = new_slice;
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_check_collision_ex(const char *o_name,
                                                const char *o_sid,
                                                struct sss_idmap_range *o_range,
                                                uint32_t o_first_rid,
                                                const char *o_range_id,
                                                bool o_external_mapping,
                                                const char *n_name,
                                                const char *n_sid,
                                                struct sss_idmap_range *n_range,
                                                uint32_t n_first_rid,
                                                const char *n_range_id,
                                                bool n_external_mapping)
{
    bool names_equal;
    bool sids_equal;

    /* TODO: if both ranges have the same ID check if an update is
     * needed. */

    /* Check if ID ranges overlap.
     * ID ranges with external mapping may overlap. */
    if ((!n_external_mapping && !o_external_mapping)
        && ((n_range->min >= o_range->min
                && n_range->min <= o_range->max)
            || (n_range->max >= o_range->min
                && n_range->max <= o_range->max))) {
        return IDMAP_COLLISION;
    }

    names_equal = (strcasecmp(n_name, o_name) == 0);
    sids_equal = ((n_sid == NULL && o_sid == NULL)
                    || (n_sid != NULL && o_sid != NULL
                        && strcasecmp(n_sid, o_sid) == 0));

    /* check if domain name and SID are consistent */
    if ((names_equal && !sids_equal) || (!names_equal && sids_equal)) {
        return IDMAP_COLLISION;
    }

    /* check if external_mapping is consistent */
    if (names_equal && sids_equal
            && n_external_mapping != o_external_mapping) {
        return IDMAP_COLLISION;
    }

    /* check if RID ranges overlap */
    if (names_equal && sids_equal
            && n_external_mapping == false
            && n_first_rid >= o_first_rid
            && n_first_rid <= o_first_rid + (o_range->max - o_range->min)) {
        return IDMAP_COLLISION;
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_check_collision(struct sss_idmap_ctx *ctx,
                                                char *n_name, char *n_sid,
                                                struct sss_idmap_range *n_range,
                                                uint32_t n_first_rid,
                                                char *n_range_id,
                                                bool n_external_mapping)
{
    struct idmap_domain_info *dom;
    enum idmap_error_code err;
    struct sss_idmap_range range;

    for (dom = ctx->idmap_domain_info; dom != NULL; dom = dom->next) {

        range.min = dom->range_params.min_id;
        range.max = dom->range_params.max_id;

        err = sss_idmap_check_collision_ex(dom->name, dom->sid,
                                           &range,
                                           dom->range_params.first_rid,
                                           dom->range_params.range_id,
                                           dom->external_mapping,
                                           n_name, n_sid, n_range, n_first_rid,
                                           n_range_id, n_external_mapping);
        if (err != IDMAP_SUCCESS) {
            return err;
        }
    }
    return IDMAP_SUCCESS;
}

static enum
idmap_error_code dom_check_collision(struct idmap_domain_info *dom_list,
                                     struct idmap_domain_info *new_dom)
{
    struct idmap_domain_info *dom;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    struct sss_idmap_range new_dom_range = { new_dom->range_params.min_id,
                                             new_dom->range_params.max_id };

    for (dom = dom_list; dom != NULL; dom = dom->next) {
        range.min = dom->range_params.min_id;
        range.max = dom->range_params.max_id;

        err = sss_idmap_check_collision_ex(dom->name, dom->sid,
                                           &range,
                                           dom->range_params.first_rid,
                                           dom->range_params.range_id,
                                           dom->external_mapping,
                                           new_dom->name, new_dom->sid,
                                           &new_dom_range,
                                           new_dom->range_params.first_rid,
                                           new_dom->range_params.range_id,
                                           new_dom->external_mapping);
        if (err != IDMAP_SUCCESS) {
            return err;
        }
    }
    return IDMAP_SUCCESS;
}

static char*
generate_sec_slice_name(struct sss_idmap_ctx *ctx,
                        const char *domain_sid, uint32_t rid)
{
    const char *SEC_SLICE_NAME_FMT = "%s-%"PRIu32;
    char *slice_name;
    int len, len2;

    len = snprintf(NULL, 0, SEC_SLICE_NAME_FMT, domain_sid, rid);
    if (len <= 0) {
        return NULL;
    }

    slice_name = ctx->alloc_func(len + 1, ctx->alloc_pvt);
    if (slice_name == NULL) {
        return NULL;
    }

    len2 = snprintf(slice_name, len + 1, SEC_SLICE_NAME_FMT, domain_sid,
                    rid);
    if (len != len2) {
        ctx->free_func(slice_name, ctx->alloc_pvt);
        return NULL;
    }

    return slice_name;
}

static enum idmap_error_code
generate_slice(struct sss_idmap_ctx *ctx, char *slice_name, uint32_t first_rid,
               struct idmap_range_params **_slice)
{
    struct idmap_range_params *slice;
    struct sss_idmap_range tmp_range;
    enum idmap_error_code err;

    slice = ctx->alloc_func(sizeof(struct idmap_range_params), ctx->alloc_pvt);
    if (slice == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }

    slice->next = NULL;

    err = sss_idmap_calculate_range(ctx, slice_name, NULL, &tmp_range);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(slice, ctx->alloc_pvt);
        return err;
    }

    slice->min_id = tmp_range.min;
    slice->max_id = tmp_range.max;
    slice->range_id = slice_name;
    slice->first_rid = first_rid;

    *_slice = slice;
    return IDMAP_SUCCESS;
}

static enum idmap_error_code
get_helpers(struct sss_idmap_ctx *ctx,
            const char *domain_sid,
            uint32_t first_rid,
            struct idmap_range_params **_sec_slices)
{
    struct idmap_range_params *prev = NULL;
    struct idmap_range_params *sec_slices = NULL;
    static enum idmap_error_code err;
    struct idmap_range_params *slice;
    char *secondary_name;

    for (int i = 0; i < ctx->idmap_opts.extra_slice_init; i++) {
        secondary_name = generate_sec_slice_name(ctx, domain_sid, first_rid);
        if (secondary_name == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }

        err = generate_slice(ctx, secondary_name, first_rid, &slice);
        if (err != IDMAP_SUCCESS) {
            goto fail;
        }

        first_rid += ctx->idmap_opts.rangesize;

        if (prev != NULL) {
            prev->next = slice;
        }

        if (sec_slices == NULL) {
            sec_slices = slice;
        }

        prev = slice;
    }

    *_sec_slices = sec_slices;
    return IDMAP_SUCCESS;

fail:
    ctx->free_func(secondary_name, ctx->alloc_pvt);

    /* Free already generated helpers. */
    free_helpers(ctx, sec_slices, true);

    return err;
}

enum idmap_error_code sss_idmap_add_gen_domain_ex(struct sss_idmap_ctx *ctx,
                                                  const char *domain_name,
                                                  const char *domain_id,
                                                  struct sss_idmap_range *range,
                                                  const char *range_id,
                                                  idmap_offset_func *offset_func,
                                                  idmap_rev_offset_func *rev_offset_func,
                                                  void *offset_func_pvt,
                                                  uint32_t shift,
                                                  bool external_mapping)
{
    struct idmap_domain_info *dom = NULL;
    enum idmap_error_code err;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (domain_name == NULL || domain_id == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    if (range == NULL) {
        return IDMAP_NO_RANGE;
    }

    dom = ctx->alloc_func(sizeof(struct idmap_domain_info), ctx->alloc_pvt);
    if (dom == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom, 0, sizeof(struct idmap_domain_info));

    dom->name = idmap_strdup(ctx, domain_name);
    if (dom->name == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto fail;
    }

    dom->sid = idmap_strdup(ctx, domain_id);
    if (dom->sid == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto fail;
    }

    dom->range_params.min_id = range->min;
    dom->range_params.max_id = range->max;

    if (range_id != NULL) {
        dom->range_params.range_id = idmap_strdup(ctx, range_id);
        if (dom->range_params.range_id == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }
    }

    dom->range_params.first_rid = shift;
    dom->external_mapping = external_mapping;

    dom->offset_func = offset_func;
    dom->rev_offset_func = rev_offset_func;
    dom->offset_func_pvt = offset_func_pvt;

    err = dom_check_collision(ctx->idmap_domain_info, dom);
    if (err != IDMAP_SUCCESS) {
        goto fail;
    }

    dom->next = ctx->idmap_domain_info;
    ctx->idmap_domain_info = dom;

    return IDMAP_SUCCESS;

fail:
    sss_idmap_free_domain(ctx, dom);

    return err;
}

enum idmap_error_code sss_idmap_add_domain_ex(struct sss_idmap_ctx *ctx,
                                              const char *domain_name,
                                              const char *domain_sid,
                                              struct sss_idmap_range *range,
                                              const char *range_id,
                                              uint32_t rid,
                                              bool external_mapping)
{
    struct idmap_domain_info *dom = NULL;
    enum idmap_error_code err;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (domain_name == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    if (range == NULL) {
        return IDMAP_NO_RANGE;
    }

    /* For algorithmic mapping a valid domain SID is required, for external
     * mapping it may be NULL, but if set it should be valid. */
    if ((!external_mapping && !is_domain_sid(domain_sid))
            || (external_mapping
                && domain_sid != NULL
                && !is_domain_sid(domain_sid))) {
        return IDMAP_SID_INVALID;
    }

    dom = ctx->alloc_func(sizeof(struct idmap_domain_info), ctx->alloc_pvt);
    if (dom == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom, 0, sizeof(struct idmap_domain_info));

    dom->name = idmap_strdup(ctx, domain_name);
    if (dom->name == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto fail;
    }

    if (domain_sid != NULL) {
        dom->sid = idmap_strdup(ctx, domain_sid);
        if (dom->sid == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }
    }

    dom->range_params.min_id = range->min;
    dom->range_params.max_id = range->max;

    if (range_id != NULL) {
        dom->range_params.range_id = idmap_strdup(ctx, range_id);
        if (dom->range_params.range_id == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }
    }

    dom->range_params.first_rid = rid;
    dom->external_mapping = external_mapping;

    err = dom_check_collision(ctx->idmap_domain_info, dom);
    if (err != IDMAP_SUCCESS) {
        goto fail;
    }

    dom->next = ctx->idmap_domain_info;
    ctx->idmap_domain_info = dom;

    return IDMAP_SUCCESS;

fail:
    sss_idmap_free_domain(ctx, dom);

    return err;
}

enum idmap_error_code
sss_idmap_add_auto_domain_ex(struct sss_idmap_ctx *ctx,
                             const char *domain_name,
                             const char *domain_sid,
                             struct sss_idmap_range *range,
                             const char *range_id,
                             uint32_t rid,
                             bool external_mapping,
                             idmap_store_cb cb,
                             void *pvt)
{
    enum idmap_error_code err;

    err = sss_idmap_add_domain_ex(ctx, domain_name, domain_sid, range,
                                  range_id, rid, external_mapping);
    if (err != IDMAP_SUCCESS) {
        return err;
    }

    if (external_mapping) {
        /* There's no point in generating secondary ranges if external_mapping
           is enabled. */
        ctx->idmap_domain_info->auto_add_ranges = false;
        return IDMAP_SUCCESS;
    }

    if ((range->max - range->min + 1) != ctx->idmap_opts.rangesize) {
        /* Range of primary slice is not equal to the value of
           ldap_idmap_range_size option. */
        return IDMAP_ERROR;
    }

    /* No additional secondary ranges should be added if no sec ranges are
       predeclared. */
    if (ctx->idmap_opts.extra_slice_init == 0) {
        ctx->idmap_domain_info->auto_add_ranges = false;
        return IDMAP_SUCCESS;
    }

    /* Add size of primary slice for first_rid of secondary slices. */
    rid += ctx->idmap_opts.rangesize;
    err = get_helpers(ctx, domain_sid, rid,
                      &ctx->idmap_domain_info->helpers);
    if (err == IDMAP_SUCCESS) {
        ctx->idmap_domain_info->auto_add_ranges = true;
        ctx->idmap_domain_info->helpers_owner = true;
    } else {
        /* Running out of slices for secondary mapping is a non-fatal
         * problem. */
        if (err == IDMAP_OUT_OF_SLICES) {
            err = IDMAP_SUCCESS;
        }
        ctx->idmap_domain_info->auto_add_ranges = false;
    }

    ctx->idmap_domain_info->cb = cb;
    ctx->idmap_domain_info->pvt = pvt;

    return err;
}

enum idmap_error_code sss_idmap_add_domain(struct sss_idmap_ctx *ctx,
                                           const char *domain_name,
                                           const char *domain_sid,
                                           struct sss_idmap_range *range)
{
    return sss_idmap_add_domain_ex(ctx, domain_name, domain_sid, range, NULL,
                                   0, false);
}

static bool sss_idmap_sid_is_builtin(const char *sid)
{
    if (strncmp(sid, "S-1-5-32-", 9) == 0) {
        return true;
    }

    return false;
}

static bool parse_rid(const char *sid, size_t dom_prefix_len, long long *_rid)
{
    long long rid;
    char *endptr;

    errno = 0;
    /* Use suffix of sid - part after domain and following '-' */
    rid = strtoull(sid + dom_prefix_len + 1, &endptr, 10);
    if (errno != 0 || rid > UINT32_MAX || *endptr != '\0') {
        return false;
    }

    *_rid = rid;
    return true;
}

static bool is_from_dom(const char *domain_id, const char *id)
{
    if (domain_id == NULL) {
        return false;
    }

    return strcmp(domain_id, id) == 0;
}

static bool is_sid_from_dom(const char *dom_sid, const char *sid,
                            size_t *_dom_sid_len)
{
    size_t dom_sid_len;

    if (dom_sid == NULL) {
        return false;
    }

    dom_sid_len = strlen(dom_sid);
    *_dom_sid_len = dom_sid_len;

    if (strlen(sid) < dom_sid_len || sid[dom_sid_len] != '-') {
        return false;
    }

    return strncmp(sid, dom_sid, dom_sid_len) == 0;
}

static bool comp_id(struct idmap_range_params *range_params, long long rid,
                    uint32_t *_id)
{
    uint32_t id;

    if (rid >= range_params->first_rid
            && ((UINT32_MAX - range_params->min_id) >
               (rid - range_params->first_rid))) {
        id = range_params->min_id + (rid - range_params->first_rid);
        if (id <= range_params->max_id) {
            *_id = id;
            return true;
        }
    }
    return false;
}

static enum idmap_error_code
get_range(struct sss_idmap_ctx *ctx,
          struct idmap_range_params *helpers,
          const char *dom_sid,
          long long rid,
          struct idmap_range_params **_range)
{
    char *secondary_name = NULL;
    enum idmap_error_code err;
    int first_rid;
    struct idmap_range_params *range;
    struct idmap_range_params *helper;

    first_rid = (rid / ctx->idmap_opts.rangesize) * ctx->idmap_opts.rangesize;

    secondary_name = generate_sec_slice_name(ctx, dom_sid, first_rid);
    if (secondary_name == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto error;
    }

    helper = get_helper_by_id(helpers, secondary_name);
    if (helper != NULL) {
        /* Utilize helper's range. */
        err = construct_range(ctx, helper, secondary_name, &range);
    } else {
        /* Have to generate a whole new range. */
        err = generate_slice(ctx, secondary_name, first_rid, &range);
    }

    if (err != IDMAP_SUCCESS) {
        goto error;
    }

    *_range = range;
    return IDMAP_SUCCESS;

error:
    ctx->free_func(secondary_name, ctx->alloc_pvt);
    return err;
}

static enum idmap_error_code
spawn_dom(struct sss_idmap_ctx *ctx,
          struct idmap_domain_info *parent,
          struct idmap_range_params *range)
{
    struct sss_idmap_range tmp;
    static enum idmap_error_code err;
    struct idmap_domain_info *it;

    tmp.min = range->min_id;
    tmp.max = range->max_id;

    err = sss_idmap_add_domain_ex(ctx,
                                  parent->name,
                                  parent->sid,
                                  &tmp, range->range_id,
                                  range->first_rid, false);
    if (err != IDMAP_SUCCESS) {
        return err;
    }

    it = ctx->idmap_domain_info;
    while (it != NULL) {
        /* Find the newly added domain. */
        if (ranges_eq(&it->range_params, range)) {

            /* Share helpers. */
            it->helpers = parent->helpers;
            it->auto_add_ranges = parent->auto_add_ranges;

            /* Share call back for storing domains */
            it->cb = parent->cb;
            it->pvt = parent->pvt;
            break;
        }

        it = it->next;
    }

    if (it == NULL) {
        /* Failed to find just added domain. */
        return IDMAP_ERROR;
    }

    /* Store mapping for newly created domain. */
    if (it->cb != NULL) {
        err = it->cb(it->name,
                     it->sid,
                     it->range_params.range_id,
                     it->range_params.min_id,
                     it->range_params.max_id,
                     it->range_params.first_rid,
                     it->pvt);
        if (err != IDMAP_SUCCESS) {
            return err;
        }
    }

    return IDMAP_SUCCESS;
}

static enum idmap_error_code
add_dom_for_sid(struct sss_idmap_ctx *ctx,
                struct idmap_domain_info *matched_dom,
                const char *sid,
                uint32_t *_id)
{
    enum idmap_error_code err;
    long long rid;
    struct idmap_range_params *range = NULL;

    if (parse_rid(sid, strlen(matched_dom->sid), &rid) == false) {
        err = IDMAP_SID_INVALID;
        goto done;
    }

    err = get_range(ctx, matched_dom->helpers, matched_dom->sid, rid, &range);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = spawn_dom(ctx, matched_dom, range);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    if (!comp_id(range, rid, _id)) {
        err = IDMAP_ERROR;
        goto done;
    }

    err =  IDMAP_SUCCESS;

done:
    if (range != NULL) {
        ctx->free_func(range->range_id, ctx->alloc_pvt);
    }
    ctx->free_func(range, ctx->alloc_pvt);
    return err;
}

enum idmap_error_code offset_identity(void *pvt, uint32_t range_size,
                                      const char *input, long long *offset)
{
    long long out;
    char *endptr;

    if (input == NULL || offset == NULL) {
        return IDMAP_ERROR;
    }

    errno = 0;
    out = strtoull(input, &endptr, 10);
    if (errno != 0 || out >= range_size || *endptr != '\0'
                   || endptr == input) {
        return IDMAP_ERROR;
    }

    *offset = out;

    return IDMAP_SUCCESS;
}

enum idmap_error_code rev_offset_identity(struct sss_idmap_ctx *ctx, void *pvt,
                                          uint32_t id, char **_out)
{
    char *out;
    int len;
    int ret;

    len = snprintf(NULL, 0, "%"PRIu32, id);
    if (len <= 0 || len > SID_STR_MAX_LEN) {
        return IDMAP_ERROR;
    }

    out = ctx->alloc_func(len + 1, ctx->alloc_pvt);
    if (out == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }

    ret = snprintf(out, len + 1, "%"PRIu32, id);
    if (ret != len) {
        ctx->free_func(out, ctx->alloc_pvt);
        return IDMAP_ERROR;
    }

    *_out = out;
    return IDMAP_SUCCESS;
}

static char *normalize_casefold(const char *input, bool normalize,
                                bool casefold)
{
    if (casefold) {
        return (char *) utf8proc_NFKC_Casefold((const utf8proc_uint8_t *) input);
    }

    if (normalize) {
        return (char *) utf8proc_NFKC((const utf8proc_uint8_t *) input);
    }

    return NULL;
}

struct offset_murmurhash3_data offset_murmurhash3_data_default =
                                                          { .seed = 0xdeadbeef,
                                                            .normalize = true,
                                                            .casefold = false };

enum idmap_error_code offset_murmurhash3(void *pvt, uint32_t range_size,
                                         const char *input, long long *offset)
{
    struct offset_murmurhash3_data *offset_murmurhash3_data;
    long long out;
    char *tmp = NULL;
    const char *val;

    if (input == NULL || offset == NULL) {
        return IDMAP_ERROR;
    }

    if (pvt != NULL) {
        offset_murmurhash3_data = (struct offset_murmurhash3_data *) pvt;
    } else {
        offset_murmurhash3_data = &offset_murmurhash3_data_default;
    }

    if (offset_murmurhash3_data->normalize || offset_murmurhash3_data->casefold) {
        tmp = normalize_casefold(input, offset_murmurhash3_data->normalize,
                                 offset_murmurhash3_data->casefold);
        if (tmp == NULL) {
            return IDMAP_UTF8_ERROR;
        }
    }

    val = (tmp == NULL) ? input : tmp;

    out = murmurhash3(val, strlen(val), offset_murmurhash3_data->seed);
    free(tmp);

    out %= range_size;

    *offset = out;

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_gen_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *domain_id,
                                            const char *input,
                                            uint32_t *_id)
{
    struct idmap_domain_info *idmap_domain_info;
    struct idmap_domain_info *matched_dom = NULL;
    long long offset;
    uint32_t range_size;
    enum idmap_error_code err;
    idmap_offset_func *offset_func = offset_murmurhash3;
    void *offset_func_pvt = NULL;

    if (domain_id == NULL || input == NULL || _id == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    if (idmap_domain_info->offset_func != NULL) {
        offset_func = idmap_domain_info->offset_func;
        if (idmap_domain_info->offset_func_pvt != NULL) {
            offset_func_pvt = idmap_domain_info->offset_func_pvt;
        }
    }

    /* Try primary slices */
    while (idmap_domain_info != NULL) {

        if (is_from_dom(idmap_domain_info->sid, domain_id)) {

            if (idmap_domain_info->external_mapping == true) {
                return IDMAP_EXTERNAL;
            }

            range_size = 1 + (idmap_domain_info->range_params.max_id - idmap_domain_info->range_params.min_id);
            err = offset_func(offset_func_pvt, range_size, input, &offset);
            if (err != IDMAP_SUCCESS) {
                return err;
            }

            if (offset >= range_size) {
                return IDMAP_ERROR;
            }

            if (comp_id(&idmap_domain_info->range_params, offset, _id)) {
                return IDMAP_SUCCESS;
            }

            matched_dom = idmap_domain_info;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return matched_dom ? IDMAP_NO_RANGE : IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_unix_to_gen(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **_out)
{
    struct idmap_domain_info *idmap_domain_info;
    uint32_t offset;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (id_is_in_range(id, &idmap_domain_info->range_params, &offset)) {

            if (idmap_domain_info->external_mapping == true
                    || idmap_domain_info->sid == NULL) {
                return IDMAP_EXTERNAL;
            }

            if (idmap_domain_info->rev_offset_func == NULL) {
                return IDMAP_NO_REVERSE;
            }

            return idmap_domain_info->rev_offset_func(ctx,
                                             idmap_domain_info->offset_func_pvt,
                                             offset, _out);
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_sid_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *sid,
                                            uint32_t *_id)
{
    struct idmap_domain_info *idmap_domain_info;
    struct idmap_domain_info *matched_dom = NULL;
    size_t dom_len;
    long long rid;

    if (sid == NULL || _id == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    if (sss_idmap_sid_is_builtin(sid)) {
        return IDMAP_BUILTIN_SID;
    }

    /* Try primary slices */
    while (idmap_domain_info != NULL) {

        if (is_sid_from_dom(idmap_domain_info->sid, sid, &dom_len)) {

            if (idmap_domain_info->external_mapping == true) {
                return IDMAP_EXTERNAL;
            }

            if (parse_rid(sid, dom_len, &rid) == false) {
                return IDMAP_SID_INVALID;
            }

            if (comp_id(&idmap_domain_info->range_params, rid, _id)) {
                return IDMAP_SUCCESS;
            }

            matched_dom = idmap_domain_info;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    if (matched_dom != NULL && matched_dom->auto_add_ranges) {
        return add_dom_for_sid(ctx, matched_dom, sid, _id);
    }

    return matched_dom ? IDMAP_NO_RANGE : IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_check_sid_unix(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint32_t id)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t dom_len;
    bool no_range = false;

    if (sid == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    if (sss_idmap_sid_is_builtin(sid)) {
        return IDMAP_BUILTIN_SID;
    }

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->sid != NULL) {
            dom_len = strlen(idmap_domain_info->sid);
            if (strlen(sid) > dom_len && sid[dom_len] == '-'
                    && strncmp(sid, idmap_domain_info->sid, dom_len) == 0) {

                if (id >= idmap_domain_info->range_params.min_id
                    && id <= idmap_domain_info->range_params.max_id) {
                    return IDMAP_SUCCESS;
                }

                no_range = true;
            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return no_range ? IDMAP_NO_RANGE : IDMAP_SID_UNKNOWN;
}

static enum idmap_error_code generate_sid(struct sss_idmap_ctx *ctx,
                                          const char *dom_sid,
                                          uint32_t rid,
                                          char **_sid)
{
    char *sid;
    int len;
    int ret;

    len = snprintf(NULL, 0, SID_FMT, dom_sid, rid);
    if (len <= 0 || len > SID_STR_MAX_LEN) {
        return IDMAP_ERROR;
    }

    sid = ctx->alloc_func(len + 1, ctx->alloc_pvt);
    if (sid == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }

    ret = snprintf(sid, len + 1, SID_FMT, dom_sid, rid);
    if (ret != len) {
        ctx->free_func(sid, ctx->alloc_pvt);
        return IDMAP_ERROR;
    }

    *_sid = sid;
    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_unix_to_sid(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **_sid)
{
    struct idmap_domain_info *idmap_domain_info;
    uint32_t rid;
    enum idmap_error_code err;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (id_is_in_range(id, &idmap_domain_info->range_params, &rid)) {

            if (idmap_domain_info->external_mapping == true
                    || idmap_domain_info->sid == NULL) {
                return IDMAP_EXTERNAL;
            }

            return generate_sid(ctx, idmap_domain_info->sid, rid, _sid);
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    /* Check secondary ranges. */
    idmap_domain_info = ctx->idmap_domain_info;
    while (idmap_domain_info != NULL) {

        for (struct idmap_range_params *it = idmap_domain_info->helpers;
             it != NULL;
             it = it->next) {

            if (idmap_domain_info->helpers_owner == false) {
                /* Checking helpers on owner is sufficient. */
                continue;
            }

            if (id_is_in_range(id, it, &rid)) {

                if (idmap_domain_info->external_mapping == true
                    || idmap_domain_info->sid == NULL) {
                    return IDMAP_EXTERNAL;
                }

                err = spawn_dom(ctx, idmap_domain_info, it);
                if (err != IDMAP_SUCCESS) {
                    return err;
                }

                return generate_sid(ctx, idmap_domain_info->sid, rid, _sid);
            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct sss_dom_sid *dom_sid,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_bin_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                uint8_t *bin_sid,
                                                size_t length,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_bin_sid_to_sid(ctx, bin_sid, length, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_smb_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct dom_sid *smb_sid,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_smb_sid_to_sid(ctx, smb_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                    struct sss_dom_sid *dom_sid,
                                                    uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_bin_sid_unix(struct sss_idmap_ctx *ctx,
                                                   uint8_t *bin_sid,
                                                   size_t length,
                                                   uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_bin_sid_to_sid(ctx, bin_sid, length, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_smb_sid_unix(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_smb_sid_to_sid(ctx, smb_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}
enum idmap_error_code sss_idmap_unix_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                struct sss_dom_sid **_dom_sid)
{
    enum idmap_error_code err;
    char *sid = NULL;
    struct sss_dom_sid *dom_sid = NULL;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_unix_to_sid(ctx, id, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_dom_sid(ctx, sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_dom_sid = dom_sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(dom_sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_unix_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                uint8_t **_bin_sid,
                                                size_t *_length)
{
    enum idmap_error_code err;
    char *sid = NULL;
    uint8_t *bin_sid = NULL;
    size_t length;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_unix_to_sid(ctx, id, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_bin_sid(ctx, sid, &bin_sid, &length);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_bin_sid = bin_sid;
    *_length = length;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(bin_sid, ctx->alloc_pvt);
    }

    return err;

}

enum idmap_error_code
sss_idmap_ctx_set_autorid(struct sss_idmap_ctx *ctx, bool use_autorid)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.autorid_mode = use_autorid;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_lower(struct sss_idmap_ctx *ctx, id_t lower)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.idmap_lower = lower;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_upper(struct sss_idmap_ctx *ctx, id_t upper)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.idmap_upper = upper;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_rangesize(struct sss_idmap_ctx *ctx, id_t rangesize)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.rangesize = rangesize;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_extra_slice_init(struct sss_idmap_ctx *ctx,
                                  int extra_slice_init)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.extra_slice_init = extra_slice_init;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_autorid(struct sss_idmap_ctx *ctx, bool *_autorid)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
     *_autorid = ctx->idmap_opts.autorid_mode;
     return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_lower(struct sss_idmap_ctx *ctx, id_t *_lower)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_lower = ctx->idmap_opts.idmap_lower;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_upper(struct sss_idmap_ctx *ctx, id_t *_upper)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_upper = ctx->idmap_opts.idmap_upper;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_rangesize(struct sss_idmap_ctx *ctx, id_t *_rangesize)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_rangesize =  ctx->idmap_opts.rangesize;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_domain_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                         const char *dom_sid,
                                         bool *has_algorithmic_mapping)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t len;
    size_t dom_sid_len;

    if (dom_sid == NULL) {
        return IDMAP_SID_INVALID;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->sid != NULL) {
            len = strlen(idmap_domain_info->sid);
            dom_sid_len = strlen(dom_sid);
            if (((dom_sid_len > len && dom_sid[len] == '-')
                        || dom_sid_len == len)
                    && strncmp(dom_sid, idmap_domain_info->sid, len) == 0) {

                *has_algorithmic_mapping = !idmap_domain_info->external_mapping;
                return IDMAP_SUCCESS;

            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_SID_UNKNOWN;
}

enum idmap_error_code
sss_idmap_domain_by_name_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                                 const char *dom_name,
                                                 bool *has_algorithmic_mapping)
{
    struct idmap_domain_info *idmap_domain_info;

    if (dom_name == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->name != NULL
                && strcmp(dom_name, idmap_domain_info->name) == 0) {

            *has_algorithmic_mapping = !idmap_domain_info->external_mapping;
            return IDMAP_SUCCESS;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NAME_UNKNOWN;
}
