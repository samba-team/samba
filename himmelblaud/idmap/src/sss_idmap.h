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

#ifndef SSS_IDMAP_H_
#define SSS_IDMAP_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define DOM_SID_PREFIX "S-1-5-21-"
#define DOM_SID_PREFIX_LEN (sizeof(DOM_SID_PREFIX) - 1)

/**
 * @defgroup sss_idmap Map Unix UIDs and GIDs to SIDs and back
 * Libsss_idmap provides a mechanism to translate a SID to a UNIX UID or GID
 * or the other way round.
 * @{
 */

/**
 * Error codes used by libsss_idmap
 */
enum idmap_error_code {
    /** Success */
    IDMAP_SUCCESS = 0,

    /** Function is not yet implemented */
    IDMAP_NOT_IMPLEMENTED,

    /** General error */
    IDMAP_ERROR,

    /** Ran out of memory during processing */
    IDMAP_OUT_OF_MEMORY,

    /** No domain added */
    IDMAP_NO_DOMAIN,

    /** The provided idmap context is invalid */
    IDMAP_CONTEXT_INVALID,

    /** The provided SID is invalid */
    IDMAP_SID_INVALID,

    /** The provided  SID was not found */
    IDMAP_SID_UNKNOWN,

    /** The provided UID or GID could not be mapped */
    IDMAP_NO_RANGE,

    /** The provided SID is a built-in one */
    IDMAP_BUILTIN_SID,

    /** No more free slices */
    IDMAP_OUT_OF_SLICES,

    /** New domain collides with existing one */
    IDMAP_COLLISION,

    /** External source should be consulted for idmapping */
    IDMAP_EXTERNAL,

    /** The provided  name was not found */
    IDMAP_NAME_UNKNOWN,

    /** It is not possible to convert an id into the original value the id was
     *  derived from */
    IDMAP_NO_REVERSE,

    /** Error during UTF8 operation like normalization or casefolding */
    IDMAP_UTF8_ERROR,

    /** Sentinel to indicate the end of the error code list, not returned by
     * any call */
    IDMAP_ERR_LAST
};

/**
 * Typedef for memory allocation functions
 */
typedef void *(idmap_alloc_func)(size_t size, void *pvt);
typedef void (idmap_free_func)(void *ptr, void *pvt);

/**
 * Typedef for storing mappings of dynamically created domains
 */
typedef enum idmap_error_code (*idmap_store_cb)(const char *dom_name,
                                                const char *dom_sid,
                                                const char *range_id,
                                                uint32_t min_id,
                                                uint32_t max_id,
                                                uint32_t first_rid,
                                                void *pvt);

/**
 * Structure for id ranges
 * FIXME: this struct might change when it is clear how ranges are handled on
 * the server side
 */
struct sss_idmap_range {
    uint32_t min;
    uint32_t max;
};

/**
 * Opaque type for SIDs
 */
struct sss_dom_sid;

/**
 * Opaque type for the idmap context
 */
struct sss_idmap_ctx;

/**
 * Placeholder for Samba's struct dom_sid. Consumers of libsss_idmap should
 * include an appropriate Samba header file to define struct dom_sid. We use
 * it here to avoid a hard dependency on Samba devel packages.
 */
struct dom_sid;

/**
 * @brief Initialize idmap context
 *
 * @param[in] alloc_func Function to allocate memory for the context, if
 *                       NULL malloc() id used
 * @param[in] alloc_pvt  Private data for allocation routine
 * @param[in] free_func  Function to free the memory the context, if
 *                       NULL free() id used
 * @param[out] ctx       idmap context
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to create the context
 */
enum idmap_error_code sss_idmap_init(idmap_alloc_func *alloc_func,
                                     void *alloc_pvt,
                                     idmap_free_func *free_func,
                                     struct sss_idmap_ctx **ctx);

/**
 * @brief Set/unset autorid compatibility mode
 *
 * @param[in] ctx           idmap context
 * @param[in] use_autorid   If true, autorid compatibility mode will be used
 */
enum idmap_error_code
sss_idmap_ctx_set_autorid(struct sss_idmap_ctx *ctx, bool use_autorid);

/**
 * @brief Set the lower bound of the range of POSIX IDs
 *
 * @param[in] ctx           idmap context
 * @param[in] lower         lower bound of the range
 */
enum idmap_error_code
sss_idmap_ctx_set_lower(struct sss_idmap_ctx *ctx, id_t lower);

/**
 * @brief Set the upper bound of the range of POSIX IDs
 *
 * @param[in] ctx           idmap context
 * @param[in] upper         upper bound of the range
 */
enum idmap_error_code
sss_idmap_ctx_set_upper(struct sss_idmap_ctx *ctx, id_t upper);

/**
 * @brief Set the range size of POSIX IDs available for single domain
 *
 * @param[in] ctx           idmap context
 * @param[in] rangesize     range size of IDs
 */
enum idmap_error_code
sss_idmap_ctx_set_rangesize(struct sss_idmap_ctx *ctx, id_t rangesize);

/**
 * @brief Set the number of secondary slices available for domain
 *
 * @param[in] ctx                  idmap context
 * @param[in] extra_slice_init     number of secondary slices to be generated
 *                                 at startup
 */
enum idmap_error_code
sss_idmap_ctx_set_extra_slice_init(struct sss_idmap_ctx *ctx,
                                  int extra_slice_init);

/**
 * @brief Check if autorid compatibility mode is set
 *
 * @param[in] ctx           idmap context
 * @param[out] _autorid     true if autorid is used
 */
enum idmap_error_code
sss_idmap_ctx_get_autorid(struct sss_idmap_ctx *ctx, bool *_autorid);

/**
 * @brief Get the lower bound of the range of POSIX IDs
 *
 * @param[in] ctx           idmap context
 * @param[out] _lower       returned lower bound
 */
enum idmap_error_code
sss_idmap_ctx_get_lower(struct sss_idmap_ctx *ctx, id_t *_lower);

/**
 * @brief Get the upper bound of the range of POSIX IDs
 *
 * @param[in] ctx           idmap context
 * @param[out] _upper       returned upper bound
 */
enum idmap_error_code
sss_idmap_ctx_get_upper(struct sss_idmap_ctx *ctx, id_t *_upper);

/**
 * @brief Get the range size of POSIX IDs available for single domain
 *
 * @param[in] ctx           idmap context
 * @param[out] rangesize    returned range size
 */
enum idmap_error_code
sss_idmap_ctx_get_rangesize(struct sss_idmap_ctx *ctx, id_t *rangesize);

/**
 * @brief Calculate new range of available POSIX IDs
 *
 * @param[in] ctx           Idmap context
 * @param[in] dom_sid       Zero-terminated string representation of the domain
 *                          SID (S-1-15-.....)
 * @param[in,out] slice_num Slice number to be used. Set this pointer to NULL or
 *                          the addressed value to -1 to calculate slice number
 *                          automatically. The calculated value will be
 *                          returned in this parameter.
 * @param[out] range        Structure containing upper and lower bound of the
 *                          range of POSIX IDs
 *
 * @return
 *  - #IDMAP_OUT_OF_SLICES: Cannot calculate new range because all slices are
 *                          used.
 */
enum idmap_error_code sss_idmap_calculate_range(struct sss_idmap_ctx *ctx,
                                                const char *dom_sid,
                                                id_t *slice_num,
                                                struct sss_idmap_range *range);

/**
 * @brief Add a domain to the idmap context
 *
 * @param[in] ctx         Idmap context
 * @param[in] domain_name Zero-terminated string with the domain name
 * @param[in] domain_sid  Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....)
 * @param[in] range       TBD Some information about the id ranges of this
 *                        domain
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to store the data in the idmap
 *                          context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_NO_DOMAIN:     No domain domain name given
 *  - #IDMAP_COLLISION:     New domain collides with existing one
 */
enum idmap_error_code sss_idmap_add_domain(struct sss_idmap_ctx *ctx,
                                           const char *domain_name,
                                           const char *domain_sid,
                                           struct sss_idmap_range *range);

/**
 * @brief Add a domain with the first mappable RID to the idmap context
 *
 * @param[in] ctx         Idmap context
 * @param[in] domain_name Zero-terminated string with the domain name
 * @param[in] domain_sid  Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....)
 * @param[in] range       TBD Some information about the id ranges of this
 *                        domain
 * @param[in] range_id    optional unique identifier of a range, it is needed
 *                        to allow updates at runtime
 * @param[in] rid         The RID that should be mapped to the first ID of the
 *                        given range.
 * @param[in] external_mapping  If set to true the ID will not be mapped
 *                        algorithmically, but the *_to_unix and *_unix_to_*
 *                        calls will return IDMAP_EXTERNAL to instruct the
 *                        caller to check external sources. For a single
 *                        domain all ranges must be of the same type. It is
 *                        not possible to mix algorithmic and external
 *                        mapping.
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to store the data in the idmap
 *                          context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_NO_DOMAIN:     No domain domain name given
 *  - #IDMAP_COLLISION:     New domain collides with existing one
 */
enum idmap_error_code sss_idmap_add_domain_ex(struct sss_idmap_ctx *ctx,
                                              const char *domain_name,
                                              const char *domain_sid,
                                              struct sss_idmap_range *range,
                                              const char *range_id,
                                              uint32_t rid,
                                              bool external_mapping);

/**
 * @brief Add a domain with the first mappable RID to the idmap context and
 * generate automatically secondary slices
 *
 * @param[in] ctx         Idmap context
 * @param[in] domain_name Zero-terminated string with the domain name
 * @param[in] domain_sid  Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....)
 * @param[in] range       TBD Some information about the id ranges of this
 *                        domain
 * @param[in] range_id    optional unique identifier of a range, it is needed
 *                        to allow updates at runtime
 * @param[in] rid         The RID that should be mapped to the first ID of the
 *                        given range.
 * @param[in] external_mapping  If set to true the ID will not be mapped
 *                        algorithmically, but the *_to_unix and *_unix_to_*
 *                        calls will return IDMAP_EXTERNAL to instruct the
 *                        caller to check external sources. For a single
 *                        domain all ranges must be of the same type. It is
 *                        not possible to mix algorithmic and external
 *                        mapping.
 * @param[in] cb          The callback for storing mapping of dynamically
 *                        created domains.
 * @param[in] pvt         Private data for callback cb.
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to store the data in the idmap
 *                          context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_NO_DOMAIN:     No domain domain name given
 *  - #IDMAP_COLLISION:     New domain collides with existing one
 */
enum idmap_error_code
sss_idmap_add_auto_domain_ex(struct sss_idmap_ctx *ctx,
                             const char *domain_name,
                             const char *domain_sid,
                             struct sss_idmap_range *range,
                             const char *range_id,
                             uint32_t rid,
                             bool external_mapping,
                             idmap_store_cb cb,
                             void *pvt);

/**
 * @brief Check if a new range would collide with any existing one
 *
 * @param[in] ctx         Idmap context
 * @param[in] n_name      Zero-terminated string with the domain name the new
 *                        range should belong to
 * @param[in] n_sid       Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....) the new range should belong to
 * @param[in] n_range     The new id range
 * @param[in] n_range_id  unique identifier of the new range, it is needed
 *                        to allow updates at runtime, may be NULL
 * @param[in] n_first_rid The RID that should be mapped to the first ID of the
 *                        new range.
 * @param[in] n_external_mapping Mapping type of the new range
 *
 * @return
 *  - #IDMAP_COLLISION:     New range collides with existing one
 */
enum idmap_error_code sss_idmap_check_collision(struct sss_idmap_ctx *ctx,
                                                char *n_name, char *n_sid,
                                                struct sss_idmap_range *n_range,
                                                uint32_t n_first_rid,
                                                char *n_range_id,
                                                bool n_external_mapping);

/**
 * @brief Check if two ranges would collide
 *
 * @param[in] o_name      Zero-terminated string with the domain name the
 *                        first range should belong to
 * @param[in] o_sid       Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....) the first range should belong to
 * @param[in] o_range     The first id range
 * @param[in] o_range_id  unique identifier of the first range, it is needed
 *                        to allow updates at runtime, may be NULL
 * @param[in] o_first_rid The RID that should be mapped to the first ID of the
 *                        first range.
 * @param[in] o_external_mapping Mapping type of the first range
 * @param[in] n_name      Zero-terminated string with the domain name the
 *                        second range should belong to
 * @param[in] n_sid       Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....) the second range should belong to
 * @param[in] n_range     The second id range
 * @param[in] n_range_id  unique identifier of the second range, it is needed
 *                        to allow updates at runtime, may be NULL
 * @param[in] n_first_rid The RID that should be mapped to the first ID of the
 *                        second range.
 * @param[in] n_external_mapping Mapping type of the second range
 *
 * @return
 *  - #IDMAP_COLLISION:     New range collides with existing one
 */
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
                                                bool n_external_mapping);

/**
 * @brief Translate SID to a unix UID or GID
 *
 * @param[in] ctx Idmap context
 * @param[in] sid Zero-terminated string representation of the SID
 * @param[out] id Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_sid_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *sid,
                                            uint32_t *id);

/**
 * @brief Translate a SID structure to a unix UID or GID
 *
 * @param[in] ctx     Idmap context
 * @param[in] dom_sid SID structure
 * @param[out] id     Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct sss_dom_sid *dom_sid,
                                                uint32_t *id);

/**
 * @brief Translate a binary SID to a unix UID or GID
 *
 * @param[in] ctx     Idmap context
 * @param[in] bin_sid Array with the binary SID
 * @param[in] length  Size of the array containing the binary SID
 * @param[out] id     Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_bin_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                uint8_t *bin_sid,
                                                size_t length,
                                                uint32_t *id);

/**
 * @brief Translate a Samba dom_sid structure to a unix UID or GID
 *
 * @param[in] ctx     Idmap context
 * @param[in] smb_sid Samba dom_sid structure
 * @param[out] id     Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_smb_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct dom_sid *smb_sid,
                                                uint32_t *id);

/**
 * @brief Check if a SID and a unix UID or GID belong to the same range
 *
 * @param[in] ctx Idmap context
 * @param[in] sid Zero-terminated string representation of the SID
 * @param[in] id  Unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_NO_RANGE       No matching ID range found
 */
enum idmap_error_code sss_idmap_check_sid_unix(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint32_t id);

/**
 * @brief Check if a SID structure and a unix UID or GID belong to the same range
 *
 * @param[in] ctx     Idmap context
 * @param[in] dom_sid SID structure
 * @param[in] id      Unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_NO_RANGE       No matching ID range found
 */
enum idmap_error_code sss_idmap_check_dom_sid_unix(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   uint32_t id);

/**
 * @brief Check if a binary SID and a unix UID or GID belong to the same range
 *
 * @param[in] ctx     Idmap context
 * @param[in] bin_sid Array with the binary SID
 * @param[in] length  Size of the array containing the binary SID
 * @param[in] id      Unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_NO_RANGE       No matching ID range found
 */
enum idmap_error_code sss_idmap_check_bin_sid_unix(struct sss_idmap_ctx *ctx,
                                                   uint8_t *bin_sid,
                                                   size_t length,
                                                   uint32_t id);

/**
 * @brief Check if a Samba dom_sid structure and a unix UID or GID belong to
 * the same range
 *
 * @param[in] ctx     Idmap context
 * @param[in] smb_sid Samba dom_sid structure
 * @param[in] id      Unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 *  - #IDMAP_NO_RANGE       No matching ID range found
 */
enum idmap_error_code sss_idmap_check_smb_sid_unix(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint32_t id);

/**
 * @brief Translate unix UID or GID to a SID
 *
 * @param[in] ctx  Idmap context
 * @param[in] id   unix UID or GID
 * @param[out] sid Zero-terminated string representation of the SID, must be
 *                 freed if not needed anymore
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 *  - #IDMAP_EXTERNAL:  external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_unix_to_sid(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **sid);

/**
 * @brief Translate unix UID or GID to a SID structure
 *
 * @param[in] ctx      Idmap context
 * @param[in] id       unix UID or GID
 * @param[out] dom_sid SID structure, must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 *  - #IDMAP_EXTERNAL:  external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_unix_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                struct sss_dom_sid **dom_sid);

/**
 * @brief Translate unix UID or GID to a binary SID
 *
 * @param[in] ctx      Idmap context
 * @param[in] id       unix UID or GID
 * @param[out] bin_sid Array with the binary SID,
 *                     must be freed if not needed anymore
 * @param[out] length  size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 *  - #IDMAP_EXTERNAL:  external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_unix_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                uint8_t **bin_sid,
                                                size_t *length);

/**
 * @brief Free all the allocated memory of the idmap context
 *
 * @param[in] ctx         Idmap context
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free(struct sss_idmap_ctx *ctx);

/**
 * @brief Free mapped SID.
 *
 * @param[in] ctx         Idmap context
 * @param[in] sid         SID to be freed.
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free_sid(struct sss_idmap_ctx *ctx,
                                         char *sid);

/**
 * @brief Free mapped domain SID.
 *
 * @param[in] ctx         Idmap context
 * @param[in] dom_sid     Domain SID to be freed.
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free_dom_sid(struct sss_idmap_ctx *ctx,
                                             struct sss_dom_sid *dom_sid);

/**
 * @brief Free mapped Samba SID.
 *
 * @param[in] ctx         Idmap context
 * @param[in] smb_sid     Samba SID to be freed.
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free_smb_sid(struct sss_idmap_ctx *ctx,
                                             struct dom_sid *smb_sid);

/**
 * @brief Free mapped binary SID.
 *
 * @param[in] ctx         Idmap context
 * @param[in] bin_sid     Binary SID to be freed.
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free_bin_sid(struct sss_idmap_ctx *ctx,
                                             uint8_t *bin_sid);

/**
 * @brief Translate error code to a string
 *
 * @param[in] err  Idmap error code
 *
 * @return
 *  - Error description as a zero-terminated string
 */
const char *idmap_error_string(enum idmap_error_code err);

/**
 * @brief Check if given string can be used as domain SID
 *
 * @param[in] str   String to check
 *
 * @return
 *  - true: String can be used as domain SID
 *  - false: String can not be used as domain SID
 */
bool is_domain_sid(const char *str);

/**
 * @brief Check if a domain is configured with algorithmic mapping
 *
 * @param[in] ctx                      Idmap context
 * @param[in] dom_sid                  SID string, can be either a domain SID
 *                                     or an object SID
 * @param[out] has_algorithmic_mapping Boolean value indicating if the given
 *                                     domain is configured for algorithmic
 *                                     mapping or not.
 *
 * @return
 *  - #IDMAP_SUCCESS:         Domain for the given SID was found and
 *                            has_algorithmic_mapping is set accordingly
 *  - #IDMAP_SID_INVALID:     Provided SID is invalid
 *  - #IDMAP_CONTEXT_INVALID: Provided idmap context is invalid
 *  - #IDMAP_NO_DOMAIN:       No domains are available in the idmap context
 *  - #IDMAP_SID_UNKNOWN:     No domain with the given SID was found in the
 *                            idmap context
 */
enum idmap_error_code
sss_idmap_domain_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                         const char *dom_sid,
                                         bool *has_algorithmic_mapping);

/**
 * @brief Check if a domain is configured with algorithmic mapping
 *
 * @param[in]  ctx                     Idmap context
 * @param[in]  dom_name                Name of the domain
 * @param[out] has_algorithmic_mapping Boolean value indicating if the given
 *                                     domain is configured for algorithmic
 *                                     mapping or not.
 *
 * @return
 *  - #IDMAP_SUCCESS:         Domain for the given name was found and
 *                            has_algorithmic_mapping is set accordingly
 *  - #IDMAP_ERROR:           Provided name is invalid
 *  - #IDMAP_CONTEXT_INVALID: Provided idmap context is invalid
 *  - #IDMAP_NO_DOMAIN:       No domains are available in the idmap context
 *  - #IDMAP_NAME_UNKNOWN:    No domain with the given name was found in the
 *                            idmap context
 */
enum idmap_error_code
sss_idmap_domain_by_name_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                                 const char *dom_name,
                                                 bool *has_algorithmic_mapping);

/**
 * @brief Convert binary SID to SID structure
 *
 * @param[in] ctx      Idmap context
 * @param[in] bin_sid  Array with the binary SID
 * @param[in] length   Size of the array containing the binary SID
 * @param[out] dom_sid SID structure,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct sss_dom_sid **dom_sid);

/**
 * @brief Convert binary SID to SID string
 *
 * @param[in] ctx      Idmap context
 * @param[in] bin_sid  Array with the binary SID
 * @param[in] length   Size of the array containing the binary SID
 * @param[out] sid     Zero-terminated string representation of the SID,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               const uint8_t *bin_sid,
                                               size_t length,
                                               char **sid);

/**
 * @brief Convert SID structure to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] dom_sid   SID structure
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   uint8_t **bin_sid,
                                                   size_t *length);

/**
 * @brief Convert SID string to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint8_t **bin_sid,
                                               size_t *length);

/**
 * @brief Convert SID structure to SID string
 *
 * @param[in] ctx      Idmap context
 * @param[in] dom_sid  SID structure
 * @param[out] sid     Zero-terminated string representation of the SID,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct sss_dom_sid *dom_sid,
                                               char **sid);

/**
 * @brief Convert SID string to SID structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] dom_sid  SID structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct sss_dom_sid **dom_sid);

/**
 * @brief Convert SID string to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to SID string
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] sid      Zero-terminated string representation of the SID,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct dom_sid *smb_sid,
                                               char **sid);

/**
 * @brief Convert SID structure to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] dom_sid   SID structure
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to SID structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] dom_sid  SID structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   struct sss_dom_sid **dom_sid);

/**
 * @brief Convert binary SID to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] bin_sid   Array with the binary SID
 * @param[in] length    Size of the array containing the binary SID
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint8_t **bin_sid,
                                                   size_t *length);

/**
 * Typedef for functions to calculate an offset for id-mapping and, if
 * possible, for the reverse operation.
 */
typedef enum idmap_error_code (idmap_offset_func)(void *pvt,
                                                  uint32_t range_size,
                                                  const char *input,
                                                  long long *offset);

typedef enum idmap_error_code (idmap_rev_offset_func)(struct sss_idmap_ctx *ctx,
                                                      void *pvt,
                                                      uint32_t offset,
                                                      char **out);

/**
 * @brief Add a generic domain to the idmap context
 *
 * @param[in] ctx         Idmap context
 * @param[in] domain_name Zero-terminated string with the domain name
 * @param[in] domain_id   Zero-terminated string representation of a unique
 *                        identifier of the domain, e.g. if available a domain
 *                        UUID or the URI of domain specific service
 * @param[in] range       Id ranges struct with smallest and largest id of the
 *                        range
 * @param[in] range_id    A name for the id range, currently not used, might
 *                        become important when we allow multiple ranges for a
 *                        single domain
 * @param[in] offset_func Function to calculate an offset in a given range
 *                        from some input given as string, if NULL
 *                        offset_murmurhash3 will be used.
 * @param[in] rev_offset_func Function to calculate the original input from a
 *                        given offset, i.e. the reverse of offset_func, may
 *                        be NULL
 * @param[in] offset_func_pvt Private data for offset_func and
 *                        rev_offset_func, may be NULL
 * @param[in] shift       Currently not used, might become important when we
 *                        allow multiple ranges for a single domain
 * @param[in] external_mapping Indicates that for this domain the mapping
 *                        should not be done by libsss_idmap, the related
 *                        calls will return IDMAP_EXTERNAL in this case.
 *                        Nevertheless it might be important to add the domain
 *                        to the idmap context so that libsss_idmap will not
 *                        use the related ranges for mapping.
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to store the data in the idmap
 *                          context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_NO_DOMAIN:     No domain domain name given
 *  - #IDMAP_COLLISION:     New domain collides with existing one
 */
enum idmap_error_code sss_idmap_add_gen_domain_ex(struct sss_idmap_ctx *ctx,
                                                  const char *domain_name,
                                                  const char *domain_id,
                                                  struct sss_idmap_range *range,
                                                  const char *range_id,
                                                  idmap_offset_func *offset_func,
                                                  idmap_rev_offset_func *rev_offset_func,
                                                  void *offset_func_pvt,
                                                  uint32_t shift,
                                                  bool external_mapping);

/**
 * @brief Calculate offset from string containing only numbers
 */
enum idmap_error_code offset_identity(void *pvt, uint32_t range_size,
                                      const char *input, long long *offset);

/**
 * @brief Reverse of offset_identity, return a string containing only numbers
 * representing the given offset
 */
enum idmap_error_code rev_offset_identity(struct sss_idmap_ctx *ctx, void *pvt,
                                          uint32_t id, char **_out);

/**
 * @brief Calculate offset from string with the help of murmurhash3
 */
enum idmap_error_code offset_murmurhash3(void *pvt, uint32_t range_size,
                                         const char *input, long long *offset);

/**
 * Structure for private data for offset_murmurhash3. If not given 0xdeadbeef
 * will be used as seed. UTF8 strings will be normalized by default but not
 * casefolded.
 */
struct offset_murmurhash3_data {
    uint32_t seed;
    bool normalize;
    bool casefold;
};

/**
 * @brief Translate some input to a unix UID or GID
 *
 * @param[in] ctx       Idmap context
 * @param[in] domain_id Zero-terminated string with the domain ID of a known
 *                      domain
 * @param[in] input     Zero-terminated string which should be translated into
 *                      an offset to calculate the unix UID or GID
 * @param[out] id       Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domain with domain_id found in ctx
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 */
enum idmap_error_code sss_idmap_gen_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *domain_id,
                                            const char *input,
                                            uint32_t *_id);

/**
 * @brief Translate some input to a unix UID or GID
 *
 * @param[in] ctx       Idmap context
 * @param[in] id        UNIX UID or GID
 *                      an offset to calculate the unix UID or GID
 * @param[out] out      Original value the UID or GID was derived from
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domain with domain_id found in ctx
 *  - #IDMAP_EXTERNAL:      external source is authoritative for mapping
 *  - #IDMAP_NO_REVERSE:    the id cannot be reverted back to the original
 *                          source
 */
enum idmap_error_code sss_idmap_unix_to_gen(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **out);

/**
 * @}
 */
#endif /* SSS_IDMAP_H_ */
