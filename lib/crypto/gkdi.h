/*
   Unix SMB/CIFS implementation.
   Group Key Distribution Protocol functions

   Copyright (C) Catalyst.Net Ltd 2023

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIB_CRYPTO_GKDI_H
#define LIB_CRYPTO_GKDI_H

#include <stdint.h>

#include <gnutls/gnutls.h>

#include "lib/util/data_blob.h"

#include "libcli/util/ntstatus.h"

#include "librpc/gen_ndr/misc.h"
#include "lib/util/time.h"
#include "talloc.h"

enum KdfAlgorithmId {
	KDF_ALGORITHM_SP800_108_CTR_HMAC,
};

#define SP800_108_CTR_HMAC "SP800_108_CTR_HMAC"

enum KdfSp800_108Param {
	KDF_PARAM_SHA1,
	KDF_PARAM_SHA256,
	KDF_PARAM_SHA384,
	KDF_PARAM_SHA512,
};

struct KdfAlgorithm {
	union {
		enum KdfSp800_108Param sp800_108;
	} param;
	enum KdfAlgorithmId id;
};

enum {
	root_key_version_1 = 1,
};

struct ProvRootKey {
	struct GUID id;
	DATA_BLOB data;
	NTTIME create_time;
	NTTIME use_start_time;
	const char *domain_id;
	struct KdfAlgorithm kdf_algorithm;
	int32_t version;
};

NTSTATUS ProvRootKey(TALLOC_CTX *mem_ctx,
		     const struct GUID root_key_id,
		     const int32_t version,
		     const DATA_BLOB root_key_data,
		     const NTTIME create_time,
		     const NTTIME use_start_time,
		     const char *const domain_id,
		     const struct KdfAlgorithm kdf_algorithm,
		     const struct ProvRootKey **const root_key_out);

struct Gkid {
	int32_t l0_idx;
	int8_t l1_idx; /* [range(0, 31)] */
	int8_t l2_idx; /* [range(0, 31)] */
};

enum GkidType {
	GKID_DEFAULT = -1,
	GKID_L0_SEED_KEY = 0,
	GKID_L1_SEED_KEY = 1,
	GKID_L2_SEED_KEY = 2,
};

/*
 * Construct a GKID. The caller must check the returned GKID is valid before
 * using it!
 */
static inline struct Gkid Gkid(int32_t l0_idx, int8_t l1_idx, int8_t l2_idx)
{
	return (struct Gkid){l0_idx, l1_idx, l2_idx};
}

static const struct Gkid invalid_gkid = {
	INT32_MIN,
	INT8_MIN,
	INT8_MIN,
};

static const uint32_t key_envelope_magic = 0x4b53444b; /* ‘KDSK’ */

struct KeyEnvelopeId {
	struct GUID root_key_id;
	struct Gkid gkid;
};

struct KeyEnvelope;
NTSTATUS gkdi_pull_KeyEnvelope(TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *pwd_id_blob,
			       struct KeyEnvelope *pwd_id_out);

const struct KeyEnvelopeId *gkdi_pull_KeyEnvelopeId(
	const DATA_BLOB key_env,
	struct KeyEnvelopeId *key_env_out);

enum GkidType gkid_key_type(const struct Gkid gkid);

bool gkid_is_valid(const struct Gkid gkid);

static const int gkdi_l1_key_iteration = 32;
static const int gkdi_l2_key_iteration = 32;

static const int64_t gkdi_key_cycle_duration = 360000000000; /* ten hours */
static const int gkdi_max_clock_skew_mins = 5;
static const int64_t gkdi_max_clock_skew = 3000000000;	     /* five minutes */

#define GKDI_KEY_LEN 64

struct Gkid gkdi_get_interval_id(const NTTIME time);

bool gkdi_get_key_start_time(const struct Gkid gkid, NTTIME *start_time_out);

NTTIME gkdi_get_interval_start_time(const NTTIME time);

bool gkid_less_than_or_equal_to(const struct Gkid g1, const struct Gkid g2);

bool gkdi_rollover_interval(const int64_t managed_password_interval,
			    NTTIME *result);

gnutls_mac_algorithm_t get_sp800_108_mac_algorithm(
	const struct KdfAlgorithm kdf_algorithm);

NTSTATUS compute_seed_key(TALLOC_CTX *mem_ctx,
			  const DATA_BLOB target_security_descriptor,
			  const struct ProvRootKey *const root_key,
			  const struct Gkid gkid,
			  uint8_t out[static const GKDI_KEY_LEN]);

NTSTATUS kdf_sp_800_108_from_params(
	const DATA_BLOB *const kdf_param,
	struct KdfAlgorithm *const kdf_algorithm_out);

NTSTATUS kdf_algorithm_from_params(
	const char *const kdf_algorithm_id,
	const DATA_BLOB *const kdf_param,
	struct KdfAlgorithm *const kdf_algorithm_out);

#endif /* LIB_CRYPTO_GKDI_H */
