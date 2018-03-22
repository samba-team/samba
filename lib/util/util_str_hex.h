#include "../libcli/util/ntstatus.h"

NTSTATUS read_hex_bytes(const char *s, uint hexchars, uint64_t *dest);

NTSTATUS parse_guid_string(const char *s,
			   uint32_t *time_low,
			   uint32_t *time_mid,
			   uint32_t *time_hi_and_version,
			   uint32_t clock_seq[2],
			   uint32_t node[6]);
