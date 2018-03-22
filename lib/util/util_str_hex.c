#include "replace.h"
#include "libcli/util/ntstatus.h"
#include "util_str_hex.h"

NTSTATUS read_hex_bytes(const char *s, uint hexchars, uint64_t *dest)
{
	uint64_t x = 0;
	uint i;
	char c;

	if ((hexchars & 1) || hexchars > 16) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < hexchars; i++) {
		x <<= 4;
		c = s[i];
		if (c >= '0' && c <= '9') {
			x += c - '0';
		}
		else if (c >= 'a' && c <= 'f') {
			x += c - 'a' + 10;
		}
		else if (c >= 'A' && c <= 'F') {
			x += c - 'A' + 10;
		}
		else {
			/* BAD character (including '\0') */
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	*dest = x;
	return NT_STATUS_OK;
}


NTSTATUS parse_guid_string(const char *s,
			   uint32_t *time_low,
			   uint32_t *time_mid,
			   uint32_t *time_hi_and_version,
			   uint32_t clock_seq[2],
			   uint32_t node[6])
{
	uint64_t tmp;
	NTSTATUS status;
	int i;
	/* "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
                |     |    |    |    |
                |     |    |    |    \ node[6]
                |     |    |    \_____ clock_seq[2]
                |     |    \__________ time_hi_and_version
		|     \_______________ time_mid
		\_____________________ time_low
	*/
	status = read_hex_bytes(s, 8, &tmp);
	if (!NT_STATUS_IS_OK(status) || s[8] != '-') {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*time_low = tmp;
	s += 9;

	status = read_hex_bytes(s, 4, &tmp);
	if (!NT_STATUS_IS_OK(status) || s[4] != '-') {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*time_mid = tmp;
	s += 5;

	status = read_hex_bytes(s, 4, &tmp);
	if (!NT_STATUS_IS_OK(status) || s[4] != '-') {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*time_hi_and_version = tmp;
	s += 5;

	for (i = 0; i < 2; i++) {
		status = read_hex_bytes(s, 2, &tmp);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		clock_seq[i] = tmp;
		s += 2;
	}
	if (s[0] != '-') {
		return NT_STATUS_INVALID_PARAMETER;
	}

	s++;

	for (i = 0; i < 6; i++) {
		status = read_hex_bytes(s, 2, &tmp);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		node[i] = tmp;
		s += 2;
	}

	return NT_STATUS_OK;
}
