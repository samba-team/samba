#include "replace.h"
#include "util_str_hex.h"
#include "lib/util/data_blob.h"
#include "librpc/gen_ndr/misc.h"

static bool hex_uint16(const char *in, uint16_t *out)
{
	uint8_t hi=0, lo=0;
	bool ok = hex_byte(in, &hi) && hex_byte(in+2, &lo);
	*out = (((uint16_t)hi)<<8) + lo;
	return ok;
}

bool hex_uint32(const char *in, uint32_t *out)
{
	uint16_t hi=0, lo=0;
	bool ok = hex_uint16(in, &hi) && hex_uint16(in+4, &lo);
	*out = (((uint32_t)hi)<<16) + lo;
	return ok;
}

bool parse_guid_string(const char *s, struct GUID *guid)
{
	bool ok;
	int i;
	/* "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
                |     |    |    |    |
                |     |    |    |    \ node[6]
                |     |    |    \_____ clock_seq[2]
                |     |    \__________ time_hi_and_version
		|     \_______________ time_mid
		\_____________________ time_low
	*/

	ok = hex_uint32(s, &guid->time_low);
	if (!ok || (s[8] != '-')) {
		return false;
	}
	s += 9;

	ok = hex_uint16(s, &guid->time_mid);
	if (!ok || (s[4] != '-')) {
		return false;
	}
	s += 5;

	ok = hex_uint16(s, &guid->time_hi_and_version);
	if (!ok || (s[4] != '-')) {
		return false;
	}
	s += 5;

	ok = hex_byte(s, &guid->clock_seq[0]) &&
		hex_byte(s+2, &guid->clock_seq[1]);
	if (!ok || (s[4] != '-')) {
		return false;
	}
	s += 5;

	for (i = 0; i < 6; i++) {
		ok = hex_byte(s, &guid->node[i]);
		if (!ok) {
			return false;
		}
		s += 2;
	}

	return true;
}
