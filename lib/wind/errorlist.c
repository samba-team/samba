#include "windlocl.h"

#include <stdlib.h>

#include "errorlist_table.h"

static int
error_entry_cmp(const void *a, const void *b)
{
    const struct error_entry *ea = (const struct error_entry*)a;
    const struct error_entry *eb = (const struct error_entry*)b;

    if (ea->start >= eb->start && ea->start < eb->start + eb->len)
	return 0;
    return ea->start - eb->start;
}

int
_wind_stringprep_error(uint32_t cp, wind_profile_flags flags)
{
    struct error_entry ee = {cp};
    const struct error_entry *s;

    s = (const struct error_entry *)
	bsearch(&ee, _wind_errorlist_table,
		_wind_errorlist_table_size,
		sizeof(_wind_errorlist_table[0]),
		error_entry_cmp);
    if (s == NULL)
	return 0;
    return (s->flags & flags);
}

int
_wind_stringprep_prohibited(const uint32_t *in, size_t in_len,
			    wind_profile_flags flags)
{
    unsigned i;

    for (i = 0; i < in_len; ++i)
	if (_wind_stringprep_error(in[i], flags))
	    return 1;
    return 0;
}
