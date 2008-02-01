#include "windlocl.h"

#include <stdlib.h>

#include "combining_table.h"

static int
translation_cmp(const void *key, const void *data)
{
    const struct translation *t1 = (const struct translation *)key;
    const struct translation *t2 = (const struct translation *)data;

    return t1->key - t2->key;
}

int
_wind_combining_class(uint32_t code_point)
{
    struct translation ts = {code_point};
    void *s = bsearch(&ts, _wind_combining_table, _wind_combining_table_size,
		      sizeof(_wind_combining_table[0]),
		      translation_cmp);
    if (s != NULL) {
	const struct translation *t = (const struct translation *)s;
	return t->combining_class;
    } else {
	return 0;
    }
}
