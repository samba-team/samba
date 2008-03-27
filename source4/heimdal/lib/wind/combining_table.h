/* combining_table.h */
/* Automatically generated at 2008-03-18T11:38:08.165877 */

#ifndef COMBINING_TABLE_H
#define COMBINING_TABLE_H 1

#include <stddef.h>
#include <stdint.h>

struct translation {
  uint32_t key;
  unsigned combining_class;	
};

extern const struct translation _wind_combining_table[];

extern const size_t _wind_combining_table_size;
#endif /* COMBINING_TABLE_H */
