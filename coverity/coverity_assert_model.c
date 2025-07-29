/*
 * Modelling file for Coverity Scan
 *
 * This is a modeling file for Coverity Scan. Modeling helps to avoid false
 * positives.
 *
 * - A model file can't import any header files.
 * - Therefore only some built-in primitives like int, char and void are
 *   available but not NULL etc.
 * - Modeling doesn't need full structs and typedefs. Rudimentary structs
 *   and similar types are sufficient.
 * - An uninitialized local pointer is not an error. It signifies that the
 *   variable could be either NULL or have some data.
 *
 * Coverity Scan doesn't pick up modifications automatically. The model file
 * must be uploaded by an admin.
 *
 * See also https://scan.coverity.com/models
 */

#define LargestIntegralType unsigned long long
#define NULL (void *)0
#define bool unsigned int
#define true 1
#define false 0
/* size_t is already defined by Coverity */

void _assert_true(const LargestIntegralType result,
                  const char* const expression,
                  const char * const file, const int line)
{
      __coverity_panic__();
}

void _assert_int_equal(
    const LargestIntegralType a, const LargestIntegralType b,
    const char * const file, const int line)
{
      __coverity_panic__();
}

void _assert_int_not_equal(
    const LargestIntegralType a, const LargestIntegralType b,
    const char * const file, const int line)
{
      __coverity_panic__();
}

void _assert_return_code(const LargestIntegralType result,
                         size_t rlen,
                         const LargestIntegralType error,
                         const char * const expression,
                         const char * const file,
                         const int line)
{
      __coverity_panic__();
}

void _assert_string_equal(const char * const a, const char * const b,
                          const char * const file, const int line)
{
      __coverity_panic__();
}

void _assert_string_not_equal(const char * const a, const char * const b,
                              const char *file, const int line)
{
      __coverity_panic__();
}

void _assert_memory_equal(const void * const a, const void * const b,
                          const size_t size, const char* const file,
                          const int line)
{
      __coverity_panic__();
}

void _assert_memory_not_equal(const void * const a, const void * const b,
                              const size_t size, const char* const file,
                              const int line)
{
      __coverity_panic__();
}

void _assert_in_range(
    const LargestIntegralType value, const LargestIntegralType minimum,
    const LargestIntegralType maximum, const char* const file, const int line)
{
      __coverity_panic__();
}

void _assert_not_in_range(
    const LargestIntegralType value, const LargestIntegralType minimum,
    const LargestIntegralType maximum, const char* const file, const int line)
{
      __coverity_panic__();
}

void _assert_in_set(
    const LargestIntegralType value, const LargestIntegralType values[],
    const size_t number_of_values, const char* const file, const int line)
{
      __coverity_panic__();
}

void _assert_not_in_set(
    const LargestIntegralType value, const LargestIntegralType values[],
    const size_t number_of_values, const char* const file, const int line)
{
      __coverity_panic__();
}

/***********************************************************
 * SAMBA
 ***********************************************************/

/* ./lib/util */

bool strequal(const char *a, const char *b)
{
	/* Require NUL-terminated arguments */
	__coverity_string_null_sink__(a);
	__coverity_string_null_sink__(b);

	return true;
}
