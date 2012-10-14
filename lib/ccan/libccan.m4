dnl find the ccan sources.
ccandir="../lib/ccan"
for d in $ccanpaths; do
	if test -f "$srcdir/$d/str/str.c"; then
		ccandir="$d"
		AC_SUBST(ccandir)
		break
	fi
done
if test -f "$ccandir/str/str.c"; then :; else
   AC_MSG_ERROR([cannot find ccan source in $ccandir])
fi
CCAN_OBJ="$ccandir/hash/hash.o $ccandir/htable/htable.o $ccandir/ilog/ilog.o $ccandir/likely/likely.o $ccandir/str/debug.o $ccandir/str/str.o $ccandir/tally/tally.o"

AC_SUBST(CCAN_OBJ)

# Preferred method for including ccan modules is #include <ccan/module/...>.
CCAN_CFLAGS="-I$ccandir/.."
AC_SUBST(CCAN_CFLAGS)

# All the configuration checks.  Regrettably, the __attribute__ checks will
# give false positives on old GCCs, since they just cause warnings.  But that's
# fairly harmless.
AC_CHECK_HEADERS(err.h)

AC_CHECK_HEADERS(byteswap.h)

AC_CACHE_CHECK([whether we can compile with __attribute__((cold))],
	       samba_cv_attribute_cold,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((cold))
				cleanup(void) { }
			])],
			samba_cv_attribute_cold=yes)
		])

if test x"$samba_cv_attribute_cold" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_COLD, 1,
	     [whether we can compile with __attribute__((cold))])
fi

AC_CACHE_CHECK([whether we can compile with __attribute__((const))],
	       samba_cv_attribute_const,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((const))
				cleanup(void) { }
			])],
			samba_cv_attribute_const=yes)
		])

if test x"$samba_cv_attribute_const" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_CONST, 1,
	     [whether we can compile with __attribute__((const))])
fi

AC_CACHE_CHECK([whether we can compile with __attribute__((noreturn))],
	       samba_cv_attribute_noreturn,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((noreturn))
				cleanup(void) { exit(1); }
			])],
			samba_cv_attribute_noreturn=yes)
		])

if test x"$samba_cv_attribute_noreturn" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_NORETURN, 1,
	     [whether we can compile with __attribute__((noreturn))])
fi

AC_CACHE_CHECK([whether we can compile with __attribute__((printf))],
	       samba_cv_attribute_printf,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((format(__printf__, 1, 2)))
				cleanup(const char *fmt, ...) { }
			])],
			samba_cv_attribute_printf=yes)
		])

if test x"$samba_cv_attribute_printf" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_PRINTF, 1,
	     [whether we can compile with __attribute__((format(printf)))])
fi

AC_CACHE_CHECK([whether we can compile with __attribute__((unused))],
	       samba_cv_attribute_unused,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((unused))
				cleanup(void) { }
			])],
			samba_cv_attribute_unused=yes)
		])

if test x"$samba_cv_attribute_unused" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_UNUSED, 1,
	     [whether we can compile with __attribute__((unused))])
fi

AC_CACHE_CHECK([whether we can compile with __attribute__((used))],
	       samba_cv_attribute_used,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[
				static void __attribute__((used))
				cleanup(void) { }
			])],
			samba_cv_attribute_used=yes)
		])

if test x"$samba_cv_attribute_used" = xyes ; then
   AC_DEFINE(HAVE_ATTRIBUTE_USED, 1,
	     [whether we can compile with __attribute__((used))])
fi

# FIXME: We could use endian.h or sys/endian.h here, and __BYTE_ORDER for
# cross-compiling.
AC_CACHE_CHECK([whether we are big endian],samba_cv_big_endian,[
AC_TRY_RUN([int main(void) {
union { int i; char c[sizeof(int)]; } u;
	  u.i = 0x01020304;
	  return u.c[0] == 0x01 && u.c[1] == 0x02 && u.c[2] == 0x03 && u.c[3] == 0x04 ? 0 : 1;
}],
samba_cv_big_endian=yes,
samba_cv_big_endian=no)])
if test x"$samba_cv_big_endian" = xyes ; then
   AC_DEFINE(HAVE_BIG_ENDIAN, 1,
	     [whether we are big endian])
fi

AC_CACHE_CHECK([whether we have __builtin_clz],
	       samba_cv_builtin_clz,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_clz(1) == (sizeof(int)*8 - 1) ? 0 : 1;
			}])],
			samba_cv_builtin_clz=yes)
		])

if test x"$samba_cv_builtin_clz" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_CLZ, 1,
	     [whether we have __builtin_clz])
fi

AC_CACHE_CHECK([whether we have __builtin_clzl],
	       samba_cv_builtin_clzl,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_clzl(1) == (sizeof(int)*8 - 1) ? 0 : 1;
			}])],
			samba_cv_builtin_clzl=yes)
		])

if test x"$samba_cv_builtin_clzl" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_CLZL, 1,
	     [whether we have __builtin_clzl])
fi
AC_CACHE_CHECK([whether we have __builtin_clzll],
	       samba_cv_builtin_clzll,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_clzll(1) == (sizeof(int)*8 - 1) ? 0 : 1;
			}])],
			samba_cv_builtin_clzll=yes)
		])

if test x"$samba_cv_builtin_clzll" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_CLZLL, 1,
	     [whether we have __builtin_clzll])
fi

AC_CACHE_CHECK([whether we have __builtin_constant_p],
	       samba_cv_builtin_constant_p,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_constant_p(1) ? 0 : 1;
			}])],
			samba_cv_builtin_constant_p=yes)
		])

if test x"$samba_cv_builtin_constant_p" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_CONSTANT_P, 1,
	     [whether we have __builtin_constant_p])
fi

AC_CACHE_CHECK([whether we have __builtin_expect],
	       samba_cv_builtin_expect,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_expect(main != 0, 1) ? 0 : 1;
			}])],
			samba_cv_builtin_expect=yes)
		])

if test x"$samba_cv_builtin_expect" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_EXPECT, 1,
	     [whether we have __builtin_expect])
fi

AC_CACHE_CHECK([whether we have __builtin_popcountl],
	       samba_cv_builtin_popcountl,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_popcountl(255L) == 8 ? 0 : 1;
			}])],
			samba_cv_builtin_popcountl=yes)
		])

if test x"$samba_cv_builtin_popcountl" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_POPCOUNTL, 1,
	     [whether we have __builtin_popcountl])
fi

AC_CACHE_CHECK([whether we have __builtin_types_compatible_p],
	       samba_cv_builtin_types_compatible_p,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_types_compatible_p(char *, int) ? 1 : 0;
			}])],
			samba_cv_builtin_types_compatible_p=yes)
		])

if test x"$samba_cv_builtin_types_compatible_p" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_TYPES_COMPATIBLE_P, 1,
	     [whether we have __builtin_types_compatible_p])
fi

AC_CACHE_CHECK([whether we have __builtin_choose_expr],
	       samba_cv_builtin_choose_expr,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				return __builtin_choose_expr(1, 0, "garbage");
			}])],
			samba_cv_builtin_choose_expr=yes)
		])

if test x"$samba_cv_builtin_choose_expr" = xyes ; then
   AC_DEFINE(HAVE_BUILTIN_CHOOSE_EXPR, 1,
	     [whether we have __builtin_choose_expr])
fi

# We use @<:@ and @:>@ here for embedded [ and ].
AC_CACHE_CHECK([whether we have compound literals],
	       samba_cv_compound_literals,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				int *foo = (int@<:@@:>@) { 1, 2, 3, 4 };
				return foo@<:@0@:>@ == 1 ? 0 : 1;
			}])],
			samba_cv_compound_literals=yes)
		])

if test x"$samba_cv_compound_literals" = xyes ; then
   AC_DEFINE(HAVE_COMPOUND_LITERALS, 1,
	     [whether we have compound literals])
fi

AC_CACHE_CHECK([whether we have flexible array members],
	       samba_cv_have_flex_arr_member,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[struct foo { unsigned int x; int arr@<:@@:>@; }; ])],
			samba_cv_have_flex_arr_member=yes)
		])

if test x"$samba_cv_have_flex_arr_member" = xyes ; then
   AC_DEFINE(HAVE_FLEXIBLE_ARRAY_MEMBER, 1,
	     [whether we have flexible array member support])
fi

AC_CACHE_CHECK([whether we have isblank],
	       samba_cv_have_isblank,
	       [
	         AC_LINK_IFELSE([AC_LANG_SOURCE(
			[#include <ctype.h>
			 int main(void) { return isblank(' ') ? 0 : 1; }
			])],
			samba_cv_have_isblank=yes)
		])

if test x"$samba_cv_have_isblank" = xyes ; then
   AC_DEFINE(HAVE_ISBLANK, 1,
	     [whether we have isblank])
fi

# FIXME: We could use endian.h or sys/endian.h here, and __BYTE_ORDER for
# cross-compiling.
AC_CACHE_CHECK([whether we are little endian],samba_cv_little_endian,[
AC_TRY_RUN([int main(void) {
union { int i; char c[sizeof(int)]; } u;
	  u.i = 0x01020304;
	  return u.c[0] == 0x04 && u.c[1] == 0x03 && u.c[2] == 0x02 && u.c[3] == 0x01 ? 0 : 1;
}],
samba_cv_little_endian=yes,
samba_cv_little_endian=no)])
if test x"$samba_cv_little_endian" = xyes ; then
   AC_DEFINE(HAVE_LITTLE_ENDIAN, 1,
	     [whether we are little endian])
fi

AC_CACHE_CHECK([whether we have __typeof__],
	       samba_cv_typeof,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[int main(void) {
				int x = 1;
				__typeof__(x) i;
				i = x;
				return i == x ? 0 : 1;
			}])],
			samba_cv_typeof=yes)
		])

if test x"$samba_cv_typeof" = xyes ; then
   AC_DEFINE(HAVE_TYPEOF, 1,
	     [whether we have __typeof__])
fi

AC_CACHE_CHECK([whether we have __attribute__((warn_unused_result))],
	       samba_cv_warn_unused_result,
	       [
	         AC_COMPILE_IFELSE([AC_LANG_SOURCE(
			[int __attribute__((warn_unused_result)) func(int x)
			    { return x; }])],
			samba_cv_warn_unused_result=yes)
		])

if test x"$samba_cv_warn_unused_result" = xyes ; then
   AC_DEFINE(HAVE_WARN_UNUSED_RESULT, 1,
	     [whether we have __attribute__((warn_unused_result))])
fi
AC_HAVE_DECL(bswap_64, [#include <byteswap.h>])
