# SMB Build Environment CC Checks
# -------------------------------------------------------
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Released under the GNU GPL
# -------------------------------------------------------
#

$CC = $ENV{"CC"} if (defined($ENV{"CC"}));
$CC = "cc" if not defined($CC);
$CC = "" if not -x $CC;

die("No c compiler was not found!\nPlease Install gcc from http://gcc.gnu.org/") if not defined($CC);

# Check if C compiler understands -c and -o at the same time
$cc_c_o = check_cache("if the compiler understands -c and -o at the same time", sub { my $FIXME = 1; return $FIXME;  });

$precompiled_headers = check_cache("that the C compiler can precompile header files", sub { my $FIXME = 1; return $FIXME; });

# Check if the C compiler understands volatile (it should, being ANSI).
$cc_volatile = check_compile("that the C compiler understands volatile", 
"#include <sys/types.h>", "volatile int i = 0;");

$cc_immediate_struct = check_compile("for immediate structures", 
"#include <stdio.h>",
"
   typedef struct {unsigned x;} FOOBAR;
   #define X_FOOBAR(x) ((FOOBAR) { x })
   #define FOO_ONE X_FOOBAR(1)
   FOOBAR f = FOO_ONE;   
   static struct {
	FOOBAR y; 
	} f2[] = {
		{FOO_ONE}
	};   
");

die("cant find test code. Aborting config") unless check_run("for test routines", "#include \"$srcdir/build/tests/trivial.c\"");

#
# Check if the compiler can handle the options we selected by
# --enable-*developer
#
if ($DEVELOPER_CFLAGS ne "") {
	$OLD_CFLAGS=$CFLAGS;
	$CFLAGS.=$DEVELOPER_CFLAGS;
	
	$DEVELOPER_CFLAGS = "" unless check_run("that the C compiler can use the DEVELOPER_CFLAGS", "#include \"$srcdir/build/tests/trivial.c\"");
	
	$CFLAGS = $OLD_CFLAGS;
}
1;
