# SMB Build Environment Types Checks
# -------------------------------------------------------
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2004
#  Released under the GNU GPL
# -------------------------------------------------------
#

# Add #include for broken IRIX header files
if ($host_os =~ /.*irix6.*/) {
	AC_ADD_INCLUDE(<standards.h>)
}

#FIXME: AC_C_BIGENDIAN
#FIXME: AC_HEADER_STDC

check_headers("stdbool.h");
die("Sorry we need type 'long long'\n") if not check_sizeof("long long");
die("Sorry we need sizeof(long long) >= 8") if check_sizeof("long long") < 8;
1;
