# SMB Build Environment LD Checks
# -------------------------------------------------------
#  Copyright (C) Stefan (metze) Metzmacher 2004
#  Copyright (C) Jelmer Vernooij 2004
#  Released under the GNU GPL
# -------------------------------------------------------
#
# Check if we use GNU ld
$LD = find_prog("ld");

sub prog_ld_gnu
{
	open IN, "$LD -v 2>&1 < /dev/null |";
	while(<IN>) { return 1 if (/(GNU|with BFD)/); }
	close IN;
	return 0;
}

$PROG_LD_GNU = check_cache("whether LD is GNU LD", \&prog_ld_gnu);
1;
