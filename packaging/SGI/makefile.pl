#!/usr/bin/perl

while (<>) {
    if (/^BASEDIR =/) {
	print "BASEDIR = /usr/samba\n";
    }
    elsif (/^MANDIR =/) {
	print "MANDIR = /usr/share/man\n";
    }
    elsif (/^# FOR SGI IRIX 6/) {
	print;
	$a = <>;
	print $a;
	<>;
	<>;
	<>;
	print "FLAGSM = -DSGI5 -DSHADOW_PWD -DHAVE_TIMEZONE -DFAST_SHARE_MODES\n";
	print "LIBSM =\n";
	print "FLAGS1 = -O -n32 -g3 -OPT:fold_arith_limit=1256\n";
    }
    else {
	print;
    }
}
