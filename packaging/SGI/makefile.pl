#!/usr/bin/perl

# This perl script creates the SGI specific Makefile. 
# The BASEDIR is set to /usr/samba, MANDIR is set to /usr/share/man, and
# the lines are uncommented for the requested OS version. If no version
# is specified, IRIX 6 is used.

if (!@ARGV) {
  $OSver = "6";
}
else {
  $OSver = $ARGV[0];
}

open(MAKEIN,"../../source/Makefile") || die "Unable to open source Makefile\n";
open(MAKEOUT,">Makefile") || die "Unable to open Makefile for output\n";
while (<MAKEIN>) {
    if (/^BASEDIR =/) {
	print MAKEOUT "BASEDIR = /usr/samba\n";
    }
    elsif (/^MANDIR =/) {
	print MAKEOUT "MANDIR = /usr/share/man\n";
    }
    elsif (/^# FOR SGI IRIX $OSver/) {
	print MAKEOUT;
	while (<MAKEIN>) {
	    last if ($_ eq "\n");
	    if (/^# (FLAGSM|LIBSM|FLAGS1)/) {
		s/^# //;
	    }
	    print MAKEOUT;
	}
	print MAKEOUT;
    }
    else {
	print MAKEOUT;
    }
}
