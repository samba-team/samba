#!/usr/bin/perl

open(MAKEIN,"../../source/Makefile");
open(MAKEOUT,">Makefile");
while (<MAKEIN>) {
    if (/^BASEDIR =/) {
	print MAKEOUT "BASEDIR = /usr/samba\n";
    }
    elsif (/^MANDIR =/) {
	print MAKEOUT "MANDIR = /usr/share/man\n";
    }
    elsif (/^# FOR SGI IRIX 6/) {
	print MAKEOUT;
	$a = <MAKEIN>;
	print MAKEOUT $a;
	($a = <MAKEIN>) =~ s/^# //;
	print MAKEOUT $a;
	($a = <MAKEIN>) =~ s/^# //;
	print MAKEOUT $a;
	($a = <MAKEIN>) =~ s/^# //;
	print MAKEOUT $a;
    }
    else {
	print MAKEOUT;
    }
}
