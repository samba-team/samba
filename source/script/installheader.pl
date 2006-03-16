#!/usr/bin/perl
use strict;
use File::Basename;

my $includedir = shift;

sub install_header($$)
{
	my ($src,$dst) = @_;

	open(IN, "<$src");
	open(OUT, ">$dst");

	while (<IN>) {
		print OUT $_;
	}

	close(OUT);
	close(IN);
}

foreach my $p (@ARGV)
{
 my $p2 = basename($p);
 print "Installing $p as $includedir/$p2\n";

 if ( -f "$includedir/$p2" ) {
   unlink("$includedir/$p2.old");
   rename("$includedir/$p2", "$includedir/$p2.old");
 }

 install_header($p,"$includedir/$p2");
}

print <<EOF;
======================================================================
The headers are installed. You may restore the old headers (if there
were any) using the command "make revert". You may uninstall the headers
using the command "make uninstallheader" or "make uninstall" to uninstall
binaries, man pages and shell scripts.
======================================================================
EOF

exit 0;
