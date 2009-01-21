#!/usr/bin/perl
# Expand the include lines in a Makefile
# Copyright (C) 2009 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPLv3 or later

sub process($)
{
	my ($f) = @_;
	open(IN, $f) or die("Unable to open $f: $!");
	foreach (<IN>) {
		my $l = $_;
		if ($l =~ /^include (.*)$/) {
			process($1);
		} else {
			print $l;
		}
	}
}

my $path = shift;
unless ($path) {
	print STDERR "Usage: $0 Makefile.in > Makefile-noincludes.in\n";
	exit(1);
}
process($path);
