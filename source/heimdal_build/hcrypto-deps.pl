#!/usr/bin/perl
use strict;

foreach (@ARGV) {
	my $old = $_;
	my $new = $old; $new =~ s/des/des\/hcrypto/g;
	my $dir = $old; 
	print "$new: heimdal/lib/des/hcrypto\n";
}
