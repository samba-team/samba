#!/usr/bin/perl
use strict;

foreach (@ARGV) {
	my $old = $_;
	my $new = $old; $new =~ s/hcrypto/hcrypto\/hcrypto/g;
	my $dir = $old; 
	print "$new: heimdal/lib/hcrypto/hcrypto\n";
}
