#!/usr/bin/perl
# Script that reads in configure and outputs the names of all the defines 
# it defines that are used nowhere in the code

# Arguments:
#  1: configure.in
#  2: C files pattern

my %symbols;

# First, make a list of defines in configure
$in = shift;

while($tmp = shift) { 
	open(FI, $tmp);
	while(<FI>) { 
		while(/([A-Za-z0-9_]+)/sgm) { 
			$symbols{$1} = 1;
		}
	}
	close FI;
}

open(IN, $in) or die("Can't open $in");

while(<IN>) {
	if(/AC_DEFINE\(([^,]+),/ and $symbols{$1} != 1) { print "$1\n"; } 
}

close IN;
