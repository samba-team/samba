#!/usr/bin/perl
# Script that reads in configure and outputs the names of all the defines 
# it defines that are used nowhere in the code

# Arguments:
#  1: configure.in
#  2: header files
#
# You might want to specify configure.in again in the list of header files 
# as well, because it also uses some includes.

my %symbols;

# First, make a list of defines in configure
$in = shift;

while($tmp = shift) { 
	open(FI, $tmp);
	while(<FI>) { 
		while(/\#([ \t]*)include <(.*)>/sgm) { 
			$symbols{$2} = 1;
		}
	}
	close FI;
}

open(IN, $in) or die("Can't open $in");

while(<IN>) {
	if(/AC_CHECK_HEADERS\(([\[]*)(.*)([\]]*)\)/) {
		@hs = split / /, $2;
		foreach(@hs) { 
			if($symbols{$_} != 1) { print "|$_|\n"; }
		}
	}
}

close IN;
