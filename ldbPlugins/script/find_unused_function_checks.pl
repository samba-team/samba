#!/usr/bin/perl
# Arguments:
#  1: configure.in
#  2: C files
#
# You might want to specify configure.in again in the list of header files 
# as well, because it also uses some includes.
# Note that this script does not process any includes, so you might 
# have to run "cat configure.in */config.m4 > foo.in" first.

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
	if(/AC_CHECK_FUNCS\(([\[]*)(.*)([\]]*)\)/) {
		@hs = split / /, $2;
		foreach(@hs) { 
			if($symbols{$_} != 1) { print "$_\n"; }
		}
	}
}

close IN;
