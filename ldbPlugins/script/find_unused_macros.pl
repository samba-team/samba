#!/usr/bin/perl
# Script that reads in configure and outputs the names of all the defines 
# it defines that are used nowhere in the code

# Arguments: C and H files

my %defined,%used,%files;

# First, make a list of defines in configure
$in = shift;

while($tmp = shift) { 
	$files{$tmp} = $tmp;
	open(FI, $tmp);
	while(<FI>) { 
		$line = $_;
		$cur = "";
		if(/^#define ([A-Za-z0-9_]+)/) {
			$defined{$1} = $tmp;
			$cur = $1;
		}

		$_ = $line;
		while(/([A-Za-z0-9_]+)/sgm) { 
			if($cur cmp $1) { $used{$1} = $tmp; }
		}
	}
	close FI;
}

foreach(keys %defined) {
	if(!$used{$_}) { print "$_\n"; }
}
