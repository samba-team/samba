#!/usr/bin/perl

$invar = 0;
$topdir = (shift @ARGV) or $topdir = ".";
$makefile = "$topdir/source/Makefile.in";
$mandir = "$topdir/docs-xml/manpages-3";
$progs = "";

chdir($topdir);

if(! -e "$makefile") {
	print "$makefile does not exist!\n";
	print "Wrong directory?\n";
	exit(1);
}

if(! -d "$mandir") {
        print "$mandir does not exist!\n";
        exit(1);
}

open(IN, "$makefile");
while(<IN>) {
	if($invar && /^([ \t]*)(.*?)([\\])$/) {
		$progs.=" " . $2;
		if($4) { $invar = 1; } else { $invar = 0; }
	} elsif(/^([^ ]*)_PROGS([0-9]*) = (.*?)([\\])$/) {
		$progs.=" " . $3;
		if($4) { $invar = 1; }
	} else { $invar = 0; }
}

foreach(split(/bin\//, $progs)) {
	next if($_ eq " ");
	s/\@EXEEXT\@//g;
	s/\@EXTRA_BIN_PROGS\@//g;
	s/ //g;


	$f = $_;

	$found = 0;


	for($i = 0; $i < 9; $i++) {
		if(-e "$mandir/$f.$i.xml") { $found = 1; }
	}

	if(!$found) {
		print "'$f' does not have a manpage\n";
	}
}
