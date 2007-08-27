#!/usr/bin/perl

my $firstline = 1;

while(<STDIN>) {
	if ($firstline) {
		$firstline = 0;
		next;
	}
	if (/^not ok (\d+) - (.*)$/) {
		print "test: $2\n";
		print "failure: $2\n";
	} elsif (/^ok (\d+) - (.*)$/) {
		print "test: $2\n";
		print "success: $2\n";
	} elsif (/^ok (\d+)$/) {
		print "test: $1\n";
		print "success: $1\n";
	} elsif (/^ok (\d+) # skip (.*)$/) {
		print "test: $1\n";
		print "skip: $1 [\n$2\n]\n";
	} elsif (/^not ok (\d+)$/) {
		print "test: $1\n";
		print "failure: $1\n";
	} else {
		print;
	}
}
