#!/usr/bin/perl

$ignore = 0;

print "<!DOCTYPE article PUBLIC \"-//OASIS//DTD DocBook V4.1//EN\">\n";

while (<STDIN>) {

	$_ =~ s/<chapter/<article/g;
	$_ =~ s/<\/chapter/<\/article/g;

	if ( $_ =~ '<articleinfo>') {
		$ignore = 1;
	}

	if ( $_ =~ '</articleinfo>') {
		$ignore = 0;
		$_ = "";
	}


	if (! $ignore) { print "$_"; }


}
