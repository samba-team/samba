#!/usr/bin/perl

## small script to stirp the <URL:...> tags from 
## manpages generated from docbook2man.  we'll leave
## the <URL:ftp://...> and <URL:mailto:...> links for now

while (<STDIN>) {

	chomp ($_);
	$_ =~ s/\s*<URL:.*html.*>\s*//g;
	print "$_\n";

}
exit 0;
