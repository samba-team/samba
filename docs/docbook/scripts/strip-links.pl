#!/usr/bin/perl

## small script to strip the <URL:...> tags from
## manpages generated from docbook2man.  we'll leave
## the <URL:ftp://...> and <URL:mailto:...> links for now

while (<STDIN>) {

	chomp ($_);
	$_ =~ s/\s*<URL:.*html.*>\s+/ /g;
	$_ =~ s/\s*<URL:.*html.*>\S//g;
	$_ =~ s/\s*<URL:.*html.*>$//g;
	print "$_\n";

}
exit 0;
