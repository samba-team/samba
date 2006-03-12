# Samba Build System
# - write out summary
#
#  Copyright (C) Jelmer Vernooij 2006
#  Released under the GNU GPL

package summary;
use strict;

sub showitem($$$)
{
	my ($output,$desc,$items) = @_;

	my @need = ();

	foreach (@$items) {
		if ($output->{"EXT_LIB_$_"}->{ENABLE} ne "YES") {
			push (@need, $_);
		}
	}

	print "Support for $desc: ";
	if ($#need >= 0) {
		print "no (install " . join(',',@need) . ")\n";
	} else {
		print "yes\n";
	}
}

sub show($$)
{
	my ($output,$config) = @_;

	print "Summary:\n\n";
	showitem($output, "GTK+ frontends", ["gtk","gconf"]);
	showitem($output, "SSL in SWAT", ["GNUTLS"]);
	showitem($output, "threads in smbd (see --with-pthread)", ["PTHREAD"]);
	showitem($output, "intelligent command line editing", ["READLINE"]);
	showitem($output, "changing process titles (see --with-setproctitle)", ["SETPROCTITLE"]);
	showitem($output, "using extended attributes", ["XATTR"]);
	showitem($output, "using libblkid", ["BLKID"]);
	showitem($output, "using pam", ["PAM"]);
	print "Using external popt: $output->{EXT_LIB_POPT}->{ENABLE}\n";
	print "Using shared libraries internally (experimental): ";

	if ($config->{BLDSHARED} eq "true") {
		print "yes\n";
	} else {
		print "no (try --enable-dso)\n";

	}
	print "\n";
}

1;
