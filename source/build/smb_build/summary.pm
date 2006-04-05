# Samba Build System
# - write out summary
#
#  Copyright (C) Jelmer Vernooij 2006
#  Released under the GNU GPL

package summary;
use strict;

sub enabled($)
{
    my ($val) = @_;

    return (defined($val) && $val =~ m/yes|true/i);
}

sub showitem($$$)
{
	my ($output,$desc,$items) = @_;

	my @need = ();

	foreach (@$items) {
		if (!enabled($output->{"EXT_LIB_$_"}->{ENABLE})) {
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
	print "Using external popt: ".
	    (enabled($output->{EXT_LIB_POPT}->{ENABLE})?"yes":"no")."\n";
	print "Developer mode: ".(enabled($config->{developer})?"yes":"no")."\n";
	print "Automatic dependencies: ".
	    (enabled($config->{automatic_dependencies})
		    ? "yes" : "no (install GNU make >= 3.81)") .
	     "\n";
	
	print "Using shared libraries internally (experimental): " .
	    (enabled($config->{BLDSHARED})
		    ? "yes" : "no (try --enable-dso)") .
	    "\n";

	print "\n";
}

1;
