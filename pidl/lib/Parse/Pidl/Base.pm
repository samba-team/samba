# Superclass for IDL structure generators
# GPL3

package Parse::Pidl::Base;

use strict;
use warnings;

use Parse::Pidl qw(fatal warning error);

use vars qw($VERSION);
$VERSION = '0.01';

sub indent {
	my $self = shift;
	$self->{tabs} .= "\t";
}

sub deindent {
	my $self = shift;
	$self->{tabs} = substr($self->{tabs}, 1);
}

sub pidl {
	my ($self, $txt) = @_;
	if ($txt) {
		if ($txt !~ /^#/) {
			$self->{res} .= $self->{tabs};
		}
		$self->{res} .= $txt;
	}
	$self->{res} .= "\n";
}


sub pidl_hdr {
	my ($self, $txt) = @_;
	$self->{res_hdr} .= "$txt\n";
}


sub pidl_both {
	my ($self, $txt) = @_;
	$self->{res} .= "$txt\n";
	$self->{res_hdr} .= "$txt\n";
}


# When the PIDL_DEVELOPER env flag is set, we overwrite $self->pidl()
# and $self->pidl_hdr() to annotate the output with location
# information.

sub pidl_dev_msg {
	my $self = shift;
	my ($pkg, $file, $line, $sub) = caller(2);
	# minimise the path
	if ($file =~ m{/pidl/(lib/.+|pidl)$}) {
		$file = $1;
	}
	my $state = $self->{dev_state} // ['uninitialised', 0, ''];
	my ($ploc, $pline, $ptabs) = @$state;
	my $loc = "$sub	 $file";

	if ($loc ne $ploc or
	    abs($line - $pline) > 20 or
	    $self->{tabs} ne $ptabs) {
		$self->{dev_state} = [$loc, $line, $self->{tabs}];
		return "  //<PIDL> $loc:$line";
	}
	return '';
}


if ($ENV{PIDL_DEVELOPER}) {
	undef &pidl;
	undef &pidl_hdr;

	*Parse::Pidl::Base::pidl = sub {
		my ($self, $txt) = @_;

		if ($txt) {
			if ($txt !~ /^#/) {
				$self->{res} .= $self->{tabs};
			}
			$self->{res} .= $txt;
		}
		$self->{res} .= $self->pidl_dev_msg;
		$self->{res} .= "\n";
	};

	*Parse::Pidl::Base::pidl_hdr = sub {
		my ($self, $txt) = @_;
		$txt .= $self->pidl_dev_msg;
		$self->{res_hdr} .= "$txt\n";
	}
}


1;
