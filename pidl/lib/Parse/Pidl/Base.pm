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
