#! /usr/bin/perl
#
# Summarise tshark pdml output into a form suitable for the load test tool
#
# Copyright (C) Catalyst.Net Ltd 2017
#
# Catalyst.Net's contribution was written by Gary Lockyer
# <gary@catalyst.net.nz>.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

use warnings;
use strict;

use Getopt::Long;
use Pod::Usage;

BEGIN {
    unless (eval "require XML::Twig") {
        warn "traffic_summary requires the perl module XML::Twig\n" .
             "on Ubuntu/Debian releases run\n".
             "  sudo apt install libxml-twig-perl \n".
             "or install from CPAN\n".
             "\nThe reported error was:\n$@";
        exit(1);
    }
}


my %ip_map;              # Map of IP address to sequence number
my $ip_sequence = 0;     # count of unique IP addresses seen


my $timestamp;           # Packet timestamp
my $stream;              # Wireshark stream number
my $ip_proto;            # IP protocol (IANA protocl number)
my $source;              # source IP address
my $dest;                # destination address
my $proto;               # application protocol name
my $description;         # protocol specific description
my %proto_data;          # protocol specific data captured for the current packet
my $malformed_packet;    # Indicates the current packet has errors
my $ldap_filter;         # cleaned ldap filter
my $ldap_attributes;     # attributes requested in an ldap query



# Dispatch table mapping the wireshark variables of interest to the
# functions responsible for processing them
my %field_dispatch_table = (
    'timestamp'                       => \&timestamp,
    'ip.src'                          => \&ip_src,
    'ipv6.src'                        => \&ip_src,
    'ip.dst'                          => \&ip_dst,
    'ipv6.dst'                        => \&ip_dst,
    'ip.proto'                        => \&ip_proto,
    'udp.stream'                      => \&stream,
    'tcp.stream'                      => \&stream,
    'dns.flags.opcode'                => \&field_data,
    'dns.flags.response'              => \&field_data,
    'netlogon.opnum'                  => \&field_data,
    'kerberos.msg_type'               => \&field_data,
    'smb.cmd'                         => \&field_data,
    'smb2.cmd'                        => \&field_data,
    'ldap.protocolOp'                 => \&field_data,
    'gss-api.OID'                     => \&field_data,
    'ldap.gssapi_encrypted_payload'   => \&field_data,
    'ldap.baseObject'                 => \&field_data,
    'ldap.scope'                      => \&field_data,
    'ldap.AttributeDescription'       => \&ldap_attribute,
    'ldap.modification_element'       => \&ldap_add_modify,
    'ldap.AttributeList_item_element' => \&ldap_add_modify,
    'ldap.operation'                  => \&field_data,
    'ldap.authentication'             => \&field_data,
    'lsarpc.opnum'                    => \&field_data,
    'samr.opnum'                      => \&field_data,
    'dcerpc.pkt_type'                 => \&field_data,
    'epm.opnum'                       => \&field_data,
    'dnsserver.opnum'                 => \&field_data,
    'drsuapi.opnum'                   => \&field_data,
    'browser.command'                 => \&field_data,
    'smb_netlogon.command'            => \&field_data,
    'srvsvc.opnum'                    => \&field_data,
    'nbns.flags.opcode'               => \&field_data,
    'nbns.flags.response'             => \&field_data,
    '_ws.expert.message'              => \&field_data,
);

# Dispatch table mapping protocols to the routine responsible for formatting
# their output.  Protocols not in this table are ignored.
#
my %proto_dispatch_table = (
    'dns'          => sub { return format_opcode( 'dns.flags.response')},
    'rpc_netlogon' => sub { return format_opcode( 'netlogon.opnum')},
    'kerberos'     => \&format_kerberos,
    'smb'          => sub { return format_opcode( 'smb.cmd')},
    'smb2'         => sub { return format_opcode( 'smb2.cmd')},
    'ldap'         => \&format_ldap,
    'cldap'        => \&format_ldap,
    'lsarpc'       => sub { return format_opcode( 'lsarpc.opnum')},
    'samr'         => sub { return format_opcode( 'samr.opnum')},
    'dcerpc'       => sub { return format_opcode( 'dcerpc.pkt_type')},
    'epm'          => sub { return format_opcode( 'epm.opnum')},
    'dnsserver'    => sub { return format_opcode( 'dnsserver.opnum')},
    'drsuapi'      => sub { return format_opcode( 'drsuapi.opnum')},
    'browser'      => sub { return format_opcode( 'browser.command')},
    'smb_netlogon' => sub { return format_opcode( 'smb_netlogon.command')},
    'srvsvc'       => sub { return format_opcode( 'srvsvc.opnum')},
    'nbns'         => sub { return format_opcode( 'nbns.flags.response')},
);

# XPath entry to extract the kerberos cname
my $kerberos_cname_path =
      'packet/proto/field[@name = "kerberos.as_req_element"]'
    . '/field[@name = "kerberos.req_body_element"]'
    . '/field[@name = "kerberos.cname_element"]'
    . '/field[@name = "kerberos.name_string"]'
    . '/field[@name = "kerberos.KerberosString"]';

# XPath entry to extract the ldap filter
my $ldap_filter_path =
      'field[@name = "ldap.searchRequest_element"]/field';


# Create an XML Twig parser and register the event handlers.
#
my $t = XML::Twig->new(
    start_tag_handlers => {
        'packet'       => \&packet_start,
    },
    twig_handlers => {
         'packet'              => \&packet,
         'proto'               => \&protocol,
         'field'               => \&field,
         $kerberos_cname_path  => \&kerberos_cname,
         $ldap_filter_path     => \&ldap_filter,
    },
);

#------------------------------------------------------------------------------
# Main loop
#
#------------------------------------------------------------------------------
my $help = 0;
GetOptions( 'help|h' => \$help) or pod2usage(2);
pod2usage(1) if $help;

if (@ARGV) {
    foreach my $file (@ARGV) {
        eval {
            $t->parsefile( $file);
        };
        if ($@) {
            print STDERR "Unable to process $file, ".
                         "did you run tshark with the -T pdml option?";
        }
    }
} else {
    pod2usage(1) if -t STDIN;
    eval {
        $t->parse( \*STDIN);
    };
    if ($@) {
        print STDERR "Unable to process input, ".
                     "are you running tshark with the -T pdml option?";
    }
}


#------------------------------------------------------------------------------
# New packet detected reset the globals
#------------------------------------------------------------------------------
sub packet_start
{
    my ($t, $packet) = @_;
    $timestamp           = "";
    $stream              = "";
    $ip_proto            = "";
    $source              = "";
    $dest                = "";
    $description         = undef;
    %proto_data          = ();
    $malformed_packet    = undef;
    $ldap_filter         = "";
    $ldap_attributes     = "";
}

#------------------------------------------------------------------------------
# Complete packet element parsed from the XML feed
# output the protocol summary if required
#------------------------------------------------------------------------------
sub packet
{
    my ($t, $packet) = @_;

    my $data;
    if (exists $proto_dispatch_table{$proto}) {
        if ($malformed_packet) {
            $data = "\t\t** Malformed Packet ** " . ($proto_data{'_ws.expert.message.show'} || '');
        } else {
            my $rsub = $proto_dispatch_table{$proto};
            $data = &$rsub();
        }
        print "$timestamp\t$ip_proto\t$stream\t$source\t$dest\t$proto\t$data\n";
    }
    $t->purge;
}

#------------------------------------------------------------------------------
# Complete protocol element parsed from the XML input
# Update the protocol name
#------------------------------------------------------------------------------
sub protocol
{
    my ($t, $protocol) = @_;
    if ($protocol->{att}->{showname}) {
    }
    # Tag a packet as malformed if the protocol is _ws.malformed
    # and the hide attribute is not 'yes'
    if ($protocol->{att}->{name} eq '_ws.malformed'
        && !($protocol->{att}->{hide} && $protocol->{att}->{hide} eq 'yes')
    ) {
        $malformed_packet = 1;
    }
    # Don't set the protocol name if it's a wireshark malformed
    # protocol entry, or the packet was truncated during capture
    my $p = $protocol->{att}->{name};
    if ($p ne '_ws.malformed' && $p ne '_ws.short')  {
        $proto = $p;
    }
}


#------------------------------------------------------------------------------
# Complete field element parsed, extract any data of interest
#------------------------------------------------------------------------------
sub field
{
    my ($t, $field) = @_;
    my $name = $field->{att}->{name};

    # Only process the field if it has a corresponding entry in
    # %field_dispatch_table
    if (exists $field_dispatch_table{$name}) {
        my $rsub = $field_dispatch_table{$name};
        &$rsub( $field);
    }
}

#------------------------------------------------------------------------------
# Process a timestamp field element
#------------------------------------------------------------------------------
sub timestamp
{
    my ($field) = @_;
    $timestamp = $field->{att}->{value};
}

#------------------------------------------------------------------------------
# Process a wireshark stream element, used to group a sequence of requests
# and responses between two IP addresses
#------------------------------------------------------------------------------
sub stream
{
    my ($field) = @_;
    $stream = $field->{att}->{show};
}

#------------------------------------------------------------------------------
# Process a source ip address field, mapping the IP address to it's
# corresponding sequence number.
#------------------------------------------------------------------------------
sub ip_src
{
    my ($field) = @_;
    $source = map_ip( $field);
}

#------------------------------------------------------------------------------
# Process a destination ip address field, mapping the IP address to it's
# corresponding sequence number.
#------------------------------------------------------------------------------
sub ip_dst
{
    my ($field) = @_;
    $dest = map_ip( $field);
}

#------------------------------------------------------------------------------
# Process an ip protocol element, extracting IANA protocol number
#------------------------------------------------------------------------------
sub ip_proto
{
    my ($field) = @_;
    $ip_proto = $field->{att}->{value};
}



#------------------------------------------------------------------------------
# Extract an ldap attribute and append it to ldap_attributes
#------------------------------------------------------------------------------
sub ldap_attribute
{
    my ($field) = @_;
    my $attribute =  $field->{att}->{show};

    if (defined $attribute) {
        $ldap_attributes .= "," if $ldap_attributes;
        $ldap_attributes .= $attribute;
    }
}

#------------------------------------------------------------------------------
# Process a field element, extract the value, show and showname attributes
# and store them in the %proto_data hash.
#
#------------------------------------------------------------------------------
sub field_data
{
    my ($field) = @_;
    my $name  = $field->{att}->{name};
    $proto_data{$name.'.value'}    = $field->{att}->{value};
    $proto_data{$name.'.show'}     = $field->{att}->{show};
    $proto_data{$name.'.showname'} = $field->{att}->{showname};
}

#------------------------------------------------------------------------------
# Process a kerberos cname element, if the cname ends with a $ it's a machine
# name. Otherwise it's a user name.
#
#------------------------------------------------------------------------------
sub kerberos_cname
{
    my ($t, $field) = @_;
    my $cname =  $field->{att}->{show};
    my  $type;
    if( $cname =~ /\$$/) {
        $type = 'machine';
     } else {
        $type = 'user';
     }
     $proto_data{'kerberos.cname.type'} = $type;
}


#------------------------------------------------------------------------------
# Process an ldap filter, remove the values but keep the attribute names
#------------------------------------------------------------------------------
sub ldap_filter
{
    my ($t, $field) = @_;
    if ( $field->{att}->{show} && $field->{att}->{show} =~ /^Filter:/) {
        my $filter = $field->{att}->{show};

        # extract and save the objectClass to keep the value
        my @object_classes;
        while ( $filter =~ m/\((objectClass=.*?)\)/g) {
           push  @object_classes, $1;
        }

        # extract and save objectCategory and the top level value
        my @object_categories;
        while ( $filter =~ m/(\(objectCategory=.*?,|\(objectCategory=.*?\))/g
        ) {
            push @object_categories, $1;
        }

        # Remove all the values from the attributes
        # Input
        #     Filter: (nCName=DC=DomainDnsZones,DC=sub1,DC=ad,DC=rh,DC=at,DC=net)
        # Output
        #     (nCName)
        $filter =~ s/^Filter:\s*//; # Remove the 'Filter: ' prefix
        $filter =~ s/=.*?\)/\)/g;   # Remove from the = to the first )

        # Now restore the parts of objectClass and objectCategory that are being
        # retained
        #
        for my $cat (@object_categories) {
            $filter =~ s/\(objectCategory\)/$cat/;
        }

        for my $class (@object_classes) {
            $filter =~ s/\(objectClass\)/($class)/;
        }

        $ldap_filter = $filter;
    } else {
        # Ok not an ldap filter so call the default field handler
        field( $t, $field);
    }
}


#------------------------------------------------------------------------------
# Extract the attributes from ldap modification and add requests
#------------------------------------------------------------------------------
sub ldap_add_modify
{
    my ($field) = @_;
    my $type      = $field->first_child('field[@name="ldap.type"]');
    my $attribute = $type->{att}->{show} if $type;
    if (defined $attribute) {
        $ldap_attributes .= "," if $ldap_attributes;
        $ldap_attributes .= $attribute;
    }
}
#------------------------------------------------------------------------------
# Map an IP address to a unique sequence number. Assigning it a sequence number
# if one has not already been assigned.
#
#------------------------------------------------------------------------------
sub map_ip
{
    my ($field) = @_;
    my $ip = $field->{att}->{show};
    if ( !exists( $ip_map{$ip})) {
        $ip_sequence++;
        $ip_map{$ip} = $ip_sequence;
    }
    return $ip_map{$ip};
}

#------------------------------------------------------------------------------
# Format a protocol operation code for output.
#
#------------------------------------------------------------------------------
sub format_opcode
{
    my ($name) = @_;
    my $operation   = $proto_data{$name.'.show'};
    my $description = $proto_data{$name.'.showname'} || '';

    # Strip off the common prefix text, and the trailing (n).
    # This tidies up most but not all descriptions.
    $description =~ s/^[^:]*?: ?//     if $description;
    $description =~ s/^Message is a // if $description;
    $description =~ s/\(\d+\)\s*$//    if $description;
    $description =~ s/\s*$//           if $description;

    return "$operation\t$description";
}

#------------------------------------------------------------------------------
# Format ldap protocol details for output
#------------------------------------------------------------------------------
sub format_ldap
{
    my ($name) = @_;
    if (   exists( $proto_data{'ldap.protocolOp.show'})
        || exists( $proto_data{'gss-api.OID.show'})
    ) {
        my $operation   = $proto_data{'ldap.protocolOp.show'};
        my $description = $proto_data{'ldap.protocolOp.showname'} || '';
        my $oid         = $proto_data{'gss-api.OID.show'}         || '';
        my $base_object = $proto_data{'ldap.baseObject.show'}     || '';
        my $scope       = $proto_data{'ldap.scope.show'}          || '';

        # Now extract operation specific data
        my $extra;
        my $extra_desc;
        $operation = '' if !defined $operation;
        if ($operation eq 6) {
            # Modify operation
            $extra         = $proto_data{'ldap.operation.show'};
            $extra_desc    = $proto_data{'ldap.operation.showname'};
        } elsif ($operation eq 0) {
            # Bind operation
            $extra         = $proto_data{'ldap.authentication.show'};
            $extra_desc    = $proto_data{'ldap.authentication.showname'};
        }
        $extra      = '' if !defined $extra;
        $extra_desc = '' if !defined $extra_desc;


        # strip the values out of the base object
        if ($base_object) {
            $base_object =~ s/^<//;       # leading '<' if present
            $base_object =~ s/>$//;       # trailing '>' if present
            $base_object =~ s/=.*?,/,/g;  # from = up to the next comma
            $base_object =~ s/=.*?$//;    # from = up to the end of string
        }

        # strip off the leading prefix on the extra_description
        # and the trailing (n);
        $extra_desc =~ s/^[^:]*?: ?//  if $extra_desc;
        $extra_desc =~ s/\(\d+\)\s*$// if $extra_desc;
        $extra_desc =~ s/\s*$//        if $extra_desc;

        # strip off the common prefix on the description
        # and the trailing (n);
        $description =~ s/^[^:]*?: ?//  if $description;
        $description =~ s/\(\d+\)\s*$// if $description;
        $description =~ s/\s*$//        if $description;

        return "$operation\t$description\t$scope\t$base_object"
              ."\t$ldap_filter\t$ldap_attributes\t$extra\t$extra_desc\t$oid";
    } else {
        return "\t*** Unknown ***";
    }
}

#------------------------------------------------------------------------------
# Format kerberos protocol details for output.
#------------------------------------------------------------------------------
sub format_kerberos
{
    my $msg_type    = $proto_data{'kerberos.msg_type.show'} || '';
    my $cname_type  = $proto_data{'kerberos.cname.type'} || '';
    my $description = $proto_data{'kerberos.msg_type.showname'} || '';

    # Tidy up the description
    $description =~ s/^[^:]*?: ?//  if $description;
    $description =~ s/\(\d+\)\s*$// if $description;
    $description =~ s/\s*$//        if $description;
    return "$msg_type\t$description\t$cname_type";
}

=pod

=head1 NAME

traffic_summary.pl - summarise tshark pdml output

=head1 USAGE

B<traffic_summary.pl> [FILE...]

Summarise samba network traffic from tshark pdml output.  Produces a tsv
delimited summary of samba activity.

To process unencrypted traffic

 tshark -r capture.file -T pdml | traffic_summary.pl

To process encrypted kerberos traffic

 tshark -r capture.file -K krb5.keytab -o kerberos.decrypt:true -T pdml | traffic_summary.pl

To display more detailed documentation, including details of the output format

 perldoc traffic_summary.pl

 NOTE: tshark pdml output is very verbose, so it's better to pipe the tshark
       output directly to traffic_summary, rather than generating
       intermediate pdml format files.

=head1 OPTIONS
 B<--help> Display usage message and exit.

=head1 DESCRIPTION

Summarises tshark pdml output into a format suitable for load analysis
and input into load generation tools.

It reads the pdml input from stdin or the list of files passed on the command line.


=head2 Output format
    The output is tab delimited fields and one line per summarised packet.

=head3 Fields
     B<timestamp>                Packet timestamp
     B<IP protocol>              The IANA protocol number
     B<Wireshark Stream Number>  Calculated by wireshark groups related requests and responses
     B<Source IP>                The unique sequence number for the source IP address
     B<Destination IP>           The unique sequence number for the destination IP address
     B<protocl>                  The protocol name
     B<opcode>                   The protocol operation code
     B<Description>              The protocol or operation description
     B<extra>                    Extra protocol specific data, may be more than one field


=head2 IP address mapping
    Rather than capturing and printing the IP addresses. Each unique IP address
    seen is assigned a sequence number. So the first IP address seen will be 1,
    the second 2 ...

=head2 Packets collected
    Packets containing the following protocol records are summarised:
      dns
      rpc_netlogon
      kerberos
      smb
      smb2
      ldap
      cldap
      lsarpc
      samr
      dcerpc
      epm
      dnsserver
      drsuapi
      browser
      smb_netlogon
      srvsvc
      nbns

   Any other packets are ignored.

   In addition to the standard elements extra data is returned for the following
   protocol record.

=head3 kerberos
     cname_type  machine cname ends with a $
                 user    cname does not end with a $

=head3 ldap

     scope                Query Scope
                            0 - Base
                            1 - One level
                            2 - sub tree
     base_object          ldap base object
     ldap_filter          the ldap filter, attribute names are retained but the values
                          are removed.
     ldap_attributes      ldap attributes, only the names are retained any values are
                          discarded, with the following two exceptions
                            objectClass    all the attribute values are retained
                            objectCategory the top level value is retained
                                           i.e. everything from the = to the first ,

=head3 ldap modifiyRequest
     In addition to the standard ldap fields the modification type is also captured

     modify_operator      for modifyRequests this contains the modifiy operation
                            0 - add
                            1 - delete
                            2 - replace
     modify_description   a description of the operation if available

=head3 modify bindRequest
     In addition to the standard ldap fields details of the authentication
     type are captured

     authentication type  0 - Simple
                          3 - SASL
     description          Description of the authentication mechanism
     oid                  GSS-API OID's
                            1.2.840.113554.1.2.2   - Kerberos v5
                            1.2.840.48018.1.2.2    - Kerberos V5
                               (incorrect, used by old Windows versions)
                            1.3.6.1.5.5.2          - SPNEGO
                            1.3.6.1.5.2.5          - IAKERB
                            1.3.6.1.4.1.311.2.2.10 - NTLM SSP
                            1.3.6.1.5.5.14         - SCRAM-SHA-1
                            1.3.6.1.5.5.18         - SCRAM-SHA-256
                            1.3.6.1.5.5.15.1.1.*   - GSS-EAP
                            1.3.6.1.5.2.7          - PKU2U
                            1.3.6.1.5.5.1.1        - SPKM-1
                            1.3.6.1.5.5.1.2        - SPKM-2
                            1.3.6.1.5.5.1.3        - SPKM-3
                            1.3.6.1.5.5.9          - LIPKEY
                            1.2.752.43.14.2        - NETLOGON

=head1 DEPENDENCIES
tshark
XML::Twig         For Ubuntu libxml-twig-perl, or from CPAN
use Getopt::Long
use Pod::Usage


=head1 Diagnostics

=head2 ** Unknown **
Unable to determine the operation being performed, for ldap it typically
indicates a kerberos encrypted operation.

=head2 ** Malformed Packet **
tshark indicated that the packet was malformed, for ldap it usually indicates TLS
encrypted traffic.

=head1 LISENCE AND COPYRIGHT

 Copyright (C) Catalyst.Net Ltd 2017

 Catalyst.Net's contribution was written by Gary Lockyer
 <gary@catalyst.net.nz>.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.


=cut
