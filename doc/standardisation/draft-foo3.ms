.pl 10.0i
.po 0
.ll 7.2i
.lt 7.2i
.nr LL 7.2i
.nr LT 7.2i
.ds LF Westerlund, Danielsson
.ds RF [Page %]
.ds CF
.ds LH Internet Draft
.ds RH November, 1997
.ds CH Kerberos vs firewalls
.de Ip
.in 6
.ta 3
.ti -3
\\$1\t\c
..
.hy 0
.ad l
.in 0
.ta \n(.luR
.nf
Network Working Group	Assar Westerlund
<draft-ietf-cat-krb5-firewalls.txt>	SICS
Internet-Draft	Johan Danielsson
November, 1997	PDC, KTH
Expire in six months	
.fi

.ce
Kerberos vs firewalls

.ti 0
Status of this Memo

.in 3
This document is an Internet-Draft.  Internet-Drafts are working
documents of the Internet Engineering Task Force (IETF), its
areas, and its working groups.  Note that other groups may also
distribute working documents as Internet-Drafts.

Internet-Drafts are draft documents valid for a maximum of six
months and may be updated, replaced, or obsoleted by other
documents at any time.  It is inappropriate to use Internet-
Drafts as reference material or to cite them other than as
\*Qwork in progress.\*U

To view the entire list of current Internet-Drafts, please check
the \*Q1id-abstracts.txt\*U listing contained in the Internet-Drafts
Shadow Directories on ftp.is.co.za (Africa), ftp.nordu.net
(Europe), munnari.oz.au (Pacific Rim), ds.internic.net (US East
Coast), or ftp.isi.edu (US West Coast).

Distribution of this memo is unlimited.  Please send comments to the
<cat-ietf@mit.edu> mailing list.

.ti 0
Abstract

.ti 0
Introduction

Kerberos[RFC1510] is a protocol for authenticating parties
communicating over insecure networks.

Firewalling is a technique for achieving an illusion of security by
putting restrictions on what kinds of packets and how these are sent
between the internal (so called \*Qsecure\*U) network and the global (or
\*Qinsecure\*U) Internet.

.ti 0
Definitions

client: the user, process, and host acquiring tickets from the KDC and
authenticating itself to the kerberised server.

KDC: the Kerberos Key Distribution Center

Kerberised server: the server using Kerberos to authenticate the
client, for example telnetd.

.ti 0
Firewalls

A firewall is usually placed between the \*Qinside\*U and the
\*Qoutside\*U networks, and is supposed to protect the inside from the
evils on the outside.  There are different kinds of firewalls.  The
main differences are in the way they forward packets.

.Ip \(bu
The most straight forward type is the one that just imposes
restrictions on incoming packets. Such a firewall could be described
as a router that filters packets that match some criteria.

.Ip \(bu
They may also \*Qhide\*U some or all addresses on the inside of the
firewall, replacing the addresses in the outgoing packets with the
address of the firewall (aka network address translation, or NAT). NAT
can also be used without any packet filtering, for instance when you
have more than one host sharing a single address (for example, with a
dialed-in PPP connection).

.in 3
There are also firewalls that does NAT both on the inside and the
outside (a server on the inside will see this as a connection from the
firewall).

.Ip \(bu
A third type is the proxy type firewall, that parses the contents of
the packets, basically acting as a server to the client, and as a
client to the server (man-in-the-middle). If Kerberos is to be used
with this kind of firewall, a protocol module that handles KDC
requests has to be written.

.in 3
This type of firewall might also cause extra trouble when used with
kerberised versions of protocols that the proxy understands, in
addition to the ones mentioned below. This is the case with the FTP
Security Extensions [RFC2228], that adds a new set of commands to the
FTP protocol [RFC959], for integrity, confidentiality, and privacy
protecting commands. When transferring data, the FTP protocol uses a
separate data channel, and an FTP proxy will have to look out for
commands that start a data transfer. If all commands are encrypted,
this is impossible. A protocol that doesn't suffer from this is the
Telnet Authentication Option [RFC1416] that does all authentication
and encryption in-bound.

.ti 0
Scenarios

Here the different scenarios we have considered are described, the
problems they introduce and the proposed ways of solving them.
Combinations of these can also occur.

.ti 1
Client behind firewall

This is the most typical and common scenario.  First of all the client
needs some way of communicating with the KDC.  This can be done with
whatever means and is usually much simpler when the KDC is able to
communicate over TCP.

Apart from that, the client needs to be sure that the ticket it will
acquire from the KDC can be used to authenticate to a server outside
its firewall.  For this, it needs to add the address(es) of potential
firewalls between itself and the KDC/server, to the list of its own
addresses when requesting the ticket.  We are not aware of any
protocol for determining this set of addresses, thus this will have to
be manually configured in the client.

The client could also request a ticket with no addresses, but some
KDCs and servers might not accept such a ticket.

With the ticket in possession, communication with the kerberised
server will not need to be any different from communicating between a
non-kerberised client and server.

.ti 1
Kerberised server behind firewall

The kerberised server does not talk to the KDC at all so nothing
beyond normal firewall-traversal techniques for reaching the server
itself needs to be applied.

The kerberised server needs to be able to retrieve the original
address (before its firewall) that the request was sent for.  If this
is done via some out-of-band mechanism or it's directly able to see it
doesn't matter.

.ti 1
KDC behind firewall

The same restrictions applies for a KDC as for any other server.

.ti 0
Specification

.ti 0
Security considerations

.in 3
Since the whole network behind a NAT-type firewall looks like one
computer from the outside, any security added by the addresses in the
ticket will be lost.

.ti 0
References

[RFC959] Postel, J. and Reynolds, J., \*QFile Transfer Protocol
(FTP)\*U, RFC 969, October 1985

[RFC1416] Borman, D., \*QTelnet Authentication Option\*U, RFC 1416,
February 1993.

[RFC1510] Kohl, J. and Neuman, C., \*QThe Kerberos Network
Authentication Service (V5)\*U, RFC 1510, September 1993.

[RFC2228] Horowitz, M. and Lunt, S., \*QFTP Security Extensions\*U,
RFC2228, October 1997.

.ti 0
Authors' Addresses

Assar Westerlund
.br
Swedish Institute of Computer Science
.br
Box 1263
.br
S-164 29  KISTA
.br
Sweden

Phone: +46-8-7521526
.br
Fax:   +46-8-7517230
.br
EMail: assar@sics.se

Johan Danielsson
.br
PDC, KTH
.br
S-100 44  STOCKHOLM
.br
Sweden

Phone: +46-8-7907885
.br
Fax:   +46-8-247784
.br
EMail: joda@pdc.kth.se
