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
"work in progress."

To view the entire list of current Internet-Drafts, please check
the "1id-abstracts.txt" listing contained in the Internet-Drafts
Shadow Directories on ftp.is.co.za (Africa), ftp.nordu.net
(Europe), munnari.oz.au (Pacific Rim), ds.internic.net (US East
Coast), or ftp.isi.edu (US West Coast).

Distribution of this memo is unlimited.  Please send comments to the
<cat-ietf@mit.edu> mailing list.

.ti 0
Abstract

.in 3

.ti 0
Introduction

Kerberos is a protocol for authenticating parties communicating over
insecure networks.

Firewalling is a technique for achieving an illusion of security by
putting restrictions on what kinds of packets and how these are sent
between the internal (so called ``secure'') network and the global
Internet.

.ti 0
Definitions

types of firewalls: ...

client: the user, process, and host acquiring tickets from the KDC and
authenticating itself to the kerberised server.

KDC: the Kerberos Key Distribution Center

Kerberised server: the server using Kerberos to authenticate the
client, for example telnetd.

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
firewalls to the list of its own addresses when requesting the
ticket.  We are not aware of any protocol for determining this set of
addresses, thus this will have to be manually configured in the
client.

With the ticket in possession, communication with the kerberised
server will not need to be any different from communicating between a
non-kerberised client and server.

.ti 1
KDC behind firewall

Once there is some way of getting the requests through the firewall to
the KDC and back to the requesting client there is nothing else that
can go wrong.

.ti 1
Kerberised server behind firewall

The kerberised server does not talk to the KDC at all so nothing
beyond normal firewall-traversal techniques for reaching the server
itself needs to be applied.

The kerberised server needs to be able to retrieve the original
address (before its firewall) that the request was sent for.  If this
is done via some out-of-band mechanism or it's directly able to see it
doesn't matter.

.ti 0
Specification

.ti 0
Security considerations

.in 3
This memo does not introduce any known security considerations in
addition to those mentioned in [RFC1510].

.ti 0
References

.in 3
[RFC1510] Kohl, J. and Neuman, C., "The Kerberos Network
Authentication Service (V5)", RFC 1510, September 1993.

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
