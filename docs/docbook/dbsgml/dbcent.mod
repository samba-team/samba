<!-- ...................................................................... -->
<!-- DocBook character entities module V4.1 ............................... -->
<!-- File dbcent.mod ...................................................... -->

<!-- Copyright 1992-2000 HaL Computer Systems, Inc.,
     O'Reilly & Associates, Inc., ArborText, Inc., Fujitsu Software
     Corporation, and the Organization for the Advancement of
     Structured Information Standards (OASIS).

     $Id: dbcent.mod,v 1.1.2.1 2001/02/28 19:05:00 jerry Exp $

     Permission to use, copy, modify and distribute the DocBook DTD and
     its accompanying documentation for any purpose and without fee is
     hereby granted in perpetuity, provided that the above copyright
     notice and this paragraph appear in all copies.  The copyright
     holders make no representation about the suitability of the DTD for
     any purpose.  It is provided "as is" without expressed or implied
     warranty.

     If you modify the DocBook DTD in any way, except for declaring and
     referencing additional sets of general entities and declaring
     additional notations, label your DTD as a variant of DocBook.  See
     the maintenance documentation for more information.

     Please direct all questions, bug reports, or suggestions for
     changes to the docbook@lists.oasis-open.org mailing list. For more
     information, see http://www.oasis-open.org/docbook/.
-->

<!-- ...................................................................... -->

<!-- This module contains the entity declarations for the standard ISO
     entity sets used by DocBook.

     In DTD driver files referring to this module, please use an entity
     declaration that uses the public identifier shown below:

     <!ENTITY % dbcent PUBLIC
     "-//OASIS//ENTITIES DocBook Character Entities V4.1//EN">
     %dbcent;

     See the documentation for detailed information on the parameter
     entity and module scheme used in DocBook, customizing DocBook and
     planning for interchange, and changes made since the last release
     of DocBook.
-->

<!-- ...................................................................... -->

<!ENTITY % ISOamsa.module "INCLUDE">
<![ %ISOamsa.module; [
<!ENTITY % ISOamsa PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Arrow Relations//EN">
%ISOamsa;
<!--end of ISOamsa.module-->]]>

<!ENTITY % ISOamsb.module "INCLUDE">
<![ %ISOamsb.module; [
<!ENTITY % ISOamsb PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Binary Operators//EN">
%ISOamsb;
<!--end of ISOamsb.module-->]]>

<!ENTITY % ISOamsc.module "INCLUDE">
<![ %ISOamsc.module; [
<!ENTITY % ISOamsc PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Delimiters//EN">
%ISOamsc;
<!--end of ISOamsc.module-->]]>

<!ENTITY % ISOamsn.module "INCLUDE">
<![ %ISOamsn.module; [
<!ENTITY % ISOamsn PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Negated Relations//EN">
%ISOamsn;
<!--end of ISOamsn.module-->]]>

<!ENTITY % ISOamso.module "INCLUDE">
<![ %ISOamso.module; [
<!ENTITY % ISOamso PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Ordinary//EN">
%ISOamso;
<!--end of ISOamso.module-->]]>

<!ENTITY % ISOamsr.module "INCLUDE">
<![ %ISOamsr.module; [
<!ENTITY % ISOamsr PUBLIC
"ISO 8879:1986//ENTITIES Added Math Symbols: Relations//EN">
%ISOamsr;
<!--end of ISOamsr.module-->]]>

<!ENTITY % ISObox.module "INCLUDE">
<![ %ISObox.module; [
<!ENTITY % ISObox PUBLIC
"ISO 8879:1986//ENTITIES Box and Line Drawing//EN">
%ISObox;
<!--end of ISObox.module-->]]>

<!ENTITY % ISOcyr1.module "INCLUDE">
<![ %ISOcyr1.module; [
<!ENTITY % ISOcyr1 PUBLIC
"ISO 8879:1986//ENTITIES Russian Cyrillic//EN">
%ISOcyr1;
<!--end of ISOcyr1.module-->]]>

<!ENTITY % ISOcyr2.module "INCLUDE">
<![ %ISOcyr2.module; [
<!ENTITY % ISOcyr2 PUBLIC
"ISO 8879:1986//ENTITIES Non-Russian Cyrillic//EN">
%ISOcyr2;
<!--end of ISOcyr2.module-->]]>

<!ENTITY % ISOdia.module "INCLUDE">
<![ %ISOdia.module; [
<!ENTITY % ISOdia PUBLIC
"ISO 8879:1986//ENTITIES Diacritical Marks//EN">
%ISOdia;
<!--end of ISOdia.module-->]]>

<!ENTITY % ISOgrk1.module "INCLUDE">
<![ %ISOgrk1.module; [
<!ENTITY % ISOgrk1 PUBLIC
"ISO 8879:1986//ENTITIES Greek Letters//EN">
%ISOgrk1;
<!--end of ISOgrk1.module-->]]>

<!ENTITY % ISOgrk2.module "INCLUDE">
<![ %ISOgrk2.module; [
<!ENTITY % ISOgrk2 PUBLIC
"ISO 8879:1986//ENTITIES Monotoniko Greek//EN">
%ISOgrk2;
<!--end of ISOgrk2.module-->]]>

<!ENTITY % ISOgrk3.module "INCLUDE">
<![ %ISOgrk3.module; [
<!ENTITY % ISOgrk3 PUBLIC
"ISO 8879:1986//ENTITIES Greek Symbols//EN">
%ISOgrk3;
<!--end of ISOgrk3.module-->]]>

<!ENTITY % ISOgrk4.module "INCLUDE">
<![ %ISOgrk4.module; [
<!ENTITY % ISOgrk4 PUBLIC
"ISO 8879:1986//ENTITIES Alternative Greek Symbols//EN">
%ISOgrk4;
<!--end of ISOgrk4.module-->]]>

<!ENTITY % ISOlat1.module "INCLUDE">
<![ %ISOlat1.module; [
<!ENTITY % ISOlat1 PUBLIC
"ISO 8879:1986//ENTITIES Added Latin 1//EN">
%ISOlat1;
<!--end of ISOlat1.module-->]]>

<!ENTITY % ISOlat2.module "INCLUDE">
<![ %ISOlat2.module; [
<!ENTITY % ISOlat2 PUBLIC
"ISO 8879:1986//ENTITIES Added Latin 2//EN">
%ISOlat2;
<!--end of ISOlat2.module-->]]>

<!ENTITY % ISOnum.module "INCLUDE">
<![ %ISOnum.module; [
<!ENTITY % ISOnum PUBLIC
"ISO 8879:1986//ENTITIES Numeric and Special Graphic//EN">
%ISOnum;
<!--end of ISOnum.module-->]]>

<!ENTITY % ISOpub.module "INCLUDE">
<![ %ISOpub.module; [
<!ENTITY % ISOpub PUBLIC
"ISO 8879:1986//ENTITIES Publishing//EN">
%ISOpub;
<!--end of ISOpub.module-->]]>

<!ENTITY % ISOtech.module "INCLUDE">
<![ %ISOtech.module; [
<!ENTITY % ISOtech PUBLIC
"ISO 8879:1986//ENTITIES General Technical//EN">
%ISOtech;
<!--end of ISOtech.module-->]]>
