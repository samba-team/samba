##
## submitted by Martin.Dehn@comparex.de
##
## Experiement sambaAccount schema file Netscape DS 5.0
##
## INSTALL-DIRECTORY/slapd-your_name/config/schema/samba-schema-netscapeds5.ldif
##
dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
aci: (target="ldap:///cn=schema")(targetattr !="aci")(version 3.0;acl "anonymo
 us, no acis"; allow (read, search, compare) userdn = "ldap:///anyone";)
aci: (targetattr = "*")(version 3.0; acl "Configuration Administrator"; allow 
 (all) userdn = "ldap:///uid=admin,ou=Administrators, ou=TopologyManagement, 
 o=NetscapeRoot";)
aci: (targetattr = "*")(version 3.0; acl "Local Directory Administrators Group
 "; allow (all) groupdn = "ldap:///cn=Directory Administrators, dc=samba,dc=org";)
aci: (targetattr = "*")(version 3.0; acl "SIE Group"; allow (all)groupdn = "ld
 ap:///cn=slapd-sambaldap, cn=iPlanet Directory Server, cn=Server Group, cn=iPlanetDirectory.samba.org, ou=samba.org, o=NetscapeRoot";)
modifiersName: cn=directory manager
modifyTimestamp: 20020322124844Z
objectClasses: ( 1.3.1.5.1.4.1.7165.2.2.2 NAME 'sambaAccount' SUP top STRUCTUR
 AL MAY ( acctFlags $ domain $ homeDrive $ kickoffTime $ lmPassword $ logofft
 ime $ logonTime $ ntPassword $ primaryGroupID $ profilePath $ pwdCanChange $
  pwdLastSet $ pwdMustChange $ rid $ scriptPath $ smbHome $ userWorkstations 
 ) X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.11 NAME 'scriptPath' DESC 'NT script pa
 th' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defined
 ' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.5 NAME 'logonTime' DESC 'NT logon time'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.12 NAME 'profilePath' DESC 'NT profile 
 path' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defin
 ed' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.8 NAME 'pwdCanChange' DESC 'NT passwd c
 an change' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user 
 defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.17 NAME 'smbHome' DESC 'smbHome' SYNTAX
  1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.3 NAME 'pwdLastSet'  SYNTAX 1.3.6.1.4.1
 .1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.18 NAME 'domain' DESC 'Windows NT domai
 n Samba' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user de
 fined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.10 NAME 'homeDrive' DESC 'NT home drive
 ' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defined' 
 )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.6 NAME 'logofftime' DESC 'logoff Time' 
 SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.15 NAME 'primaryGroupID' DESC 'NT Group
  RID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defin
 ed' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.1 NAME 'lmPassword' DESC 'LanManager Pa
 sswd' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defin
 ed' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.9 NAME 'pwdMustChange' DESC 'NT pwdmust
 chnage' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user def
 ined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.4 NAME 'acctFlags' DESC 'Account Flags'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.13 NAME 'userWorkstations' DESC 'userWo
 rkstations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user
  defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.7 NAME 'kickoffTime' DESC 'NT kickoff T
 ime' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user define
 d' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.14 NAME 'rid' DESC 'rid' SYNTAX 1.3.6.1
 .4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'user defined' )
attributeTypes: ( 1.3.6.1.4.1.7165.2.1.2 NAME 'ntPassword' DESC 'NT Passwd' SY
 NTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORIGIN 'user defined' )
nsSchemaCSN: 3c9b282c000000000000

