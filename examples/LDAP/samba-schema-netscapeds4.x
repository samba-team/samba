#
# LDAP Schema file for SAMBA attribute storage 
# This file is suitable for usage with Netscape Directory Server 4.1x
# Adapted by Scott Lawson with help from Ron Creamer
#

attribute       lmPassword              1.3.6.1.4.1.7165.2.1.1  cis single
attribute       ntPassword              1.3.6.1.4.1.7165.2.1.2  cis single
attribute       acctFlags               1.3.6.1.4.1.7165.2.1.4  cis single
attribute       pwdLastSet              1.3.6.1.4.1.7165.2.1.3  int single
attribute       logonTime               1.3.6.1.4.1.7165.2.1.5  int single
attribute       logoffTime              1.3.6.1.4.1.7165.2.1.6  int single
attribute       kickoffTime             1.3.6.1.4.1.7165.2.1.7  int single
attribute       pwdCanChange            1.3.6.1.4.1.7165.2.1.8  int single
attribute       pwdMustChange           1.3.6.1.4.1.7165.2.1.9  int single
attribute       homedrive               1.3.6.1.4.1.7165.2.1.10 cis single
attribute       scriptPath              1.3.6.1.4.1.7165.2.1.11 cis single
attribute       profilePath             1.3.6.1.4.1.7165.2.1.12 cis single
attribute       userWorkstations        1.3.6.1.4.1.7165.2.1.13 cis single
attribute       rid                     1.3.6.1.4.1.7165.2.1.14 int single
attribute       primaryGroupID          1.3.6.1.4.1.7165.2.1.15 int single
attribute       smbHome                 1.3.6.1.4.1.7165.2.1.17 cis single
attribute       domain                  1.3.6.1.4.1.7165.2.1.18 cis single

objectclass sambaAccount
       oid
               1.3.1.5.1.4.1.7165.2.2.2
       superior
               top
       requires
               objectClass,
               uid,
               rid
       allows
               cn,
               lmPassword,
               ntPassword,
               pwdLastSet,
               logonTime,
               logoffTime,
               KickoffTime,
               pwdCanChange,
               pwdMustChange,
               acctFlags,
               displayName,
               smbHome,
               homeDrive,
               scriptPath,
               profilePath,
               description,
               userWorkstations,
               primaryGroupID,
               domain

