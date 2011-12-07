<?php
/**
 * The phpLDAPadmin config file, customised for use with Samba4
 *
 * Use config.php.example to create config.php, if you don't have one.
 *
 * Append this file to config.php.
 */

/* Create a new LDAP server for SAMBA4 */
$servers->newServer('ldap_pla');

/* A convenient name that will appear in the tree viewer and throughout
   phpLDAPadmin to identify this LDAP server to users. */
$servers->setValue('server','name','Samba4 LDAP Server');
$servers->setValue('server','host','${S4_LDAPI_URI}');
$servers->setValue('login','auth_type','session');
$servers->setValue('login','attr','dn');

?>
