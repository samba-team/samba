dnl # PASSDB Server subsystem

SMB_MODULE(passdb_smbpasswd,PASSDB,STATIC,[passdb/pdb_smbpasswd.o])
SMB_MODULE(passdb_tdb,PASSDB,NOT,[passdb/pdb_tdb.o])
SMB_MODULE(passdb_guest,PASSDB,STATIC,[passdb/pdb_guest.o])
SMB_MODULE(passdb_unix,PASSDB,STATIC,[passdb/pdb_unix.o])

if test x"$with_ldap_support" = x"yes"; then
	SMB_MODULE_DEFAULT(passdb_ldap,STATIC)
fi
SMB_MODULE(passdb_ldap,PASSDB,NOT,[passdb/pdb_ldap.o])

SMB_SUBSYSTEM(PASSDB,passdb/pdb_interface.o,
		[passdb/passdb.o
		passdb/machine_sid.o
		passdb/util_sam_sid.o
		passdb/pdb_get_set.o
		passdb/pdb_compat.o])
