dnl # PASSDB Server subsystem

SMB_MODULE(pdb_smbpasswd,PASSDB,STATIC,[passdb/pdb_smbpasswd.o])
SMB_MODULE(pdb_tdb,PASSDB,NOT,[passdb/pdb_tdb.o])
SMB_MODULE(pdb_guest,PASSDB,STATIC,[passdb/pdb_guest.o])
SMB_MODULE(pdb_unix,PASSDB,STATIC,[passdb/pdb_unix.o])

if test x"$with_ldap_support" = x"yes"; then
	SMB_MODULE_DEFAULT(pdb_ldap,STATIC)
fi
SMB_MODULE(pdb_ldap,PASSDB,NOT,[passdb/pdb_ldap.o],[],[$LDAP_LIBS])

SMB_SUBSYSTEM(PASSDB,passdb/pdb_interface.o,
		[passdb/passdb.o passdb/machine_sid.o passdb/util_sam_sid.o passdb/pdb_get_set.o passdb/pdb_compat.o],
		passdb/passdb_public_proto.h)
