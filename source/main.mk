mkinclude dynconfig.mk
heimdalsrcdir := heimdal
mkinclude heimdal_build/config.mk
mkinclude config.mk
mkinclude dsdb/config.mk
mkinclude smbd/config.mk
mkinclude cluster/config.mk
mkinclude smbd/process_model.mk
libnetsrcdir := libnet
mkinclude libnet/config.mk
mkinclude auth/config.mk
mkinclude nsswitch/config.mk
mkinclude lib/basic.mk
mkinclude param/config.mk
mkinclude smb_server/config.mk
mkinclude rpc_server/config.mk
mkinclude ldap_server/config.mk
mkinclude web_server/config.mk
mkinclude winbind/config.mk
mkinclude nbt_server/config.mk
mkinclude wrepl_server/config.mk
mkinclude cldap_server/config.mk
mkinclude utils/net/config.mk
mkinclude utils/config.mk
mkinclude ntvfs/config.mk
mkinclude ntptr/config.mk
mkinclude torture/config.mk
mkinclude librpc/config.mk
mkinclude client/config.mk
mkinclude libcli/config.mk
mkinclude scripting/ejs/config.mk
pyscriptsrcdir := scripting/python
mkinclude scripting/python/config.mk
mkinclude kdc/config.mk
