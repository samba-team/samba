mkinclude dynconfig.mk
heimdalsrcdir := heimdal
mkinclude heimdal_build/config.mk
mkinclude config.mk
dsdbsrcdir := dsdb
mkinclude dsdb/config.mk
smbdsrcdir := smbd
mkinclude smbd/config.mk
clustersrcdir := cluster
mkinclude cluster/config.mk
mkinclude smbd/process_model.mk
libnetsrcdir := libnet
mkinclude libnet/config.mk
authsrcdir := auth
mkinclude auth/config.mk
nsswitchsrcdir = nsswitch
mkinclude nsswitch/config.mk
mkinclude lib/samba3/config.mk
mkinclude lib/socket/config.mk
mkinclude lib/charset/config.mk
mkinclude lib/ldb-samba/config.mk
mkinclude lib/tls/config.mk
mkinclude lib/registry/config.mk
mkinclude lib/messaging/config.mk
mkinclude lib/events/config.mk
mkinclude lib/cmdline/config.mk
mkinclude lib/socket_wrapper/config.mk
mkinclude lib/nss_wrapper/config.mk
mkinclude lib/appweb/config.mk
mkinclude lib/stream/config.mk
mkinclude lib/util/config.mk
mkinclude lib/tdr/config.mk
mkinclude lib/dbwrap/config.mk
mkinclude lib/crypto/config.mk
mkinclude lib/torture/config.mk
mkinclude lib/basic.mk
paramsrcdir := param
mkinclude param/config.mk
smb_serversrcdir := smb_server
mkinclude smb_server/config.mk
rpc_serversrcdir := rpc_server
mkinclude rpc_server/config.mk
ldap_serversrcdir := ldap_server
mkinclude ldap_server/config.mk
web_serversrcdir := web_server
mkinclude web_server/config.mk
winbindsrcdir := winbind
mkinclude winbind/config.mk
nbt_serversrcdir := nbt_server
mkinclude nbt_server/config.mk
wrepl_serversrcdir := wrepl_server
mkinclude wrepl_server/config.mk
cldap_serversrcdir := cldap_server
mkinclude cldap_server/config.mk
utilssrcdir := utils
mkinclude utils/net/config.mk
mkinclude utils/config.mk
ntvfssrcdir := ntvfs
mkinclude ntvfs/config.mk
ntptrsrcdir := ntptr
mkinclude ntptr/config.mk
torturesrcdir := torture
mkinclude torture/config.mk
librpcsrcdir := librpc
mkinclude librpc/config.mk
clientsrcdir := client
mkinclude client/config.mk
libclisrcdir := libcli
mkinclude libcli/config.mk
ejsscriptsrcdir := scripting/ejs
mkinclude scripting/ejs/config.mk
pyscriptsrcdir := scripting/python
mkinclude scripting/python/config.mk
kdcsrcdir := kdc
mkinclude kdc/config.mk
