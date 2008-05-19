mkinclude dynconfig.mk
heimdalsrcdir := $(srcdir)/../samba4/source/heimdal
mkinclude heimdal_build/config.mk
mkinclude config.mk
dsdbsrcdir := $(srcdir)/../samba4/source/dsdb
mkinclude dsdb/config.mk
smbdsrcdir := $(srcdir)/../samba4/source/smbd
mkinclude smbd/config.mk
clustersrcdir := $(srcdir)/../samba4/source/cluster
mkinclude cluster/config.mk
mkinclude smbd/process_model.mk
libnetsrcdir := $(srcdir)/../samba4/source/libnet
mkinclude libnet/config.mk
authsrcdir := $(srcdir)/../samba4/source/auth
mkinclude auth/config.mk
nsswitchsrcdir := $(srcdir)/../samba4/source/nsswitch
mkinclude nsswitch/config.mk
libsrcdir := $(srcdir)/../samba4/source/lib
mkinclude lib/samba3/config.mk
libsocketsrcdir := $(srcdir)/../samba4/source/lib/socket
mkinclude lib/socket/config.mk
libcharsetsrcdir := $(srcdir)/../samba4/source/lib/charset
mkinclude lib/charset/config.mk
ldb_sambasrcdir := $(srcdir)/../samba4/source/lib/ldb-samba
mkinclude lib/ldb-samba/config.mk
libtlssrcdir := $(srcdir)/../samba4/source/lib/tls
mkinclude lib/tls/config.mk
libregistrysrcdir := $(srcdir)/../samba4/source/lib/registry
mkinclude lib/registry/config.mk
libmessagingsrcdir := $(srcdir)/../samba4/source/lib/messaging
mkinclude lib/messaging/config.mk
libeventssrcdir := $(srcdir)/../samba4/source/lib/events
mkinclude lib/events/config.mk
libcmdlinesrcdir := $(srcdir)/../samba4/source/lib/cmdline
mkinclude lib/cmdline/config.mk
socketwrappersrcdir := $(srcdir)/../samba4/source/lib/socket_wrapper
mkinclude lib/socket_wrapper/config.mk
nsswrappersrcdir := $(srcdir)/../samba4/source/lib/nss_wrapper
mkinclude lib/nss_wrapper/config.mk
appwebsrcdir := $(srcdir)/../samba4/source/lib/appweb
mkinclude lib/appweb/config.mk
libstreamsrcdir := $(srcdir)/../samba4/source/lib/stream
mkinclude lib/stream/config.mk
libutilsrcdir := $(srcdir)/../samba4/source/lib/util
mkinclude lib/util/config.mk
libtdrsrcdir := $(srcdir)/../samba4/source/lib/tdr
mkinclude lib/tdr/config.mk
libdbwrapsrcdir := $(srcdir)/../samba4/source/lib/dbwrap
mkinclude lib/dbwrap/config.mk
libcryptosrcdir := $(srcdir)/../samba4/source/lib/crypto
mkinclude lib/crypto/config.mk
libtorturesrcdir := $(srcdir)/../samba4/source/lib/torture
mkinclude lib/torture/config.mk
libcompressionsrcdir := $(srcdir)/../samba4/source/lib/compression
libgencachesrcdir := $(srcdir)/../samba4/source/lib
mkinclude lib/basic.mk
paramsrcdir := $(srcdir)/../samba4/source/param
mkinclude param/config.mk
smb_serversrcdir := $(srcdir)/../samba4/source/smb_server
mkinclude smb_server/config.mk
rpc_serversrcdir := $(srcdir)/../samba4/source/rpc_server
mkinclude rpc_server/config.mk
ldap_serversrcdir := $(srcdir)/../samba4/source/ldap_server
mkinclude ldap_server/config.mk
web_serversrcdir := $(srcdir)/../samba4/source/web_server
mkinclude web_server/config.mk
winbindsrcdir := $(srcdir)/../samba4/source/winbind
mkinclude winbind/config.mk
nbt_serversrcdir := $(srcdir)/../samba4/source/nbt_server
mkinclude nbt_server/config.mk
wrepl_serversrcdir := $(srcdir)/../samba4/source/wrepl_server
mkinclude wrepl_server/config.mk
cldap_serversrcdir := $(srcdir)/../samba4/source/cldap_server
mkinclude cldap_server/config.mk
utilssrcdir := $(srcdir)/../samba4/source/utils
mkinclude utils/net/config.mk
mkinclude utils/config.mk
ntvfssrcdir := $(srcdir)/../samba4/source/ntvfs
mkinclude ntvfs/config.mk
ntptrsrcdir := $(srcdir)/../samba4/source/ntptr
mkinclude ntptr/config.mk
torturesrcdir := $(srcdir)/../samba4/source/torture
mkinclude torture/config.mk
librpcsrcdir := $(srcdir)/../samba4/source/librpc
mkinclude librpc/config.mk
clientsrcdir := $(srcdir)/../samba4/source/client
mkinclude client/config.mk
libclisrcdir := $(srcdir)/../samba4/source/libcli
mkinclude libcli/config.mk
ejsscriptsrcdir := $(srcdir)/../samba4/source/scripting/ejs
mkinclude scripting/ejs/config.mk
pyscriptsrcdir := $(srcdir)/../samba4/source/scripting/python
mkinclude scripting/python/config.mk
kdcsrcdir := $(srcdir)/../samba4/source/kdc
mkinclude kdc/config.mk
