/* show a menu for the esp test pages */
simple_menu(
	"Main Menu",
	"File Server",        session_uri("/smb_server/"),
	"LDAP Server",        session_uri("/ldap_server/"),
	"CLDAP Server",       session_uri("/cldap_server/"),
	"RPC Server",         session_uri("/rpc_server/"),
	"NBT Server",         session_uri("/nbt_server/"),
	"WINS Server",        session_uri("/wins_server/"),
	"Kerberos Server",    session_uri("/kdc_server/"),
	"Installation",       session_uri("/install/"),
	"ESP Tests",          session_uri("/esptest/"));
