/* show a menu for the esp test pages */
simple_menu(
	"Main Menu",
	"File Server",         session_uri("/smb_server/"),
	"LDAP Server",         session_uri("/ldap_server/"),
	"CLDAP Server",         session_uri("/cldap_server/"),
	"NBT Server",         session_uri("/nbt_server/"),
	"ESP Tests",          session_uri("/esptest/"));
