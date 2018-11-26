typedef opaque utf8string<>;
typedef utf8string utf8str_mixed;

const ACE4_ACCESS_ALLOWED_ACE_TYPE      = 0x00000000;
const ACE4_ACCESS_DENIED_ACE_TYPE       = 0x00000001;
const ACE4_SYSTEM_AUDIT_ACE_TYPE        = 0x00000002;
const ACE4_SYSTEM_ALARM_ACE_TYPE        = 0x00000003;

typedef u_int acetype4;

const ACE4_FILE_INHERIT_ACE             = 0x00000001;
const ACE4_DIRECTORY_INHERIT_ACE        = 0x00000002;
const ACE4_NO_PROPAGATE_INHERIT_ACE     = 0x00000004;
const ACE4_INHERIT_ONLY_ACE             = 0x00000008;
const ACE4_SUCCESSFUL_ACCESS_ACE_FLAG   = 0x00000010;
const ACE4_FAILED_ACCESS_ACE_FLAG       = 0x00000020;
const ACE4_IDENTIFIER_GROUP             = 0x00000040;
const ACE4_INHERITED_ACE                = 0x00000080;

typedef u_int aceflag4;

/*
 * The following aceiflag4 is extensions for RFC 5661 that deals with storing
 * identifiers as numerical ids instead UTF8 strings in order to avoid wasting
 * CPU cycles for the costly conversion.
 *
 * Placed in a seperate field to avoid ever running into conflicts with newly
 * defined NFSv4 flags.
 */

const ACEI4_SPECIAL_WHO                  = 0x00000001;

typedef u_int aceiflag4;

/*
 * Numerical representation of special identifiers from 6.2.1.5.
 * ACEI4_SPECIAL_WHO MUST be set in nfsace4.aceiflag4.
 */
const ACE4_SPECIAL_OWNER                = 1;
const ACE4_SPECIAL_GROUP                = 2;
const ACE4_SPECIAL_EVERYONE             = 3;
const ACE4_SPECIAL_INTERACTIVE          = 4;
const ACE4_SPECIAL_NETWORK              = 5;
const ACE4_SPECIAL_DIALUP               = 6;
const ACE4_SPECIAL_BATCH                = 7;
const ACE4_SPECIAL_ANONYMOUS            = 8;
const ACE4_SPECIAL_AUTHENTICATED        = 9;
const ACE4_SPECIAL_SERVICE              = 10;

const ACE4_READ_DATA            = 0x00000001;
const ACE4_LIST_DIRECTORY       = 0x00000001;
const ACE4_WRITE_DATA           = 0x00000002;
const ACE4_ADD_FILE             = 0x00000002;
const ACE4_APPEND_DATA          = 0x00000004;
const ACE4_ADD_SUBDIRECTORY     = 0x00000004;
const ACE4_READ_NAMED_ATTRS     = 0x00000008;
const ACE4_WRITE_NAMED_ATTRS    = 0x00000010;
const ACE4_EXECUTE              = 0x00000020;
const ACE4_DELETE_CHILD         = 0x00000040;
const ACE4_READ_ATTRIBUTES      = 0x00000080;
const ACE4_WRITE_ATTRIBUTES     = 0x00000100;
const ACE4_WRITE_RETENTION      = 0x00000200;
const ACE4_WRITE_RETENTION_HOLD = 0x00000400;

const ACE4_DELETE               = 0x00010000;
const ACE4_READ_ACL             = 0x00020000;
const ACE4_WRITE_ACL            = 0x00040000;
const ACE4_WRITE_OWNER          = 0x00080000;
const ACE4_SYNCHRONIZE          = 0x00100000;

typedef u_int acemask4;

/* ACL structure definition as per RFC 7530 Section-6.2.1 */
struct nfsace4 {
        acetype4        type;
        aceflag4        flag;
        acemask4        access_mask;
        utf8str_mixed   who;
};

struct nfsace4i {
        acetype4        type;
        aceflag4        flag;
        aceiflag4       iflag;
        acemask4        access_mask;
        u_int           who;
};

const ACL4_XATTR_VERSION_40      = 0;
const ACL4_XATTR_VERSION_41      = 1;
const ACL4_XATTR_VERSION_DEFAULT = ACL4_XATTR_VERSION_40;

const ACL4_AUTO_INHERIT         = 0x00000001;
const ACL4_PROTECTED            = 0x00000002;
const ACL4_DEFAULTED            = 0x00000004;

typedef u_int aclflag4;

struct nfsacl40 {
        nfsace4         na40_aces<>;
};

struct nfsacl41 {
        aclflag4        na41_flag;
        nfsace4         na41_aces<>;
};

struct nfsacl41i {
        aclflag4        na41_flag;
        nfsace4i        na41_aces<>;
};
