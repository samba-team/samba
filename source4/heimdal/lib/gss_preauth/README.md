# GSS-API Pre-authentication in Heimdal

GSS-API pre-authentication in Heimdal is based on
[draft-perez-krb-wg-gss-preauth](https://datatracker.ietf.org/doc/html/draft-perez-krb-wg-gss-preauth)
but with some simplifications to the protocol.

The following text assumes the reader is familiar with the draft.

## Client side

Because libkrb5 cannot have a recursive dependency on libgssapi, it instead
exports the function `_krb5_init_creds_init_gss()` which allows libgssapi to
register a set of function pointers for:

  - Generating context tokens
  - Finalizing a context (inquiring the initiator name and reply key)
  - Releasing context and credential handles

This is a private API.

This architecture also means that the libkrb5 implementation could be used with
an alternative GSS-API implementation such as SSPI, without too much work. The
bulk of the pre-authentication logic remains in libkrb5, however, in
[`init_creds_pw.c`](../../krb5/init_creds_pw.c).

libgssapi itself exports `krb5_gss_set_init_creds()`, which is the public
interface for GSS-API pre-authentication.

`krb5_gss_set_init_creds()` enables GSS-API pre-authentication on an initial
credentials context, taking a GSS-API credential handle and mechanism. Both are
optional; defaults will be used if absent. These two parameters are exposed as
the `--gss-name` and `--gss-mech` options to `kinit` (see
[kinit(1)](../../../kuser/kinit.1) for further details). `kinit` supports
acquiring anonymous, keytab- and password-based GSS-API credentials using the
same arguments as regular Kerberos.

The selected GSS-API mechanism must support mutual authentication (ie.
authenticating the KDC) as it replaces the AS-REP reply key, However, if FAST
was used, and we know that the KDC was verified, then this requirement is
removed.

If the client does not know its initiator name, it can specify the last
arugment to `kinit` as `@REALM`, and the initiator name will be filled in when
the authentication is complete. (The realm is required to select a KDC.)

## KDC side

The KDC implements the acceptor side of the GSS-API authentication exchange.
The selected GSS-API mechanism must allow `gss_export_sec_context()` to be
called by the acceptor before the context is established, if it needs more than
a single round trip of token exchanges.

### Configuration

Configuration directives live in the [kdc] section of
[krb5.conf(5)](../../krb5/krb5.conf.5).

The `enable_gss_preauth` krb5.conf option must be set in order to enable
GSS-API pre-authentication in the KDC. When authenticating federated principals
which may not exist in the KDC, the `synthetic_clients` option should also be
set.

The `gss_mechanisms_allowed` option can be used to limit the set of GSS-API
mechanisms which are allowed to perform pre-authentication. Mechanisms are
specified as dot-separated OIDs or by a short name, such as `sanon-x25519`.

The `enable_gss_auth_data` option will include a composite GSS name in the
authorization data of returned tickets.

### Authorization

The default is that the initiator is permitted to authenticate to the Kerberos
principal that directly corresponds to it. The correspondence is governed as
follows: if the authenticating mechanism is in the list of mechanisms in the
`gss_cross_realm_mechanisms_allowed` configuration option, then the principal
is mapped identically: an initiator named `lukeh@AAA.PADL.COM` will be mapped
to the Kerberos principal `lukeh@AAA.PADL.COM`.

If the authenticating mechanism is not in this list, then the initiator will be
mapped to an enterprise principal in the service realm. For example,
`lukeh@AAA.PADL.COM` might be mapped to `lukeh\@AAA.PADL.COM@PADL.COM`
(enterprise principal name type);

This mapping has no effect for principals that exist in the HDB, because
enterprise principal names are always looked up by their first component (as if
they were an ordinary principal name). This logic is instead useful when
synthetic principals are enabled as we wish to avoid issuing tickets with a
client name in a foreign Kerberos realm, as that would conflate GSS-API
"realms" with Kerberos realms.

A custom authorization plugin installed in `$prefix/lib/plugin/kdc` will
replace this mapping and authorization logic. The plugin interface is defined in
[`gss_preauth_authorizer_plugin.h`](../../../kdc/gss_preauth_authorizer_plugin.h)).

### Anonymous authentication

A further note on the interaction of anonymous GSS-API authentication and
pre-authentication. Initiator contexts that set `GSS_C_ANON_FLAG` and a
`GSS_C_NT_ANONYMOUS` name are mapped to the unauthenticated anonymous Kerberos
principal, `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`. However, the local
`WELLKNOWN/ANONYMOUS` HDB entry is used to perform any authorization decisions
(as it would be for anonymous PKINIT). The AP-REP will contain the well-known
anonymous realm.

If `GSS_C_NT_ANONYMOUS` was set but a different name type was returned, then
the initiator is treated as authenticated anonymous, and the client realm will
be present in the AP-REP.

The `request-anonymous` AP-REQ flag must also be set for GSS-API anonymous
authentication to succeed.
