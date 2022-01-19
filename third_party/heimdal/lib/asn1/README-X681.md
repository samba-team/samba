# Automatic Open Type Handling via X.68x Support in Heimdal's ASN.1 Compiler

## Table of Contents

 1. [Introduction](#Introduction)
 2. [Typed Holes / Open Types](#typed-holes--open-types)
 3. [ASN.1 IOS, Constraint, and Parameterization](#asn1-ios-constraint-and-parameterization)
    - [IOS Crash Course](#ios-crash-course)
 4. [Usage](#Usage)
 5. [Limitations](#Limitations)
 6. [Implementation Design](#implementation-design)
 7. [Moving From C](#moving-from-c)

## Introduction

ASN.1 is a set of specifications for "syntax" for defining data schemas, and
"encoding rules" for encoding values of data of types defined in those schemas.
There are many encoding rules, but one syntax.

The base of ASN.1 _syntax_ is specified by X.680, an ITU-T standard.  The
encoding rules are specified by the X.69x series (X.690 through X.697).

This README is concerned primarily with the X.68x series.

While X.680 is essential for implementing many Internet (and other) protocols,
and sufficient for implementing all of those, there are extensions in the
remainder of the X.68x series that can make life a lot easier for developers
who have to use ASN.1 for interoperability reasons.

Various syntax extensions are specified in X.68x series documents:

 - X.681: Information Object specification
 - X.682: Constraint specification
 - X.683: Parameterization of ASN.1 specifications

The intent of X.681, X.682, and X.683 is to add ways to formally express
constraints that would otherwise require natural language to express.  Give a
compiler more formally-expressed constraints and it can do more labor-saving
than it could otherwise.

A subset of these three extensions, X.681, X.682, and X.683, can enable some
rather magical features.  These magical features are generally not the focus of
those ITU-T specifications nor of many RFCs that make use of them, but
nonetheless they are of interest to us.

This README covers some ideas for what this magic is, and implementation of it.

RFC 6025 does an excellent job of elucidating X.681, which otherwise most
readers unfamiliar with it will no doubt find inscrutable.  Hopefully this
README improves that further.

The magic that we're after is simply the *automatic and recursive handling of
open types by an ASN.1 compiler*.

Combined with eventual support for the ASN.1 JSON Encoding Rules (JER) [X.697],
this feature could give us unprecendented visibility into really complex data
structures, such as Endorsement Key Certificates (EKcerts) for Trusted Platform
Module (TPM) applications.

Support for JER and automatic handling of open types should allow us to
trivially implement a command-line tool that can parse any DER or JER (JSON)
encoding of any value whose type is known and compiled, and which could
transcode to the other encoding rules.  I.e., dump DER to JSON, and parse JSON
to output DER.

Indeed, Heimdal's `asn1_print` program currently supports transcoding of DER to
JSON, though it's not quite X.697-compliant JSON!  Heimdal does not currently
support parsing JSON-encoded values of ASN.1 types.

Combined with transcoders for JSON/CBOR and other binary-JSON formats, we could
support those encodings too.

We could really see how much space OER/JER/CBOR save over DER for Kerberos
tickets, PKIX certificates, and much else.

We especially want this for PKIX, and more than anything for certificates, as
the TBSCertificate type is full of deeply nested open types: DNs and
subjectDirectory attributes, otherName SAN types, and certificate extensions.

Besides a magical ASN.1 DER/JER dumper/transcoder utility, we want to replace
DN attribute and subject alternative name (SAN) `otherName` tables and much
hand-coded handling of certificate extensions in `lib/hx509/`.

The reader should already be familiar with ASN.1, which anyways is a set of two
things:

 - an abstract syntax for specifying schemas for data interchange

 - a set of encoding rules

A very common thing to see in projects that use ASN.1, as well as projects that
use alternatives to ASN.1, is a pattern known as the "typed hole" or "open
type".

The ASN.1 Information Object System (IOS) [X.681] is all about automating the
otherwise very annoying task of dealing with "typed holes" / "open types".

The ASN.1 IOS is not sufficient to implement the magic we're after.  Also
needed is constraint specification and parameterization of types.

ITU-T references:

https://www.itu.int/rec/T-REC-X.680-201508-I/en
https://www.itu.int/rec/T-REC-X.681-201508-I/en
https://www.itu.int/rec/T-REC-X.682-201508-I/en
https://www.itu.int/rec/T-REC-X.683-201508-I/en


## Typed Holes / Open Types

A typed hole or open type is a pattern of data structure that generally looks
like:

```
    { type_id, bytes_encoding_a_value_of_a_type_identified_by_type_id }
```

I.e., an opaque datum and an identifier of what kind of datum that is.  This
happens because the structure with the typed hole is used in contexts where it
can't know all possible things that can go in it.  In many cases we do know
what all possible things are that can go in a typed hole, but many years ago
didn't, say, or anyways, had a reason to use a typed hole.

These are used not only in protocols that use ASN.1, but in many protocols that
use syntaxes and encodings unrelated to ASN.1.  I.e., these concepts are *not*
ASN.1-specific.

Many Internet protocols use typed holes, and many use typed holes in ASN.1
types.  For example, PKIX, Kerberos, LDAP, and others, use ASN.1 and typed
holes.

For examples of an Internet protocol that does not use ASN.1 but which still
has typed holes, see IP, MIME, SSHv2, IKEv2, and others.  Most quintessentilly,
IP itself, since IP packet payloads are for some upper layer protocol
identified in the IP packet header.

In ASN.1 these generally look like:

```ASN.1
    TypedHole ::= SEQUENCE {
        typeId INTEGER,
        opaque OCTET STRING
    }
```

or

```ASN.1
    -- Old ASN.1 style
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY DEFINED BY typeID
    }
```

or

```ASN.1
    -- Old ASN.1 style
    TypedHole ::= SEQUENCE {
        typeId OBJECT IDENTIFIER,
        opaque ANY -- DEFINED BY typeID
    }
```

or any number of variations.

    Note: the `ANY` variations are no longer conformant to X.680 (the base
    ASN.1 specification).

The pattern is `{ id, hole }` where the `hole` is ultimately an opaque sequence
of bytes whose content's schema is identified by the `id` in the same data
structure.  The pattern does not require just two fields, and it does not
require any particular type for the hole, nor for the type ID.  Sometimes the
"hole" is an `OCTET STRING`, sometimes it's a `BIT STRING`, sometimes it's an
`ANY` or `ANY DEFINED BY`.  Sometimes the hole is even an array of (`SET OF` or
`SEQUENCE OF`, in ASN.1) values of the type identified by the id field.

An example from PKIX:

```ASN.1
Extension ::= SEQUENCE {
  extnID          OBJECT IDENTIFIER, -- <- type ID
  critical        BOOLEAN OPTIONAL,
  extnValue       OCTET STRING,      -- <- hole
}
```

which shows that typed holes don't always have just three fields, and the type
identifier isn't always an integer.

Now, Heimdal's ASN.1 compiler generates the obvious C data structure for PKIX's
`Extension` type:

```C
    typedef struct Extension {
      heim_oid extnID;
      int *critical;
      heim_octet_string extnValue;
    } Extension;
```

and applications using this compiler have to inspect the `extnID` field,
comparing it to any number of OIDs, to determine the type of `extnValue`, then
must call `decode_ThatType()` to decode whatever that octet string has.

This is very inconvenient.

Compare this to the handling of discriminated unions (what ASN.1 calls a
`CHOICE`):

```C
    /*
     * ASN.1 definition:
     *
     *  DistributionPointName ::= CHOICE {
     *    fullName                  [0] IMPLICIT SEQUENCE OF GeneralName,
     *    nameRelativeToCRLIssuer   [1] RelativeDistinguishedName,
     *  }
    */

    /* C equivalent */
    typedef struct DistributionPointName {
      enum DistributionPointName_enum {
        choice_DistributionPointName_fullName = 1,
        choice_DistributionPointName_nameRelativeToCRLIssuer
      } element;
      union {
        struct DistributionPointName_fullName {
          unsigned int len;
          GeneralName *val;
        } fullName;
        RelativeDistinguishedName nameRelativeToCRLIssuer;
      } u;
    } DistributionPointName;
```

The ASN.1 encoding on the wire of a `CHOICE` value, almost no matter the
encoding rules, looks... remarkably like the encoding of a typed hole.  Though
generally the alternatives of a discriminated union have to all be encoded with
the same encoding rules, whereas with typed holes the encoded data could be
encoded in radically different encoding rules than the structure containing it
in a typed hole.

In fact, extensible `CHOICE`s are handled by our compiler as a discriminated
union one of whose alternatives is a typed hole when the `CHOICE` is
extensible:

```C
    typedef struct DigestRepInner {
      enum DigestRepInner_enum {
        choice_DigestRepInner_asn1_ellipsis = 0, /* <--- unknown CHOICE arm */
        choice_DigestRepInner_error,
        choice_DigestRepInner_initReply,
        choice_DigestRepInner_response,
        choice_DigestRepInner_ntlmInitReply,
        choice_DigestRepInner_ntlmResponse,
        choice_DigestRepInner_supportedMechs
        /* ... */
      } element;
      union {
        DigestError error;
        DigestInitReply initReply;
        DigestResponse response;
        NTLMInitReply ntlmInitReply;
        NTLMResponse ntlmResponse;
        DigestTypes supportedMechs;
        heim_octet_string asn1_ellipsis; /* <--- unknown CHOICE arm */
      } u;
    } DigestRepInner;
```

The critical thing to understand is that our compiler automatically decodes
(and encodes) `CHOICE`s' alternatives, but it used to NOT do that for typed
holes because it knows nothing about them.  Now, however, our compiler can
do this for typed holes provided the module specifies what the alternatives
are.

It would be nice if we could treat *all* typed holes like `CHOICE`s whenever
the compiler knows the alternatives!

And that's exactly what the ASN.1 IOS system makes possible.  With ASN.1 IOS
support, our compiler can automatically decode all the `Certificate`
extensions, and all the distinguished name extensions it knows about.

There is a fair bit of code in `lib/hx509/` that deals with encoding and
decoding things in typed holes where the compiler could just handle that
automatically for us, allowing us to delete a lot of code.

Even more importantly, if we ever add support for visual encoding rules of
ASN.1, such as JSON Encoding Rules (JER) [X.697] or Generic String Encoding
Rules (GSER) [RFC2641], we could have a utility program to automatically
display or compile DER (and other encodings) of certifcates and many other
interesting data structures.

Indeed, we do now have such a utility (`asn1_print`), able to transcode DER to
JSON.

## ASN.1 IOS, Constraint, and Parameterization

The ASN.1 IOS is additional syntax that allows ASN.1 module authors to express
all the details about typed holes that ASN.1 compilers need to make developers'
lives much easier.

RFC5912 has lots of examples, such as this `CLASS` corresponding to the
`Extension` type from PKIX:

```ASN.1
  -- A class that provides some of the details of the PKIX Extension typed
  -- hole:
  EXTENSION ::= CLASS {
      -- The following are fields of a class (as opposed to "members" of
      -- SEQUENCE or SET types):
      &id  OBJECT IDENTIFIER UNIQUE,    -- This is a fixed-type value field.
                                        -- UNIQUE -> There can be only one
                                        --           object with this OID
                                        --           in any object set of
                                        --           this class.
                                        --           I.e., this is like a
                                        --           PRIMARY KEY in a SQL
                                        --           TABLE spec.
      &ExtnType,                        -- This is a type field (the hole).
      &Critical    BOOLEAN DEFAULT {TRUE | FALSE } -- fixed-type value set field.
  } WITH SYNTAX {
      -- This is a specification of easy to use (but hard-to-parse) syntax for
      -- specifying instances of this CLASS:
      SYNTAX &ExtnType IDENTIFIED BY &id
      [CRITICALITY &Critical]
  }

  -- Here's a parameterized Extension type.  The formal parameter is an as-yet
  -- unspecified set of valid things this hole can carry for some particular
  -- instance of this type.  The actual parameter will be specified later (see
  -- below).
  Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
      -- The type ID has to be the &id field of the EXTENSION CLASS of the
      -- ExtensionSet object set parameter.
      extnID      EXTENSION.&id({ExtensionSet}),
      -- This is the critical field, whose DEFAULT value should be that of
      -- the &Critical field of the EXTENSION CLASS of the ExtensionSet object
      -- set parameter.
      critical    BOOLEAN
  --                     (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                       DEFAULT FALSE,
      -- Finally, the hole is an OCTET STRING constrained to hold the encoding
      -- of the type named by the &ExtnType field of the EXTENSION CLASS of the
      -- ExtensionSet object set parameter.
      --
      -- Note that for all members of this SEQUENCE, the fields of the object
      -- referenced must be of the same object in the ExtensionSet object set
      -- parameter.  That's how we get to say that some OID implies some type
      -- for the hole.
      extnValue   OCTET STRING (CONTAINING
                  EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
                  --  contains the DER encoding of the ASN.1 value
                  --  corresponding to the extension type identified
                  --  by extnID
  }

  -- This is just a SEQUENCE of Extensions, the parameterized version.
  Extensions{EXTENSION:ExtensionSet} ::=
      SEQUENCE SIZE (1..MAX) OF Extension{{ExtensionSet}}
```

and these uses of it in RFC5280 (PKIX base) where the actual parameter is
given:

```ASN.1
   -- Here we have an individual "object" specifying that the OID
   -- id-ce-authorityKeyIdentifier implies AuthorityKeyIdentifier as the hole
   -- type:
   ext-AuthorityKeyIdentifier EXTENSION ::= { SYNTAX
       AuthorityKeyIdentifier IDENTIFIED BY
       id-ce-authorityKeyIdentifier }

   -- And here's the OID, for completeness:
   id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
   ...

   -- And Here's an object set for the EXTENSION CLASS collecting a bunch of
   -- related extensions (here they are the extensions that certificates can
   -- carry in their extensions member):
   CertExtensions EXTENSION ::= {
           ext-AuthorityKeyIdentifier | ext-SubjectKeyIdentifier |
           ext-KeyUsage | ext-PrivateKeyUsagePeriod |
           ext-CertificatePolicies | ext-PolicyMappings |
           ext-SubjectAltName | ext-IssuerAltName |
           ext-SubjectDirectoryAttributes |
           ext-BasicConstraints | ext-NameConstraints |
           ext-PolicyConstraints | ext-ExtKeyUsage |
           ext-CRLDistributionPoints | ext-InhibitAnyPolicy |
           ext-FreshestCRL | ext-AuthorityInfoAccess |
           ext-SubjectInfoAccessSyntax, ... }
   ...

   -- Lastly, we have a Certificate, and the place where the Extensions type's
   -- actual parameter is specified.
   --
   -- This is where the rubber meets the road:

   Certificate  ::=  SIGNED{TBSCertificate}

   TBSCertificate  ::=  SEQUENCE  {
       version         [0]  Version DEFAULT v1,
       serialNumber         CertificateSerialNumber,
       signature            AlgorithmIdentifier{SIGNATURE-ALGORITHM,
                                 {SignatureAlgorithms}},
       issuer               Name,
       validity             Validity,
       subject              Name,
       subjectPublicKeyInfo SubjectPublicKeyInfo,
       ... ,
       [[2:               -- If present, version MUST be v2
       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
       ]],
       [[3:               -- If present, version MUST be v3 --
       extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
                         -- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                         -- The rubber meets the road *here*.
                         --
                         -- This says that the set of *known* certificate
                         -- extensions are those for which there are "objects"
                         -- in the "object set" named CertExtensions.
       ]], ... }
```

Notice that the `extensions` field of `TBSCertificate` is of type `Extensions`
parametrized by the `CertExtensions` "information object set".

This allows the compiler to know that if any of the OIDs listed in the
`CertExtensions` object set appear as the actual value of the `extnID` member
of an `Extension` value, then the `extnValue` member of the same `Extension`
value must be an instance of the type associated with that OID.  For example,
an `Extension` with `extnID` value of `id-ce-authorityKeyIdentifier` must have
an `extnValue` of type `AuthorityKeyIdentifier`.


### IOS Crash Course

The ASN.1 IOS may be... a bit difficult to understand -- the syntax isn't
pretty.  And X.681 has a lot of strange terminology, like "variable type value
set field".

An IOS "class" has fields, and those fields are of kind
`[Fixed]Type[Value[Set]]` or `Object[Set]`.  Then there's "objects" and "object
sets".  Hopefully this section will make all of that comprehensible.

_Classes_ have fields of various kinds.  More on this below.

_Classes_ can also have zero, one, or more _object sets_ associated with them,
and each object set has zero, one, or more _objects_ that are also themselves
associated with classes.  Each object has a setting for each required field of
a class, and possibly also for optional/defaulted fields as well.

As X.681 explains, IOS object sets really are akin to relational database
tables, while objects are akin to rows of the same, with columns specified by
classes.

Or one can think of _classes_ as relational tables with one predefined column
naming object sets, and rows being objects grouped into object sets by that
column.  IOS supports complex path expressions across these objects (but we
won't need to support that yet).

These relational entities are immutable in that they are defined in ASN.1
modules that are compiled and there is no way to change them at run-time, only
query them (although perhaps object sets marked as extensible are intended to
be extensible at run-time?).  To mutate them one must edit the ASN.1 module
that defines them and recompile it.  IOS entities also have no on-the-wire
representation.

So far, the IOS seems just so useless to us: we have some, but non-urgent need
to specify immutable relational data.  For example, cryptosystem parameters,
which PKIX does define using IOS, but again: not urgent.

The magic for us lies in being able to document and constrain actual datatypes
using the IOS [X.681], constraint specification [X.682], and type
parameterization [X.683].  We can express the following things:

 - that some _member_ of a `SET` or `SEQUENCE` is of open type

 - that some  _member_ of a `SET` or `SEQUENCE` identifies a type encoded into
   an open type member of the same (or related) `SET` or `SEQUENCE`

 - what pairs of `{type ID value, type}` are allowed for some `SET`'s or
   `SEQUENCE`'s open type members

With this our ASN.1 compiler has the metadata it needs in order to
auto-generate decoding and encoding of values of open types.

A termnology point: `CHOICE`, `SET`, and `SEQUENCE` types have "members", but
_classes_ and _objects_ have "fields", and _object sets_ have "elements".

Objects must have "_settings_" for all the required fields of the object's
class and none, some, or all of the `OPTIONAL` or `DEFAULT` fields of the
class.  This is very similar to `SET`/`SEQUENCE` members, which can be
`OPTIONAL` or `DEFAULT`ed.

The _members_ (we call them fields in C, instance variables in C++, Java, ...)
of a `SET` or `SEQUENCE` type are typed, just as in C, C++, Java, etc. for
struct or object types.

There are several kinds of fields of classes.  These can be confusing, so it is
useful that we explain them by reference to how they relate to the members of
`SEQUENCE` types constrained by object sets:

 - A `type field` of a class is one that specifies a `SET` or `SEQUENCE` member
   of unknown (i.e., open) type.

   The type of that `SET` or `SEQUENCE` member will not be not truly unknown,
   but determined by some other member of the SET or SEQUENCE, and that will be
   specified in a "value field" (or "value set" field) an "object" in an
   "object set" of that class.

   This is essentially a "type variable", akin to those seen in high-level
   languages like Haskell.

 - A `fixed type value field` of a class is one that specifies a SET or
   SEQUENCE member of fixed type.  Being of fixed-type, this is not a type
   variable, naturally.

 - A `fixed type value set field` of a class is like a `fixed type value
   field`, but where object sets should provide a set of values with which to
   constrain `SET`/`SEQUENCE` members corresponding to the field.

 - A `variable type value [set] field` is one where the type of the `SET` or
   `SEQUENCE` member corresponding to the field will vary according to some
   specified `type field` of the same class.

 - An `object field` will be a field that names another class (possibly the
   same class), which can be used to provide rich hierarchical type semantics
   that... we mostly don't need for now.

   These define relations between classes, much like `FOREIGN KEY`s in SQL.

   These are also known as `link fields`.

 - Similarly for `object set field`s.

As usual for ASN.1, the case of the first letter of a field name is meaningful:

 - value and object field names start with a lower case letter;
 - type, value set, and object set fields start with an upper-case letter.

The form of a `fixed type value` field and a `fixed type value set` field is
the same, differing only the case of the first letter of the field name.
Similarly for `variable type value` and `variable type value set` fields.
Similarly, again, for `object` and `object set` fields.

Here's a simple example from PKIX:

```ASN.1
  -- An IOS class used to impose constraints on the PKIX Extension type:
  EXTENSION ::= CLASS {
      &id  OBJECT IDENTIFIER UNIQUE,
      &ExtnType,
      &Critical    BOOLEAN DEFAULT {TRUE | FALSE }
  } WITH SYNTAX {
      SYNTAX &ExtnType IDENTIFIED BY &id
      [CRITICALITY &Critical]
  }
```

 - The `&id` field of `EXTENSION` is a fixed-type value field.  It's not a
   fixed-type value _set_ field because its identifier (`id`) starts with a
   lower-case letter.

   The `&id` field is intended to make the `extnId` member of the `Extension`
   `SEQUENCE` type name identify the actual type of the `extnValue` member of
   the same `SEQUENCE` type.

   Note that `UNIQUE` keyword tells us there can be only one object with any
   given value of this field in any object set of this class.  (There is no way
   to specify the equivalent of a multi-column `PRIMARY KEY` from SQL, only
   single-column primary/unique keys.  Note that the `&id` field is not marked
   `OPTIONAL` or `DEFAULT`, which is like saying it's `NOT NULL` in SQL.)

 - The `&ExtnType` field is a type field.  We can tell because no type is named
   in its declaration!

 - The `&Critical` field is a fixed-type value set field.  We can tell because
   it specifies a type (`BOOLEAN`) and starts with an upper-case letter.

   In-tree we could avoid having to implement fixed-type value set fields by
   renaming this one to `&critical` and eliding its `DEFAULT <ValueSet>` given
   that we know there are only two possible values for a `BOOLEAN` field.

 - Ignore the `WITH SYNTAX` clause for now.  All it does is specify a
   user-friendly but implementor-hostile syntax for specifying objects.

Note that none of the `Extension` extensions in PKIX actually specify
`CRITICALITY`/`&Critical`, so... we just don't need fixed-type value set
fields.  We could elide the `&Critical` field of the `EXTENSION` class
altogether.

Here's another, much more complex example from PKIX:

```ASN.1
  ATTRIBUTE ::= CLASS {
      &id             OBJECT IDENTIFIER UNIQUE,
      &Type           OPTIONAL,
      &equality-match MATCHING-RULE OPTIONAL,
      &minCount       INTEGER DEFAULT 1,
      &maxCount       INTEGER OPTIONAL
  }
  MATCHING-RULE ::= CLASS {
      &ParentMatchingRules   MATCHING-RULE OPTIONAL,
      &AssertionType         OPTIONAL,
      &uniqueMatchIndicator  ATTRIBUTE OPTIONAL,
      &id                    OBJECT IDENTIFIER UNIQUE
  }
```

 - For `ATTRIBUTE` the fields are:
    - The `&id` field is a fixed-type value field (intended to name the type of
      members linked to the `&Type` field).
    - The `&Type` field is a type field (open type).
    - The `&equality-match` is an object field linking to object sets of the
      `MATCHING-RULE` class.
    - The `minCount` and `maxCount` fields are fixed-type value fields.
 - For `MATCHING-RULE` the fields are:
    - The `&ParentMatchingRules` is an object set field linking to more
      `MATCHING-RULE`s.
    - The `&AssertionType` field is a type field (open type).
    - The `&uniqueMatchIndicator` field is an object field linking back to some
      object of the `ATTRIBUTE` class that indicates whether the match is
      unique (presumably).
    - The `&id` field is a fixed-type value field (intended to name the type of
      members linked to the `&AssertionType` field).

No `Attribute`s in PKIX (at least RFC 5912) specify matching rules, so we
really don't need support for object nor object set fields.

Because
 - no objects in object sets of `EXTENSION` in PKIX specify "criticality",
 - and no objects in object sets of `ATTRIBUTE` in PKIX specify matching rules,
 - and no matching rules are specified in PKIX (or maybe just one),
we can drop `MATCHING-RULE` and simplify `ATTRIBUTE` and `EXTENSION` as:

```ASN.1
  EXTENSION ::= CLASS {
      &id  OBJECT IDENTIFIER UNIQUE,
      &ExtnType
  }
  ATTRIBUTE ::= CLASS {
      &id             OBJECT IDENTIFIER UNIQUE,
      &Type           OPTIONAL,
      &minCount       INTEGER DEFAULT 1,
      &maxCount       INTEGER OPTIONAL
  }
```

X.681 has an example in appendix D.2 that has at least one field of every kind.

Again, the rubber that are IOS classes and object sets meet the road when
defining types:

```ASN.1
  -- Define the Extension type but link it to the EXTENSION class so that
  -- an object set for that class can constrain it:
  Extension{EXTENSION:ExtensionSet} ::= SEQUENCE {
      extnID      EXTENSION.&id({ExtensionSet}),
      critical    BOOLEAN
                  (EXTENSION.&Critical({ExtensionSet}{@extnID}))
                  DEFAULT FALSE,
      extnValue   OCTET STRING (CONTAINING
                  EXTENSION.&ExtnType({ExtensionSet}{@extnID}))
  }
  -- Most members of TBSCertificate elided for brevity:
  TBSCertificate  ::=  SEQUENCE  {
      ...,
      extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
                                   -- ^^^^^^^^^^^^^^^^
                                   -- the rubber meets the road here!!
      ...
  }

  OTHER-NAME ::= TYPE-IDENTIFIER
  -- Most members of GeneralName elided for brevity:
  GeneralName ::= CHOICE {
      otherName       [0]  INSTANCE OF OTHER-NAME({KnownOtherNames}),
                                               -- ^^^^^^^^^^^^^^^^^
                                               -- rubber & road meet!
      ...
  }
```

(The `CertExtensions` and `KnownOtherNames` object sets are not shown here for
brevity.  PKIX doesn't even define an `KnownOtherNames` object set, though it
well could.)

The above demonstrates two ways to create `SEQUENCE` types that are constrained
by IOS classes.  One is by defining the types of the members of a `SEQUENCE`
type by reference to class fields.  The other is by using `INSTANCE OF` to say
that the class defines the type directly.  The first lets us do things like
have a mix members of a `SEQUENCE` type where some are defined by relation to a
class and others are not, or where multiple classes are used.

In the case of `INSTANCE OF`, what shall the names of the members of the
derived type be?  Well, such types can _only_ be instances of `TYPE-IDENTIFIER`
or classes copied from and isomorphic to it (as `OTHER-NAME` is in the above
exammle), and so the names of their two members are just baked in by X.681
annex C.1 as:

```ASN.1
    SEQUENCE {
        type-id     <DefinedObjectClass>.&id,
        value[0]    <DefinedObjectClass>.&Type
    }
    -- where <DefinedObjectClass> is the name of the class, which has to be
    -- `TYPE-IDENTIFIER` or exactly like it.
```

(This means we can't use `INSTANCE OF` with `EXTENSION`, though we can for
`OTHER-NAME`.)

PKIX has much more complex classes for relating and constraining cryptographic
algorithms and their parameters:

 - `DIGEST-ALGORITHM`,
 - `SIGNATURE-ALGORITHM`,
 - `PUBLIC-KEY`,
 - `KEY-TRANSPORT`,
 - `KEY-AGREE`,
 - `KEY-WRAP`,
 - `KEY-DERIVATION`,
 - `MAC-ALGORITHM`,
 - `CONTENT-ENCRYPTION`,
 - `ALGORITHM`,
 - `SMIME-CAPS`,
 - and `CURVE`.

These show the value of just the relational data aspect of IOS.  They can not
only be used by the codecs at run-time to perform validation of, e.g.,
cryptographic algorithm parameters, but also to provide those rules to other
code in the application so that the programmer doesn't have to manually write
the same in C, C++, Java, etc, and can refer to them when applying those
cryptographic algorithms.  And, of course, the object sets for the above
classes can be and are specified in standards documents, making it very easy to
import them into projects that have an IOS-capable ASN.1 compiler.

Still, for Heimdal we won't bother with the full power of X.681/X.682/X.683 for
now.

## Usage

To use this feature you must use the `--template` and `--one-code-file`
arguments to `asn1_compile`.  C types are generated from ASN.1 types as
described above.

Note that failure to decode open type values does not cause decoding to fail
altogether.  It is important that applications check for undecoded open types.
Open type decoding failures manifest as `NULL` values for the `u` field of the
decoded open type structures (see above).

For examples of X.681/X.682/X.683 usage, look at `lib/asn1/rfc2459.asn1`.

## Limitations

 - `AtNotation` supported is very limited.

 - Object set extensibility is not supported.

 - Only one formal (and actual) type parameter is supported at this time.

 - `TYPE-IDENTIFIER` is not built-in at this time.  (But users can define it as
   specified.)

 - `CLASS` "copying" is not supported at this time.

 - Link fields are not supported.

 - `Information from objects` constructs are not supported.

 - `IMPORTS` of IOS entities are not supported at this time.

 - ...

## Implementation Design

NOTE: This has already be implemented in the `master` branch of Heimdal.

 - The required specifications, X.681, X.682, and X.683, are fairly large and
   non-trivial.  We can implement just the subset of those three that we need
   to implement PKIX, just as we already implement just the subset of X.680
   that we need to implement PKIX and Kerberos.

   For dealing with PKIX, the bare minimum of IOS classes we want are:

    - `ATTRIBUTE` (used for `DN` attributes in RFC5280, specifically for the
      `SingleAttribute` and `AttributeSet` types, RDNs, and the
      `subjectDirectoryAttributes` extension)
    - `EXTENSION` (used for `Extension`, i.e., certificate extensions in
      RFC5280)
    - `TYPE-IDENTIFIER` (used for `OtherName` and for CMS' `Content-Type`)

   The minimal subset of X.681, X.682, and X.683 needed to implement those
   three is all we need.

   _Eventually_ we may want to increase that subset so as to implement other
   IOS classes from PKIX, such as `DIGEST-ALGORITHM`, and to provide object
   sets and query functionality for them to applications so that we can use
   standard modules to encode information about cryptosystems.  But not right
   now.

   Note that there's no object set specified for OTHER-NAME instances, but we
   can and have creates our own.  We want magic open type decoding to recurse
   all the way down and handle DN attributes, extensions, SANs, policy
   qualifiers, the works.

 - We'll really want to do this mainly for the template compiler and begin
   abandoning the original compiler.  The codegen backend generates the same C
   types, but no code for automatic, recursive handling of open types.

   Maintaining two compiler backends is difficult enough; adding complex
   features beyond X.680 to both is too much work.  The template compiler is
   simply superior just on account of its output size scaling as `O(N)` instead
   of `O(M * N)` where `M` is the number of encoding rules supported and `N` is
   the size of an ASN.1 module (or all modules).

 - Also, to make the transition to using IOS in-tree, we'll want to keep
   existing fields of C structures as generated by the compiler today, only
   adding new ones, that way code that hasn't been updated to use the automatic
   encoding/decoding can still work and we can then update Heimdal in-tree
   slowly to take advantage of the new magic.

   Below are the C types for the ASN.1 PKIX types we care about, as generated
   by the current prototype.

   `Extension` compiles to:

```C
typedef struct Extension {
    heim_oid extnID;
    int critical;
    heim_octet_string extnValue;
    /* NEW: */
    struct {
        enum {
            choice_Extension_iosnumunknown = 0,
            choice_Extension_iosnum_id_x509_ce_authorityKeyIdentifier,
            choice_Extension_iosnum_id_x509_ce_subjectKeyIdentifier,
            choice_Extension_iosnum_id_x509_ce_keyUsage,
            choice_Extension_iosnum_id_x509_ce_privateKeyUsagePeriod,
            choice_Extension_iosnum_id_x509_ce_certificatePolicies,
            choice_Extension_iosnum_id_x509_ce_policyMappings,
            choice_Extension_iosnum_id_x509_ce_subjectAltName,
            choice_Extension_iosnum_id_x509_ce_issuerAltName,
            choice_Extension_iosnum_id_x509_ce_basicConstraints,
            choice_Extension_iosnum_id_x509_ce_nameConstraints,
            choice_Extension_iosnum_id_x509_ce_policyConstraints,
            choice_Extension_iosnum_id_x509_ce_extKeyUsage,
            choice_Extension_iosnum_id_x509_ce_cRLDistributionPoints,
            choice_Extension_iosnum_id_x509_ce_inhibitAnyPolicy,
            choice_Extension_iosnum_id_x509_ce_freshestCRL,
            choice_Extension_iosnum_id_pkix_pe_authorityInfoAccess,
            choice_Extension_iosnum_id_pkix_pe_subjectInfoAccess,
        } element;
        union {
            void *_any;
            AuthorityKeyIdentifier* ext_AuthorityKeyIdentifier;
            SubjectKeyIdentifier* ext_SubjectKeyIdentifier;
            KeyUsage* ext_KeyUsage;
            PrivateKeyUsagePeriod* ext_PrivateKeyUsagePeriod;
            CertificatePolicies* ext_CertificatePolicies;
            PolicyMappings* ext_PolicyMappings;
            GeneralNames* ext_SubjectAltName;
            GeneralNames* ext_IssuerAltName;
            BasicConstraints* ext_BasicConstraints;
            NameConstraints* ext_NameConstraints;
            PolicyConstraints* ext_PolicyConstraints;
            ExtKeyUsage* ext_ExtKeyUsage;
            CRLDistributionPoints* ext_CRLDistributionPoints;
            SkipCerts* ext_InhibitAnyPolicy;
            CRLDistributionPoints* ext_FreshestCRL;
            AuthorityInfoAccessSyntax* ext_AuthorityInfoAccess;
            SubjectInfoAccessSyntax* ext_SubjectInfoAccessSyntax;
        } u;
    } _ioschoice_extnValue;
} Extension;
```

   The `SingleAttribute` and `AttributeSet` types compile to:

```C
typedef struct SingleAttribute {
    heim_oid type;
    HEIM_ANY value;
    struct {
        enum {
            choice_SingleAttribute_iosnumunknown = 0,
            choice_SingleAttribute_iosnum_id_at_name,
            choice_SingleAttribute_iosnum_id_at_surname,
            choice_SingleAttribute_iosnum_id_at_givenName,
            choice_SingleAttribute_iosnum_id_at_initials,
            choice_SingleAttribute_iosnum_id_at_generationQualifier,
            choice_SingleAttribute_iosnum_id_at_commonName,
            choice_SingleAttribute_iosnum_id_at_localityName,
            choice_SingleAttribute_iosnum_id_at_stateOrProvinceName,
            choice_SingleAttribute_iosnum_id_at_organizationName,
            choice_SingleAttribute_iosnum_id_at_organizationalUnitName,
            choice_SingleAttribute_iosnum_id_at_title,
            choice_SingleAttribute_iosnum_id_at_dnQualifier,
            choice_SingleAttribute_iosnum_id_at_countryName,
            choice_SingleAttribute_iosnum_id_at_serialNumber,
            choice_SingleAttribute_iosnum_id_at_pseudonym,
            choice_SingleAttribute_iosnum_id_domainComponent,
            choice_SingleAttribute_iosnum_id_at_emailAddress,
        } element;
        union {
            void *_any;
            X520name* at_name;
            X520name* at_surname;
            X520name* at_givenName;
            X520name* at_initials;
            X520name* at_generationQualifier;
            X520CommonName* at_x520CommonName;
            X520LocalityName* at_x520LocalityName;
            DirectoryString* at_x520StateOrProvinceName;
            DirectoryString* at_x520OrganizationName;
            DirectoryString* at_x520OrganizationalUnitName;
            DirectoryString* at_x520Title;
            heim_printable_string* at_x520dnQualifier;
            heim_printable_string* at_x520countryName;
            heim_printable_string* at_x520SerialNumber;
            DirectoryString* at_x520Pseudonym;
            heim_ia5_string* at_domainComponent;
            heim_ia5_string* at_emailAddress;
        } u;
    } _ioschoice_value;
} SingleAttribute;
```

   and

```C
typedef struct AttributeSet {
    heim_oid type;
    struct AttributeSet_values
    {
        unsigned int len;
        HEIM_ANY* val;
    } values;
    struct {
        enum {
            choice_AttributeSet_iosnumunknown = 0,
            choice_AttributeSet_iosnum_id_at_name,
            choice_AttributeSet_iosnum_id_at_surname,
            choice_AttributeSet_iosnum_id_at_givenName,
            choice_AttributeSet_iosnum_id_at_initials,
            choice_AttributeSet_iosnum_id_at_generationQualifier,
            choice_AttributeSet_iosnum_id_at_commonName,
            choice_AttributeSet_iosnum_id_at_localityName,
            choice_AttributeSet_iosnum_id_at_stateOrProvinceName,
            choice_AttributeSet_iosnum_id_at_organizationName,
            choice_AttributeSet_iosnum_id_at_organizationalUnitName,
            choice_AttributeSet_iosnum_id_at_title,
            choice_AttributeSet_iosnum_id_at_dnQualifier,
            choice_AttributeSet_iosnum_id_at_countryName,
            choice_AttributeSet_iosnum_id_at_serialNumber,
            choice_AttributeSet_iosnum_id_at_pseudonym,
            choice_AttributeSet_iosnum_id_domainComponent,
            choice_AttributeSet_iosnum_id_at_emailAddress,
        } element;
        unsigned int len;
        union {
            void *_any;
            X520name* at_name;
            X520name* at_surname;
            X520name* at_givenName;
            X520name* at_initials;
            X520name* at_generationQualifier;
            X520CommonName* at_x520CommonName;
            X520LocalityName* at_x520LocalityName;
            DirectoryString* at_x520StateOrProvinceName;
            DirectoryString* at_x520OrganizationName;
            DirectoryString* at_x520OrganizationalUnitName;
            DirectoryString* at_x520Title;
            heim_printable_string* at_x520dnQualifier;
            heim_printable_string* at_x520countryName;
            heim_printable_string* at_x520SerialNumber;
            DirectoryString* at_x520Pseudonym;
            heim_ia5_string* at_domainComponent;
            heim_ia5_string* at_emailAddress;
        } *val;
    } _ioschoice_values;
} AttributeSet;
```

   The `OtherName` type compiles to:

```C
typedef struct OtherName {
    heim_oid type_id;
    HEIM_ANY value;
    struct {
        enum {
            choice_OtherName_iosnumunknown = 0,
            choice_OtherName_iosnum_id_pkix_on_xmppAddr,
            choice_OtherName_iosnum_id_pkix_on_dnsSRV,
            choice_OtherName_iosnum_id_pkix_on_hardwareModuleName,
            choice_OtherName_iosnum_id_pkix_on_permanentIdentifier,
            choice_OtherName_iosnum_id_pkix_on_pkinit_san,
            choice_OtherName_iosnum_id_pkix_on_pkinit_ms_san,
        } element;
        union {
            void *_any;
            heim_utf8_string* on_xmppAddr;
            heim_ia5_string* on_dnsSRV;
            HardwareModuleName* on_hardwareModuleName;
            PermanentIdentifier* on_permanentIdentifier;
            KRB5PrincipalName* on_krb5PrincipalName;
            heim_utf8_string* on_pkinit_ms_san;
        } u;
    } _ioschoice_value;
} OtherName;
```

   If a caller to `encode_Certificate()` passes a certificate object with
   extensions with `_ioselement == choice_Extension_iosnumunknown` (or
   whatever, for each open type), then the encoder will use the `extnID` and
   `extnValue` fields, otherwise it will use the new `_ioschoice_extnValue`
   field and leave `extnID` and `extnValue` cleared.  If both are set, the
   `extnID` and `extnValue` fields, and also the new `_ioschoice_extnValue`
   field, then the encoder will ignore the latter.

   In both cases, the `critical` field gets used as-is.  The rule is be that we
   support *two* special C struct fields for open types: a hole type ID enum
   field, and a decoded hole value union.  All other fields will map to either
   normal (possibly constrained) members of the SET/SEQUENCE.

 - Type ID values get mapped to discrete enum values.  Object sets get sorted
   by object type IDs so that for decoding they can be and are binary-searched.
   For encoding and other cases (destructors and copy constructors) we directly
   index the object set by the mapped type ID enum.

 - The C header generator remains shared between the two backends.

 - SET and SEQUENCE types containing an open type are represented as follows in
   their templates.

```C
    extern const struct asn1_template asn1_CertExtensions[];
    /*...*/
    const struct asn1_template asn1_Extension_tag__22[] = {
        /* 0 */ { 0, sizeof(struct Extension), ((void*)5) },
        /* 1 */ { A1_TAG_T(ASN1_C_UNIV, PRIM, UT_OID),
                  offsetof(struct Extension, extnID),
                  asn1_AttributeType_tag__1 },
        /* 2 */ { A1_OP_DEFVAL | A1_DV_BOOLEAN, ~0, (void*)0 },
        /* 3 */ { A1_TAG_T(ASN1_C_UNIV, PRIM, UT_Boolean) | A1_FLAG_DEFAULT,
                  offsetof(struct Extension, critical),
                  asn1_Extension_tag_critical_24 },
        /* 4 */ { A1_TAG_T(ASN1_C_UNIV, PRIM, UT_OctetString),
                  offsetof(struct Extension, extnValue),
                  asn1_Extension_tag_extnValue_25 },
        /* NEW: vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
        /* 5 */ { A1_OP_OPENTYPE_OBJSET | 0 | (2 << 10) | 0,
                  offsetof(Extension, _ioschoice_extnValue),
                  asn1_CertExtensions }
    };
    const struct asn1_template asn1_Extension[] = {
        /* 0 */ { 0, sizeof(Extension), ((void*)1) },
        /* 1 */ { A1_TAG_T(ASN1_C_UNIV, CONS, UT_Sequence),
                  0, asn1_Extension_tag__22 }
    };

    /* NEW: */
    const struct asn1_template asn1_CertExtensions[] = {
        /*
         * Header template entry bearing the count of objects in
         * this object set:
         */
        /* 0 */ { 0, 0, ((void*)18) },

        /*
         * Value of object #0 in this set: two entries, one naming
         * a type ID field value, and the other naming the type
         * that corresponds to that value.
         *
         * In this case, the first object is for the
         * AuthorityKeyIdentifier type as a certificate extension.
         */
        /* 1 */ { A1_OP_OPENTYPE_ID, 0,
                  (const void*)&asn1_oid_id_x509_ce_authorityKeyIdentifier },
        /* 2 */ { A1_OP_OPENTYPE, sizeof(AuthorityKeyIdentifier),
                  (const void*)&asn1_AuthorityKeyIdentifier },

        /* Value of object #1 (SubjectKeyIdentifier): */

        /* 3 */ { A1_OP_OPENTYPE_ID, 0,
                  (const void*)&asn1_oid_id_x509_ce_subjectKeyIdentifier },
        /* 4 */ { A1_OP_OPENTYPE, sizeof(SubjectKeyIdentifier),
                  (const void*)&asn1_SubjectKeyIdentifier },
        /* 5 */

        /* And so on...*/

        /* Value of object #17 */
        /* 35 */ { A1_OP_OPENTYPE_ID, 0,
                   (const void*)&asn1_oid_id_pkix_pe_subjectInfoAccess },
        /* 36 */ { A1_OP_OPENTYPE, sizeof(SubjectInfoAccessSyntax),
                   (const void*)&asn1_SubjectInfoAccessSyntax }
    };
```

   After the template entries for all the normal fields of a struct there will
   be an object set reference entry identifying the type ID and open type
   fields's entries' indices in the same template.  The object set has a header
   entry followed by pairs of entries each representing a single object and all
   of them representing the object set.

   This allows the encoder and decoder to both find the object set quickly,
   especially since the objects are sorted by type ID value.

## Moving From C

 - Generate and output a JSON representation of the compiled ASN.1 module.

 - Code codegen/templategen backends in jq or Haskell or whatever.

 - Code template interpreters in &lt;host&gt; language.

 - Eventually rewrite the compiler itself in Rust or whatever.
