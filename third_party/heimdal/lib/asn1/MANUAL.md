# Introduction

Heimdal is an implementation of PKIX and Kerberos.  As such it must handle the
use of [Abstract Syntax Notation One (ASN.1)](https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en)
by those protocols.  ASN.1 is a language for describing the schemata of network
protocol messages.  Associated with ASN.1 are the ASN.1 Encoding Rules (ERs)
that specify how to encode such messages.

In short:

 - ASN.1 is just a _schema description language_

 - ASN.1 Encoding Rules are specifications for encoding formats for values of
   types described by ASN.1 schemas ("modules")

Similar languages include:

 - [DCE RPC's Interface Description Language (IDL)](https://pubs.opengroup.org/onlinepubs/9629399/chap4.htm#tagcjh_08)
 - [Microsoft Interface Description Language (IDL)](https://docs.microsoft.com/en-us/windows/win32/midl/midl-start-page)
   (MIDL is derived from the DCE RPC IDL)
 - ONC RPC's eXternal Data Representation (XDR) [RFC4506](https://datatracker.ietf.org/doc/html/rfc4506)
 - [XML Schema](https://en.wikipedia.org/wiki/XML_schema)
 - Various JSON schema languages
 - [Protocol Buffers](https://developers.google.com/protocol-buffers)
 - and [many, many others](https://en.wikipedia.org/wiki/Comparison_of_data-serialization_formats)!
   Many are not even listed there.

Similar encoding rules include:

 - DCE RPC's [NDR](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm)
 - ONC RPC's [XDR](https://datatracker.ietf.org/doc/html/rfc4506)
 - XML
 - FastInfoSet
 - JSON
 - CBOR
 - [Protocol Buffers](https://developers.google.com/protocol-buffers)
 - [Flat Buffers](https://google.github.io/flatbuffers/)
 - and [many, many others](https://en.wikipedia.org/wiki/Comparison_of_data-serialization_formats)!
   Many are not even listed there.

Many such languages are quite old.  ASN.1 itself dates to the early 1980s, with
the first specification published in 1984.  XDR was first published in 1987.
IDL's lineage dates back to sometime during the 1980s, via the Apollo Domain
operating system.

ASN.1 is standardized by the International Telecommunications Union (ITU-T),
and has continued evolving over the years, with frequent updates.

The two most useful and transcending features of ASN.1 are:

 - the ability to formally express what some know as "open types", "typed
   holes", or "references";

 - the ability to add encoding rules over type, which for ASN.1 includes:

    - binary, tag-length-value (TLV) encoding rules
    - binary, non-TLV encoding rules
    - textual encoding rules using XML and JSON
    - an ad-hoc generic text-based ER called GSER

   In principle ASN.1 can add encoding rules that would allow it to
   interoperate with many others, such as: CBOR, protocol buffers, flat
   buffers, NDR, and others.

   Readers may recognize that some alternatives to ASN.1 have followed a
   similar arc.  For example, Protocol Buffers was originally a syntax and
   encoding, and has become a syntax and set of various encodings (e.g., Flat
   Buffers was added later).  And XML has FastInfoSet as a binary encoding
   alternative to XML's textual encoding.

As well, ASN.1 has [high-quality, freely-available specifications](https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en).

## ASN.1 Example

For example, this is a `Certificate` as used in TLS and other protocols, taken
from [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280):

   ```ASN.1
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING
   }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
        extensions      [3]  EXPLICIT Extensions OPTIONAL
   }
   ```

and the same `Certificate` taken from a more modern version -from
[RFC5912](https://datatracker.ietf.org/doc/html/rfc5912)- using newer features
of ASN.1:

   ```ASN.1
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
       [[2:
       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
       ]],
       [[3:
       extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
       ]], ...
   }
   ```

As you can see, a `Certificate` is a structure containing a to-be-signed
sub-structure, and a signature of that sub-structure, and the sub-structure
has: a version number, a serial number, a signature algorithm, an issuer name,
a validity period, a subject name, a public key for the subject name, "unique
identifiers" for the issuer and subject entities, and "extensions".

To understand more we'd have to look at the types of those fields of
`TBSCertificate`, but for now we won't do that.  The point here is to show that
ASN.1 allows us to describe "types" of data in a way that resembles
"structures", "records", or "classes" in various programming languages.

To be sure, there are some "noisy" artifacts in the definition of
`TBSCertificate` which mostly have to do with the original encoding rules for
ASN.1.  The original encoding rules for ASN.1 were tag-length-value (TLV)
binary encodings, meaning that for every type, the encoding of a value of that
type consisted of a _tag_, a _length_ of the value's encoding, and the _actual
value's encoding_.  Over time other encoding rules were added that do not
require tags, such as the octet encoding rules (OER), but also JSON encoding
rules (JER), XML encoding rules (XER), and others.  There is almost no need for
tagging directives like `[1] IMPLICIT` when using OER.  But in existing
protocols like PKIX and Kerberos that date back to the days when DER was king,
tagging directives are unfortunately commonplace.

## ASN.1 Crash Course

This is not a specification.  Readers should refer to the ITU-T's X.680 base
specification for ASN.1's syntax.

A schema is called a "module".

A module looks like:

```ASN.1
-- This is a comment

-- Here's the name of the module, here given as an "object identifier" or
-- OID:
PKIXAlgs-2009 { iso(1) identified-organization(3) dod(6)
  internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
  id-mod-pkix1-algorithms2008-02(56) }


-- `DEFINITIONS` is a required keyword
-- `EXPLICIT TAGS` will be explained later
DEFINITIONS EXPLICIT TAGS ::=
BEGIN
-- list exported types, or `ALL`:
EXPORTS ALL;
-- import some types:
IMPORTS PUBLIC-KEY, SIGNATURE-ALGORITHM, ... FROM AlgorithmInformation-2009
        mda-sha224, mda-sha256, ... FROM PKIX1-PSS-OAEP-Algorithms-2009;

-- type definitions follow:
...

END
```

Type names start with capital upper-case letters.  Value names start with
lower-case letters.

Type definitions are of the form `TypeName ::= TypeDefinition`.

Value (constant) definitions are of the form `valueName ::= TypeName <literal>`.

There are some "universal" primitive types (e.g., string types, numeric types),
and several "constructed" types (arrays, structures.

Some useful primitive types include `BOOLEAN`, `INTEGER` and `UTF8String`.

Structures are either `SEQUENCE { ... }` or `SET { ... }`.  The "fields" of
these are known as "members".

Arrays are either `SEQUENCE OF SomeType` or `SET OF SomeType`.

A `SEQUENCE`'s elements or members are ordered, while a `SET`'s are not.  In
practice this means that for _canonical_ encoding rules a `SET OF` type's
values must be sorted, while a `SET { ... }` type's members need not be sorted
at run-time, but are sorted by _tag_ at compile-time.

Anonymous types are supported, such as `SET OF SET { a A, b B }` (which is a
set of structures with an `a` field (member) of type `A` and a `b` member of
type `B`).

The members of structures can be `OPTIONAL` or have a `DEFAULT` value.

There are also discriminated union types known as `CHOICE`s: `U ::= CHOICE { a
A, b B, c C }` (in this case `U` is either an `A`, a `B`, or a `C`.

Extensibility is supported.  "Extensibility" means: the ability to add new
members to structures, new alternatives to discriminated unions, etc.  For
example, `A ::= SEQUENCE { a0 A0, a1 A1, ... }` means that type `A` is a
structure that has two fields and which may have more fields added in future
revisions, therefore decoders _must_ be able to receive and decode encodings of
extended versions of `A`, even encoders produced prior to the extensions being
specified!  (Normally a decoder "skips" extensions it doesn't know about, and
the encoding rules need only make it possible to do so.)

## TLV Encoding Rules

The TLV encoding rules for ASN.1 are:

 - Basic Encoding Rules (BER)
 - Distinguished Encoding Rules (DER), a canonical subset of BER
 - Canonical Encoding Rules (CER), another canonical subset of BER

"Canonical" encoding rules yield just one way to encode any value of any type,
while non-canonical rules possibly yield many ways to encode values of certain
types.  For example, JSON is not a canonical data encoding.  A canonical form
of JSON would have to specify what interstitial whitespace is allowed, a
canonical representation of strings (which Unicode codepoints must be escaped
and in what way, and which must not), and a canonical representation of decimal
numbers.

It is important to understand that originally ASN.1 came with TLV encoding
rules, and some considerations around TLV encoding rules leaked into the
language.  For example, `A ::= SET { a0 [0] A0, a1 [1] A1 }` is a structure
that has two members `a0` and `a1`, and when encoded those members will be
tagged with a "context-specific" tags `0` and `1`, respectively.

Tags only have to be specified when needed to disambiguate encodings.
Ambiguities arise only in `CHOICE` types and sometimes in `SEQUENCE`/`SET`
types that have `OPTIONAL`/`DEFAULT`ed members.

In modern ASN.1 it is possible to specify that a module uses `AUTOMATIC`
tagging so that one need never specify tags explicitly in order to fix
ambiguities.

Also, there are two types of tags: `IMPLICIT` and `EXPLICIT`.  Implicit tags
replace the tags that the tagged type would have otherwise.  Explicit tags
treat the encoding of a type's value (including its tag and length) as the
value of the tagged type, thus yielding a tag-length-tag-length-value encoding
-- a TLTLV encoding!

Thus explicit tagging is more redundant and wasteful than implicit tagging.
But implicit tagging loses metadata that is useful for tools that can decode
TLV encodings without reference to the schema (module) corresponding to the
types of values encoded.

TLV encodings were probably never justified except by lack of tooling and
belief that codecs for TLV ERs can be hand-coded.  But TLV RTs exist, and
because they are widely used, cannot be removed.

## Other Encoding Rules

The Packed Encoding Rules (PER) and Octet Encoding Rules (OER) are rules that
resemble XDR, but with a 1-byte word size instead of 4-byte word size, and also
with a 1-byte alignment instead of 4-byte alignment, yielding space-efficient
encodings.

Hand-coding XDR codecs is quite common and fairly easy.  Hand-coding PER and
OER is widely considered difficult because PER and OER try to be quite
space-efficient.

Hand-coding TLV codecs used to be considered easy, but really, never was.

But no one should hand-code codecs for any encoding rules.

Instead, one should use a compiler.  This is true for ASN.1, and for all schema
languages.

## Encoding Rule Specific Syntactic Forms

Some encoding rules require specific syntactic forms for some aspects of them.

For example, the JER (JSON Encoding Rules) provide for syntax to select the use
of JSON arrays vs. JSON objects for encoding structure types.

For example, the TLV encoding rules provide for syntax for specifying
alternative tags for disambiguation.

## ASN.1 Syntax Specifications

 - The base specification is ITU-T
   [X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).

 - Additional syntax extensions include:

    - [X.681 ASN.1 Information object specification](https://www.itu.int/rec/T-REC-X.681/en)
    - [X.682 ASN.1 Constraint specification](https://www.itu.int/rec/T-REC-X.682/en)
    - [X.682 ASN.1 Parameterization of ASN.1 specifications](https://www.itu.int/rec/T-REC-X.683/en)

   Together these three specifications make the formal specification of open
   types possible.

## ASN.1 Encoding Rules Specifications

 - The TLV Basic, Distinguished, and Canonical Encoding Rules (BER, DER, CER)
   are described in ITU-T [X.690](https://www.itu.int/rec/T-REC-X.690/en).

 - The more flat-buffers/XDR-like Packed Encoding Rules (PER) are described in
   ITU-T [X.691](https://www.itu.int/rec/T-REC-X.691/en), and its successor,
   the Octet Encoding Rules (OER) are described in
   [X.696](https://www.itu.int/rec/T-REC-X.692/en).

 - The XML Encoding Rules (XER) are described in ITU-T
   [X.693](https://www.itu.int/rec/T-REC-X.693/en).

   Related is the [X.694 Mapping W3C XML schema definitions into ASN.1](https://www.itu.int/rec/T-REC-X.694/en)

 - The JSON Encoding Rules (JER) are described in ITU-T
   [X.697](https://www.itu.int/rec/T-REC-X.697/en).

 - The Generic String Encoding Rules are specified by IETF RFCs
   [RFC3641](https://datatracker.ietf.org/doc/html/rfc3641),
   [RFC3642](https://datatracker.ietf.org/doc/html/rfc3642),
   [RFC4792](https://datatracker.ietf.org/doc/html/rfc4792).

Additional ERs can be added.

For example, XDR can clearly encode a very large subset of ASN.1, and with a
few additional conventions, all of ASN.1.

NDR too can clearly encode a very large subset of ASN.1, and with a few
additional conventions, all of ASN.  However, ASN.1 is not sufficiently rich a
_syntax_ to express all of what NDR can express (think of NDR conformant and/or
varying arrays), though with some extensions it could.

## Commentary

The text in this section is the personal opinion of the author(s).

 - ASN.1 gets a bad rap because BER/DER/CER are terrible encoding rules, as are
   all TLV encoding rules.

   The BER family of encoding rules is a disaster, yes, but ASN.1 itself is
   not.  On the contrary, ASN.1 is quite rich in features and semantics -as
   rich as any competitor- while also being very easy to write and understand
   _as a syntax_.

 - ASN.1 also gets a bad rap because its full syntax is not context-free, and
   so parsing it can be tricky.

   And yet the Heimdal ASN.1 compiler manages, using LALR(1) `yacc`/`bison`/`byacc`
   parser-generators.  For the subset of ASN.1 that this compiler handles,
   there are no ambiguities.  However, we understand that eventually we will
   need run into ambiguities.

   For example, `ValueSet` and `ObjectSet` are ambiguous.  X.680 says:

   ```
   ValueSet ::= "{" ElementSetSpecs "}"
   ```

   while X.681 says:

   ```
   ObjectSet ::= "{" ObjectSetSpec "}"
   ```

   and the set members can be just the symbolic names of members, in which case
   there's no grammatical difference between those two productions.  These then
   cause a conflict in the `FieldSetting` production, which is used in the
   `ObjectDefn` production, which is used in defining an object (which is to be
   referenced from some `ObjectSet` or `FieldSetting`).

   This particular conflict can be resolved by one of:

    - limiting the power of object sets by disallowing recursion (object sets
      containing objects that have field settings that are object sets ...),

    - or by introducing additional required and disambiguating syntactic
      elements that preclude full compliance with ASN.1,

    - or by simply using the same production and type internally to handle
      both, the `ValueSet` and `ObjectSet` productions and then internally
      resolving the actual type as late as possible by either inspecting the
      types of the set members or by inspecting the expected kind of field that
      the `ValueSet`-or-`ObjectSet` is setting.

   Clearly, only the last of these is satisfying, but it is more work for the
   compiler developer.

 - TLV encodings are bad because they yield unnecessary redundance in
   encodings.  This is space-inefficient, but also a source of bugs in
   hand-coded codecs for TLV encodings.

   EXPLICIT tagging makes this worse by making the encoding a TLTLV encoding
   (tag length tag length value).  (The inner TLV is the V for the outer TL.)

 - TLV encodings are often described as "self-describing" because one can
   usually write a `dumpasn1` style of tool that attempts to decode a TLV
   encoding of a value without reference to the value's type definition.

   The use of `IMPLICIT` tagging with BER/DER/CER makes schema-less `dumpasn1`
   style tools harder to use, as some type information is lost.  E.g., a
   primitive type implicitly tagged with a context tag results in a TLV
   encoding where -without reference to the schema- the tag denotes no
   information about the type of the value encoded.  The user is left to figure
   out what kind of data that is and to then decode it by hand.  For
   constructed types (arrays and structures), implicit tagging does not really
   lose any metadata about the type that wasn't already lost by BER/DER/CER, so
   there is no great loss there.

   However, Heimdal's ASN.1 compiler includes an `asn1_print(1)` utility that
   can print DER-encoded values in much more detail than a schema-less
   `dumpasn1` style of tool can.  This is because `asn1_print(1)` includes
   a number of compiled ASN.1 modules, and it can be extended to include more.

 - There is some merit to BER, however.  Specifically, an appropriate use of
   indeterminate length encoding with BER can yield on-line encoding.  Think of
   encoding streams of indeterminate size -- this cannot be done with DER or
   Flat Buffers, or most encodings, though it can be done with some encodings,
   such as BER and NDR (NDR has "pipes" for this).

   Some clues are needed in order to produce an codec that can handle such
   on-line behavior.  In IDL/NDR that clue comes from the "pipe" type.  In
   ASN.1 there is no such clue and it would have to be provided separately to
   the ASN.1 compiler (e.g., as a command-line option).

 - Protocol Buffers is a TLV encoding.  There was no need to make it a TLV
   encoding.

   Public opinion seems to prefer Flat Buffers now, which is not a TLV encoding
   and which is more comparable to XDR/NDR/PER/OER.

# Heimdal ASN.1 Compiler

The Heimdal ASN.1 compiler and library implement a very large subset of the
ASN.1 syntax, meanign large parts of X.680, X.681, X.682, and X.683.

The compiler currently emits:

 - a JSON representation of ASN.1 modules
 - C types corresponding to ASN.1 modules' types
 - C functions for DER (and some BER) codecs for ASN.1 modules' types

We vaguely hope to eventually move to using the JSON representation of ASN.1
modules to do code generation in a programming language like `jq` rather than
in C.  The idea there is to make it much easier to target other programming
languages than C, especially Rust, so that we can start moving Heimdal to Rust
(first after this would be `lib/hx509`, then `lib/krb5`, then `lib/hdb`, then
`lib/gssapi`, then `kdc/`).

The compiler has two "backends":

 - C code generation
 - "template" (byte-code) generation and interpretation

## Features and Limitations

Supported encoding rules:

 - DER
 - BER decoding (but not encoding)

As well, the Heimdal ASN.1 compiler can render values as JSON using an ad-hoc
metaschema that is not quite JER-compliant.  A sample rendering of a complex
PKIX `Certificate` with all typed holes automatically decoded is shown in
[README.md#features](README.md#features).

The Heimdal ASN.1 compiler supports open types via X.681/X.682/X.683 syntax.
Specifically: (when using the template backend) the generated codecs can
automatically and recursively decode and encode through "typed holes".

An "open type", also known as "typed holes" or "references", is a part of a
structure that can contain the encoding of a value of some arbitrary data type,
with a hint of that value's type expressed in some way such as: via an "object
identifier", or an integer, or even a string (e.g., like a URN).

Open types are widely used as a form of extensibility.

Historically, open types were never documented formally, but with natural
language (e.g., English) meant only for humans to understand.  Documenting open
types with formal syntax allows compilers to support them specially.

See the the [`asn1_compile(1)` manual page](#Manual-Page-for-asn1_compile)
below and [README.md#features](README.md#features), for more details on
limitations.  Excerpt from the manual page:

```
The Information Object System support includes automatic codec support
for encoding and decoding through “open types” which are also known as
“typed holes”.  See RFC5912 for examples of how to use the ASN.1 Infor-
mation Object System via X.681/X.682/X.683 annotations.  See the com-
piler's README files for more information on ASN.1 Information Object
System support.

Extensions specific to Heimdal are generally not syntactic in nature but
rather command-line options to this program.  For example, one can use
command-line options to:
      •       enable decoding of BER-encoded values;
      •       enable RFC1510-style handling of ‘BIT STRING’ types;
      •       enable saving of as-received encodings of specific types
              for the purpose of signature validation;
      •       generate add/remove utility functions for array types;
      •       decorate generated ‘struct’ types with fields that are nei-
              ther encoded nor decoded;
etc.

ASN.1 x.680 features supported:
      •       most primitive types (except BMPString and REAL);
      •       all constructed types, including SET and SET OF;
      •       explicit and implicit tagging.

Size and range constraints on the ‘INTEGER’ type cause the compiler to
generate appropriate C types such as ‘int’, ‘unsigned int’, ‘int64_t’,
‘uint64_t’.  Unconstrained ‘INTEGER’ is treated as ‘heim_integer’, which
represents an integer of arbitrary size.

Caveats and ASN.1 x.680 features not supported:
      •       JSON encoding support is not quite X.697 (JER) compatible.
              Its JSON schema is subject to change without notice.
      •       Control over C types generated is very limited, mainly only
              for integer types.
      •       When using the template backend, `SET { .. }` types are
              currently not sorted by tag as they should be, but if the
              module author sorts them by hand then correct DER will be
              produced.
      •       ‘AUTOMATIC TAGS’ is not supported.
      •       The REAL type is not supported.
      •       The EmbeddedPDV type is not supported.
      •       The BMPString type is not supported.
      •       The IA5String is not properly supported, as it's essen‐
              tially treated as a UTF8String with a different tag.
      •       All supported non-octet strings are treated as like the
              UTF8String type.
      •       Only types can be imported into ASN.1 modules at this time.
      •       Only simple value syntax is supported.  Constructed value
              syntax (i.e., values of SET, SEQUENCE, SET OF, and SEQUENCE
              OF types), is not supported.  Values of `CHOICE` types are
              also not supported.
```

## Easy-to-Use C Types

The Heimdal ASN.1 compiler generates easy-to-use C types for ASN.1 types.

Unconstrained `INTEGER` becomes `heim_integer` -- a large integer type.

Constrained `INTEGER` types become `int`, `unsigned int`, `int64_t`, or
`uint64_t`.

String types generally become `char *` (C strings, i.e., NUL-terminated) or
`heim_octet_string` (a counted byte string type).

`SET` and `SEQUENCE` types become `struct` types.

`SET OF SomeType` and `SEQUENCE OF SomeType` types become `struct` types with a
`size_t len` field counting the number of elements of the array, and a pointer
to `len` consecutive elements of the `SomeType` type.

`CHOICE` types become a `struct` type with an `enum` discriminant and a
`union`.

Type names have hyphens turned to underscores.

Every ASN.1 gets a `typedef`.

`OPTIONAL` members of `SET`s and `SEQUENCE`s become pointer types (`NULL`
values mean "absent", while non-`NULL` values mean "present").

Tags are of no consequence to the C types generated.

Types definitions to be topographically sorted because of the need to have
forward declarations.

Forward `typedef` declarations are emmitted.

Circular type dependencies are allowed provided that `OPTIONAL` members are
used for enough circular references so as to avoid creating types whose values
have infinite size!  (Circular type dependencies can be used to build linked
lists, though that is a bit of a silly trick when one can use arrays instead,
though in principle this could be used to do on-line encoding and decoding of
arbitrarily large streams of objects.  See the [commentary](#Commentary)
section.)

Thus `Certificate` becomes:

```C
typedef struct TBSCertificate {
  heim_octet_string _save; /* see below! */
  Version *version;
  CertificateSerialNumber serialNumber;
  AlgorithmIdentifier signature;
  Name issuer;
  Validity validity;
  Name subject;
  SubjectPublicKeyInfo subjectPublicKeyInfo;
  heim_bit_string *issuerUniqueID;
  heim_bit_string *subjectUniqueID;
  Extensions *extensions;
} TBSCertificate;

typedef struct Certificate {
  TBSCertificate tbsCertificate;
  AlgorithmIdentifier signatureAlgorithm;
  heim_bit_string signatureValue;
} Certificate;
```

The `_save` field in `TBSCertificate` is generated when the compiler is invoked
with `--preserve-binary=TBSCertificate`, and the decoder will place the
original encoding of the value of a `TBSCertificate` in the decoded
`TBSCertificate`'s `_save` field.  This is very useful for signature
validation: the application need not attempt to re-encode a `TBSCertificate` in
order to validate its signature from the containing `Certificate`!

Let's compare to the `Certificate` as defined in ASN.1:

```ASN.1
   Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING
   }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
        extensions      [3]  EXPLICIT Extensions OPTIONAL
   }
```

The conversion from ASN.1 to C is quite mechanical and natural.  That's what
code-generators do, of course, so it's not surprising.  But you can see that
`Certificate` in ASN.1 and C differs only in:

 - in C `SEQUENCE { }` becomes `struct { }`
 - in C the type name comes first
 - in C we drop the tagging directives (e.g., `[0]  EXPLICIT`)
 - `DEFAULT` and `OPTIONAL` become pointers
 - in C we use `typedef`s to make the type names usable without having to add
   `struct`

## Circular Type Dependencies

As noted above, circular type dependencies are supported.

Here's a toy example from [XDR](https://datatracker.ietf.org/doc/html/rfc4506)
-- a linked list:

```XDR
struct stringentry {
   string item<>;
   stringentry *next;
};

typedef stringentry *stringlist;
```

Here is the same example in ASN.1:

```ASN.1
Stringentry ::= SEQUENCE {
    item UTF8String,
    next Stringentry OPTIONAL
}
```

which compiles to:

```C
typedef struct Stringentry Stringentry;
struct Stringentry {
    char *item;
    Stringentry *next;
};
```

This illustrates that `OPTIONAL` members in ASN.1 are like pointers in XDR.

Making the `next` member not `OPTIONAL` would cause `Stringentry` to be
infinitely large, and there is no way to declare the equivalent in C anyways
(`struct foo { int a; struct foo b; };` will not compile in C).

Mutual circular references are allowed too.  In the following example `A`
refers to `B` and `B` refers to `A`, but as long as one (or both) of those
references is `OPTIONAL`, then it will be allowed:

```ASN1
A ::= SEQUENCE { name UTF8String, b B }
B ::= SEQUENCE { name UTF8String, a A OPTIONAL }
```

```ASN1
A ::= SEQUENCE { name UTF8String, b B OPTIONAL }
B ::= SEQUENCE { name UTF8String, a A }
```

```ASN1
A ::= SEQUENCE { name UTF8String, b B OPTIONAL }
B ::= SEQUENCE { name UTF8String, a A OPTIONAL }
```

In the above example values of types `A` and `B` together form a linked list.

Whereas this is broken and will not compile:

```ASN1
A ::= SEQUENCE { name UTF8String, b B }
B ::= SEQUENCE { name UTF8String, a A } -- infinite size!
```

## Generated APIs For Any Given Type T

The C functions generated for ASN.1 types are all of the same form, for any
type `T`:

```C
int    decode_T(const unsigned char *, size_t, TBSCertificate *, size_t *);
int    encode_T(unsigned char *, size_t, const TBSCertificate *, size_t *);
size_t length_T(const TBSCertificate *);
int      copy_T(const TBSCertificate *, TBSCertificate *);
void     free_T(TBSCertificate *);
char *  print_T(const TBSCertificate *, int);
```

The `decode_T()` functions take a pointer to the encoded data, its length in
bytes, a pointer to a C object of type `T` to decode into, and a pointer into
which the number of bytes consumed will be written.

The `length_T()` functions take a pointer to a C object of type `T` and return
the number of bytes its encoding would need.

The `encode_T()` functions take a pointer to enough bytes to encode the value,
the number of bytes found there, a pointer to a C object of type `T` whose
value to encode, and a pointer into which the number of bytes output will be
written.

> NOTE WELL: The first argument to `encode_T()` functions must point to the
> last byte in the buffer into which the encoder will encode the value.  This
> is because the encoder encodes from the end towards the beginning.

The `print_T()` functions encode the value of a C object of type `T` in JSON
(though not in JER-compliant JSON).  A sample printing of a complex PKIX
`Certificate` can be seen in [README.md#features](README.md#features).

The `copy_T()` functions take a pointer to a source C object of type `T` whose
value they then copy to the destination C object of the same type.  The copy
constructor is equivalent to encoding the source value and decoding it onto the
destination.

The `free_T()` functions take a pointer to a C object of type `T` whose value's
memory resources will be released.  Note that the C object _itself_ is not
freed, only its _content_.

See [sample usage](#Using-the-Generated-APIs).

These functions are all recursive.

> NOTE WELL: These functions use the standard C memory allocator.
> When using the Windows statically-linked C run-time, you must link with
> `LIBASN1.LIB` to avoid possibly freeing memory allocated by a different
> allocator.

## Error Handling

All codec functions that return errors return them as `int`.

Error values are:

 - system error codes (use `strerror()` to display them)

or

 - `ASN1_BAD_TIMEFORMAT`
 - `ASN1_MISSING_FIELD`
 - `ASN1_MISPLACED_FIELD`
 - `ASN1_TYPE_MISMATCH`
 - `ASN1_OVERFLOW`
 - `ASN1_OVERRUN`
 - `ASN1_BAD_ID`
 - `ASN1_BAD_LENGTH`
 - `ASN1_BAD_FORMAT`
 - `ASN1_PARSE_ERROR`
 - `ASN1_EXTRA_DATA`
 - `ASN1_BAD_CHARACTER`
 - `ASN1_MIN_CONSTRAINT`
 - `ASN1_MAX_CONSTRAINT`
 - `ASN1_EXACT_CONSTRAINT`
 - `ASN1_INDEF_OVERRUN`
 - `ASN1_INDEF_UNDERRUN`
 - `ASN1_GOT_BER`
 - `ASN1_INDEF_EXTRA_DATA`

You can use the `com_err` library to display these errors as strings:

```C
    struct et_list *etl = NULL;
    initialize_asn1_error_table_r(&etl);
    int ret;

    ...

    ret = decode_T(...);
    if (ret) {
        const char *error_message;

        if ((error_message = com_right(etl, ret)) == NULL)
            error_message = strerror(ret);

        fprintf(stderr, "Failed to decode T: %s\n",
                error_message ? error_message : "<unknown error>");
    }
```

## Using the Generated APIs

Value construction is as usual in C.  Use the standard C allocator for
allocating values of `OPTIONAL` fields.

Value destruction is done with the `free_T()` destructors.

Decoding is just:

```C
    Certificate c;
    size_t sz;
    int ret;

    ret = decode_Certificate(pointer_to_encoded_bytes,
                             number_of_encoded_bytes,
                             &c, &sz);
    if (ret == 0) {
        if (sz != number_of_encoded_bytes)
            warnx("Extra bytes after Certificate!");
    } else {
        warnx("Failed to decode certificate!");
        return ret;
    }

    /* Now do stuff with the Certificate */
    ...

    /* Now release the memory */
    free_Certificate(&c);
```

Encoding involves calling the `length_T()` function to compute the number of
bytes needed for the encoding, then allocating that many bytes, then calling
`encode_T()` to encode into that memory.  A convenience macro,
`ASN1_MALLOC_ENCODE()`, does all three operations:

```C
    Certificate c;
    size_t num_bytes, sz;
    char *bytes = NULL;
    int ret;

    /* Build a `Certificate` in `c` */
    ...

    /* Encode `c` */
    ASN1_MALLOC_ENCODE(Certificate, bytes, num_bytes, &c, sz, ret);
    if (ret)
        errx(1, "Out of memory encoding a Certificate");

    /* This check isn't really needed -- it never fails */
    if (num_bytes != sz)
        errx(1, "ASN.1 encoder internal error");

    /* Send the `num_bytes` in `bytes` */
    ...

    /* Free the memory allocated by `ASN1_MALLOC_ENCODE()` */
    free(bytes);
```

or, the same code w/o the `ASN1_MALLOC_ENCODE()` macro:

```C
    Certificate c;
    size_t num_bytes, sz;
    char *bytes = NULL;
    int ret;

    /* Build a `Certificate` in `c` */
    ...

    /* Encode `c` */
    num_bytes = length_Certificate(&c);
    bytes = malloc(num_bytes);
    if (bytes == NULL)
        errx(1, "Out of memory");

    /*
     * Note that the memory to encode into, passed to encode_Certificate()
     * must be a pointer to the _last_ byte of that memory, not the first!
     */
    ret = encode_Certificate(bytes + num_bytes - 1, num_bytes,
                             &c, &sz);
    if (ret)
        errx(1, "Out of memory encoding a Certificate");

    /* This check isn't really needed -- it never fails */
    if (num_bytes != sz)
        errx(1, "ASN.1 encoder internal error");

    /* Send the `num_bytes` in `bytes` */
    ...

    /* Free the memory allocated by `ASN1_MALLOC_ENCODE()` */
    free(bytes);
```

## Open Types

The handling of X.681/X.682/X.683 syntax for open types is described at length
in [README-X681.md](README-X681.md).

## Command-line Usage

The compiler takes an ASN.1 module file name and outputs a C header and C
source files, as well as various other metadata files:

 - `<module>_asn1.h`

   This file defines all the exported types from the given ASN.1 module as C
   types.

 - `<module>_asn1-priv.h`

   This file defines all the non-exported types from the given ASN.1 module as
   C types.

 - `<module>_asn1_files`

   This file is needed because the default is to place the code for each type
   in a separate C source file, which can help improve the performance of
   builds by making it easier to parallelize the building of the ASN.1 module.

 - `asn1_<Type>.c` or `asn1_<module>_asn1.c`

   If `--one-code-file` is used, then the implementation of the module will be
   in a file named `asn1_<module>_asn1.c`, otherwise the implementation of each
   type in the module will be in `asn1_<Type>.c`.

 - `<module>_asn1.json`

   This file contains a JSON description of the module (the schema for this
   file is ad-hoc and subject to change w/o notice).

 - `<module>_asn1_oids.c`

   This file is meant to be `#include`d, and contains just calls to a
   `DEFINE_OID_WITH_NAME(sym)` macro that the user must define, where `sym` is
   the suffix of the name of a variable of type `heim_oid`.  The full name of
   the variable is `asn1_oid_ ## sym`.

 - `<module>_asn1_syms.c`

   This file is meant to be `#include`d, and contains just calls to these
   macros that the user must define:

    - `ASN1_SYM_INTVAL(name, genname, sym, num)`
    - `ASN1_SYM_OID(name, genname, sym)`
    - `ASN1_SYM_TYPE(name, genname, sym)`

   where `name` is the C string literal name of the value or type as it appears
   in the ASN.1 module, `genname` is the C string literal name of the value or
   type as generated (e.g., with hyphens replaced by underscores), `sym` is the
   symbol or symbol suffix (see above0, and `num` is the numeric value of the
   integer value.

Control over the C types used for ASN.1 `INTEGER` types is done by ASN.1 usage
convention:

 - unconstrained `INTEGER` types, or `INTEGER` types where only the minimum, or
   only the maximum value is specified generate `heim_integer`

 - constrained `INTEGER` types whose minimum and maximum fit in `unsigned`'s
   range generate `unsigned`

 - constrained `INTEGER` types whose minimum and maximum fit in `int`'s
   range generate `int`

 - constrained `INTEGER` types whose minimum and maximum fit in `uin64_t`'s
   range generate `uin64_t`

 - constrained `INTEGER` types whose minimum and maximum fit in `in64_t`'s
   range generate `in64_t`

 - `INTEGER` types with named members generate a C `struct` with `unsigned int`
   bit-field members

 - all other `INTEGER` types generate `heim_integer`

Various code generation options are provided as command-line options or as
ASN.1 usage conventions:

 - `--type-file=C-HEADER-FILE` -- generate an `#include` directive to include
   that header for some useful base types (within Heimdal we use `krb5-types.h`
   as that header)

 - `--template` -- use the "template" (byte-coded) backend

 - `--one-code-file` -- causes all the code generated to be placed in one C
   source file (mutually exclusive with `--template`)

 - `--support-ber` -- accept non-DER BER when decoding

 - `--preserve-binary=TYPE` -- add a `_save` field to the C struct type for the
   ASN.1 `TYPE` where the decoder will save the original encoding of the value
   of `TYPE` it decodes (useful for cryptographic signature verification!)

 - `--sequence=TYPE` -- generate `add_TYPE()` and `remove_TYPE()` utility
   functions (`TYPE` must be a `SET OF` or `SEQUENCE OF` type)

 - `--decorate=DECORATION` -- add fields to generated C struct types as
   described in the `DECORATION` (see the
   [manual page](#Manual-Page-for-asn1_compile) below)

   Decoration fields are never encoded or decoded.  They are meant to be used
   for, e.g., application state keeping.

 - `--no-parse-units` -- normally the compiler generates code to use the
   Heimdal `libroken` "units" utility for displaying bit fields; this option
   disables this

See the [manual page for `asn1_compile(1)`](#Manual-Page-for-asn1_compile) for
a full listing of command-line options.

### Manual Page for `asn1_compile(1)`

```
ASN1_COMPILE(1)		  BSD General Commands Manual	       ASN1_COMPILE(1)

NAME
     asn1_compile — compile ASN.1 modules

SYNOPSIS
     asn1_compile [--template] [--prefix-enum] [--enum-prefix=PREFIX]
		  [--encode-rfc1510-bit-string] [--decode-dce-ber]
		  [--support-ber] [--preserve-binary=TYPE] [--sequence=TYPE]
		  [--decorate=DECORATION] [--one-code-file] [--gen-name=NAME]
		  [--option-file=FILE] [--original-order] [--no-parse-units]
		  [--type-file=C-HEADER-FILE] [--version] [--help]
		  [FILE.asn1 [NAME]]

DESCRIPTION
     asn1_compile compiles an ASN.1 module into C source code and header
     files.

     A fairly large subset of ASN.1 as specified in X.680, and the ASN.1 In‐
     formation Object System as specified in X.681, X.682, and X.683 is sup‐
     ported, with support for the Distinguished Encoding Rules (DER), partial
     Basic Encoding Rules (BER) support, and experimental JSON support (encod‐
     ing only at this time).

     See the compiler's README files for details about the C code and inter‐
     faces it generates.

     The Information Object System support includes automatic codec support
     for encoding and decoding through “open types” which are also known as
     “typed holes”.  See RFC 5912 for examples of how to use the ASN.1 Infor‐
     mation Object System via X.681/X.682/X.683 annotations.  See the com‐
     piler's README files for more information on ASN.1 Information Object
     System support.

     Extensions specific to Heimdal are generally not syntactic in nature but
     rather command-line options to this program.  For example, one can use
     command-line options to:
	   •	   enable decoding of BER-encoded values;
	   •	   enable RFC1510-style handling of ‘BIT STRING’ types;
	   •	   enable saving of as-received encodings of specific types
		   for the purpose of signature validation;
	   •	   generate add/remove utility functions for array types;
	   •	   decorate generated ‘struct’ types with fields that are nei‐
		   ther encoded nor decoded;
     etc.

     ASN.1 x.680 features supported:
	   •	   most primitive types (except BMPString and REAL);
	   •	   all constructed types, including SET and SET OF;
	   •	   explicit and implicit tagging.

     Size and range constraints on the ‘INTEGER’ type cause the compiler to
     generate appropriate C types such as ‘int’, ‘unsigned int’, ‘int64_t’,
     ‘uint64_t’.  Unconstrained ‘INTEGER’ is treated as ‘heim_integer’, which
     represents an integer of arbitrary size.

     Caveats and ASN.1 x.680 features not supported:
	   •	   JSON encoding support is not quite X.697 (JER) compatible.
		   Its JSON schema is subject to change without notice.
	   •	   Control over C types generated is very limited, mainly only
		   for integer types.
	   •	   When using the template backend, `SET { .. }` types are
		   currently not sorted by tag as they should be, but if the
		   module author sorts them by hand then correct DER will be
		   produced.
	   •	   ‘AUTOMATIC TAGS’ is not supported.
	   •	   The REAL type is not supported.
	   •	   The EmbeddedPDV type is not supported.
	   •	   The BMPString type is not supported.
	   •	   The IA5String is not properly supported, as it's essen‐
		   tially treated as a UTF8String with a different tag.
	   •	   All supported non-octet strings are treated as like the
		   UTF8String type.
	   •	   Only types can be imported into ASN.1 modules at this time.
	   •	   Only simple value syntax is supported.  Constructed value
		   syntax (i.e., values of SET, SEQUENCE, SET OF, and SEQUENCE
		   OF types), is not supported.	 Values of `CHOICE` types are
		   also not supported.

     Options supported:

     --template
	     Use the “template” backend instead of the “codegen” backend
	     (which is the default backend).

	     The template backend generates “templates” which are akin to
	     bytecode, and which are interpreted at run-time.

	     The codegen backend generates C code for all functions directly,
	     with no template interpretation.

	     The template backend scales better than the codegen backend be‐
	     cause as we add support for more encoding rules and more opera‐
	     tions (we may add value comparators) the templates stay mostly
	     the same, thus scaling linearly with size of module.  Whereas the
	     codegen backend scales linear with the product of module size and
	     number of encoding rules supported.

     --prefix-enum
	     This option should be removed because ENUMERATED types should al‐
	     ways have their labels prefixed.

     --enum-prefix=PREFIX
	     This option should be removed because ENUMERATED types should al‐
	     ways have their labels prefixed.

     --encode-rfc1510-bit-string
	     Use RFC1510, non-standard handling of “BIT STRING” types.

     --decode-dce-ber

     --support-ber

     --preserve-binary=TYPE
	     Generate a field named ‘_save’ in the C struct generated for the
	     named TYPE.  This field is used to preserve the original encoding
	     of the value of the TYPE.

	     This is useful for cryptographic applications so that they can
	     check signatures of encoded values as-received without having to
	     re-encode those values.

	     For example, the TBSCertificate type should have values preserved
	     so that Certificate validation can check the signatureValue over
	     the tbsCertificate's value as-received.

	     The alternative of encoding a value to check a signature of it is
	     brittle.  For types where non-canonical encodings (such as BER)
	     are allowed, this alternative is bound to fail.  Thus the point
	     of this option.

     --sequence=TYPE
	     Generate add/remove functions for the named ASN.1 TYPE which must
	     be a ‘SET OF’ or ‘SEQUENCE OF’ type.

     --decorate=ASN1-TYPE:FIELD-ASN1-TYPE:fname[?]
	     Add to the C struct generated for the given ASN.1 SET, SEQUENCE,
	     or CHOICE type named ASN1-TYPE a “hidden” field named fname of
	     the given ASN.1 type FIELD-ASN1-TYPE, but do not encode or decode
	     it.  If the fname ends in a question mark, then treat the field
	     as OPTIONAL.

	     This is useful for adding fields to existing types that can be
	     used for internal bookkeeping but which do not affect interoper‐
	     ability because they are neither encoded nor decoded.  For exam‐
	     ple, one might decorate a request type with state needed during
	     processing of the request.

     --decorate=ASN1-TYPE:void*:fname
	     Add to the C struct generated for the given ASN.1 SET, SEQUENCE,
	     or CHOICE type named ASN1-TYPE a “hidden” field named fname of
	     type ‘void *’ (but do not encode or decode it.

	     The destructor and copy constructor functions generated by this
	     compiler for ASN1-TYPE will set this field to the ‘NULL’ pointer.

     --decorate=ASN1-TYPE:FIELD-C-TYPE:fname[?]:[copyfn]:[freefn]:header
	     Add to the C struct generated for the given ASN.1 SET, SEQUENCE,
	     or CHOICE type named ASN1-TYPE a “hidden” field named fname of
	     the given external C type FIELD-C-TYPE, declared in the given
	     header but do not encode or decode this field.  If the fname ends
	     in a question mark, then treat the field as OPTIONAL.

	     The header must include double quotes or angle brackets.  The
	     copyfn must be the name of a copy constructor function that takes
	     a pointer to a source value of the type, and a pointer to a des‐
	     tination value of the type, in that order, and which returns zero
	     on success or else a system error code on failure.	 The freefn
	     must be the name of a destructor function that takes a pointer to
	     a value of the type and which releases resources referenced by
	     that value, but does not free the value itself (the run-time al‐
	     locates this value as needed from the C heap).  The freefn should
	     also reset the value to a pristine state (such as all zeros).

	     If the copyfn and freefn are empty strings, then the decoration
	     field will neither be copied nor freed by the functions generated
	     for the TYPE.

     --one-code-file
	     Generate a single source code file.  Otherwise a separate code
	     file will be generated for every type.

     --gen-name=NAME
	     Use NAME to form the names of the files generated.

     --option-file=FILE
	     Take additional command-line options from FILE.

     --original-order
	     Attempt to preserve the original order of type definition in the
	     ASN.1 module.  By default the compiler generates types in a topo‐
	     logical sort order.

     --no-parse-units
	     Do not generate to-int / from-int functions for enumeration
	     types.

     --type-file=C-HEADER-FILE
	     Generate an include of the named header file that might be needed
	     for common type defintions.

     --version

     --help

NOTES
     Currently only the template backend supports automatic encoding and de‐
     coding of open types via the ASN.1 Information Object System and
     X.681/X.682/X.683 annotations.

HEIMDAL			       February 22, 2021		       HEIMDAL
```

# Future Directions

The Heimdal ASN.1 compiler is focused on PKIX and Kerberos, and is almost
feature-complete for dealing with those.  It could use additional support for
X.681/X.682/X.683 elements that would allow the compiler to understand
`Certificate ::= SIGNED{TBSCertificate}`, particularly the ability to
automatically validate cryptographic algorithm parameters.  However, this is
not that important.

Another feature that might be nice is the ability of callers to specify smaller
information object sets when decoding values of types like `Certificate`,
mainly to avoid spending CPU cycles and memory allocations on decoding types in
typed holes that are not of interest to the application.

For testing purposes, a JSON reader to go with the JSON printer might be nice,
and anyways, would make for a generally useful tool.

Another feature that would be nice would to automatically generate SQL and LDAP
code for HDB based on `lib/hdb/hdb.asn1` (with certain usage conventions and/or
compiler command-line options to make it possible to map schemas usefully).

For the `hxtool` command, it would be nice if the user could input arbitrary
certificate extensions and `subjectAlternativeName` (SAN) values in JSON + an
ASN.1 module and type reference that `hxtool` could then parse and encode using
the ASN.1 compiler and library.  Currently the `hx509` library and its `hxtool`
command must be taught about every SAN type.
