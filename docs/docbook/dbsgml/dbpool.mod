<!-- ...................................................................... -->
<!-- DocBook information pool module V4.1 ................................. -->
<!-- File dbpool.mod ...................................................... -->

<!-- Copyright 1992-2000 HaL Computer Systems, Inc.,
     O'Reilly & Associates, Inc., ArborText, Inc., Fujitsu Software
     Corporation, and the Organization for the Advancement of
     Structured Information Standards (OASIS).

     $Id: dbpool.mod,v 1.1.2.1 2001/02/28 19:05:00 jerry Exp $

     Permission to use, copy, modify and distribute the DocBook DTD and
     its accompanying documentation for any purpose and without fee is
     hereby granted in perpetuity, provided that the above copyright
     notice and this paragraph appear in all copies.  The copyright
     holders make no representation about the suitability of the DTD for
     any purpose.  It is provided "as is" without expressed or implied
     warranty.

     If you modify the DocBook DTD in any way, except for declaring and
     referencing additional sets of general entities and declaring
     additional notations, label your DTD as a variant of DocBook.  See
     the maintenance documentation for more information.

     Please direct all questions, bug reports, or suggestions for
     changes to the docbook@lists.oasis-open.org mailing list. For more
     information, see http://www.oasis-open.org/docbook/.
-->

<!-- ...................................................................... -->

<!-- This module contains the definitions for the objects, inline
     elements, and so on that are available to be used as the main
     content of DocBook documents.  Some elements are useful for general
     publishing, and others are useful specifically for computer
     documentation.

     This module has the following dependencies on other modules:

     o It assumes that a %notation.class; entity is defined by the
       driver file or other high-level module.  This entity is
       referenced in the NOTATION attributes for the graphic-related and
       ModeSpec elements.

     o It assumes that an appropriately parameterized table module is
       available for use with the table-related elements.

     In DTD driver files referring to this module, please use an entity
     declaration that uses the public identifier shown below:

     <!ENTITY % dbpool PUBLIC
     "-//OASIS//ELEMENTS DocBook Information Pool V4.1//EN">
     %dbpool;

     See the documentation for detailed information on the parameter
     entity and module scheme used in DocBook, customizing DocBook and
     planning for interchange, and changes made since the last release
     of DocBook.
-->

<!-- ...................................................................... -->
<!-- General-purpose semantics entities ................................... -->

<!ENTITY % yesorno.attvals	"NUMBER">

<![IGNORE[
<!ENTITY % yes.attval		"1"> <!-- never actually used -->
]]>

<!ENTITY % no.attval		"0">

<!-- ...................................................................... -->
<!-- Entities for module inclusions ....................................... -->

<!ENTITY % dbpool.redecl.module "IGNORE">

<!-- ...................................................................... -->
<!-- Entities for element classes and mixtures ............................ -->

<!-- Object-level classes ................................................. -->

<!ENTITY % local.list.class "">
<!ENTITY % list.class
		"CalloutList|GlossList|ItemizedList|OrderedList|SegmentedList
		|SimpleList|VariableList %local.list.class;">

<!ENTITY % local.admon.class "">
<!ENTITY % admon.class
		"Caution|Important|Note|Tip|Warning %local.admon.class;">

<!ENTITY % local.linespecific.class "">
<!ENTITY % linespecific.class
		"LiteralLayout|ProgramListing|ProgramListingCO|Screen
		|ScreenCO|ScreenShot %local.linespecific.class;">

<!ENTITY % local.method.synop.class "">
<!ENTITY % method.synop.class
		"ConstructorSynopsis
                 |DestructorSynopsis
                 |MethodSynopsis %local.method.synop.class;">

<!ENTITY % local.synop.class "">
<!ENTITY % synop.class
		"Synopsis|CmdSynopsis|FuncSynopsis
                 |ClassSynopsis|FieldSynopsis
                 |%method.synop.class; %local.synop.class;">

<!ENTITY % local.para.class "">
<!ENTITY % para.class
		"FormalPara|Para|SimPara %local.para.class;">

<!ENTITY % local.informal.class "">
<!ENTITY % informal.class
		"Address|BlockQuote
		|Graphic|GraphicCO|MediaObject|MediaObjectCO
		|InformalEquation
		|InformalExample
		|InformalFigure
		|InformalTable %local.informal.class;">

<!ENTITY % local.formal.class "">
<!ENTITY % formal.class
		"Equation|Example|Figure|Table %local.formal.class;">

<!-- The DocBook TC may produce an official EBNF module for DocBook. -->
<!-- This PE provides the hook by which it can be inserted into the DTD. -->
<!ENTITY % ebnf.block.hook "">

<!ENTITY % local.compound.class "">
<!ENTITY % compound.class
		"MsgSet|Procedure|Sidebar|QandASet
                 %ebnf.block.hook;
                 %local.compound.class;">

<!ENTITY % local.genobj.class "">
<!ENTITY % genobj.class
		"Anchor|BridgeHead|Remark|Highlights
		%local.genobj.class;">

<!ENTITY % local.descobj.class "">
<!ENTITY % descobj.class
		"Abstract|AuthorBlurb|Epigraph
		%local.descobj.class;">

<!-- Character-level classes .............................................. -->

<!ENTITY % local.ndxterm.class "">
<!ENTITY % ndxterm.class
		"IndexTerm %local.ndxterm.class;">

<!ENTITY % local.xref.char.class "">
<!ENTITY % xref.char.class
		"FootnoteRef|XRef %local.xref.char.class;">

<!ENTITY % local.gen.char.class "">
<!ENTITY % gen.char.class
		"Abbrev|Acronym|Citation|CiteRefEntry|CiteTitle|Emphasis
		|FirstTerm|ForeignPhrase|GlossTerm|Footnote|Phrase
		|Quote|Trademark|WordAsWord %local.gen.char.class;">

<!ENTITY % local.link.char.class "">
<!ENTITY % link.char.class
		"Link|OLink|ULink %local.link.char.class;">

<!-- The DocBook TC may produce an official EBNF module for DocBook. -->
<!-- This PE provides the hook by which it can be inserted into the DTD. -->
<!ENTITY % ebnf.inline.hook "">

<!ENTITY % local.tech.char.class "">
<!ENTITY % tech.char.class
		"Action|Application
                |ClassName|MethodName|InterfaceName|ExceptionName
                |OOClass|OOInterface|OOException
                |Command|ComputerOutput
		|Database|Email|EnVar|ErrorCode|ErrorName|ErrorType|Filename
		|Function|GUIButton|GUIIcon|GUILabel|GUIMenu|GUIMenuItem
		|GUISubmenu|Hardware|Interface|KeyCap
		|KeyCode|KeyCombo|KeySym|Literal|Constant|Markup|MediaLabel
		|MenuChoice|MouseButton|Option|Optional|Parameter
		|Prompt|Property|Replaceable|ReturnValue|SGMLTag|StructField
		|StructName|Symbol|SystemItem|Token|Type|UserInput|VarName
                %ebnf.inline.hook;
		%local.tech.char.class;">

<!ENTITY % local.base.char.class "">
<!ENTITY % base.char.class
		"Anchor %local.base.char.class;">

<!ENTITY % local.docinfo.char.class "">
<!ENTITY % docinfo.char.class
		"Author|AuthorInitials|CorpAuthor|ModeSpec|OtherCredit
		|ProductName|ProductNumber|RevHistory
		%local.docinfo.char.class;">

<!ENTITY % local.other.char.class "">
<!ENTITY % other.char.class
		"Remark|Subscript|Superscript %local.other.char.class;">

<!ENTITY % local.inlineobj.char.class "">
<!ENTITY % inlineobj.char.class
		"InlineGraphic|InlineMediaObject|InlineEquation %local.inlineobj.char.class;">

<!-- Redeclaration placeholder ............................................ -->

<!-- For redeclaring entities that are declared after this point while
     retaining their references to the entities that are declared before
     this point -->

<![ %dbpool.redecl.module; [
%rdbpool;
<!--end of dbpool.redecl.module-->]]>

<!-- Object-level mixtures ................................................ -->

<!--
                      list admn line synp para infm form cmpd gen  desc
Component mixture       X    X    X    X    X    X    X    X    X    X
Sidebar mixture         X    X    X    X    X    X    X    a    X
Footnote mixture        X         X    X    X    X
Example mixture         X         X    X    X    X
Highlights mixture      X    X              X
Paragraph mixture       X         X    X         X
Admonition mixture      X         X    X    X    X    X    b    c
Figure mixture                    X    X         X
Table entry mixture     X    X    X         X    d
Glossary def mixture    X         X    X    X    X         e
Legal notice mixture    X    X    X         X    f

a. Just Procedure; not Sidebar itself or MsgSet.
b. No MsgSet.
c. No Highlights.
d. Just Graphic; no other informal objects.
e. No Anchor, BridgeHead, or Highlights.
f. Just BlockQuote; no other informal objects.
-->

<!ENTITY % local.component.mix "">
<!ENTITY % component.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;		|%compound.class;
		|%genobj.class;		|%descobj.class;
		|%ndxterm.class;
		%local.component.mix;">

<!ENTITY % local.sidebar.mix "">
<!ENTITY % sidebar.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;		|Procedure
		|%genobj.class;
		|%ndxterm.class;
		%local.sidebar.mix;">

<!ENTITY % local.qandaset.mix "">
<!ENTITY % qandaset.mix
		"%list.class;           |%admon.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;		|Procedure
		|%genobj.class;
		|%ndxterm.class;
		%local.qandaset.mix;">

<!ENTITY % local.revdescription.mix "">
<!ENTITY % revdescription.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;		|Procedure
		|%genobj.class;
		|%ndxterm.class;
		%local.revdescription.mix;">

<!ENTITY % local.footnote.mix "">
<!ENTITY % footnote.mix
		"%list.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		%local.footnote.mix;">

<!ENTITY % local.example.mix "">
<!ENTITY % example.mix
		"%list.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%ndxterm.class;
		%local.example.mix;">

<!ENTITY % local.highlights.mix "">
<!ENTITY % highlights.mix
		"%list.class;		|%admon.class;
		|%para.class;
		|%ndxterm.class;
		%local.highlights.mix;">

<!-- %formal.class; is explicitly excluded from many contexts in which
     paragraphs are used -->

<!ENTITY % local.para.mix "">
<!ENTITY % para.mix
		"%list.class;           |%admon.class;
		|%linespecific.class;
					|%informal.class;
		|%formal.class;
		%local.para.mix;">

<!ENTITY % local.admon.mix "">
<!ENTITY % admon.mix
		"%list.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;		|Procedure|Sidebar
		|Anchor|BridgeHead|Remark
		|%ndxterm.class;
		%local.admon.mix;">

<!ENTITY % local.figure.mix "">
<!ENTITY % figure.mix
		"%linespecific.class;	|%synop.class;
					|%informal.class;
		|%ndxterm.class;
		%local.figure.mix;">

<!ENTITY % local.tabentry.mix "">
<!ENTITY % tabentry.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;
		|%para.class;		|Graphic|MediaObject
		%local.tabentry.mix;">

<!ENTITY % local.glossdef.mix "">
<!ENTITY % glossdef.mix
		"%list.class;
		|%linespecific.class;	|%synop.class;
		|%para.class;		|%informal.class;
		|%formal.class;
		|Remark
		|%ndxterm.class;
		%local.glossdef.mix;">

<!ENTITY % local.legalnotice.mix "">
<!ENTITY % legalnotice.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;
		|%para.class;		|BlockQuote
		|%ndxterm.class;
		%local.legalnotice.mix;">

<!ENTITY % local.textobject.mix "">
<!ENTITY % textobject.mix
		"%list.class;		|%admon.class;
		|%linespecific.class;
		|%para.class;		|BlockQuote
		%local.textobject.mix;">

<!ENTITY % local.mediaobject.mix "">
<!ENTITY % mediaobject.mix 
		"VideoObject|AudioObject|ImageObject %local.mediaobject.mix">

<!-- Character-level mixtures ............................................. -->

<!ENTITY % local.ubiq.mix "">
<!ENTITY % ubiq.mix
		"%ndxterm.class;|BeginPage %local.ubiq.mix;">

<!ENTITY % ubiq.exclusion "-(%ubiq.mix)">
<!ENTITY % ubiq.inclusion "+(%ubiq.mix)">

<!ENTITY % footnote.exclusion "-(Footnote|%formal.class;)">
<!ENTITY % highlights.exclusion "-(%ubiq.mix;|%formal.class;)">
<!ENTITY % admon.exclusion "-(%admon.class;)">
<!ENTITY % formal.exclusion "-(%formal.class;)">
<!ENTITY % acronym.exclusion "-(Acronym)">
<!ENTITY % beginpage.exclusion "-(BeginPage)">
<!ENTITY % ndxterm.exclusion "-(%ndxterm.class;)">
<!ENTITY % blockquote.exclusion "-(Epigraph)">
<!ENTITY % remark.exclusion "-(Remark|%ubiq.mix;)">
<!ENTITY % glossterm.exclusion "-(GlossTerm)">
<!ENTITY % links.exclusion "-(Link|OLink|ULink|XRef)">

<!--
                    #PCD xref word link cptr base dnfo othr inob (synop)
para.char.mix         X    X    X    X    X    X    X    X    X
title.char.mix        X    X    X    X    X    X    X    X    X
ndxterm.char.mix      X    X    X    X    X    X    X    X    a
cptr.char.mix         X              X    X    X         X    a
smallcptr.char.mix    X                   b                   a
word.char.mix         X         c    X         X         X    a
docinfo.char.mix      X         d    X    b              X    a

a. Just InlineGraphic; no InlineEquation.
b. Just Replaceable; no other computer terms.
c. Just Emphasis and Trademark; no other word elements.
d. Just Acronym, Emphasis, and Trademark; no other word elements.
-->

<!-- The DocBook TC may produce an official forms module for DocBook. -->
<!-- This PE provides the hook by which it can be inserted into the DTD. -->
<!ENTITY % forminlines.hook "">

<!ENTITY % local.para.char.mix "">
<!ENTITY % para.char.mix
		"#PCDATA
		|%xref.char.class;	|%gen.char.class;
		|%link.char.class;	|%tech.char.class;
		|%base.char.class;	|%docinfo.char.class;
		|%other.char.class;	|%inlineobj.char.class;
		|%synop.class;
		|%ndxterm.class;
                %forminlines.hook;
		%local.para.char.mix;">

<!ENTITY % local.title.char.mix "">
<!ENTITY % title.char.mix
		"#PCDATA
		|%xref.char.class;	|%gen.char.class;
		|%link.char.class;	|%tech.char.class;
		|%base.char.class;	|%docinfo.char.class;
		|%other.char.class;	|%inlineobj.char.class;
		|%ndxterm.class;
		%local.title.char.mix;">

<!ENTITY % local.ndxterm.char.mix "">
<!ENTITY % ndxterm.char.mix
		"#PCDATA
		|%xref.char.class;	|%gen.char.class;
		|%link.char.class;	|%tech.char.class;
		|%base.char.class;	|%docinfo.char.class;
		|%other.char.class;	|InlineGraphic|InlineMediaObject
		%local.ndxterm.char.mix;">

<!ENTITY % local.cptr.char.mix "">
<!ENTITY % cptr.char.mix
		"#PCDATA
		|%link.char.class;	|%tech.char.class;
		|%base.char.class;
		|%other.char.class;	|InlineGraphic|InlineMediaObject
		|%ndxterm.class;
		%local.cptr.char.mix;">

<!ENTITY % local.smallcptr.char.mix "">
<!ENTITY % smallcptr.char.mix
		"#PCDATA
					|Replaceable
					|InlineGraphic|InlineMediaObject
		|%ndxterm.class;
		%local.smallcptr.char.mix;">

<!ENTITY % local.word.char.mix "">
<!ENTITY % word.char.mix
		"#PCDATA
					|Acronym|Emphasis|Trademark
		|%link.char.class;
		|%base.char.class;
		|%other.char.class;	|InlineGraphic|InlineMediaObject
		|%ndxterm.class;
		%local.word.char.mix;">

<!ENTITY % local.docinfo.char.mix "">
<!ENTITY % docinfo.char.mix
		"#PCDATA
		|%link.char.class;
					|Emphasis|Trademark
					|Replaceable
		|%other.char.class;	|InlineGraphic|InlineMediaObject
		|%ndxterm.class;
		%local.docinfo.char.mix;">
<!--ENTITY % bibliocomponent.mix (see Bibliographic section, below)-->
<!--ENTITY % person.ident.mix (see Bibliographic section, below)-->

<!-- ...................................................................... -->
<!-- Entities for content models .......................................... -->

<!ENTITY % formalobject.title.content "Title, TitleAbbrev?">

<!-- ...................................................................... -->
<!-- Entities for attributes and attribute components ..................... -->

<!-- Effectivity attributes ............................................... -->

<!ENTITY % arch.attrib
	--Arch: Computer or chip architecture to which element applies; no 
	default--
	"Arch		CDATA		#IMPLIED">

<!ENTITY % condition.attrib
	--Condition: General-purpose effectivity attribute--
	"Condition	CDATA		#IMPLIED">

<!ENTITY % conformance.attrib
	--Conformance: Standards conformance characteristics--
	"Conformance	NMTOKENS	#IMPLIED">

<!ENTITY % os.attrib
	--OS: Operating system to which element applies; no default--
	"OS		CDATA		#IMPLIED">

<!ENTITY % revision.attrib
	--Revision: Editorial revision to which element belongs; no default--
	"Revision	CDATA		#IMPLIED">

<!ENTITY % security.attrib
	--Security: Security classification; no default--
	"Security	CDATA		#IMPLIED">

<!ENTITY % userlevel.attrib
	--UserLevel: Level of user experience to which element applies; no 
	default--
	"UserLevel	CDATA		#IMPLIED">

<!ENTITY % vendor.attrib
	--Vendor: Computer vendor to which element applies; no default--
	"Vendor		CDATA		#IMPLIED">

<!ENTITY % local.effectivity.attrib "">
<!ENTITY % effectivity.attrib
	"%arch.attrib;
	%condition.attrib;
	%conformance.attrib;
	%os.attrib;
	%revision.attrib;
	%security.attrib;
	%userlevel.attrib;
	%vendor.attrib;
	%local.effectivity.attrib;"
>

<!-- Common attributes .................................................... -->

<!ENTITY % id.attrib
	--Id: Unique identifier of element; no default--
	"Id		ID		#IMPLIED">

<!ENTITY % idreq.attrib
	--Id: Unique identifier of element; a value must be supplied; no 
	default--
	"Id		ID		#REQUIRED">

<!ENTITY % lang.attrib
	--Lang: Indicator of language in which element is written, for
	translation, character set management, etc.; no default--
	"Lang		CDATA		#IMPLIED">

<!ENTITY % remap.attrib
	--Remap: Previous role of element before conversion; no default--
	"Remap		CDATA		#IMPLIED">

<!ENTITY % role.attrib
	--Role: New role of element in local environment; no default--
	"Role		CDATA		#IMPLIED">

<!ENTITY % xreflabel.attrib
	--XRefLabel: Alternate labeling string for XRef text generation;
	default is usually title or other appropriate label text already
	contained in element--
	"XRefLabel	CDATA		#IMPLIED">

<!ENTITY % revisionflag.attrib
	--RevisionFlag: Revision status of element; default is that element
	wasn't revised--
	"RevisionFlag	(Changed
			|Added
			|Deleted
			|Off)		#IMPLIED">

<!ENTITY % local.common.attrib "">
<!ENTITY % common.attrib
	"%id.attrib;
	%lang.attrib;
	%remap.attrib;
	--Role is included explicitly on each element--
	%xreflabel.attrib;
	%revisionflag.attrib;
	%effectivity.attrib;
	%local.common.attrib;"
>

<!ENTITY % idreq.common.attrib
	"%idreq.attrib;
	%lang.attrib;
	%remap.attrib;
	--Role is included explicitly on each element--
	%xreflabel.attrib;
	%revisionflag.attrib;
	%effectivity.attrib;
	%local.common.attrib;"
>

<!-- Semi-common attributes and other attribute entities .................. -->

<!ENTITY % local.graphics.attrib "">
<!ENTITY % graphics.attrib
	"
	--EntityRef: Name of an external entity containing the content
	of the graphic--
	EntityRef	ENTITY		#IMPLIED

	--FileRef: Filename, qualified by a pathname if desired, 
	designating the file containing the content of the graphic--
	FileRef 	CDATA		#IMPLIED

	--Format: Notation of the element content, if any--
	Format		(%notation.class;)
					#IMPLIED

	--SrcCredit: Information about the source of the Graphic--
	SrcCredit	CDATA		#IMPLIED

	--Width: Same as CALS reprowid (desired width)--
	Width		NUTOKEN		#IMPLIED

	--Depth: Same as CALS reprodep (desired depth)--
	Depth		NUTOKEN		#IMPLIED

	--Align: Same as CALS hplace with 'none' removed; #IMPLIED means 
	application-specific--
	Align		(Left
			|Right 
			|Center)	#IMPLIED

	--Scale: Conflation of CALS hscale and vscale--
	Scale		NUMBER		#IMPLIED

	--Scalefit: Same as CALS scalefit--
	Scalefit	%yesorno.attvals;
					#IMPLIED
	%local.graphics.attrib;"
>

<!ENTITY % local.keyaction.attrib "">
<!ENTITY % keyaction.attrib
	"
	--Action: Key combination type; default is unspecified if one 
	child element, Simul if there is more than one; if value is 
	Other, the OtherAction attribute must have a nonempty value--
	Action		(Click
			|Double-Click
			|Press
			|Seq
			|Simul
			|Other)		#IMPLIED

	--OtherAction: User-defined key combination type--
	OtherAction	CDATA		#IMPLIED
	%local.keyaction.attrib;"
>

<!ENTITY % label.attrib
	--Label: Identifying number or string; default is usually the
	appropriate number or string autogenerated by a formatter--
	"Label		CDATA		#IMPLIED">

<!ENTITY % linespecific.attrib
	--Format: whether element is assumed to contain significant white
	space--
	"Format		NOTATION
			(linespecific)	linespecific
         LineNumbering	(Numbered|Unnumbered) 	#IMPLIED">

<!ENTITY % linkend.attrib
	--Linkend: link to related information; no default--
	"Linkend	IDREF		#IMPLIED">

<!ENTITY % linkendreq.attrib
	--Linkend: required link to related information--
	"Linkend	IDREF		#REQUIRED">

<!ENTITY % linkends.attrib
	--Linkends: link to one or more sets of related information; no 
	default--
	"Linkends	IDREFS		#IMPLIED">

<![IGNORE[
<!-- Declared for completeness, but never used -->
<!ENTITY % linkendsreq.attrib
	--Linkends: required link to one or more sets of related information--
	"Linkends	IDREFS		#REQUIRED">
]]>

<!ENTITY % local.mark.attrib "">
<!ENTITY % mark.attrib
	"Mark		CDATA		#IMPLIED
	%local.mark.attrib;"
>

<!ENTITY % moreinfo.attrib
	--MoreInfo: whether element's content has an associated RefEntry--
	"MoreInfo	(RefEntry|None)	None">

<!ENTITY % pagenum.attrib
	--Pagenum: number of page on which element appears; no default--
	"Pagenum	CDATA		#IMPLIED">

<!ENTITY % local.status.attrib "">
<!ENTITY % status.attrib
	--Status: Editorial or publication status of the element
	it applies to, such as "in review" or "approved for distribution"--
	"Status		CDATA		#IMPLIED
	%local.status.attrib;"
>

<!ENTITY % width.attrib
	--Width: width of the longest line in the element to which it
	pertains, in number of characters--
	"Width		NUMBER		#IMPLIED">

<!-- ...................................................................... -->
<!-- Title elements ....................................................... -->

<!ENTITY % title.module "INCLUDE">
<![ %title.module; [
<!ENTITY % local.title.attrib "">
<!ENTITY % title.role.attrib "%role.attrib;">

<!ENTITY % title.element "INCLUDE">
<![ %title.element; [
<!ELEMENT Title - O ((%title.char.mix;)+)>
<!--end of title.element-->]]>

<!ENTITY % title.attlist "INCLUDE">
<![ %title.attlist; [
<!ATTLIST Title
		%pagenum.attrib;
		%common.attrib;
		%title.role.attrib;
		%local.title.attrib;
>
<!--end of title.attlist-->]]>
<!--end of title.module-->]]>

<!ENTITY % titleabbrev.module "INCLUDE">
<![ %titleabbrev.module; [
<!ENTITY % local.titleabbrev.attrib "">
<!ENTITY % titleabbrev.role.attrib "%role.attrib;">

<!ENTITY % titleabbrev.element "INCLUDE">
<![ %titleabbrev.element; [
<!ELEMENT TitleAbbrev - O ((%title.char.mix;)+)>
<!--end of titleabbrev.element-->]]>

<!ENTITY % titleabbrev.attlist "INCLUDE">
<![ %titleabbrev.attlist; [
<!ATTLIST TitleAbbrev
		%common.attrib;
		%titleabbrev.role.attrib;
		%local.titleabbrev.attrib;
>
<!--end of titleabbrev.attlist-->]]>
<!--end of titleabbrev.module-->]]>

<!ENTITY % subtitle.module "INCLUDE">
<![ %subtitle.module; [
<!ENTITY % local.subtitle.attrib "">
<!ENTITY % subtitle.role.attrib "%role.attrib;">

<!ENTITY % subtitle.element "INCLUDE">
<![ %subtitle.element; [
<!ELEMENT Subtitle - O ((%title.char.mix;)+)>
<!--end of subtitle.element-->]]>

<!ENTITY % subtitle.attlist "INCLUDE">
<![ %subtitle.attlist; [
<!ATTLIST Subtitle
		%common.attrib;
		%subtitle.role.attrib;
		%local.subtitle.attrib;
>
<!--end of subtitle.attlist-->]]>
<!--end of subtitle.module-->]]>

<!-- ...................................................................... -->
<!-- Bibliographic entities and elements .................................. -->

<!-- The bibliographic elements are typically used in the document
     hierarchy. They do not appear in content models of information
     pool elements.  See also the document information elements,
     below. -->

<!ENTITY % local.person.ident.mix "">
<!ENTITY % person.ident.mix
		"Honorific|FirstName|Surname|Lineage|OtherName|Affiliation
		|AuthorBlurb|Contrib %local.person.ident.mix;">

<!ENTITY % local.bibliocomponent.mix "">
<!ENTITY % bibliocomponent.mix
		"Abbrev|Abstract|Address|ArtPageNums|Author
		|AuthorGroup|AuthorInitials|BiblioMisc|BiblioSet
		|Collab|ConfGroup|ContractNum|ContractSponsor
		|Copyright|CorpAuthor|CorpName|Date|Edition
		|Editor|InvPartNumber|ISBN|ISSN|IssueNum|OrgName
		|OtherCredit|PageNums|PrintHistory|ProductName
		|ProductNumber|PubDate|Publisher|PublisherName
		|PubsNumber|ReleaseInfo|RevHistory|SeriesVolNums
		|Subtitle|Title|TitleAbbrev|VolumeNum|CiteTitle
		|%person.ident.mix;
		|%ndxterm.class;
		%local.bibliocomponent.mix;">

<!ENTITY % biblioentry.module "INCLUDE">
<![ %biblioentry.module; [
<!ENTITY % local.biblioentry.attrib "">

<!ENTITY % biblioentry.role.attrib "%role.attrib;">

<!ENTITY % biblioentry.element "INCLUDE">
<![ %biblioentry.element; [
<!--FUTURE USE (V5.0):
......................
ArticleInfo will be droped from BiblioEntry
......................
-->
<!ELEMENT BiblioEntry - O ((ArticleInfo
                            | (%bibliocomponent.mix;))+)
                          %ubiq.exclusion;>
<!--end of biblioentry.element-->]]>

<!ENTITY % biblioentry.attlist "INCLUDE">
<![ %biblioentry.attlist; [
<!ATTLIST BiblioEntry
		%common.attrib;
		%biblioentry.role.attrib;
		%local.biblioentry.attrib;
>
<!--end of biblioentry.attlist-->]]>
<!--end of biblioentry.module-->]]>

<!ENTITY % bibliomixed.module "INCLUDE">
<![ %bibliomixed.module; [
<!ENTITY % local.bibliomixed.attrib "">
<!ENTITY % bibliomixed.role.attrib "%role.attrib;">

<!ENTITY % bibliomixed.element "INCLUDE">
<![ %bibliomixed.element; [
<!ELEMENT BiblioMixed - O ((%bibliocomponent.mix; | BiblioMSet | #PCDATA)+)
	%ubiq.exclusion;>
<!--end of bibliomixed.element-->]]>

<!ENTITY % bibliomixed.attlist "INCLUDE">
<![ %bibliomixed.attlist; [
<!ATTLIST BiblioMixed
		%common.attrib;
		%bibliomixed.role.attrib;
		%local.bibliomixed.attrib;
>
<!--end of bibliomixed.attlist-->]]>
<!--end of bibliomixed.module-->]]>

<!ENTITY % articleinfo.module "INCLUDE">
<![ %articleinfo.module; [
<!ENTITY % local.articleinfo.attrib "">
<!ENTITY % articleinfo.role.attrib "%role.attrib;">

<!ENTITY % articleinfo.element "INCLUDE">
<![ %articleinfo.element; [
<!ELEMENT ArticleInfo - - ((Graphic | MediaObject | LegalNotice | ModeSpec 
	| SubjectSet | KeywordSet | ITermSet | %bibliocomponent.mix;)+)
	-(BeginPage)>
<!--end of articleinfo.element-->]]>

<!ENTITY % articleinfo.attlist "INCLUDE">
<![ %articleinfo.attlist; [
<!ATTLIST ArticleInfo
		%common.attrib;
		%articleinfo.role.attrib;
		%local.articleinfo.attrib;
>
<!--end of articleinfo.attlist-->]]>
<!--end of articleinfo.module-->]]>

<!ENTITY % biblioset.module "INCLUDE">
<![ %biblioset.module; [
<!ENTITY % local.biblioset.attrib "">
<!ENTITY % biblioset.role.attrib "%role.attrib;">

<!ENTITY % biblioset.element "INCLUDE">
<![ %biblioset.element; [
<!ELEMENT BiblioSet - - ((%bibliocomponent.mix;)+) %ubiq.exclusion;>
<!--end of biblioset.element-->]]>

<!ENTITY % biblioset.attlist "INCLUDE">
<![ %biblioset.attlist; [
<!ATTLIST BiblioSet
		--
		Relation: Relationship of elements contained within BiblioSet
		--
		Relation	CDATA		#IMPLIED
		%common.attrib;
		%biblioset.role.attrib;
		%local.biblioset.attrib;
>
<!--end of biblioset.attlist-->]]>
<!--end of biblioset.module-->]]>

<!ENTITY % bibliomset.module "INCLUDE">
<![ %bibliomset.module; [
<!ENTITY % bibliomset.role.attrib "%role.attrib;">
<!ENTITY % local.bibliomset.attrib "">

<!ENTITY % bibliomset.element "INCLUDE">
<![ %bibliomset.element; [
<!ELEMENT BiblioMSet - - ((%bibliocomponent.mix; | BiblioMSet | #PCDATA)+)
	%ubiq.exclusion;>
<!--end of bibliomset.element-->]]>

<!ENTITY % bibliomset.attlist "INCLUDE">
<![ %bibliomset.attlist; [
<!ATTLIST BiblioMSet
		--
		Relation: Relationship of elements contained within BiblioMSet
		--
		Relation	CDATA		#IMPLIED
		%bibliomset.role.attrib;
		%common.attrib;
		%local.bibliomset.attrib;
>
<!--end of bibliomset.attlist-->]]>
<!--end of bibliomset.module-->]]>

<!ENTITY % bibliomisc.module "INCLUDE">
<![ %bibliomisc.module; [
<!ENTITY % local.bibliomisc.attrib "">
<!ENTITY % bibliomisc.role.attrib "%role.attrib;">

<!ENTITY % bibliomisc.element "INCLUDE">
<![ %bibliomisc.element; [
<!ELEMENT BiblioMisc - - ((%para.char.mix;)+)>
<!--end of bibliomisc.element-->]]>

<!ENTITY % bibliomisc.attlist "INCLUDE">
<![ %bibliomisc.attlist; [
<!ATTLIST BiblioMisc
		%common.attrib;
		%bibliomisc.role.attrib;
		%local.bibliomisc.attrib;
>
<!--end of bibliomisc.attlist-->]]>
<!--end of bibliomisc.module-->]]>

<!-- ...................................................................... -->
<!-- Subject, Keyword, and ITermSet elements .............................. -->

<!ENTITY % subjectset.content.module "INCLUDE">
<![ %subjectset.content.module; [
<!ENTITY % subjectset.module "INCLUDE">
<![ %subjectset.module; [
<!ENTITY % local.subjectset.attrib "">
<!ENTITY % subjectset.role.attrib "%role.attrib;">

<!ENTITY % subjectset.element "INCLUDE">
<![ %subjectset.element; [
<!ELEMENT SubjectSet - - (Subject+)>
<!--end of subjectset.element-->]]>

<!ENTITY % subjectset.attlist "INCLUDE">
<![ %subjectset.attlist; [
<!ATTLIST SubjectSet
		--
		Scheme: Controlled vocabulary employed in SubjectTerms
		--
		Scheme		NAME		#IMPLIED
		%common.attrib;
		%subjectset.role.attrib;
		%local.subjectset.attrib;
>
<!--end of subjectset.attlist-->]]>
<!--end of subjectset.module-->]]>

<!ENTITY % subject.module "INCLUDE">
<![ %subject.module; [
<!ENTITY % local.subject.attrib "">
<!ENTITY % subject.role.attrib "%role.attrib;">

<!ENTITY % subject.element "INCLUDE">
<![ %subject.element; [
<!ELEMENT Subject - - (SubjectTerm+)>
<!--end of subject.element-->]]>

<!ENTITY % subject.attlist "INCLUDE">
<![ %subject.attlist; [
<!ATTLIST Subject
		--
		Weight: Ranking of this group of SubjectTerms relative 
		to others, 0 is low, no highest value specified
		--
		Weight		NUMBER		#IMPLIED
		%common.attrib;
		%subject.role.attrib;
		%local.subject.attrib;
>
<!--end of subject.attlist-->]]>
<!--end of subject.module-->]]>

<!ENTITY % subjectterm.module "INCLUDE">
<![ %subjectterm.module; [
<!ENTITY % local.subjectterm.attrib "">
<!ENTITY % subjectterm.role.attrib "%role.attrib;">

<!ENTITY % subjectterm.element "INCLUDE">
<![ %subjectterm.element; [
<!ELEMENT SubjectTerm - - (#PCDATA)>
<!--end of subjectterm.element-->]]>

<!ENTITY % subjectterm.attlist "INCLUDE">
<![ %subjectterm.attlist; [
<!ATTLIST SubjectTerm
		%common.attrib;
		%subjectterm.role.attrib;
		%local.subjectterm.attrib;
>
<!--end of subjectterm.attlist-->]]>
<!--end of subjectterm.module-->]]>
<!--end of subjectset.content.module-->]]>

<!ENTITY % keywordset.content.module "INCLUDE">
<![ %keywordset.content.module; [
<!ENTITY % local.keywordset.attrib "">
<!ENTITY % keywordset.module "INCLUDE">
<![ %keywordset.module; [
<!ENTITY % local.keywordset.attrib "">
<!ENTITY % keywordset.role.attrib "%role.attrib;">

<!ENTITY % keywordset.element "INCLUDE">
<![ %keywordset.element; [
<!ELEMENT KeywordSet - - (Keyword+)>
<!--end of keywordset.element-->]]>

<!ENTITY % keywordset.attlist "INCLUDE">
<![ %keywordset.attlist; [
<!ATTLIST KeywordSet
		%common.attrib;
		%keywordset.role.attrib;
		%local.keywordset.attrib;
>
<!--end of keywordset.attlist-->]]>
<!--end of keywordset.module-->]]>

<!ENTITY % keyword.module "INCLUDE">
<![ %keyword.module; [
<!ENTITY % local.keyword.attrib "">
<!ENTITY % keyword.role.attrib "%role.attrib;">

<!ENTITY % keyword.element "INCLUDE">
<![ %keyword.element; [
<!ELEMENT Keyword - - (#PCDATA)>
<!--end of keyword.element-->]]>

<!ENTITY % keyword.attlist "INCLUDE">
<![ %keyword.attlist; [
<!ATTLIST Keyword
		%common.attrib;
		%keyword.role.attrib;
		%local.keyword.attrib;
>
<!--end of keyword.attlist-->]]>
<!--end of keyword.module-->]]>
<!--end of keywordset.content.module-->]]>

<!ENTITY % itermset.module "INCLUDE">
<![ %itermset.module; [
<!ENTITY % local.itermset.attrib "">
<!ENTITY % itermset.role.attrib "%role.attrib;">

<!ENTITY % itermset.element "INCLUDE">
<![ %itermset.element; [
<!ELEMENT ITermSet - - (IndexTerm+)>
<!--end of itermset.element-->]]>

<!ENTITY % itermset.attlist "INCLUDE">
<![ %itermset.attlist; [
<!ATTLIST ITermSet
		%common.attrib;
		%itermset.role.attrib;
		%local.itermset.attrib;
>
<!--end of itermset.attlist-->]]>
<!--end of itermset.module-->]]>

<!-- ...................................................................... -->
<!-- Compound (section-ish) elements ...................................... -->

<!-- Message set ...................... -->

<!ENTITY % msgset.content.module "INCLUDE">
<![ %msgset.content.module; [
<!ENTITY % msgset.module "INCLUDE">
<![ %msgset.module; [
<!ENTITY % local.msgset.attrib "">
<!ENTITY % msgset.role.attrib "%role.attrib;">

<!ENTITY % msgset.element "INCLUDE">
<![ %msgset.element; [
<!ELEMENT MsgSet - - ((%formalobject.title.content;)?, (MsgEntry+|SimpleMsgEntry+))>
<!--end of msgset.element-->]]>

<!ENTITY % msgset.attlist "INCLUDE">
<![ %msgset.attlist; [
<!ATTLIST MsgSet
		%common.attrib;
		%msgset.role.attrib;
		%local.msgset.attrib;
>
<!--end of msgset.attlist-->]]>
<!--end of msgset.module-->]]>

<!ENTITY % msgentry.module "INCLUDE">
<![ %msgentry.module; [
<!ENTITY % local.msgentry.attrib "">
<!ENTITY % msgentry.role.attrib "%role.attrib;">

<!ENTITY % msgentry.element "INCLUDE">
<![ %msgentry.element; [
<!ELEMENT MsgEntry - O (Msg+, MsgInfo?, MsgExplan*)>
<!--end of msgentry.element-->]]>

<!ENTITY % msgentry.attlist "INCLUDE">
<![ %msgentry.attlist; [
<!ATTLIST MsgEntry
		%common.attrib;
		%msgentry.role.attrib;
		%local.msgentry.attrib;
>
<!--end of msgentry.attlist-->]]>
<!--end of msgentry.module-->]]>

<!ENTITY % simplemsgentry.module "INCLUDE">
<![ %simplemsgentry.module; [
<!ENTITY % local.simplemsgentry.attrib "">
<!ENTITY % simplemsgentry.role.attrib "%role.attrib;">

<!ENTITY % simplemsgentry.element "INCLUDE">
<![ %simplemsgentry.element; [
<!ELEMENT SimpleMsgEntry - O (MsgText, MsgExplan)>
<!--end of simplemsgentry.element-->]]>

<!ENTITY % simplemsgentry.attlist "INCLUDE">
<![ %simplemsgentry.attlist; [
<!ATTLIST SimpleMsgEntry
		%common.attrib;
		%simplemsgentry.role.attrib;
		%local.simplemsgentry.attrib;
		Audience	CDATA	#IMPLIED
		Level		CDATA	#IMPLIED
		Origin		CDATA	#IMPLIED
>
<!--end of simplemsgentry.attlist-->]]>
<!--end of simplemsgentry.module-->]]>

<!ENTITY % msg.module "INCLUDE">
<![ %msg.module; [
<!ENTITY % local.msg.attrib "">
<!ENTITY % msg.role.attrib "%role.attrib;">

<!ENTITY % msg.element "INCLUDE">
<![ %msg.element; [
<!ELEMENT Msg - O (Title?, MsgMain, (MsgSub | MsgRel)*)>
<!--end of msg.element-->]]>

<!ENTITY % msg.attlist "INCLUDE">
<![ %msg.attlist; [
<!ATTLIST Msg
		%common.attrib;
		%msg.role.attrib;
		%local.msg.attrib;
>
<!--end of msg.attlist-->]]>
<!--end of msg.module-->]]>

<!ENTITY % msgmain.module "INCLUDE">
<![ %msgmain.module; [
<!ENTITY % local.msgmain.attrib "">
<!ENTITY % msgmain.role.attrib "%role.attrib;">

<!ENTITY % msgmain.element "INCLUDE">
<![ %msgmain.element; [
<!ELEMENT MsgMain - - (Title?, MsgText)>
<!--end of msgmain.element-->]]>

<!ENTITY % msgmain.attlist "INCLUDE">
<![ %msgmain.attlist; [
<!ATTLIST MsgMain
		%common.attrib;
		%msgmain.role.attrib;
		%local.msgmain.attrib;
>
<!--end of msgmain.attlist-->]]>
<!--end of msgmain.module-->]]>

<!ENTITY % msgsub.module "INCLUDE">
<![ %msgsub.module; [
<!ENTITY % local.msgsub.attrib "">
<!ENTITY % msgsub.role.attrib "%role.attrib;">

<!ENTITY % msgsub.element "INCLUDE">
<![ %msgsub.element; [
<!ELEMENT MsgSub - - (Title?, MsgText)>
<!--end of msgsub.element-->]]>

<!ENTITY % msgsub.attlist "INCLUDE">
<![ %msgsub.attlist; [
<!ATTLIST MsgSub
		%common.attrib;
		%msgsub.role.attrib;
		%local.msgsub.attrib;
>
<!--end of msgsub.attlist-->]]>
<!--end of msgsub.module-->]]>

<!ENTITY % msgrel.module "INCLUDE">
<![ %msgrel.module; [
<!ENTITY % local.msgrel.attrib "">
<!ENTITY % msgrel.role.attrib "%role.attrib;">

<!ENTITY % msgrel.element "INCLUDE">
<![ %msgrel.element; [
<!ELEMENT MsgRel - - (Title?, MsgText)>
<!--end of msgrel.element-->]]>

<!ENTITY % msgrel.attlist "INCLUDE">
<![ %msgrel.attlist; [
<!ATTLIST MsgRel
		%common.attrib;
		%msgrel.role.attrib;
		%local.msgrel.attrib;
>
<!--end of msgrel.attlist-->]]>
<!--end of msgrel.module-->]]>

<!-- MsgText (defined in the Inlines section, below)-->

<!ENTITY % msginfo.module "INCLUDE">
<![ %msginfo.module; [
<!ENTITY % local.msginfo.attrib "">
<!ENTITY % msginfo.role.attrib "%role.attrib;">

<!ENTITY % msginfo.element "INCLUDE">
<![ %msginfo.element; [
<!ELEMENT MsgInfo - - ((MsgLevel | MsgOrig | MsgAud)*)>
<!--end of msginfo.element-->]]>

<!ENTITY % msginfo.attlist "INCLUDE">
<![ %msginfo.attlist; [
<!ATTLIST MsgInfo
		%common.attrib;
		%msginfo.role.attrib;
		%local.msginfo.attrib;
>
<!--end of msginfo.attlist-->]]>
<!--end of msginfo.module-->]]>

<!ENTITY % msglevel.module "INCLUDE">
<![ %msglevel.module; [
<!ENTITY % local.msglevel.attrib "">
<!ENTITY % msglevel.role.attrib "%role.attrib;">

<!ENTITY % msglevel.element "INCLUDE">
<![ %msglevel.element; [
<!ELEMENT MsgLevel - - ((%smallcptr.char.mix;)+)>
<!--end of msglevel.element-->]]>

<!ENTITY % msglevel.attlist "INCLUDE">
<![ %msglevel.attlist; [
<!ATTLIST MsgLevel
		%common.attrib;
		%msglevel.role.attrib;
		%local.msglevel.attrib;
>
<!--end of msglevel.attlist-->]]>
<!--end of msglevel.module-->]]>

<!ENTITY % msgorig.module "INCLUDE">
<![ %msgorig.module; [
<!ENTITY % local.msgorig.attrib "">
<!ENTITY % msgorig.role.attrib "%role.attrib;">

<!ENTITY % msgorig.element "INCLUDE">
<![ %msgorig.element; [
<!ELEMENT MsgOrig - - ((%smallcptr.char.mix;)+)>
<!--end of msgorig.element-->]]>

<!ENTITY % msgorig.attlist "INCLUDE">
<![ %msgorig.attlist; [
<!ATTLIST MsgOrig
		%common.attrib;
		%msgorig.role.attrib;
		%local.msgorig.attrib;
>
<!--end of msgorig.attlist-->]]>
<!--end of msgorig.module-->]]>

<!ENTITY % msgaud.module "INCLUDE">
<![ %msgaud.module; [
<!ENTITY % local.msgaud.attrib "">
<!ENTITY % msgaud.role.attrib "%role.attrib;">

<!ENTITY % msgaud.element "INCLUDE">
<![ %msgaud.element; [
<!ELEMENT MsgAud - - ((%para.char.mix;)+)>
<!--end of msgaud.element-->]]>

<!ENTITY % msgaud.attlist "INCLUDE">
<![ %msgaud.attlist; [
<!ATTLIST MsgAud
		%common.attrib;
		%msgaud.role.attrib;
		%local.msgaud.attrib;
>
<!--end of msgaud.attlist-->]]>
<!--end of msgaud.module-->]]>

<!ENTITY % msgexplan.module "INCLUDE">
<![ %msgexplan.module; [
<!ENTITY % local.msgexplan.attrib "">
<!ENTITY % msgexplan.role.attrib "%role.attrib;">

<!ENTITY % msgexplan.element "INCLUDE">
<![ %msgexplan.element; [
<!ELEMENT MsgExplan - - (Title?, (%component.mix;)+)>
<!--end of msgexplan.element-->]]>

<!ENTITY % msgexplan.attlist "INCLUDE">
<![ %msgexplan.attlist; [
<!ATTLIST MsgExplan
		%common.attrib;
		%msgexplan.role.attrib;
		%local.msgexplan.attrib;
>
<!--end of msgexplan.attlist-->]]>
<!--end of msgexplan.module-->]]>
<!--end of msgset.content.module-->]]>

<!-- QandASet ........................ -->
<!ENTITY % qandset.content.module "INCLUDE">
<![ %qandset.content.module; [
<!ENTITY % qandset.module "INCLUDE">
<![ %qandset.module; [
<!ENTITY % local.qandset.attrib "">
<!ENTITY % qandset.role.attrib "%role.attrib;">

<!ENTITY % qandset.element "INCLUDE">
<![ %qandset.element; [
<!ELEMENT QandASet - - ((%formalobject.title.content;)?,
			(%qandaset.mix;)*,
                        (QandADiv+|QandAEntry+))>
<!--end of qandset.element-->]]>

<!ENTITY % qandset.attlist "INCLUDE">
<![ %qandset.attlist; [
<!ATTLIST QandASet
		DefaultLabel	(qanda|number|none)       #IMPLIED
		%common.attrib;
		%qandset.role.attrib;
		%local.qandset.attrib;>
<!--end of qandset.attlist-->]]>
<!--end of qandset.module-->]]>

<!ENTITY % qandadiv.module "INCLUDE">
<![ %qandadiv.module; [
<!ENTITY % local.qandadiv.attrib "">
<!ENTITY % qandadiv.role.attrib "%role.attrib;">

<!ENTITY % qandadiv.element "INCLUDE">
<![ %qandadiv.element; [
<!ELEMENT QandADiv - - ((%formalobject.title.content;)?, 
			(%qandaset.mix;)*,
			(QandADiv+|QandAEntry+))>
<!--end of qandadiv.element-->]]>

<!ENTITY % qandadiv.attlist "INCLUDE">
<![ %qandadiv.attlist; [
<!ATTLIST QandADiv
		%common.attrib;
		%qandadiv.role.attrib;
		%local.qandadiv.attrib;>
<!--end of qandadiv.attlist-->]]>
<!--end of qandadiv.module-->]]>

<!ENTITY % qandaentry.module "INCLUDE">
<![ %qandaentry.module; [
<!ENTITY % local.qandaentry.attrib "">
<!ENTITY % qandaentry.role.attrib "%role.attrib;">

<!ENTITY % qandaentry.element "INCLUDE">
<![ %qandaentry.element; [
<!ELEMENT QandAEntry - - (RevHistory?, Question, Answer*)>
<!--end of qandaentry.element-->]]>

<!ENTITY % qandaentry.attlist "INCLUDE">
<![ %qandaentry.attlist; [
<!ATTLIST QandAEntry
		%common.attrib;
		%qandaentry.role.attrib;
		%local.qandaentry.attrib;>
<!--end of qandaentry.attlist-->]]>
<!--end of qandaentry.module-->]]>

<!ENTITY % question.module "INCLUDE">
<![ %question.module; [
<!ENTITY % local.question.attrib "">
<!ENTITY % question.role.attrib "%role.attrib;">

<!ENTITY % question.element "INCLUDE">
<![ %question.element; [
<!ELEMENT Question - - (Label?, (%qandaset.mix;)+)>
<!--end of question.element-->]]>

<!ENTITY % question.attlist "INCLUDE">
<![ %question.attlist; [
<!ATTLIST Question
		%common.attrib;
		%question.role.attrib;
		%local.question.attrib;
>
<!--end of question.attlist-->]]>
<!--end of question.module-->]]>

<!ENTITY % answer.module "INCLUDE">
<![ %answer.module; [
<!ENTITY % local.answer.attrib "">
<!ENTITY % answer.role.attrib "%role.attrib;">

<!ENTITY % answer.element "INCLUDE">
<![ %answer.element; [
<!ELEMENT Answer - - (Label?, (%qandaset.mix;)*, QandAEntry*)>
<!--end of answer.element-->]]>

<!ENTITY % answer.attlist "INCLUDE">
<![ %answer.attlist; [
<!ATTLIST Answer
		%common.attrib;
		%answer.role.attrib;
		%local.answer.attrib;
>
<!--end of answer.attlist-->]]>
<!--end of answer.module-->]]>

<!ENTITY % label.module "INCLUDE">
<![ %label.module; [
<!ENTITY % local.label.attrib "">
<!ENTITY % label.role.attrib "%role.attrib;">

<!ENTITY % label.element "INCLUDE">
<![ %label.element; [
<!ELEMENT Label - - (%word.char.mix;)*>
<!--end of label.element-->]]>

<!ENTITY % label.attlist "INCLUDE">
<![ %label.attlist; [
<!ATTLIST Label
		%common.attrib;
		%label.role.attrib;
		%local.label.attrib;
>
<!--end of label.attlist-->]]>
<!--end of label.module-->]]>
<!--end of qandset.content.module-->]]>

<!-- Procedure ........................ -->

<!ENTITY % procedure.content.module "INCLUDE">
<![ %procedure.content.module; [
<!ENTITY % procedure.module "INCLUDE">
<![ %procedure.module; [
<!ENTITY % local.procedure.attrib "">
<!ENTITY % procedure.role.attrib "%role.attrib;">

<!ENTITY % procedure.element "INCLUDE">
<![ %procedure.element; [
<!ELEMENT Procedure - - ((%formalobject.title.content;)?,
	(%component.mix;)*, Step+)>
<!--end of procedure.element-->]]>

<!ENTITY % procedure.attlist "INCLUDE">
<![ %procedure.attlist; [
<!ATTLIST Procedure
		%common.attrib;
		%procedure.role.attrib;
		%local.procedure.attrib;
>
<!--end of procedure.attlist-->]]>
<!--end of procedure.module-->]]>

<!ENTITY % step.module "INCLUDE">
<![ %step.module; [
<!ENTITY % local.step.attrib "">
<!ENTITY % step.role.attrib "%role.attrib;">

<!ENTITY % step.element "INCLUDE">
<![ %step.element; [
<!ELEMENT Step - O (Title?, (((%component.mix;)+, (SubSteps,
		(%component.mix;)*)?) | (SubSteps, (%component.mix;)*)))>
<!--end of step.element-->]]>

<!ENTITY % step.attlist "INCLUDE">
<![ %step.attlist; [
<!ATTLIST Step
		--
		Performance: Whether the Step must be performed
		--
		Performance	(Optional
				|Required)	Required -- not #REQUIRED! --
		%common.attrib;
		%step.role.attrib;
		%local.step.attrib;
>
<!--end of step.attlist-->]]>
<!--end of step.module-->]]>

<!ENTITY % substeps.module "INCLUDE">
<![ %substeps.module; [
<!ENTITY % local.substeps.attrib "">
<!ENTITY % substeps.role.attrib "%role.attrib;">

<!ENTITY % substeps.element "INCLUDE">
<![ %substeps.element; [
<!ELEMENT SubSteps - - (Step+)>
<!--end of substeps.element-->]]>

<!ENTITY % substeps.attlist "INCLUDE">
<![ %substeps.attlist; [
<!ATTLIST SubSteps
		--
		Performance: whether entire set of substeps must be performed
		--
		Performance	(Optional
				|Required)	Required -- not #REQUIRED! --
		%common.attrib;
		%substeps.role.attrib;
		%local.substeps.attrib;
>
<!--end of substeps.attlist-->]]>
<!--end of substeps.module-->]]>
<!--end of procedure.content.module-->]]>

<!-- Sidebar .......................... -->

<!ENTITY % sidebar.content.model "INCLUDE">
<![ %sidebar.content.model; [

<!ENTITY % sidebarinfo.module "INCLUDE">
<![ %sidebarinfo.module; [
<!ENTITY % local.sidebarinfo.attrib "">
<!ENTITY % sidebarinfo.role.attrib "%role.attrib;">

<!ENTITY % sidebarinfo.element "INCLUDE">
<![ %sidebarinfo.element; [
<!ELEMENT SidebarInfo - - ((Graphic | MediaObject | LegalNotice | ModeSpec 
	| SubjectSet | KeywordSet | ITermSet | %bibliocomponent.mix;)+)
	-(BeginPage)>
<!--end of sidebarinfo.element-->]]>

<!ENTITY % sidebarinfo.attlist "INCLUDE">
<![ %sidebarinfo.attlist; [
<!ATTLIST SidebarInfo
		%common.attrib;
		%sidebarinfo.role.attrib;
		%local.sidebarinfo.attrib;
>
<!--end of sidebarinfo.attlist-->]]>
<!--end of sidebarinfo.module-->]]>

<!ENTITY % sidebar.module "INCLUDE">
<![ %sidebar.module; [
<!ENTITY % local.sidebar.attrib "">
<!ENTITY % sidebar.role.attrib "%role.attrib;">

<!ENTITY % sidebar.element "INCLUDE">
<![ %sidebar.element; [
<!ELEMENT Sidebar - - (SidebarInfo?,
		       (%formalobject.title.content;)?, (%sidebar.mix;)+)>
<!--end of sidebar.element-->]]>

<!ENTITY % sidebar.attlist "INCLUDE">
<![ %sidebar.attlist; [
<!ATTLIST Sidebar
		%common.attrib;
		%sidebar.role.attrib;
		%local.sidebar.attrib;
>
<!--end of sidebar.attlist-->]]>
<!--end of sidebar.module-->]]>
<!--end of sidebar.content.model-->]]>

<!-- ...................................................................... -->
<!-- Paragraph-related elements ........................................... -->

<!ENTITY % abstract.module "INCLUDE">
<![ %abstract.module; [
<!ENTITY % local.abstract.attrib "">
<!ENTITY % abstract.role.attrib "%role.attrib;">

<!ENTITY % abstract.element "INCLUDE">
<![ %abstract.element; [
<!ELEMENT Abstract - - (Title?, (%para.class;)+)>
<!--end of abstract.element-->]]>

<!ENTITY % abstract.attlist "INCLUDE">
<![ %abstract.attlist; [
<!ATTLIST Abstract
		%common.attrib;
		%abstract.role.attrib;
		%local.abstract.attrib;
>
<!--end of abstract.attlist-->]]>
<!--end of abstract.module-->]]>

<!ENTITY % authorblurb.module "INCLUDE">
<![ %authorblurb.module; [
<!ENTITY % local.authorblurb.attrib "">
<!ENTITY % authorblurb.role.attrib "%role.attrib;">

<!ENTITY % authorblurb.element "INCLUDE">
<![ %authorblurb.element; [
<!ELEMENT AuthorBlurb - - (Title?, (%para.class;)+)>
<!--end of authorblurb.element-->]]>

<!ENTITY % authorblurb.attlist "INCLUDE">
<![ %authorblurb.attlist; [
<!ATTLIST AuthorBlurb
		%common.attrib;
		%authorblurb.role.attrib;
		%local.authorblurb.attrib;
>
<!--end of authorblurb.attlist-->]]>
<!--end of authorblurb.module-->]]>

<!ENTITY % blockquote.module "INCLUDE">
<![ %blockquote.module; [
<!ENTITY % local.blockquote.attrib "">
<!ENTITY % blockquote.role.attrib "%role.attrib;">

<!ENTITY % blockquote.element "INCLUDE">
<![ %blockquote.element; [
<!ELEMENT BlockQuote - - (Title?, Attribution?, (%component.mix;)+)
                         %blockquote.exclusion;>
<!--end of blockquote.element-->]]>

<!ENTITY % blockquote.attlist "INCLUDE">
<![ %blockquote.attlist; [
<!ATTLIST BlockQuote
		%common.attrib;
		%blockquote.role.attrib;
		%local.blockquote.attrib;
>
<!--end of blockquote.attlist-->]]>
<!--end of blockquote.module-->]]>

<!ENTITY % attribution.module "INCLUDE">
<![ %attribution.module; [
<!ENTITY % local.attribution.attrib "">
<!ENTITY % attribution.role.attrib "%role.attrib;">

<!ENTITY % attribution.element "INCLUDE">
<![ %attribution.element; [
<!ELEMENT Attribution - O ((%para.char.mix;)+)>
<!--end of attribution.element-->]]>

<!ENTITY % attribution.attlist "INCLUDE">
<![ %attribution.attlist; [
<!ATTLIST Attribution
		%common.attrib;
		%attribution.role.attrib;
		%local.attribution.attrib;
>
<!--end of attribution.attlist-->]]>
<!--end of attribution.module-->]]>

<!ENTITY % bridgehead.module "INCLUDE">
<![ %bridgehead.module; [
<!ENTITY % local.bridgehead.attrib "">
<!ENTITY % bridgehead.role.attrib "%role.attrib;">

<!ENTITY % bridgehead.element "INCLUDE">
<![ %bridgehead.element; [
<!ELEMENT BridgeHead - - ((%title.char.mix;)+)>
<!--end of bridgehead.element-->]]>

<!ENTITY % bridgehead.attlist "INCLUDE">
<![ %bridgehead.attlist; [
<!ATTLIST BridgeHead
		--
		Renderas: Indicates the format in which the BridgeHead
		should appear
		--
		Renderas	(Other
				|Sect1
				|Sect2
				|Sect3
				|Sect4
				|Sect5)		#IMPLIED
		%common.attrib;
		%bridgehead.role.attrib;
		%local.bridgehead.attrib;
>
<!--end of bridgehead.attlist-->]]>
<!--end of bridgehead.module-->]]>

<!ENTITY % remark.module "INCLUDE">
<![ %remark.module; [
<!ENTITY % local.remark.attrib "">
<!ENTITY % remark.role.attrib "%role.attrib;">

<!ENTITY % remark.element "INCLUDE">
<![ %remark.element; [
<!ELEMENT Remark - - ((%para.char.mix;)+) %remark.exclusion;>
<!--end of remark.element-->]]>

<!ENTITY % remark.attlist "INCLUDE">
<![ %remark.attlist; [
<!ATTLIST Remark
		%common.attrib;
		%remark.role.attrib;
		%local.remark.attrib;
>
<!--end of remark.attlist-->]]>
<!--end of remark.module-->]]>

<!ENTITY % epigraph.module "INCLUDE">
<![ %epigraph.module; [
<!ENTITY % local.epigraph.attrib "">
<!ENTITY % epigraph.role.attrib "%role.attrib;">

<!ENTITY % epigraph.element "INCLUDE">
<![ %epigraph.element; [
<!ELEMENT Epigraph - - (Attribution?, (%para.class;)+)>
<!--end of epigraph.element-->]]>

<!ENTITY % epigraph.attlist "INCLUDE">
<![ %epigraph.attlist; [
<!ATTLIST Epigraph
		%common.attrib;
		%epigraph.role.attrib;
		%local.epigraph.attrib;
>
<!--end of epigraph.attlist-->]]>
<!-- Attribution (defined above)-->
<!--end of epigraph.module-->]]>

<!ENTITY % footnote.module "INCLUDE">
<![ %footnote.module; [
<!ENTITY % local.footnote.attrib "">
<!ENTITY % footnote.role.attrib "%role.attrib;">

<!ENTITY % footnote.element "INCLUDE">
<![ %footnote.element; [
<!ELEMENT Footnote - - ((%footnote.mix;)+) %footnote.exclusion;>
<!--end of footnote.element-->]]>

<!ENTITY % footnote.attlist "INCLUDE">
<![ %footnote.attlist; [
<!ATTLIST Footnote
		%label.attrib;
		%common.attrib;
		%footnote.role.attrib;
		%local.footnote.attrib;
>
<!--end of footnote.attlist-->]]>
<!--end of footnote.module-->]]>

<!ENTITY % highlights.module "INCLUDE">
<![ %highlights.module; [
<!ENTITY % local.highlights.attrib "">
<!ENTITY % highlights.role.attrib "%role.attrib;">

<!ENTITY % highlights.element "INCLUDE">
<![ %highlights.element; [
<!ELEMENT Highlights - - ((%highlights.mix;)+) %highlights.exclusion;>
<!--end of highlights.element-->]]>

<!ENTITY % highlights.attlist "INCLUDE">
<![ %highlights.attlist; [
<!ATTLIST Highlights
		%common.attrib;
		%highlights.role.attrib;
		%local.highlights.attrib;
>
<!--end of highlights.attlist-->]]>
<!--end of highlights.module-->]]>

<!ENTITY % formalpara.module "INCLUDE">
<![ %formalpara.module; [
<!ENTITY % local.formalpara.attrib "">
<!ENTITY % formalpara.role.attrib "%role.attrib;">

<!ENTITY % formalpara.element "INCLUDE">
<![ %formalpara.element; [
<!ELEMENT FormalPara - O (Title, (%ndxterm.class;)*, Para)>
<!--end of formalpara.element-->]]>

<!ENTITY % formalpara.attlist "INCLUDE">
<![ %formalpara.attlist; [
<!ATTLIST FormalPara
		%common.attrib;
		%formalpara.role.attrib;
		%local.formalpara.attrib;
>
<!--end of formalpara.attlist-->]]>
<!--end of formalpara.module-->]]>

<!ENTITY % para.module "INCLUDE">
<![ %para.module; [
<!ENTITY % local.para.attrib "">
<!ENTITY % para.role.attrib "%role.attrib;">

<!ENTITY % para.element "INCLUDE">
<![ %para.element; [
<!ELEMENT Para - O ((%para.char.mix; | %para.mix;)+)>
<!--end of para.element-->]]>

<!ENTITY % para.attlist "INCLUDE">
<![ %para.attlist; [
<!ATTLIST Para
		%common.attrib;
		%para.role.attrib;
		%local.para.attrib;
>
<!--end of para.attlist-->]]>
<!--end of para.module-->]]>

<!ENTITY % simpara.module "INCLUDE">
<![ %simpara.module; [
<!ENTITY % local.simpara.attrib "">
<!ENTITY % simpara.role.attrib "%role.attrib;">

<!ENTITY % simpara.element "INCLUDE">
<![ %simpara.element; [
<!ELEMENT SimPara - O ((%para.char.mix;)+)>
<!--end of simpara.element-->]]>

<!ENTITY % simpara.attlist "INCLUDE">
<![ %simpara.attlist; [
<!ATTLIST SimPara
		%common.attrib;
		%simpara.role.attrib;
		%local.simpara.attrib;
>
<!--end of simpara.attlist-->]]>
<!--end of simpara.module-->]]>

<!ENTITY % admon.module "INCLUDE">
<![ %admon.module; [
<!ENTITY % local.admon.attrib "">
<!ENTITY % admon.role.attrib "%role.attrib;">

<!ENTITY % admon.elements "INCLUDE">
<![ %admon.elements; [
<!ELEMENT (%admon.class;) - - (Title?, (%admon.mix;)+) %admon.exclusion;>
<!--end of admon.elements-->]]>

<!ENTITY % admon.attlists "INCLUDE">
<![ %admon.attlists; [
<!ATTLIST (%admon.class;)
		%common.attrib;
		%admon.role.attrib;
		%local.admon.attrib;
>
<!--end of admon.attlists-->]]>
<!--end of admon.module-->]]>

<!-- ...................................................................... -->
<!-- Lists ................................................................ -->

<!-- GlossList ........................ -->

<!ENTITY % glosslist.module "INCLUDE">
<![ %glosslist.module; [
<!ENTITY % local.glosslist.attrib "">
<!ENTITY % glosslist.role.attrib "%role.attrib;">

<!ENTITY % glosslist.element "INCLUDE">
<![ %glosslist.element; [
<!ELEMENT GlossList - - (GlossEntry+)>
<!--end of glosslist.element-->]]>

<!ENTITY % glosslist.attlist "INCLUDE">
<![ %glosslist.attlist; [
<!ATTLIST GlossList
		%common.attrib;
		%glosslist.role.attrib;
		%local.glosslist.attrib;
>
<!--end of glosslist.attlist-->]]>
<!--end of glosslist.module-->]]>

<!ENTITY % glossentry.content.module "INCLUDE">
<![ %glossentry.content.module; [
<!ENTITY % glossentry.module "INCLUDE">
<![ %glossentry.module; [
<!ENTITY % local.glossentry.attrib "">
<!ENTITY % glossentry.role.attrib "%role.attrib;">

<!ENTITY % glossentry.element "INCLUDE">
<![ %glossentry.element; [
<!ELEMENT GlossEntry - O (GlossTerm, Acronym?, Abbrev?,
			  (%ndxterm.class;)*,
			  RevHistory?, (GlossSee|GlossDef+))>
<!--end of glossentry.element-->]]>

<!ENTITY % glossentry.attlist "INCLUDE">
<![ %glossentry.attlist; [
<!ATTLIST GlossEntry
		--
		SortAs: String by which the GlossEntry is to be sorted
		(alphabetized) in lieu of its proper content
		--
		SortAs		CDATA		#IMPLIED
		%common.attrib;
		%glossentry.role.attrib;
		%local.glossentry.attrib;
>
<!--end of glossentry.attlist-->]]>
<!--end of glossentry.module-->]]>

<!-- GlossTerm (defined in the Inlines section, below)-->
<!ENTITY % glossdef.module "INCLUDE">
<![ %glossdef.module; [
<!ENTITY % local.glossdef.attrib "">
<!ENTITY % glossdef.role.attrib "%role.attrib;">

<!ENTITY % glossdef.element "INCLUDE">
<![ %glossdef.element; [
<!ELEMENT GlossDef - O ((%glossdef.mix;)+, GlossSeeAlso*)>
<!--end of glossdef.element-->]]>

<!ENTITY % glossdef.attlist "INCLUDE">
<![ %glossdef.attlist; [
<!ATTLIST GlossDef
		--
		Subject: List of subjects; keywords for the definition
		--
		Subject		CDATA		#IMPLIED
		%common.attrib;
		%glossdef.role.attrib;
		%local.glossdef.attrib;
>
<!--end of glossdef.attlist-->]]>
<!--end of glossdef.module-->]]>

<!ENTITY % glosssee.module "INCLUDE">
<![ %glosssee.module; [
<!ENTITY % local.glosssee.attrib "">
<!ENTITY % glosssee.role.attrib "%role.attrib;">

<!ENTITY % glosssee.element "INCLUDE">
<![ %glosssee.element; [
<!ELEMENT GlossSee - O ((%para.char.mix;)+)>
<!--end of glosssee.element-->]]>

<!ENTITY % glosssee.attlist "INCLUDE">
<![ %glosssee.attlist; [
<!ATTLIST GlossSee
		--
		OtherTerm: Reference to the GlossEntry whose GlossTerm
		should be displayed at the point of the GlossSee
		--
		OtherTerm	IDREF		#CONREF
		%common.attrib;
		%glosssee.role.attrib;
		%local.glosssee.attrib;
>
<!--end of glosssee.attlist-->]]>
<!--end of glosssee.module-->]]>

<!ENTITY % glossseealso.module "INCLUDE">
<![ %glossseealso.module; [
<!ENTITY % local.glossseealso.attrib "">
<!ENTITY % glossseealso.role.attrib "%role.attrib;">

<!ENTITY % glossseealso.element "INCLUDE">
<![ %glossseealso.element; [
<!ELEMENT GlossSeeAlso - O ((%para.char.mix;)+)>
<!--end of glossseealso.element-->]]>

<!ENTITY % glossseealso.attlist "INCLUDE">
<![ %glossseealso.attlist; [
<!ATTLIST GlossSeeAlso
		--
		OtherTerm: Reference to the GlossEntry whose GlossTerm
		should be displayed at the point of the GlossSeeAlso
		--
		OtherTerm	IDREF		#CONREF
		%common.attrib;
		%glossseealso.role.attrib;
		%local.glossseealso.attrib;
>
<!--end of glossseealso.attlist-->]]>
<!--end of glossseealso.module-->]]>
<!--end of glossentry.content.module-->]]>

<!-- ItemizedList and OrderedList ..... -->

<!ENTITY % itemizedlist.module "INCLUDE">
<![ %itemizedlist.module; [
<!ENTITY % local.itemizedlist.attrib "">
<!ENTITY % itemizedlist.role.attrib "%role.attrib;">

<!ENTITY % itemizedlist.element "INCLUDE">
<![ %itemizedlist.element; [
<!ELEMENT ItemizedList - - ((%formalobject.title.content;)?, ListItem+)>
<!--end of itemizedlist.element-->]]>

<!ENTITY % itemizedlist.attlist "INCLUDE">
<![ %itemizedlist.attlist; [
<!ATTLIST ItemizedList	
		--
		Spacing: Whether the vertical space in the list should be
		compressed
		--
		Spacing		(Normal
				|Compact)	#IMPLIED
		--
		Mark: Keyword, e.g., bullet, dash, checkbox, none;
		list of keywords and defaults are implementation specific
		--
		%mark.attrib;
		%common.attrib;
		%itemizedlist.role.attrib;
		%local.itemizedlist.attrib;
>
<!--end of itemizedlist.attlist-->]]>
<!--end of itemizedlist.module-->]]>

<!ENTITY % orderedlist.module "INCLUDE">
<![ %orderedlist.module; [
<!ENTITY % local.orderedlist.attrib "">
<!ENTITY % orderedlist.role.attrib "%role.attrib;">

<!ENTITY % orderedlist.element "INCLUDE">
<![ %orderedlist.element; [
<!ELEMENT OrderedList - - ((%formalobject.title.content;)?, ListItem+)>
<!--end of orderedlist.element-->]]>

<!ENTITY % orderedlist.attlist "INCLUDE">
<![ %orderedlist.attlist; [
<!ATTLIST OrderedList
		--
		Numeration: Style of ListItem numbered; default is expected
		to be Arabic
		--
		Numeration	(Arabic
				|Upperalpha
				|Loweralpha
				|Upperroman
				|Lowerroman)	#IMPLIED
		--
		InheritNum: Specifies for a nested list that the numbering
		of ListItems should include the number of the item
		within which they are nested (e.g., 1a and 1b within 1,
		rather than a and b)--
		InheritNum	(Inherit
				|Ignore)	Ignore
		--
		Continuation: Where list numbering begins afresh (Restarts,
		the default) or continues that of the immediately preceding 
		list (Continues)
		--
		Continuation	(Continues
				|Restarts)	Restarts
		--
		Spacing: Whether the vertical space in the list should be
		compressed
		--
		Spacing		(Normal
				|Compact)	#IMPLIED
		%common.attrib;
		%orderedlist.role.attrib;
		%local.orderedlist.attrib;
>
<!--end of orderedlist.attlist-->]]>
<!--end of orderedlist.module-->]]>

<!ENTITY % listitem.module "INCLUDE">
<![ %listitem.module; [
<!ENTITY % local.listitem.attrib "">
<!ENTITY % listitem.role.attrib "%role.attrib;">

<!ENTITY % listitem.element "INCLUDE">
<![ %listitem.element; [
<!ELEMENT ListItem - O ((%component.mix;)+)>
<!--end of listitem.element-->]]>

<!ENTITY % listitem.attlist "INCLUDE">
<![ %listitem.attlist; [
<!ATTLIST ListItem
		--
		Override: Indicates the mark to be used for this ListItem
		instead of the default mark or the mark specified by
		the Mark attribute on the enclosing ItemizedList
		--
		Override	CDATA		#IMPLIED
		%common.attrib;
		%listitem.role.attrib;
		%local.listitem.attrib;
>
<!--end of listitem.attlist-->]]>
<!--end of listitem.module-->]]>

<!-- SegmentedList .................... -->
<!ENTITY % segmentedlist.content.module "INCLUDE">
<![ %segmentedlist.content.module; [
<!ENTITY % segmentedlist.module "INCLUDE">
<![ %segmentedlist.module; [
<!ENTITY % local.segmentedlist.attrib "">
<!ENTITY % segmentedlist.role.attrib "%role.attrib;">

<!ENTITY % segmentedlist.element "INCLUDE">
<![ %segmentedlist.element; [
<!ELEMENT SegmentedList - - ((%formalobject.title.content;)?, 
                             SegTitle, SegTitle+,
                             SegListItem+)>
<!--end of segmentedlist.element-->]]>

<!ENTITY % segmentedlist.attlist "INCLUDE">
<![ %segmentedlist.attlist; [
<!ATTLIST SegmentedList
		%common.attrib;
		%segmentedlist.role.attrib;
		%local.segmentedlist.attrib;
>
<!--end of segmentedlist.attlist-->]]>
<!--end of segmentedlist.module-->]]>

<!ENTITY % segtitle.module "INCLUDE">
<![ %segtitle.module; [
<!ENTITY % local.segtitle.attrib "">
<!ENTITY % segtitle.role.attrib "%role.attrib;">

<!ENTITY % segtitle.element "INCLUDE">
<![ %segtitle.element; [
<!ELEMENT SegTitle - O ((%title.char.mix;)+)>
<!--end of segtitle.element-->]]>

<!ENTITY % segtitle.attlist "INCLUDE">
<![ %segtitle.attlist; [
<!ATTLIST SegTitle
		%common.attrib;
		%segtitle.role.attrib;
		%local.segtitle.attrib;
>
<!--end of segtitle.attlist-->]]>
<!--end of segtitle.module-->]]>

<!ENTITY % seglistitem.module "INCLUDE">
<![ %seglistitem.module; [
<!ENTITY % local.seglistitem.attrib "">
<!ENTITY % seglistitem.role.attrib "%role.attrib;">

<!ENTITY % seglistitem.element "INCLUDE">
<![ %seglistitem.element; [
<!ELEMENT SegListItem - O (Seg, Seg+)>
<!--end of seglistitem.element-->]]>

<!ENTITY % seglistitem.attlist "INCLUDE">
<![ %seglistitem.attlist; [
<!ATTLIST SegListItem
		%common.attrib;
		%seglistitem.role.attrib;
		%local.seglistitem.attrib;
>
<!--end of seglistitem.attlist-->]]>
<!--end of seglistitem.module-->]]>

<!ENTITY % seg.module "INCLUDE">
<![ %seg.module; [
<!ENTITY % local.seg.attrib "">
<!ENTITY % seg.role.attrib "%role.attrib;">

<!ENTITY % seg.element "INCLUDE">
<![ %seg.element; [
<!ELEMENT Seg - O ((%para.char.mix;)+)>
<!--end of seg.element-->]]>

<!ENTITY % seg.attlist "INCLUDE">
<![ %seg.attlist; [
<!ATTLIST Seg
		%common.attrib;
		%seg.role.attrib;
		%local.seg.attrib;
>
<!--end of seg.attlist-->]]>
<!--end of seg.module-->]]>
<!--end of segmentedlist.content.module-->]]>

<!-- SimpleList ....................... -->

<!ENTITY % simplelist.content.module "INCLUDE">
<![ %simplelist.content.module; [
<!ENTITY % simplelist.module "INCLUDE">
<![ %simplelist.module; [
<!ENTITY % local.simplelist.attrib "">
<!ENTITY % simplelist.role.attrib "%role.attrib;">

<!ENTITY % simplelist.element "INCLUDE">
<![ %simplelist.element; [
<!ELEMENT SimpleList - - (Member+)>
<!--end of simplelist.element-->]]>

<!ENTITY % simplelist.attlist "INCLUDE">
<![ %simplelist.attlist; [
<!ATTLIST SimpleList
		--
		Columns: The number of columns the array should contain
		--
		Columns		NUMBER		#IMPLIED
		--
		Type: How the Members of the SimpleList should be
		formatted: Inline (members separated with commas etc.
		inline), Vert (top to bottom in n Columns), or Horiz (in
		the direction of text flow) in n Columns.  If Column
		is 1 or implied, Type=Vert and Type=Horiz give the same
		results.
		--
		Type		(Inline
				|Vert
				|Horiz)		Vert
		%common.attrib;
		%simplelist.role.attrib;
		%local.simplelist.attrib;
>
<!--end of simplelist.attlist-->]]>
<!--end of simplelist.module-->]]>

<!ENTITY % member.module "INCLUDE">
<![ %member.module; [
<!ENTITY % local.member.attrib "">
<!ENTITY % member.role.attrib "%role.attrib;">

<!ENTITY % member.element "INCLUDE">
<![ %member.element; [
<!ELEMENT Member - O ((%para.char.mix;)+)>
<!--end of member.element-->]]>

<!ENTITY % member.attlist "INCLUDE">
<![ %member.attlist; [
<!ATTLIST Member
		%common.attrib;
		%member.role.attrib;
		%local.member.attrib;
>
<!--end of member.attlist-->]]>
<!--end of member.module-->]]>
<!--end of simplelist.content.module-->]]>

<!-- VariableList ..................... -->

<!ENTITY % variablelist.content.module "INCLUDE">
<![ %variablelist.content.module; [
<!ENTITY % variablelist.module "INCLUDE">
<![ %variablelist.module; [
<!ENTITY % local.variablelist.attrib "">
<!ENTITY % variablelist.role.attrib "%role.attrib;">

<!ENTITY % variablelist.element "INCLUDE">
<![ %variablelist.element; [
<!ELEMENT VariableList - - ((%formalobject.title.content;)?, VarListEntry+)>
<!--end of variablelist.element-->]]>

<!ENTITY % variablelist.attlist "INCLUDE">
<![ %variablelist.attlist; [
<!ATTLIST VariableList
		--
		TermLength: Length beyond which the presentation engine
		may consider the Term too long and select an alternate
		presentation of the Term and, or, its associated ListItem.
		--
		TermLength	CDATA		#IMPLIED
		%common.attrib;
		%variablelist.role.attrib;
		%local.variablelist.attrib;
>
<!--end of variablelist.attlist-->]]>
<!--end of variablelist.module-->]]>

<!ENTITY % varlistentry.module "INCLUDE">
<![ %varlistentry.module; [
<!ENTITY % local.varlistentry.attrib "">
<!ENTITY % varlistentry.role.attrib "%role.attrib;">

<!ENTITY % varlistentry.element "INCLUDE">
<![ %varlistentry.element; [
<!ELEMENT VarListEntry - O (Term+, ListItem)>
<!--end of varlistentry.element-->]]>

<!ENTITY % varlistentry.attlist "INCLUDE">
<![ %varlistentry.attlist; [
<!ATTLIST VarListEntry
		%common.attrib;
		%varlistentry.role.attrib;
		%local.varlistentry.attrib;
>
<!--end of varlistentry.attlist-->]]>
<!--end of varlistentry.module-->]]>

<!ENTITY % term.module "INCLUDE">
<![ %term.module; [
<!ENTITY % local.term.attrib "">
<!ENTITY % term.role.attrib "%role.attrib;">

<!ENTITY % term.element "INCLUDE">
<![ %term.element; [
<!ELEMENT Term - O ((%para.char.mix;)+)>
<!--end of term.element-->]]>

<!ENTITY % term.attlist "INCLUDE">
<![ %term.attlist; [
<!ATTLIST Term
		%common.attrib;
		%term.role.attrib;
		%local.term.attrib;
>
<!--end of term.attlist-->]]>
<!--end of term.module-->]]>

<!-- ListItem (defined above)-->
<!--end of variablelist.content.module-->]]>

<!-- CalloutList ...................... -->

<!ENTITY % calloutlist.content.module "INCLUDE">
<![ %calloutlist.content.module; [
<!ENTITY % calloutlist.module "INCLUDE">
<![ %calloutlist.module; [
<!ENTITY % local.calloutlist.attrib "">
<!ENTITY % calloutlist.role.attrib "%role.attrib;">

<!ENTITY % calloutlist.element "INCLUDE">
<![ %calloutlist.element; [
<!ELEMENT CalloutList - - ((%formalobject.title.content;)?, Callout+)>
<!--end of calloutlist.element-->]]>

<!ENTITY % calloutlist.attlist "INCLUDE">
<![ %calloutlist.attlist; [
<!ATTLIST CalloutList
		%common.attrib;
		%calloutlist.role.attrib;
		%local.calloutlist.attrib;
>
<!--end of calloutlist.attlist-->]]>
<!--end of calloutlist.module-->]]>

<!ENTITY % callout.module "INCLUDE">
<![ %callout.module; [
<!ENTITY % local.callout.attrib "">
<!ENTITY % callout.role.attrib "%role.attrib;">

<!ENTITY % callout.element "INCLUDE">
<![ %callout.element; [
<!ELEMENT Callout - O ((%component.mix;)+)>
<!--end of callout.element-->]]>

<!ENTITY % callout.attlist "INCLUDE">
<![ %callout.attlist; [
<!ATTLIST Callout
		--
		AreaRefs: IDs of one or more Areas or AreaSets described
		by this Callout
		--
		AreaRefs	IDREFS		#REQUIRED
		%common.attrib;
		%callout.role.attrib;
		%local.callout.attrib;
>
<!--end of callout.attlist-->]]>
<!--end of callout.module-->]]>
<!--end of calloutlist.content.module-->]]>

<!-- ...................................................................... -->
<!-- Objects .............................................................. -->

<!-- Examples etc. .................... -->

<!ENTITY % example.module "INCLUDE">
<![ %example.module; [
<!ENTITY % local.example.attrib "">
<!ENTITY % example.role.attrib "%role.attrib;">

<!ENTITY % example.element "INCLUDE">
<![ %example.element; [
<!ELEMENT Example - - ((%formalobject.title.content;), (%example.mix;)+)
		%formal.exclusion;>
<!--end of example.element-->]]>

<!ENTITY % example.attlist "INCLUDE">
<![ %example.attlist; [
<!ATTLIST Example
		%label.attrib;
		%width.attrib;
		%common.attrib;
		%example.role.attrib;
		%local.example.attrib;
>
<!--end of example.attlist-->]]>
<!--end of example.module-->]]>

<!ENTITY % informalexample.module "INCLUDE">
<![ %informalexample.module; [
<!ENTITY % local.informalexample.attrib "">
<!ENTITY % informalexample.role.attrib "%role.attrib;">

<!ENTITY % informalexample.element "INCLUDE">
<![ %informalexample.element; [
<!ELEMENT InformalExample - - ((%example.mix;)+)>
<!--end of informalexample.element-->]]>

<!ENTITY % informalexample.attlist "INCLUDE">
<![ %informalexample.attlist; [
<!ATTLIST InformalExample
		%width.attrib;
		%common.attrib;
		%informalexample.role.attrib;
		%local.informalexample.attrib;
>
<!--end of informalexample.attlist-->]]>
<!--end of informalexample.module-->]]>

<!ENTITY % programlistingco.module "INCLUDE">
<![ %programlistingco.module; [
<!ENTITY % local.programlistingco.attrib "">
<!ENTITY % programlistingco.role.attrib "%role.attrib;">

<!ENTITY % programlistingco.element "INCLUDE">
<![ %programlistingco.element; [
<!ELEMENT ProgramListingCO - - (AreaSpec, ProgramListing, CalloutList*)>
<!--end of programlistingco.element-->]]>

<!ENTITY % programlistingco.attlist "INCLUDE">
<![ %programlistingco.attlist; [
<!ATTLIST ProgramListingCO
		%common.attrib;
		%programlistingco.role.attrib;
		%local.programlistingco.attrib;
>
<!--end of programlistingco.attlist-->]]>
<!-- CalloutList (defined above in Lists)-->
<!--end of programlistingco.module-->]]>

<!ENTITY % areaspec.content.module "INCLUDE">
<![ %areaspec.content.module; [
<!ENTITY % areaspec.module "INCLUDE">
<![ %areaspec.module; [
<!ENTITY % local.areaspec.attrib "">
<!ENTITY % areaspec.role.attrib "%role.attrib;">

<!ENTITY % areaspec.element "INCLUDE">
<![ %areaspec.element; [
<!ELEMENT AreaSpec - - ((Area|AreaSet)+)>
<!--end of areaspec.element-->]]>

<!ENTITY % areaspec.attlist "INCLUDE">
<![ %areaspec.attlist; [
<!ATTLIST AreaSpec
		--
		Units: global unit of measure in which coordinates in
		this spec are expressed:

		- CALSPair "x1,y1 x2,y2": lower-left and upper-right 
		coordinates in a rectangle describing repro area in which 
		graphic is placed, where X and Y dimensions are each some 
		number 0..10000 (taken from CALS graphic attributes)

		- LineColumn "line column": line number and column number
		at which to start callout text in "linespecific" content

		- LineRange "startline endline": whole lines from startline
		to endline in "linespecific" content

		- LineColumnPair "line1 col1 line2 col2": starting and ending
		points of area in "linespecific" content that starts at
		first position and ends at second position (including the
		beginnings of any intervening lines)

		- Other: directive to look at value of OtherUnits attribute
		to get implementation-specific keyword

		The default is implementation-specific; usually dependent on 
		the parent element (GraphicCO gets CALSPair, ProgramListingCO
		and ScreenCO get LineColumn)
		--
		Units		(CALSPair
				|LineColumn
				|LineRange
				|LineColumnPair
				|Other)		#IMPLIED
		--
		OtherUnits: User-defined units
		--
		OtherUnits	NAME		#IMPLIED
		%common.attrib;
		%areaspec.role.attrib;
		%local.areaspec.attrib;
>
<!--end of areaspec.attlist-->]]>
<!--end of areaspec.module-->]]>

<!ENTITY % area.module "INCLUDE">
<![ %area.module; [
<!ENTITY % local.area.attrib "">
<!ENTITY % area.role.attrib "%role.attrib;">

<!ENTITY % area.element "INCLUDE">
<![ %area.element; [
<!ELEMENT Area - O EMPTY>
<!--end of area.element-->]]>

<!ENTITY % area.attlist "INCLUDE">
<![ %area.attlist; [
<!ATTLIST Area
		%label.attrib; --bug number/symbol override or initialization--
		%linkends.attrib; --to any related information--
		--
		Units: unit of measure in which coordinates in this
		area are expressed; inherits from AreaSet and AreaSpec
		--
		Units		(CALSPair
				|LineColumn
				|LineRange
				|LineColumnPair
				|Other)		#IMPLIED
		--
		OtherUnits: User-defined units
		--
		OtherUnits	NAME		#IMPLIED
		Coords		CDATA		#REQUIRED
		%idreq.common.attrib;
		%area.role.attrib;
		%local.area.attrib;
>
<!--end of area.attlist-->]]>
<!--end of area.module-->]]>

<!ENTITY % areaset.module "INCLUDE">
<![ %areaset.module; [
<!ENTITY % local.areaset.attrib "">
<!ENTITY % areaset.role.attrib "%role.attrib;">

<!ENTITY % areaset.element "INCLUDE">
<![ %areaset.element; [
<!ELEMENT AreaSet - - (Area+)>
<!--end of areaset.element-->]]>

<!ENTITY % areaset.attlist "INCLUDE">
<![ %areaset.attlist; [
<!--FUTURE USE (V5.0):
......................
Coord attribute will be removed from AreaSet
......................
-->
<!ATTLIST AreaSet
		%label.attrib; --bug number/symbol override or initialization--

		--
		Units: unit of measure in which coordinates in this
		area are expressed; inherits from AreaSpec
		--
		Units		(CALSPair
				|LineColumn
				|LineRange
				|LineColumnPair
				|Other)		#IMPLIED
		OtherUnits	NAME		#IMPLIED
		Coords		CDATA		#REQUIRED
		%idreq.common.attrib;
		%areaset.role.attrib;
		%local.areaset.attrib;
>
<!--end of areaset.attlist-->]]>
<!--end of areaset.module-->]]>
<!--end of areaspec.content.module-->]]>

<!ENTITY % programlisting.module "INCLUDE">
<![ %programlisting.module; [
<!ENTITY % local.programlisting.attrib "">
<!ENTITY % programlisting.role.attrib "%role.attrib;">

<!ENTITY % programlisting.element "INCLUDE">
<![ %programlisting.element; [
<!ELEMENT ProgramListing - - ((CO | LineAnnotation | %para.char.mix;)+)>
<!--end of programlisting.element-->]]>

<!ENTITY % programlisting.attlist "INCLUDE">
<![ %programlisting.attlist; [
<!ATTLIST ProgramListing
		%width.attrib;
		%linespecific.attrib;
		%common.attrib;
		%programlisting.role.attrib;
		%local.programlisting.attrib;
>
<!--end of programlisting.attlist-->]]>
<!--end of programlisting.module-->]]>

<!ENTITY % literallayout.module "INCLUDE">
<![ %literallayout.module; [
<!ENTITY % local.literallayout.attrib "">
<!ENTITY % literallayout.role.attrib "%role.attrib;">

<!ENTITY % literallayout.element "INCLUDE">
<![ %literallayout.element; [
<!ELEMENT LiteralLayout - - ((CO | LineAnnotation | %para.char.mix;)+)>
<!--end of literallayout.element-->]]>

<!ENTITY % literallayout.attlist "INCLUDE">
<![ %literallayout.attlist; [
<!ATTLIST LiteralLayout
		%width.attrib;
		%linespecific.attrib;
		Class	(Monospaced|Normal)	"Normal"
		%common.attrib;
		%literallayout.role.attrib;
		%local.literallayout.attrib;
>
<!--end of literallayout.attlist-->]]>
<!-- LineAnnotation (defined in the Inlines section, below)-->
<!--end of literallayout.module-->]]>

<!ENTITY % screenco.module "INCLUDE">
<![ %screenco.module; [
<!ENTITY % local.screenco.attrib "">
<!ENTITY % screenco.role.attrib "%role.attrib;">

<!ENTITY % screenco.element "INCLUDE">
<![ %screenco.element; [
<!ELEMENT ScreenCO - - (AreaSpec, Screen, CalloutList*)>
<!--end of screenco.element-->]]>

<!ENTITY % screenco.attlist "INCLUDE">
<![ %screenco.attlist; [
<!ATTLIST ScreenCO
		%common.attrib;
		%screenco.role.attrib;
		%local.screenco.attrib;
>
<!--end of screenco.attlist-->]]>
<!-- AreaSpec (defined above)-->
<!-- CalloutList (defined above in Lists)-->
<!--end of screenco.module-->]]>

<!ENTITY % screen.module "INCLUDE">
<![ %screen.module; [
<!ENTITY % local.screen.attrib "">
<!ENTITY % screen.role.attrib "%role.attrib;">

<!ENTITY % screen.element "INCLUDE">
<![ %screen.element; [
<!ELEMENT Screen - - ((CO | LineAnnotation | %para.char.mix;)+)>
<!--end of screen.element-->]]>

<!ENTITY % screen.attlist "INCLUDE">
<![ %screen.attlist; [
<!ATTLIST Screen
		%width.attrib;
		%linespecific.attrib;
		%common.attrib;
		%screen.role.attrib;
		%local.screen.attrib;
>
<!--end of screen.attlist-->]]>
<!--end of screen.module-->]]>

<!ENTITY % screenshot.content.module "INCLUDE">
<![ %screenshot.content.module; [
<!ENTITY % screenshot.module "INCLUDE">
<![ %screenshot.module; [
<!ENTITY % local.screenshot.attrib "">
<!ENTITY % screenshot.role.attrib "%role.attrib;">

<!ENTITY % screenshot.element "INCLUDE">
<![ %screenshot.element; [
<!ELEMENT ScreenShot - - (ScreenInfo?, 
		(Graphic|GraphicCO
		|MediaObject|MediaObjectCO))>
<!--end of screenshot.element-->]]>

<!ENTITY % screenshot.attlist "INCLUDE">
<![ %screenshot.attlist; [
<!ATTLIST ScreenShot
		%common.attrib;
		%screenshot.role.attrib;
		%local.screenshot.attrib;
>
<!--end of screenshot.attlist-->]]>
<!--end of screenshot.module-->]]>

<!ENTITY % screeninfo.module "INCLUDE">
<![ %screeninfo.module; [
<!ENTITY % local.screeninfo.attrib "">
<!ENTITY % screeninfo.role.attrib "%role.attrib;">

<!ENTITY % screeninfo.element "INCLUDE">
<![ %screeninfo.element; [
<!ELEMENT ScreenInfo - O ((%para.char.mix;)+) %ubiq.exclusion;>
<!--end of screeninfo.element-->]]>

<!ENTITY % screeninfo.attlist "INCLUDE">
<![ %screeninfo.attlist; [
<!ATTLIST ScreenInfo
		%common.attrib;
		%screeninfo.role.attrib;
		%local.screeninfo.attrib;
>
<!--end of screeninfo.attlist-->]]>
<!--end of screeninfo.module-->]]>
<!--end of screenshot.content.module-->]]>

<!-- Figures etc. ..................... -->

<!ENTITY % figure.module "INCLUDE">
<![ %figure.module; [
<!ENTITY % local.figure.attrib "">
<!ENTITY % figure.role.attrib "%role.attrib;">

<!ENTITY % figure.element "INCLUDE">
<![ %figure.element; [
<!ELEMENT Figure - - ((%formalobject.title.content;), (%figure.mix; |
		%link.char.class;)+)>
<!--end of figure.element-->]]>

<!ENTITY % figure.attlist "INCLUDE">
<![ %figure.attlist; [
<!ATTLIST Figure
		--
		Float: Whether the Figure is supposed to be rendered
		where convenient (yes (1) value) or at the place it occurs
		in the text (no (0) value, the default)
		--
		Float		%yesorno.attvals;	%no.attval;
		PgWide      	%yesorno.attvals;       #IMPLIED
		%label.attrib;
		%common.attrib;
		%figure.role.attrib;
		%local.figure.attrib;
>
<!--end of figure.attlist-->]]>
<!--end of figure.module-->]]>

<!ENTITY % informalfigure.module "INCLUDE">
<![ %informalfigure.module; [
<!ENTITY % local.informalfigure.attrib "">
<!ENTITY % informalfigure.role.attrib "%role.attrib;">

<!ENTITY % informalfigure.element "INCLUDE">
<![ %informalfigure.element; [
<!ELEMENT InformalFigure - - ((%figure.mix; | %link.char.class;)+)>
<!--end of informalfigure.element-->]]>

<!ENTITY % informalfigure.attlist "INCLUDE">
<![ %informalfigure.attlist; [
<!ATTLIST InformalFigure
		--
		Float: Whether the Figure is supposed to be rendered
		where convenient (yes (1) value) or at the place it occurs
		in the text (no (0) value, the default)
		--
		Float		%yesorno.attvals;	%no.attval;
		PgWide      	%yesorno.attvals;       #IMPLIED
		%label.attrib;
		%common.attrib;
		%informalfigure.role.attrib;
		%local.informalfigure.attrib;
>
<!--end of informalfigure.attlist-->]]>
<!--end of informalfigure.module-->]]>

<!ENTITY % graphicco.module "INCLUDE">
<![ %graphicco.module; [
<!ENTITY % local.graphicco.attrib "">
<!ENTITY % graphicco.role.attrib "%role.attrib;">

<!ENTITY % graphicco.element "INCLUDE">
<![ %graphicco.element; [
<!ELEMENT GraphicCO - - (AreaSpec, Graphic, CalloutList*)>
<!--end of graphicco.element-->]]>

<!ENTITY % graphicco.attlist "INCLUDE">
<![ %graphicco.attlist; [
<!ATTLIST GraphicCO
		%common.attrib;
		%graphicco.role.attrib;
		%local.graphicco.attrib;
>
<!--end of graphicco.attlist-->]]>
<!-- AreaSpec (defined above in Examples)-->
<!-- CalloutList (defined above in Lists)-->
<!--end of graphicco.module-->]]>

<!-- Graphical data can be the content of Graphic, or you can reference
     an external file either as an entity (Entitref) or a filename
     (Fileref). -->

<!ENTITY % graphic.module "INCLUDE">
<![ %graphic.module; [
<!ENTITY % local.graphic.attrib "">
<!ENTITY % graphic.role.attrib "%role.attrib;">

<!ENTITY % graphic.element "INCLUDE">
<![ %graphic.element; [
<!ELEMENT Graphic - O EMPTY>
<!--end of graphic.element-->]]>

<!ENTITY % graphic.attlist "INCLUDE">
<![ %graphic.attlist; [
<!ATTLIST Graphic
		%graphics.attrib;
		%common.attrib;
		%graphic.role.attrib;
		%local.graphic.attrib;
>
<!--end of graphic.attlist-->]]>
<!--end of graphic.module-->]]>

<!ENTITY % inlinegraphic.module "INCLUDE">
<![ %inlinegraphic.module; [
<!ENTITY % local.inlinegraphic.attrib "">
<!ENTITY % inlinegraphic.role.attrib "%role.attrib;">

<!ENTITY % inlinegraphic.element "INCLUDE">
<![ %inlinegraphic.element; [
<!ELEMENT InlineGraphic - O EMPTY>
<!--end of inlinegraphic.element-->]]>

<!ENTITY % inlinegraphic.attlist "INCLUDE">
<![ %inlinegraphic.attlist; [
<!ATTLIST InlineGraphic
		%graphics.attrib;
		%common.attrib;
		%inlinegraphic.role.attrib;
		%local.inlinegraphic.attrib;
>
<!--end of inlinegraphic.attlist-->]]>
<!--end of inlinegraphic.module-->]]>

<!ENTITY % mediaobject.content.module "INCLUDE">
<![ %mediaobject.content.module; [

<!ENTITY % mediaobject.module "INCLUDE">
<![ %mediaobject.module; [
<!ENTITY % local.mediaobject.attrib "">
<!ENTITY % mediaobject.role.attrib "%role.attrib;">

<!ENTITY % mediaobject.element "INCLUDE">
<![ %mediaobject.element; [
<!ELEMENT MediaObject - - (ObjectInfo?,
                           (%mediaobject.mix;),
			   (%mediaobject.mix;|TextObject)*,
			   Caption?)>
<!--end of mediaobject.element-->]]>

<!ENTITY % mediaobject.attlist "INCLUDE">
<![ %mediaobject.attlist; [
<!ATTLIST MediaObject
		%common.attrib;
		%mediaobject.role.attrib;
		%local.mediaobject.attrib;
>
<!--end of mediaobject.attlist-->]]>
<!--end of mediaobject.module-->]]>

<!ENTITY % inlinemediaobject.module "INCLUDE">
<![ %inlinemediaobject.module; [
<!ENTITY % local.inlinemediaobject.attrib "">
<!ENTITY % inlinemediaobject.role.attrib "%role.attrib;">

<!ENTITY % inlinemediaobject.element "INCLUDE">
<![ %inlinemediaobject.element; [
<!ELEMENT InlineMediaObject - - (ObjectInfo?,
                	         (%mediaobject.mix;),
				 (%mediaobject.mix;|TextObject)*)>
<!--end of inlinemediaobject.element-->]]>

<!ENTITY % inlinemediaobject.attlist "INCLUDE">
<![ %inlinemediaobject.attlist; [
<!ATTLIST InlineMediaObject
		%common.attrib;
		%inlinemediaobject.role.attrib;
		%local.inlinemediaobject.attrib;
>
<!--end of inlinemediaobject.attlist-->]]>
<!--end of inlinemediaobject.module-->]]>

<!ENTITY % videoobject.module "INCLUDE">
<![ %videoobject.module; [
<!ENTITY % local.videoobject.attrib "">
<!ENTITY % videoobject.role.attrib "%role.attrib;">

<!ENTITY % videoobject.element "INCLUDE">
<![ %videoobject.element; [
<!ELEMENT VideoObject - - (ObjectInfo?, VideoData)>
<!--end of videoobject.element-->]]>

<!ENTITY % videoobject.attlist "INCLUDE">
<![ %videoobject.attlist; [
<!ATTLIST VideoObject
		%common.attrib;
		%videoobject.role.attrib;
		%local.videoobject.attrib;
>
<!--end of videoobject.attlist-->]]>
<!--end of videoobject.module-->]]>

<!ENTITY % audioobject.module "INCLUDE">
<![ %audioobject.module; [
<!ENTITY % local.audioobject.attrib "">
<!ENTITY % audioobject.role.attrib "%role.attrib;">

<!ENTITY % audioobject.element "INCLUDE">
<![ %audioobject.element; [
<!ELEMENT AudioObject - - (ObjectInfo?, AudioData)>
<!--end of audioobject.element-->]]>

<!ENTITY % audioobject.attlist "INCLUDE">
<![ %audioobject.attlist; [
<!ATTLIST AudioObject
		%common.attrib;
		%audioobject.role.attrib;
		%local.audioobject.attrib;
>
<!--end of audioobject.attlist-->]]>
<!--end of audioobject.module-->]]>

<!ENTITY % imageobject.module "INCLUDE">
<![ %imageobject.module; [
<!ENTITY % local.imageobject.attrib "">
<!ENTITY % imageobject.role.attrib "%role.attrib;">

<!ENTITY % imageobject.element "INCLUDE">
<![ %imageobject.element; [
<!ELEMENT ImageObject - - (ObjectInfo?, ImageData)>
<!--end of imageobject.element-->]]>

<!ENTITY % imageobject.attlist "INCLUDE">
<![ %imageobject.attlist; [
<!ATTLIST ImageObject
		%common.attrib;
		%imageobject.role.attrib;
		%local.imageobject.attrib;
>
<!--end of imageobject.attlist-->]]>
<!--end of imageobject.module-->]]>

<!ENTITY % textobject.module "INCLUDE">
<![ %textobject.module; [
<!ENTITY % local.textobject.attrib "">
<!ENTITY % textobject.role.attrib "%role.attrib;">

<!ENTITY % textobject.element "INCLUDE">
<![ %textobject.element; [
<!ELEMENT TextObject - - (ObjectInfo?, (Phrase|(%textobject.mix;)+))>
<!--end of textobject.element-->]]>

<!ENTITY % textobject.attlist "INCLUDE">
<![ %textobject.attlist; [
<!ATTLIST TextObject
		%common.attrib;
		%textobject.role.attrib;
		%local.textobject.attrib;
>
<!--end of textobject.attlist-->]]>
<!--end of textobject.module-->]]>

<!ENTITY % objectinfo.module "INCLUDE">
<![ %objectinfo.module; [
<!ENTITY % local.objectinfo.attrib "">
<!ENTITY % objectinfo.role.attrib "%role.attrib;">

<!ENTITY % objectinfo.element "INCLUDE">
<![ %objectinfo.element; [
<!ELEMENT ObjectInfo - - ((Graphic | MediaObject | LegalNotice | ModeSpec 
	| SubjectSet | KeywordSet | ITermSet | %bibliocomponent.mix;)+)
	-(BeginPage)>
<!--end of objectinfo.element-->]]>

<!ENTITY % objectinfo.attlist "INCLUDE">
<![ %objectinfo.attlist; [
<!ATTLIST ObjectInfo
		%common.attrib;
		%objectinfo.role.attrib;
		%local.objectinfo.attrib;
>
<!--end of objectinfo.attlist-->]]>
<!--end of objectinfo.module-->]]>

<!ENTITY % local.objectdata.attrib "">
<!ENTITY % objectdata.attrib
	"
	--EntityRef: Name of an external entity containing the content
	of the object data--
	EntityRef	ENTITY		#IMPLIED

	--FileRef: Filename, qualified by a pathname if desired, 
	designating the file containing the content of the object data--
	FileRef 	CDATA		#IMPLIED

	--Format: Notation of the element content, if any--
	Format		(%notation.class;)
					#IMPLIED

	--SrcCredit: Information about the source of the image--
	SrcCredit	CDATA		#IMPLIED

	%local.objectdata.attrib;"
>

<!ENTITY % videodata.module "INCLUDE">
<![ %videodata.module; [
<!ENTITY % local.videodata.attrib "">
<!ENTITY % videodata.role.attrib "%role.attrib;">

<!ENTITY % videodata.element "INCLUDE">
<![ %videodata.element; [
<!ELEMENT VideoData - O EMPTY>
<!--end of videodata.element-->]]>

<!ENTITY % videodata.attlist "INCLUDE">
<![ %videodata.attlist; [
<!ATTLIST VideoData
		%common.attrib;
		%objectdata.attrib;

	--Width: Same as CALS reprowid (desired width)--
	Width		NUTOKEN		#IMPLIED

	--Depth: Same as CALS reprodep (desired depth)--
	Depth		NUTOKEN		#IMPLIED

	--Align: Same as CALS hplace with 'none' removed; #IMPLIED means 
	application-specific--
	Align		(Left
			|Right 
			|Center)	#IMPLIED

	--Scale: Conflation of CALS hscale and vscale--
	Scale		NUMBER		#IMPLIED

	--Scalefit: Same as CALS scalefit--
	Scalefit	%yesorno.attvals;
					#IMPLIED

		%videodata.role.attrib;
		%local.videodata.attrib;
>
<!--end of videodata.attlist-->]]>
<!--end of videodata.module-->]]>

<!ENTITY % audiodata.module "INCLUDE">
<![ %audiodata.module; [
<!ENTITY % local.audiodata.attrib "">
<!ENTITY % audiodata.role.attrib "%role.attrib;">

<!ENTITY % audiodata.element "INCLUDE">
<![ %audiodata.element; [
<!ELEMENT AudioData - O EMPTY>
<!--end of audiodata.element-->]]>

<!ENTITY % audiodata.attlist "INCLUDE">
<![ %audiodata.attlist; [
<!ATTLIST AudioData
		%common.attrib;
		%objectdata.attrib;
		%local.audiodata.attrib;
		%audiodata.role.attrib;
>
<!--end of audiodata.attlist-->]]>
<!--end of audiodata.module-->]]>

<!ENTITY % imagedata.module "INCLUDE">
<![ %imagedata.module; [
<!ENTITY % local.imagedata.attrib "">
<!ENTITY % imagedata.role.attrib "%role.attrib;">

<!ENTITY % imagedata.element "INCLUDE">
<![ %imagedata.element; [
<!ELEMENT ImageData - O EMPTY>
<!--end of imagedata.element-->]]>

<!ENTITY % imagedata.attlist "INCLUDE">
<![ %imagedata.attlist; [
<!ATTLIST ImageData
		%common.attrib;
		%objectdata.attrib;

	--Width: Same as CALS reprowid (desired width)--
	Width		NUTOKEN		#IMPLIED

	--Depth: Same as CALS reprodep (desired depth)--
	Depth		NUTOKEN		#IMPLIED

	--Align: Same as CALS hplace with 'none' removed; #IMPLIED means 
	application-specific--
	Align		(Left
			|Right 
			|Center)	#IMPLIED

	--Scale: Conflation of CALS hscale and vscale--
	Scale		NUMBER		#IMPLIED

	--Scalefit: Same as CALS scalefit--
	Scalefit	%yesorno.attvals;
					#IMPLIED

		%local.imagedata.attrib;
		%imagedata.role.attrib;
>
<!--end of imagedata.attlist-->]]>
<!--end of imagedata.module-->]]>

<!ENTITY % caption.module "INCLUDE">
<![ %caption.module; [
<!ENTITY % local.caption.attrib "">
<!ENTITY % caption.role.attrib "%role.attrib;">

<!ENTITY % caption.element "INCLUDE">
<![ %caption.element; [
<!ELEMENT Caption - - (%textobject.mix;)*>
<!--end of caption.element-->]]>

<!ENTITY % caption.attlist "INCLUDE">
<![ %caption.attlist; [
<!ATTLIST Caption
		%common.attrib;
		%local.caption.attrib;
		%caption.role.attrib;
>
<!--end of caption.attlist-->]]>
<!--end of caption.module-->]]>

<!ENTITY % mediaobjectco.module "INCLUDE">
<![ %mediaobjectco.module; [
<!ENTITY % local.mediaobjectco.attrib "">
<!ENTITY % mediaobjectco.role.attrib "%role.attrib;">

<!ENTITY % mediaobjectco.element "INCLUDE">
<![ %mediaobjectco.element; [
<!ELEMENT MediaObjectCO - - (ObjectInfo?, ImageObjectCO,
			   (ImageObjectCO|TextObject)*)>
<!--end of mediaobjectco.element-->]]>

<!ENTITY % mediaobjectco.attlist "INCLUDE">
<![ %mediaobjectco.attlist; [
<!ATTLIST MediaObjectCO
		%common.attrib;
		%mediaobjectco.role.attrib;
		%local.mediaobjectco.attrib;
>
<!--end of mediaobjectco.attlist-->]]>
<!--end of mediaobjectco.module-->]]>

<!ENTITY % imageobjectco.module "INCLUDE">
<![ %imageobjectco.module; [
<!ENTITY % local.imageobjectco.attrib "">
<!ENTITY % imageobjectco.role.attrib "%role.attrib;">

<!ENTITY % imageobjectco.element "INCLUDE">
<![ %imageobjectco.element; [
<!ELEMENT ImageObjectCO - - (AreaSpec, ImageObject, CalloutList*)>
<!--end of imageobjectco.element-->]]>

<!ENTITY % imageobjectco.attlist "INCLUDE">
<![ %imageobjectco.attlist; [
<!ATTLIST ImageObjectCO
		%common.attrib;
		%imageobjectco.role.attrib;
		%local.imageobjectco.attrib;
>
<!--end of imageobjectco.attlist-->]]>
<!--end of imageobjectco.module-->]]>
<!--end of mediaobject.content.module-->]]>

<!-- Equations ........................ -->

<!-- This PE provides a mechanism for replacing equation content, -->
<!-- perhaps adding a new or different model (e.g., MathML) -->
<!ENTITY % equation.content "(Alt?, (Graphic+|MediaObject+))">
<!ENTITY % inlineequation.content "(Alt?, (Graphic+|InlineMediaObject+))">

<!ENTITY % equation.module "INCLUDE">
<![ %equation.module; [
<!ENTITY % local.equation.attrib "">
<!ENTITY % equation.role.attrib "%role.attrib;">

<!ENTITY % equation.element "INCLUDE">
<![ %equation.element; [
<!ELEMENT Equation - - ((%formalobject.title.content;)?, (InformalEquation |
		%equation.content;))>
<!--end of equation.element-->]]>

<!ENTITY % equation.attlist "INCLUDE">
<![ %equation.attlist; [
<!ATTLIST Equation
		%label.attrib;
	 	%common.attrib;
		%equation.role.attrib;
		%local.equation.attrib;
>
<!--end of equation.attlist-->]]>
<!--end of equation.module-->]]>

<!ENTITY % informalequation.module "INCLUDE">
<![ %informalequation.module; [
<!ENTITY % local.informalequation.attrib "">
<!ENTITY % informalequation.role.attrib "%role.attrib;">

<!ENTITY % informalequation.element "INCLUDE">
<![ %informalequation.element; [
<!ELEMENT InformalEquation - - (%equation.content;)>
<!--end of informalequation.element-->]]>

<!ENTITY % informalequation.attlist "INCLUDE">
<![ %informalequation.attlist; [
<!ATTLIST InformalEquation
		%common.attrib;
		%informalequation.role.attrib;
		%local.informalequation.attrib;
>
<!--end of informalequation.attlist-->]]>
<!--end of informalequation.module-->]]>

<!ENTITY % inlineequation.module "INCLUDE">
<![ %inlineequation.module; [
<!ENTITY % local.inlineequation.attrib "">
<!ENTITY % inlineequation.role.attrib "%role.attrib;">

<!ENTITY % inlineequation.element "INCLUDE">
<![ %inlineequation.element; [
<!ELEMENT InlineEquation - - (%inlineequation.content;)>
<!--end of inlineequation.element-->]]>

<!ENTITY % inlineequation.attlist "INCLUDE">
<![ %inlineequation.attlist; [
<!ATTLIST InlineEquation
		%common.attrib;
		%inlineequation.role.attrib;
		%local.inlineequation.attrib;
>
<!--end of inlineequation.attlist-->]]>
<!--end of inlineequation.module-->]]>

<!ENTITY % alt.module "INCLUDE">
<![ %alt.module; [
<!ENTITY % local.alt.attrib "">
<!ENTITY % alt.role.attrib "%role.attrib;">

<!ENTITY % alt.element "INCLUDE">
<![ %alt.element; [
<!ELEMENT Alt - - (#PCDATA)>
<!--end of alt.element-->]]>

<!ENTITY % alt.attlist "INCLUDE">
<![ %alt.attlist; [
<!ATTLIST Alt 
		%common.attrib;
		%alt.role.attrib;
		%local.alt.attrib;
>
<!--end of alt.attlist-->]]>
<!--end of alt.module-->]]>

<!-- Tables ........................... -->

<!ENTITY % table.module "INCLUDE">
<![ %table.module; [

<!ENTITY % tables.role.attrib "%role.attrib;">

<!-- Add Label attribute to Table element (and InformalTable element). -->
<!ENTITY % bodyatt "%label.attrib;">

<!-- Add common attributes to Table, TGroup, TBody, THead, TFoot, Row, 
     EntryTbl, and Entry (and InformalTable element). -->
<!ENTITY % secur
	"%common.attrib;
	%tables.role.attrib;">

<!-- Remove Chart. -->
<!ENTITY % tbl.table.name "Table">

<!-- Content model for Table. -->
<!ENTITY % tbl.table.mdl
	"((%formalobject.title.content;),
          (%ndxterm.class;)*,
          (Graphic+|MediaObject+|tgroup+))">

<!-- Exclude all DocBook tables and formal objects. -->
<!ENTITY % tbl.table.excep "-(InformalTable|%formal.class;)">

<!-- Remove pgbrk exception on Row. -->
<!ENTITY % tbl.row.excep "">

<!-- Allow either objects or inlines; beware of REs between elements. -->
<!ENTITY % tbl.entry.mdl "((%tabentry.mix;)+ | (%para.char.mix;)+)">

<!-- Remove pgbrk exception on Entry. -->
<!ENTITY % tbl.entry.excep "">

<!-- Remove pgbrk exception on EntryTbl, but leave exclusion of itself. -->
<!ENTITY % tbl.entrytbl.excep "-(entrytbl)">

<!-- Reference CALS table module. -->
<!ENTITY % calstbls PUBLIC "-//USA-DOD//DTD Table Model 951010//EN">
%calstbls;
<!--end of table.module-->]]>

<!ENTITY % informaltable.module "INCLUDE">
<![ %informaltable.module; [

<!-- Note that InformalTable is dependent on some of the entity
     declarations that customize Table. -->

<!ENTITY % local.informaltable.attrib "">

<!ENTITY % informaltable.element "INCLUDE">
<![ %informaltable.element; [
<!ELEMENT InformalTable - - (Graphic+|MediaObject+|tgroup+) %tbl.table.excep;>
<!--end of informaltable.element-->]]>

<!ENTITY % informaltable.attlist "INCLUDE">
<![ %informaltable.attlist; [
<!ATTLIST InformalTable
		--
		Frame, Colsep, and Rowsep must be repeated because
		they are not in entities in the table module.
		--
		Frame		(Top
				|Bottom
				|Topbot
				|All
				|Sides
				|None)			#IMPLIED
		Colsep		%yesorno.attvals;	#IMPLIED
		Rowsep		%yesorno.attvals;	#IMPLIED
		%tbl.table.att; -- includes TabStyle, ToCentry, ShortEntry, 
				Orient, PgWide --
		%bodyatt; -- includes Label --
		%secur; -- includes common attributes --
		%local.informaltable.attrib;
>
<!--end of informaltable.attlist-->]]>
<!--end of informaltable.module-->]]>

<!-- ...................................................................... -->
<!-- Synopses ............................................................. -->

<!-- Synopsis ......................... -->

<!ENTITY % synopsis.module "INCLUDE">
<![ %synopsis.module; [
<!ENTITY % local.synopsis.attrib "">
<!ENTITY % synopsis.role.attrib "%role.attrib;">

<!ENTITY % synopsis.element "INCLUDE">
<![ %synopsis.element; [
<!ELEMENT Synopsis - - ((CO | LineAnnotation | %para.char.mix;
		| Graphic | MediaObject)+)>
<!--end of synopsis.element-->]]>

<!ENTITY % synopsis.attlist "INCLUDE">
<![ %synopsis.attlist; [
<!ATTLIST Synopsis
		%label.attrib;
		%linespecific.attrib;
		%common.attrib;
		%synopsis.role.attrib;
		%local.synopsis.attrib;
>
<!--end of synopsis.attlist-->]]>

<!-- LineAnnotation (defined in the Inlines section, below)-->
<!--end of synopsis.module-->]]>

<!-- CmdSynopsis ...................... -->

<!ENTITY % cmdsynopsis.content.module "INCLUDE">
<![ %cmdsynopsis.content.module; [
<!ENTITY % cmdsynopsis.module "INCLUDE">
<![ %cmdsynopsis.module; [
<!ENTITY % local.cmdsynopsis.attrib "">
<!ENTITY % cmdsynopsis.role.attrib "%role.attrib;">

<!ENTITY % cmdsynopsis.element "INCLUDE">
<![ %cmdsynopsis.element; [
<!ELEMENT CmdSynopsis - - ((Command | Arg | Group | SBR)+, SynopFragment*)>
<!--end of cmdsynopsis.element-->]]>

<!ENTITY % cmdsynopsis.attlist "INCLUDE">
<![ %cmdsynopsis.attlist; [
<!ATTLIST CmdSynopsis
		%label.attrib;
		--
		Sepchar: Character that should separate command and all 
		top-level arguments; alternate value might be e.g., &Delta;
		--
		Sepchar		CDATA		" "
		--
		CmdLength: Length beyond which the presentation engine
		may consider a Command too long and select an alternate
		presentation of the Command and, or, its associated
		arguments.
		--
		CmdLength	CDATA		#IMPLIED
		%common.attrib;
		%cmdsynopsis.role.attrib;
		%local.cmdsynopsis.attrib;
>
<!--end of cmdsynopsis.attlist-->]]>
<!--end of cmdsynopsis.module-->]]>

<!ENTITY % arg.module "INCLUDE">
<![ %arg.module; [
<!ENTITY % local.arg.attrib "">
<!ENTITY % arg.role.attrib "%role.attrib;">

<!ENTITY % arg.element "INCLUDE">
<![ %arg.element; [
<!ELEMENT Arg - - ((#PCDATA 
		| Arg 
		| Group 
		| Option 
		| SynopFragmentRef 
		| Replaceable
		| SBR)+)>
<!--end of arg.element-->]]>

<!ENTITY % arg.attlist "INCLUDE">
<![ %arg.attlist; [
<!ATTLIST Arg
		--
		Choice: Whether Arg must be supplied: Opt (optional to 
		supply, e.g. [arg]; the default), Req (required to supply, 
		e.g. {arg}), or Plain (required to supply, e.g. arg)
		--
		Choice		(Opt
				|Req
				|Plain)		Opt
		--
		Rep: whether Arg is repeatable: Norepeat (e.g. arg without 
		ellipsis; the default), or Repeat (e.g. arg...)
		--
		Rep		(Norepeat
				|Repeat)	Norepeat
		%common.attrib;
		%arg.role.attrib;
		%local.arg.attrib;
>
<!--end of arg.attlist-->]]>
<!--end of arg.module-->]]>

<!ENTITY % group.module "INCLUDE">
<![ %group.module; [

<!ENTITY % local.group.attrib "">
<!ENTITY % group.role.attrib "%role.attrib;">

<!ENTITY % group.element "INCLUDE">
<![ %group.element; [
<!ELEMENT Group - - ((Arg | Group | Option | SynopFragmentRef 
		| Replaceable | SBR)+)>
<!--end of group.element-->]]>

<!ENTITY % group.attlist "INCLUDE">
<![ %group.attlist; [
<!ATTLIST Group
		--
		Choice: Whether Group must be supplied: Opt (optional to
		supply, e.g.  [g1|g2|g3]; the default), Req (required to
		supply, e.g.  {g1|g2|g3}), Plain (required to supply,
		e.g.  g1|g2|g3), OptMult (can supply zero or more, e.g.
		[[g1|g2|g3]]), or ReqMult (must supply one or more, e.g.
		{{g1|g2|g3}})
		--
		Choice		(Opt
				|Req
				|Plain)		Opt
		--
		Rep: whether Group is repeatable: Norepeat (e.g. group 
		without ellipsis; the default), or Repeat (e.g. group...)
		--
		Rep		(Norepeat
				|Repeat)	Norepeat
		%common.attrib;
		%group.role.attrib;
		%local.group.attrib;
>
<!--end of group.attlist-->]]>
<!--end of group.module-->]]>

<!ENTITY % sbr.module "INCLUDE">
<![ %sbr.module; [
<!ENTITY % local.sbr.attrib "">
<!-- Synopsis break -->
<!ENTITY % sbr.role.attrib "%role.attrib;">

<!ENTITY % sbr.element "INCLUDE">
<![ %sbr.element; [
<!ELEMENT SBR - O EMPTY>
<!--end of sbr.element-->]]>

<!ENTITY % sbr.attlist "INCLUDE">
<![ %sbr.attlist; [
<!ATTLIST SBR
		%common.attrib;
		%sbr.role.attrib;
		%local.sbr.attrib;
>
<!--end of sbr.attlist-->]]>
<!--end of sbr.module-->]]>

<!ENTITY % synopfragmentref.module "INCLUDE">
<![ %synopfragmentref.module; [
<!ENTITY % local.synopfragmentref.attrib "">
<!ENTITY % synopfragmentref.role.attrib "%role.attrib;">

<!ENTITY % synopfragmentref.element "INCLUDE">
<![ %synopfragmentref.element; [
<!ELEMENT SynopFragmentRef - - RCDATA >
<!--end of synopfragmentref.element-->]]>

<!ENTITY % synopfragmentref.attlist "INCLUDE">
<![ %synopfragmentref.attlist; [
<!ATTLIST SynopFragmentRef
		%linkendreq.attrib; --to SynopFragment of complex synopsis
			material for separate referencing--
		%common.attrib;
		%synopfragmentref.role.attrib;
		%local.synopfragmentref.attrib;
>
<!--end of synopfragmentref.attlist-->]]>
<!--end of synopfragmentref.module-->]]>

<!ENTITY % synopfragment.module "INCLUDE">
<![ %synopfragment.module; [
<!ENTITY % local.synopfragment.attrib "">
<!ENTITY % synopfragment.role.attrib "%role.attrib;">

<!ENTITY % synopfragment.element "INCLUDE">
<![ %synopfragment.element; [
<!ELEMENT SynopFragment - - ((Arg | Group)+)>
<!--end of synopfragment.element-->]]>

<!ENTITY % synopfragment.attlist "INCLUDE">
<![ %synopfragment.attlist; [
<!ATTLIST SynopFragment
		%idreq.common.attrib;
		%synopfragment.role.attrib;
		%local.synopfragment.attrib;
>
<!--end of synopfragment.attlist-->]]>
<!--end of synopfragment.module-->]]>

<!-- Command (defined in the Inlines section, below)-->
<!-- Option (defined in the Inlines section, below)-->
<!-- Replaceable (defined in the Inlines section, below)-->
<!--end of cmdsynopsis.content.module-->]]>

<!-- FuncSynopsis ..................... -->

<!ENTITY % funcsynopsis.content.module "INCLUDE">
<![ %funcsynopsis.content.module; [
<!ENTITY % funcsynopsis.module "INCLUDE">
<![ %funcsynopsis.module; [

<!ENTITY % local.funcsynopsis.attrib "">
<!ENTITY % funcsynopsis.role.attrib "%role.attrib;">

<!ENTITY % funcsynopsis.element "INCLUDE">
<![ %funcsynopsis.element; [
<!ELEMENT FuncSynopsis - - (FuncSynopsisInfo|FuncPrototype)+>
<!--end of funcsynopsis.element-->]]>

<!ENTITY % funcsynopsis.attlist "INCLUDE">
<![ %funcsynopsis.attlist; [
<!ATTLIST FuncSynopsis
		%label.attrib;
		%common.attrib;
		%funcsynopsis.role.attrib;
		%local.funcsynopsis.attrib;
>
<!--end of funcsynopsis.attlist-->]]>
<!--end of funcsynopsis.module-->]]>

<!ENTITY % funcsynopsisinfo.module "INCLUDE">
<![ %funcsynopsisinfo.module; [
<!ENTITY % local.funcsynopsisinfo.attrib "">
<!ENTITY % funcsynopsisinfo.role.attrib "%role.attrib;">

<!ENTITY % funcsynopsisinfo.element "INCLUDE">
<![ %funcsynopsisinfo.element; [
<!ELEMENT FuncSynopsisInfo - O ((LineAnnotation | %cptr.char.mix;)* )>
<!--end of funcsynopsisinfo.element-->]]>

<!ENTITY % funcsynopsisinfo.attlist "INCLUDE">
<![ %funcsynopsisinfo.attlist; [
<!ATTLIST FuncSynopsisInfo
		%linespecific.attrib;
		%common.attrib;
		%funcsynopsisinfo.role.attrib;
		%local.funcsynopsisinfo.attrib;
>
<!--end of funcsynopsisinfo.attlist-->]]>
<!--end of funcsynopsisinfo.module-->]]>

<!ENTITY % funcprototype.module "INCLUDE">
<![ %funcprototype.module; [
<!ENTITY % local.funcprototype.attrib "">
<!ENTITY % funcprototype.role.attrib "%role.attrib;">

<!ENTITY % funcprototype.element "INCLUDE">
<![ %funcprototype.element; [
<!ELEMENT FuncPrototype - O (FuncDef, (Void | VarArgs | ParamDef+))>
<!--end of funcprototype.element-->]]>

<!ENTITY % funcprototype.attlist "INCLUDE">
<![ %funcprototype.attlist; [
<!ATTLIST FuncPrototype
		%common.attrib;
		%funcprototype.role.attrib;
		%local.funcprototype.attrib;
>
<!--end of funcprototype.attlist-->]]>
<!--end of funcprototype.module-->]]>

<!ENTITY % funcdef.module "INCLUDE">
<![ %funcdef.module; [
<!ENTITY % local.funcdef.attrib "">
<!ENTITY % funcdef.role.attrib "%role.attrib;">

<!ENTITY % funcdef.element "INCLUDE">
<![ %funcdef.element; [
<!ELEMENT FuncDef - - ((#PCDATA 
		| Replaceable 
		| Function)*)>
<!--end of funcdef.element-->]]>

<!ENTITY % funcdef.attlist "INCLUDE">
<![ %funcdef.attlist; [
<!ATTLIST FuncDef
		%common.attrib;
		%funcdef.role.attrib;
		%local.funcdef.attrib;
>
<!--end of funcdef.attlist-->]]>
<!--end of funcdef.module-->]]>

<!ENTITY % void.module "INCLUDE">
<![ %void.module; [
<!ENTITY % local.void.attrib "">
<!ENTITY % void.role.attrib "%role.attrib;">

<!ENTITY % void.element "INCLUDE">
<![ %void.element; [
<!ELEMENT Void - O EMPTY>
<!--end of void.element-->]]>

<!ENTITY % void.attlist "INCLUDE">
<![ %void.attlist; [
<!ATTLIST Void
		%common.attrib;
		%void.role.attrib;
		%local.void.attrib;
>
<!--end of void.attlist-->]]>
<!--end of void.module-->]]>

<!ENTITY % varargs.module "INCLUDE">
<![ %varargs.module; [
<!ENTITY % local.varargs.attrib "">
<!ENTITY % varargs.role.attrib "%role.attrib;">

<!ENTITY % varargs.element "INCLUDE">
<![ %varargs.element; [
<!ELEMENT VarArgs - O EMPTY>
<!--end of varargs.element-->]]>

<!ENTITY % varargs.attlist "INCLUDE">
<![ %varargs.attlist; [
<!ATTLIST VarArgs
		%common.attrib;
		%varargs.role.attrib;
		%local.varargs.attrib;
>
<!--end of varargs.attlist-->]]>
<!--end of varargs.module-->]]>

<!-- Processing assumes that only one Parameter will appear in a
     ParamDef, and that FuncParams will be used at most once, for
     providing information on the "inner parameters" for parameters that
     are pointers to functions. -->

<!ENTITY % paramdef.module "INCLUDE">
<![ %paramdef.module; [
<!ENTITY % local.paramdef.attrib "">
<!ENTITY % paramdef.role.attrib "%role.attrib;">

<!ENTITY % paramdef.element "INCLUDE">
<![ %paramdef.element; [
<!ELEMENT ParamDef - - ((#PCDATA 
		| Replaceable 
		| Parameter 
		| FuncParams)*)>
<!--end of paramdef.element-->]]>

<!ENTITY % paramdef.attlist "INCLUDE">
<![ %paramdef.attlist; [
<!ATTLIST ParamDef
		%common.attrib;
		%paramdef.role.attrib;
		%local.paramdef.attrib;
>
<!--end of paramdef.attlist-->]]>
<!--end of paramdef.module-->]]>

<!ENTITY % funcparams.module "INCLUDE">
<![ %funcparams.module; [
<!ENTITY % local.funcparams.attrib "">
<!ENTITY % funcparams.role.attrib "%role.attrib;">

<!ENTITY % funcparams.element "INCLUDE">
<![ %funcparams.element; [
<!ELEMENT FuncParams - - ((%cptr.char.mix;)*)>
<!--end of funcparams.element-->]]>

<!ENTITY % funcparams.attlist "INCLUDE">
<![ %funcparams.attlist; [
<!ATTLIST FuncParams
		%common.attrib;
		%funcparams.role.attrib;
		%local.funcparams.attrib;
>
<!--end of funcparams.attlist-->]]>
<!--end of funcparams.module-->]]>

<!-- LineAnnotation (defined in the Inlines section, below)-->
<!-- Replaceable (defined in the Inlines section, below)-->
<!-- Function (defined in the Inlines section, below)-->
<!-- Parameter (defined in the Inlines section, below)-->
<!--end of funcsynopsis.content.module-->]]>

<!-- ClassSynopsis ..................... -->

<!ENTITY % classsynopsis.content.module "INCLUDE">
<![%classsynopsis.content.module;[

<!ENTITY % classsynopsis.module "INCLUDE">
<![%classsynopsis.module;[
<!ENTITY % local.classsynopsis.attrib "">
<!ENTITY % classsynopsis.role.attrib "%role.attrib;">

<!ENTITY % classsynopsis.element "INCLUDE">
<![%classsynopsis.element;[
<!ELEMENT ClassSynopsis - - ((OOClass|OOInterface|OOException)+,
                             (ClassSynopsisInfo
                              |FieldSynopsis|%method.synop.class;)*)>
<!--end of classsynopsis.element-->]]>

<!ENTITY % classsynopsis.attlist "INCLUDE">
<![%classsynopsis.attlist;[
<!ATTLIST ClassSynopsis
	%common.attrib;
	%classsynopsis.role.attrib;
	%local.classsynopsis.attrib;
	Language	CDATA	#IMPLIED
	Class	(Class|Interface)	"Class"
>
<!--end of classsynopsis.attlist-->]]>
<!--end of classsynopsis.module-->]]>

<!ENTITY % classsynopsisinfo.module "INCLUDE">
<![ %classsynopsisinfo.module; [
<!ENTITY % local.classsynopsisinfo.attrib "">
<!ENTITY % classsynopsisinfo.role.attrib "%role.attrib;">

<!ENTITY % classsynopsisinfo.element "INCLUDE">
<![ %classsynopsisinfo.element; [
<!ELEMENT ClassSynopsisInfo - O ((LineAnnotation | %cptr.char.mix;)* )>
<!--end of classsynopsisinfo.element-->]]>

<!ENTITY % classsynopsisinfo.attlist "INCLUDE">
<![ %classsynopsisinfo.attlist; [
<!ATTLIST ClassSynopsisInfo
		%linespecific.attrib;
		%common.attrib;
		%classsynopsisinfo.role.attrib;
		%local.classsynopsisinfo.attrib;
>
<!--end of classsynopsisinfo.attlist-->]]>
<!--end of classsynopsisinfo.module-->]]>

<!ENTITY % ooclass.module "INCLUDE">
<![%ooclass.module;[
<!ENTITY % local.ooclass.attrib "">
<!ENTITY % ooclass.role.attrib "%role.attrib;">

<!ENTITY % ooclass.element "INCLUDE">
<![%ooclass.element;[
<!ELEMENT OOClass - - (Modifier*, ClassName)>
<!--end of ooclass.element-->]]>

<!ENTITY % ooclass.attlist "INCLUDE">
<![%ooclass.attlist;[
<!ATTLIST OOClass
	%common.attrib;
	%ooclass.role.attrib;
	%local.ooclass.attrib;
>
<!--end of ooclass.attlist-->]]>
<!--end of ooclass.module-->]]>

<!ENTITY % oointerface.module "INCLUDE">
<![%oointerface.module;[
<!ENTITY % local.oointerface.attrib "">
<!ENTITY % oointerface.role.attrib "%role.attrib;">

<!ENTITY % oointerface.element "INCLUDE">
<![%oointerface.element;[
<!ELEMENT OOInterface - - (Modifier*, InterfaceName)>
<!--end of oointerface.element-->]]>

<!ENTITY % oointerface.attlist "INCLUDE">
<![%oointerface.attlist;[
<!ATTLIST OOInterface
	%common.attrib;
	%oointerface.role.attrib;
	%local.oointerface.attrib;
>
<!--end of oointerface.attlist-->]]>
<!--end of oointerface.module-->]]>

<!ENTITY % ooexception.module "INCLUDE">
<![%ooexception.module;[
<!ENTITY % local.ooexception.attrib "">
<!ENTITY % ooexception.role.attrib "%role.attrib;">

<!ENTITY % ooexception.element "INCLUDE">
<![%ooexception.element;[
<!ELEMENT OOException - - (Modifier*, ExceptionName)>
<!--end of ooexception.element-->]]>

<!ENTITY % ooexception.attlist "INCLUDE">
<![%ooexception.attlist;[
<!ATTLIST OOException
	%common.attrib;
	%ooexception.role.attrib;
	%local.ooexception.attrib;
>
<!--end of ooexception.attlist-->]]>
<!--end of ooexception.module-->]]>

<!ENTITY % modifier.module "INCLUDE">
<![%modifier.module;[
<!ENTITY % local.modifier.attrib "">
<!ENTITY % modifier.role.attrib "%role.attrib;">

<!ENTITY % modifier.element "INCLUDE">
<![%modifier.element;[
<!ELEMENT Modifier - - (%smallcptr.char.mix;)*>
<!--end of modifier.element-->]]>

<!ENTITY % modifier.attlist "INCLUDE">
<![%modifier.attlist;[
<!ATTLIST Modifier
	%common.attrib;
	%modifier.role.attrib;
	%local.modifier.attrib;
>
<!--end of modifier.attlist-->]]>
<!--end of modifier.module-->]]>

<!ENTITY % interfacename.module "INCLUDE">
<![%interfacename.module;[
<!ENTITY % local.interfacename.attrib "">
<!ENTITY % interfacename.role.attrib "%role.attrib;">

<!ENTITY % interfacename.element "INCLUDE">
<![%interfacename.element;[
<!ELEMENT InterfaceName - - (%smallcptr.char.mix;)*>
<!--end of interfacename.element-->]]>

<!ENTITY % interfacename.attlist "INCLUDE">
<![%interfacename.attlist;[
<!ATTLIST InterfaceName
	%common.attrib;
	%interfacename.role.attrib;
	%local.interfacename.attrib;
>
<!--end of interfacename.attlist-->]]>
<!--end of interfacename.module-->]]>

<!ENTITY % exceptionname.module "INCLUDE">
<![%exceptionname.module;[
<!ENTITY % local.exceptionname.attrib "">
<!ENTITY % exceptionname.role.attrib "%role.attrib;">

<!ENTITY % exceptionname.element "INCLUDE">
<![%exceptionname.element;[
<!ELEMENT ExceptionName - - (%smallcptr.char.mix;)*>
<!--end of exceptionname.element-->]]>

<!ENTITY % exceptionname.attlist "INCLUDE">
<![%exceptionname.attlist;[
<!ATTLIST ExceptionName
	%common.attrib;
	%exceptionname.role.attrib;
	%local.exceptionname.attrib;
>
<!--end of exceptionname.attlist-->]]>
<!--end of exceptionname.module-->]]>

<!ENTITY % fieldsynopsis.module "INCLUDE">
<![%fieldsynopsis.module;[
<!ENTITY % local.fieldsynopsis.attrib "">
<!ENTITY % fieldsynopsis.role.attrib "%role.attrib;">

<!ENTITY % fieldsynopsis.element "INCLUDE">
<![%fieldsynopsis.element;[
<!ELEMENT FieldSynopsis - - (Modifier*, Type?, VarName, Initializer?)>
<!--end of fieldsynopsis.element-->]]>

<!ENTITY % fieldsynopsis.attlist "INCLUDE">
<![%fieldsynopsis.attlist;[
<!ATTLIST FieldSynopsis
	%common.attrib;
	%fieldsynopsis.role.attrib;
	%local.fieldsynopsis.attrib;
>
<!--end of fieldsynopsis.attlist-->]]>
<!--end of fieldsynopsis.module-->]]>

<!ENTITY % initializer.module "INCLUDE">
<![%initializer.module;[
<!ENTITY % local.initializer.attrib "">
<!ENTITY % initializer.role.attrib "%role.attrib;">

<!ENTITY % initializer.element "INCLUDE">
<![%initializer.element;[
<!ELEMENT Initializer - - (%smallcptr.char.mix;)*>
<!--end of initializer.element-->]]>

<!ENTITY % initializer.attlist "INCLUDE">
<![%initializer.attlist;[
<!ATTLIST Initializer
	%common.attrib;
	%initializer.role.attrib;
	%local.initializer.attrib;
>
<!--end of initializer.attlist-->]]>
<!--end of initializer.module-->]]>

<!ENTITY % constructorsynopsis.module "INCLUDE">
<![%constructorsynopsis.module;[
<!ENTITY % local.constructorsynopsis.attrib "">
<!ENTITY % constructorsynopsis.role.attrib "%role.attrib;">

<!ENTITY % constructorsynopsis.element "INCLUDE">
<![%constructorsynopsis.element;[
<!ELEMENT ConstructorSynopsis - - (Modifier*,
                                   MethodName?,
                                   (MethodParam+|Void),
                                   ExceptionName*)>
<!--end of constructorsynopsis.element-->]]>

<!ENTITY % constructorsynopsis.attlist "INCLUDE">
<![%constructorsynopsis.attlist;[
<!ATTLIST ConstructorSynopsis
	%common.attrib;
	%constructorsynopsis.role.attrib;
	%local.constructorsynopsis.attrib;
>
<!--end of constructorsynopsis.attlist-->]]>
<!--end of constructorsynopsis.module-->]]>

<!ENTITY % destructorsynopsis.module "INCLUDE">
<![%destructorsynopsis.module;[
<!ENTITY % local.destructorsynopsis.attrib "">
<!ENTITY % destructorsynopsis.role.attrib "%role.attrib;">

<!ENTITY % destructorsynopsis.element "INCLUDE">
<![%destructorsynopsis.element;[
<!ELEMENT DestructorSynopsis - - (Modifier*,
                                  MethodName?,
                                  (MethodParam+|Void),
                                  ExceptionName*)>
<!--end of destructorsynopsis.element-->]]>

<!ENTITY % destructorsynopsis.attlist "INCLUDE">
<![%destructorsynopsis.attlist;[
<!ATTLIST DestructorSynopsis
	%common.attrib;
	%destructorsynopsis.role.attrib;
	%local.destructorsynopsis.attrib;
>
<!--end of destructorsynopsis.attlist-->]]>
<!--end of destructorsynopsis.module-->]]>

<!ENTITY % methodsynopsis.module "INCLUDE">
<![%methodsynopsis.module;[
<!ENTITY % local.methodsynopsis.attrib "">
<!ENTITY % methodsynopsis.role.attrib "%role.attrib;">

<!ENTITY % methodsynopsis.element "INCLUDE">
<![%methodsynopsis.element;[
<!ELEMENT MethodSynopsis - - (Modifier*,
                              (Type|Void)?,
                              MethodName,
                              (MethodParam+|Void),
                              ExceptionName*,
                              Modifier*)>
<!--end of methodsynopsis.element-->]]>

<!ENTITY % methodsynopsis.attlist "INCLUDE">
<![%methodsynopsis.attlist;[
<!ATTLIST MethodSynopsis
	%common.attrib;
	%methodsynopsis.role.attrib;
	%local.methodsynopsis.attrib;
>
<!--end of methodsynopsis.attlist-->]]>
<!--end of methodsynopsis.module-->]]>

<!ENTITY % methodname.module "INCLUDE">
<![%methodname.module;[
<!ENTITY % local.methodname.attrib "">
<!ENTITY % methodname.role.attrib "%role.attrib;">

<!ENTITY % methodname.element "INCLUDE">
<![%methodname.element;[
<!ELEMENT MethodName - - (%smallcptr.char.mix;)*>
<!--end of methodname.element-->]]>

<!ENTITY % methodname.attlist "INCLUDE">
<![%methodname.attlist;[
<!ATTLIST MethodName
	%common.attrib;
	%methodname.role.attrib;
	%local.methodname.attrib;
>
<!--end of methodname.attlist-->]]>
<!--end of methodname.module-->]]>

<!ENTITY % methodparam.module "INCLUDE">
<![%methodparam.module;[
<!ENTITY % local.methodparam.attrib "">
<!ENTITY % methodparam.role.attrib "%role.attrib;">

<!ENTITY % methodparam.element "INCLUDE">
<![%methodparam.element;[
<!ELEMENT MethodParam - - (Modifier*,
                           Type?, ((Parameter,Initializer?)|FuncParams),
                           Modifier*)>
<!--end of methodparam.element-->]]>

<!ENTITY % methodparam.attlist "INCLUDE">
<![%methodparam.attlist;[
<!ATTLIST MethodParam
	%common.attrib;
	%methodparam.role.attrib;
	%local.methodparam.attrib;
	Choice		(Opt
			|Req
			|Plain)		"Req"
	Rep		(Norepeat
			|Repeat)	"Norepeat"
>
<!--end of methodparam.attlist-->]]>
<!--end of methodparam.module-->]]>
<!--end of classsynopsis.content.module-->]]>

<!-- ...................................................................... -->
<!-- Document information entities and elements ........................... -->

<!-- The document information elements include some elements that are
     currently used only in the document hierarchy module. They are
     defined here so that they will be available for use in customized
     document hierarchies. -->

<!-- .................................. -->

<!ENTITY % docinfo.content.module "INCLUDE">
<![ %docinfo.content.module; [

<!-- Ackno ............................ -->

<!ENTITY % ackno.module "INCLUDE">
<![ %ackno.module; [
<!ENTITY % local.ackno.attrib "">
<!ENTITY % ackno.role.attrib "%role.attrib;">

<!ENTITY % ackno.element "INCLUDE">
<![ %ackno.element; [
<!ELEMENT Ackno - - ((%docinfo.char.mix;)+)>
<!--end of ackno.element-->]]>

<!ENTITY % ackno.attlist "INCLUDE">
<![ %ackno.attlist; [
<!ATTLIST Ackno
		%common.attrib;
		%ackno.role.attrib;
		%local.ackno.attrib;
>
<!--end of ackno.attlist-->]]>
<!--end of ackno.module-->]]>

<!-- Address .......................... -->

<!ENTITY % address.content.module "INCLUDE">
<![ %address.content.module; [
<!ENTITY % address.module "INCLUDE">
<![ %address.module; [
<!ENTITY % local.address.attrib "">
<!ENTITY % address.role.attrib "%role.attrib;">

<!ENTITY % address.element "INCLUDE">
<![ %address.element; [
<!ELEMENT Address - - (#PCDATA|%person.ident.mix;
		       |Street|POB|Postcode|City|State|Country|Phone
		       |Fax|Email|OtherAddr)*>
<!--end of address.element-->]]>

<!ENTITY % address.attlist "INCLUDE">
<![ %address.attlist; [
<!ATTLIST Address
		%linespecific.attrib;
		%common.attrib;
		%address.role.attrib;
		%local.address.attrib;
>
<!--end of address.attlist-->]]>
<!--end of address.module-->]]>

  <!ENTITY % street.module "INCLUDE">
  <![ %street.module; [
 <!ENTITY % local.street.attrib "">
  <!ENTITY % street.role.attrib "%role.attrib;">
  
<!ENTITY % street.element "INCLUDE">
<![ %street.element; [
<!ELEMENT Street - - ((%docinfo.char.mix;)+)>
<!--end of street.element-->]]>
  
<!ENTITY % street.attlist "INCLUDE">
<![ %street.attlist; [
<!ATTLIST Street
		%common.attrib;
		%street.role.attrib;
		%local.street.attrib;
>
<!--end of street.attlist-->]]>
  <!--end of street.module-->]]>

  <!ENTITY % pob.module "INCLUDE">
  <![ %pob.module; [
  <!ENTITY % local.pob.attrib "">
  <!ENTITY % pob.role.attrib "%role.attrib;">
  
<!ENTITY % pob.element "INCLUDE">
<![ %pob.element; [
<!ELEMENT POB - - ((%docinfo.char.mix;)+)>
<!--end of pob.element-->]]>
  
<!ENTITY % pob.attlist "INCLUDE">
<![ %pob.attlist; [
<!ATTLIST POB
		%common.attrib;
		%pob.role.attrib;
		%local.pob.attrib;
>
<!--end of pob.attlist-->]]>
  <!--end of pob.module-->]]>

  <!ENTITY % postcode.module "INCLUDE">
  <![ %postcode.module; [
  <!ENTITY % local.postcode.attrib "">
  <!ENTITY % postcode.role.attrib "%role.attrib;">
  
<!ENTITY % postcode.element "INCLUDE">
<![ %postcode.element; [
<!ELEMENT Postcode - - ((%docinfo.char.mix;)+)>
<!--end of postcode.element-->]]>
  
<!ENTITY % postcode.attlist "INCLUDE">
<![ %postcode.attlist; [
<!ATTLIST Postcode
		%common.attrib;
		%postcode.role.attrib;
		%local.postcode.attrib;
>
<!--end of postcode.attlist-->]]>
  <!--end of postcode.module-->]]>

  <!ENTITY % city.module "INCLUDE">
  <![ %city.module; [
  <!ENTITY % local.city.attrib "">
  <!ENTITY % city.role.attrib "%role.attrib;">
  
<!ENTITY % city.element "INCLUDE">
<![ %city.element; [
<!ELEMENT City - - ((%docinfo.char.mix;)+)>
<!--end of city.element-->]]>
  
<!ENTITY % city.attlist "INCLUDE">
<![ %city.attlist; [
<!ATTLIST City
		%common.attrib;
		%city.role.attrib;
		%local.city.attrib;
>
<!--end of city.attlist-->]]>
  <!--end of city.module-->]]>

  <!ENTITY % state.module "INCLUDE">
  <![ %state.module; [
  <!ENTITY % local.state.attrib "">
  <!ENTITY % state.role.attrib "%role.attrib;">
  
<!ENTITY % state.element "INCLUDE">
<![ %state.element; [
<!ELEMENT State - - ((%docinfo.char.mix;)+)>
<!--end of state.element-->]]>
  
<!ENTITY % state.attlist "INCLUDE">
<![ %state.attlist; [
<!ATTLIST State
		%common.attrib;
		%state.role.attrib;
		%local.state.attrib;
>
<!--end of state.attlist-->]]>
  <!--end of state.module-->]]>

  <!ENTITY % country.module "INCLUDE">
  <![ %country.module; [
  <!ENTITY % local.country.attrib "">
  <!ENTITY % country.role.attrib "%role.attrib;">
  
<!ENTITY % country.element "INCLUDE">
<![ %country.element; [
<!ELEMENT Country - - ((%docinfo.char.mix;)+)>
<!--end of country.element-->]]>
  
<!ENTITY % country.attlist "INCLUDE">
<![ %country.attlist; [
<!ATTLIST Country
		%common.attrib;
		%country.role.attrib;
		%local.country.attrib;
>
<!--end of country.attlist-->]]>
  <!--end of country.module-->]]>

  <!ENTITY % phone.module "INCLUDE">
  <![ %phone.module; [
  <!ENTITY % local.phone.attrib "">
  <!ENTITY % phone.role.attrib "%role.attrib;">
  
<!ENTITY % phone.element "INCLUDE">
<![ %phone.element; [
<!ELEMENT Phone - - ((%docinfo.char.mix;)+)>
<!--end of phone.element-->]]>
  
<!ENTITY % phone.attlist "INCLUDE">
<![ %phone.attlist; [
<!ATTLIST Phone
		%common.attrib;
		%phone.role.attrib;
		%local.phone.attrib;
>
<!--end of phone.attlist-->]]>
  <!--end of phone.module-->]]>

  <!ENTITY % fax.module "INCLUDE">
  <![ %fax.module; [
  <!ENTITY % local.fax.attrib "">
  <!ENTITY % fax.role.attrib "%role.attrib;">
  
<!ENTITY % fax.element "INCLUDE">
<![ %fax.element; [
<!ELEMENT Fax - - ((%docinfo.char.mix;)+)>
<!--end of fax.element-->]]>
  
<!ENTITY % fax.attlist "INCLUDE">
<![ %fax.attlist; [
<!ATTLIST Fax
		%common.attrib;
		%fax.role.attrib;
		%local.fax.attrib;
>
<!--end of fax.attlist-->]]>
  <!--end of fax.module-->]]>

  <!-- Email (defined in the Inlines section, below)-->

  <!ENTITY % otheraddr.module "INCLUDE">
  <![ %otheraddr.module; [
  <!ENTITY % local.otheraddr.attrib "">
  <!ENTITY % otheraddr.role.attrib "%role.attrib;">
  
<!ENTITY % otheraddr.element "INCLUDE">
<![ %otheraddr.element; [
<!ELEMENT OtherAddr - - ((%docinfo.char.mix;)+)>
<!--end of otheraddr.element-->]]>
  
<!ENTITY % otheraddr.attlist "INCLUDE">
<![ %otheraddr.attlist; [
<!ATTLIST OtherAddr
		%common.attrib;
		%otheraddr.role.attrib;
		%local.otheraddr.attrib;
>
<!--end of otheraddr.attlist-->]]>
  <!--end of otheraddr.module-->]]>
<!--end of address.content.module-->]]>

<!-- Affiliation ...................... -->

<!ENTITY % affiliation.content.module "INCLUDE">
<![ %affiliation.content.module; [
<!ENTITY % affiliation.module "INCLUDE">
<![ %affiliation.module; [
<!ENTITY % local.affiliation.attrib "">
<!ENTITY % affiliation.role.attrib "%role.attrib;">

<!ENTITY % affiliation.element "INCLUDE">
<![ %affiliation.element; [
<!ELEMENT Affiliation - - (ShortAffil?, JobTitle*, OrgName?, OrgDiv*,
		Address*)>
<!--end of affiliation.element-->]]>

<!ENTITY % affiliation.attlist "INCLUDE">
<![ %affiliation.attlist; [
<!ATTLIST Affiliation
		%common.attrib;
		%affiliation.role.attrib;
		%local.affiliation.attrib;
>
<!--end of affiliation.attlist-->]]>
<!--end of affiliation.module-->]]>

  <!ENTITY % shortaffil.module "INCLUDE">
  <![ %shortaffil.module; [
  <!ENTITY % local.shortaffil.attrib "">
  <!ENTITY % shortaffil.role.attrib "%role.attrib;">
  
<!ENTITY % shortaffil.element "INCLUDE">
<![ %shortaffil.element; [
<!ELEMENT ShortAffil - - ((%docinfo.char.mix;)+)>
<!--end of shortaffil.element-->]]>
  
<!ENTITY % shortaffil.attlist "INCLUDE">
<![ %shortaffil.attlist; [
<!ATTLIST ShortAffil
		%common.attrib;
		%shortaffil.role.attrib;
		%local.shortaffil.attrib;
>
<!--end of shortaffil.attlist-->]]>
  <!--end of shortaffil.module-->]]>

  <!ENTITY % jobtitle.module "INCLUDE">
  <![ %jobtitle.module; [
  <!ENTITY % local.jobtitle.attrib "">
  <!ENTITY % jobtitle.role.attrib "%role.attrib;">
  
<!ENTITY % jobtitle.element "INCLUDE">
<![ %jobtitle.element; [
<!ELEMENT JobTitle - - ((%docinfo.char.mix;)+)>
<!--end of jobtitle.element-->]]>
  
<!ENTITY % jobtitle.attlist "INCLUDE">
<![ %jobtitle.attlist; [
<!ATTLIST JobTitle
		%common.attrib;
		%jobtitle.role.attrib;
		%local.jobtitle.attrib;
>
<!--end of jobtitle.attlist-->]]>
  <!--end of jobtitle.module-->]]>

  <!-- OrgName (defined elsewhere in this section)-->

  <!ENTITY % orgdiv.module "INCLUDE">
  <![ %orgdiv.module; [
  <!ENTITY % local.orgdiv.attrib "">
  <!ENTITY % orgdiv.role.attrib "%role.attrib;">
  
<!ENTITY % orgdiv.element "INCLUDE">
<![ %orgdiv.element; [
<!ELEMENT OrgDiv - - ((%docinfo.char.mix;)+)>
<!--end of orgdiv.element-->]]>
  
<!ENTITY % orgdiv.attlist "INCLUDE">
<![ %orgdiv.attlist; [
<!ATTLIST OrgDiv
		%common.attrib;
		%orgdiv.role.attrib;
		%local.orgdiv.attrib;
>
<!--end of orgdiv.attlist-->]]>
  <!--end of orgdiv.module-->]]>

  <!-- Address (defined elsewhere in this section)-->
<!--end of affiliation.content.module-->]]>

<!-- ArtPageNums ...................... -->

<!ENTITY % artpagenums.module "INCLUDE">
<![ %artpagenums.module; [
<!ENTITY % local.artpagenums.attrib "">
<!ENTITY % argpagenums.role.attrib "%role.attrib;">

<!ENTITY % artpagenums.element "INCLUDE">
<![ %artpagenums.element; [
<!ELEMENT ArtPageNums - - ((%docinfo.char.mix;)+)>
<!--end of artpagenums.element-->]]>

<!ENTITY % artpagenums.attlist "INCLUDE">
<![ %artpagenums.attlist; [
<!ATTLIST ArtPageNums
		%common.attrib;
		%argpagenums.role.attrib;
		%local.artpagenums.attrib;
>
<!--end of artpagenums.attlist-->]]>
<!--end of artpagenums.module-->]]>

<!-- Author ........................... -->

<!ENTITY % author.module "INCLUDE">
<![ %author.module; [
<!ENTITY % local.author.attrib "">
<!ENTITY % author.role.attrib "%role.attrib;">

<!ENTITY % author.element "INCLUDE">
<![ %author.element; [
<!ELEMENT Author - - ((%person.ident.mix;)+)>
<!--end of author.element-->]]>

<!ENTITY % author.attlist "INCLUDE">
<![ %author.attlist; [
<!ATTLIST Author
		%common.attrib;
		%author.role.attrib;
		%local.author.attrib;
>
<!--end of author.attlist-->]]>
<!--(see "Personal identity elements" for %person.ident.mix;)-->
<!--end of author.module-->]]>

<!-- AuthorGroup ...................... -->

<!ENTITY % authorgroup.content.module "INCLUDE">
<![ %authorgroup.content.module; [
<!ENTITY % authorgroup.module "INCLUDE">
<![ %authorgroup.module; [
<!ENTITY % local.authorgroup.attrib "">
<!ENTITY % authorgroup.role.attrib "%role.attrib;">

<!ENTITY % authorgroup.element "INCLUDE">
<![ %authorgroup.element; [
<!ELEMENT AuthorGroup - - ((Author|Editor|Collab|CorpAuthor|OtherCredit)+)>
<!--end of authorgroup.element-->]]>

<!ENTITY % authorgroup.attlist "INCLUDE">
<![ %authorgroup.attlist; [
<!ATTLIST AuthorGroup
		%common.attrib;
		%authorgroup.role.attrib;
		%local.authorgroup.attrib;
>
<!--end of authorgroup.attlist-->]]>
<!--end of authorgroup.module-->]]>

  <!-- Author (defined elsewhere in this section)-->
  <!-- Editor (defined elsewhere in this section)-->

  <!ENTITY % collab.content.module "INCLUDE">
  <![ %collab.content.module; [
  <!ENTITY % collab.module "INCLUDE">
  <![ %collab.module; [
  <!ENTITY % local.collab.attrib "">
  <!ENTITY % collab.role.attrib "%role.attrib;">
  
<!ENTITY % collab.element "INCLUDE">
<![ %collab.element; [
<!ELEMENT Collab - - (CollabName, Affiliation*)>
<!--end of collab.element-->]]>
  
<!ENTITY % collab.attlist "INCLUDE">
<![ %collab.attlist; [
<!ATTLIST Collab
		%common.attrib;
		%collab.role.attrib;
		%local.collab.attrib;
>
<!--end of collab.attlist-->]]>
  <!--end of collab.module-->]]>

    <!ENTITY % collabname.module "INCLUDE">
  <![ %collabname.module; [
  <!ENTITY % local.collabname.attrib "">
  <!ENTITY % collabname.role.attrib "%role.attrib;">
    
<!ENTITY % collabname.element "INCLUDE">
<![ %collabname.element; [
<!ELEMENT CollabName - - ((%docinfo.char.mix;)+)>
<!--end of collabname.element-->]]>
    
<!ENTITY % collabname.attlist "INCLUDE">
<![ %collabname.attlist; [
<!ATTLIST CollabName
		%common.attrib;
		%collabname.role.attrib;
		%local.collabname.attrib;
>
<!--end of collabname.attlist-->]]>
    <!--end of collabname.module-->]]>

    <!-- Affiliation (defined elsewhere in this section)-->
  <!--end of collab.content.module-->]]>

  <!-- CorpAuthor (defined elsewhere in this section)-->
  <!-- OtherCredit (defined elsewhere in this section)-->

<!--end of authorgroup.content.module-->]]>

<!-- AuthorInitials ................... -->

<!ENTITY % authorinitials.module "INCLUDE">
<![ %authorinitials.module; [
<!ENTITY % local.authorinitials.attrib "">
<!ENTITY % authorinitials.role.attrib "%role.attrib;">

<!ENTITY % authorinitials.element "INCLUDE">
<![ %authorinitials.element; [
<!ELEMENT AuthorInitials - - ((%docinfo.char.mix;)+)>
<!--end of authorinitials.element-->]]>

<!ENTITY % authorinitials.attlist "INCLUDE">
<![ %authorinitials.attlist; [
<!ATTLIST AuthorInitials
		%common.attrib;
		%authorinitials.role.attrib;
		%local.authorinitials.attrib;
>
<!--end of authorinitials.attlist-->]]>
<!--end of authorinitials.module-->]]>

<!-- ConfGroup ........................ -->

<!ENTITY % confgroup.content.module "INCLUDE">
<![ %confgroup.content.module; [
<!ENTITY % confgroup.module "INCLUDE">
<![ %confgroup.module; [
<!ENTITY % local.confgroup.attrib "">
<!ENTITY % confgroup.role.attrib "%role.attrib;">

<!ENTITY % confgroup.element "INCLUDE">
<![ %confgroup.element; [
<!ELEMENT ConfGroup - - ((ConfDates|ConfTitle|ConfNum|Address|ConfSponsor)*)>
<!--end of confgroup.element-->]]>

<!ENTITY % confgroup.attlist "INCLUDE">
<![ %confgroup.attlist; [
<!ATTLIST ConfGroup
		%common.attrib;
		%confgroup.role.attrib;
		%local.confgroup.attrib;
>
<!--end of confgroup.attlist-->]]>
<!--end of confgroup.module-->]]>

  <!ENTITY % confdates.module "INCLUDE">
  <![ %confdates.module; [
  <!ENTITY % local.confdates.attrib "">
  <!ENTITY % confdates.role.attrib "%role.attrib;">
  
<!ENTITY % confdates.element "INCLUDE">
<![ %confdates.element; [
<!ELEMENT ConfDates - - ((%docinfo.char.mix;)+)>
<!--end of confdates.element-->]]>
  
<!ENTITY % confdates.attlist "INCLUDE">
<![ %confdates.attlist; [
<!ATTLIST ConfDates
		%common.attrib;
		%confdates.role.attrib;
		%local.confdates.attrib;
>
<!--end of confdates.attlist-->]]>
  <!--end of confdates.module-->]]>

  <!ENTITY % conftitle.module "INCLUDE">
  <![ %conftitle.module; [
  <!ENTITY % local.conftitle.attrib "">
  <!ENTITY % conftitle.role.attrib "%role.attrib;">
  
<!ENTITY % conftitle.element "INCLUDE">
<![ %conftitle.element; [
<!ELEMENT ConfTitle - - ((%docinfo.char.mix;)+)>
<!--end of conftitle.element-->]]>
  
<!ENTITY % conftitle.attlist "INCLUDE">
<![ %conftitle.attlist; [
<!ATTLIST ConfTitle
		%common.attrib;
		%conftitle.role.attrib;
		%local.conftitle.attrib;
>
<!--end of conftitle.attlist-->]]>
  <!--end of conftitle.module-->]]>

  <!ENTITY % confnum.module "INCLUDE">
  <![ %confnum.module; [
  <!ENTITY % local.confnum.attrib "">
  <!ENTITY % confnum.role.attrib "%role.attrib;">
  
<!ENTITY % confnum.element "INCLUDE">
<![ %confnum.element; [
<!ELEMENT ConfNum - - ((%docinfo.char.mix;)+)>
<!--end of confnum.element-->]]>
  
<!ENTITY % confnum.attlist "INCLUDE">
<![ %confnum.attlist; [
<!ATTLIST ConfNum
		%common.attrib;
		%confnum.role.attrib;
		%local.confnum.attrib;
>
<!--end of confnum.attlist-->]]>
  <!--end of confnum.module-->]]>

  <!-- Address (defined elsewhere in this section)-->

  <!ENTITY % confsponsor.module "INCLUDE">
  <![ %confsponsor.module; [
  <!ENTITY % local.confsponsor.attrib "">
  <!ENTITY % confsponsor.role.attrib "%role.attrib;">
  
<!ENTITY % confsponsor.element "INCLUDE">
<![ %confsponsor.element; [
<!ELEMENT ConfSponsor - - ((%docinfo.char.mix;)+)>
<!--end of confsponsor.element-->]]>
  
<!ENTITY % confsponsor.attlist "INCLUDE">
<![ %confsponsor.attlist; [
<!ATTLIST ConfSponsor
		%common.attrib;
		%confsponsor.role.attrib;
		%local.confsponsor.attrib;
>
<!--end of confsponsor.attlist-->]]>
  <!--end of confsponsor.module-->]]>
<!--end of confgroup.content.module-->]]>

<!-- ContractNum ...................... -->

<!ENTITY % contractnum.module "INCLUDE">
<![ %contractnum.module; [
<!ENTITY % local.contractnum.attrib "">
<!ENTITY % contractnum.role.attrib "%role.attrib;">

<!ENTITY % contractnum.element "INCLUDE">
<![ %contractnum.element; [
<!ELEMENT ContractNum - - ((%docinfo.char.mix;)+)>
<!--end of contractnum.element-->]]>

<!ENTITY % contractnum.attlist "INCLUDE">
<![ %contractnum.attlist; [
<!ATTLIST ContractNum
		%common.attrib;
		%contractnum.role.attrib;
		%local.contractnum.attrib;
>
<!--end of contractnum.attlist-->]]>
<!--end of contractnum.module-->]]>

<!-- ContractSponsor .................. -->

<!ENTITY % contractsponsor.module "INCLUDE">
<![ %contractsponsor.module; [
<!ENTITY % local.contractsponsor.attrib "">
<!ENTITY % contractsponsor.role.attrib "%role.attrib;">

<!ENTITY % contractsponsor.element "INCLUDE">
<![ %contractsponsor.element; [
<!ELEMENT ContractSponsor - - ((%docinfo.char.mix;)+)>
<!--end of contractsponsor.element-->]]>

<!ENTITY % contractsponsor.attlist "INCLUDE">
<![ %contractsponsor.attlist; [
<!ATTLIST ContractSponsor
		%common.attrib;
		%contractsponsor.role.attrib;
		%local.contractsponsor.attrib;
>
<!--end of contractsponsor.attlist-->]]>
<!--end of contractsponsor.module-->]]>

<!-- Copyright ........................ -->

<!ENTITY % copyright.content.module "INCLUDE">
<![ %copyright.content.module; [
<!ENTITY % copyright.module "INCLUDE">
<![ %copyright.module; [
<!ENTITY % local.copyright.attrib "">
<!ENTITY % copyright.role.attrib "%role.attrib;">

<!ENTITY % copyright.element "INCLUDE">
<![ %copyright.element; [
<!ELEMENT Copyright - - (Year+, Holder*)>
<!--end of copyright.element-->]]>

<!ENTITY % copyright.attlist "INCLUDE">
<![ %copyright.attlist; [
<!ATTLIST Copyright
		%common.attrib;
		%copyright.role.attrib;
		%local.copyright.attrib;
>
<!--end of copyright.attlist-->]]>
<!--end of copyright.module-->]]>

  <!ENTITY % year.module "INCLUDE">
  <![ %year.module; [
  <!ENTITY % local.year.attrib "">
  <!ENTITY % year.role.attrib "%role.attrib;">
  
<!ENTITY % year.element "INCLUDE">
<![ %year.element; [
<!ELEMENT Year - - ((%docinfo.char.mix;)+)>
<!--end of year.element-->]]>
  
<!ENTITY % year.attlist "INCLUDE">
<![ %year.attlist; [
<!ATTLIST Year
		%common.attrib;
		%year.role.attrib;
		%local.year.attrib;
>
<!--end of year.attlist-->]]>
  <!--end of year.module-->]]>

  <!ENTITY % holder.module "INCLUDE">
  <![ %holder.module; [
  <!ENTITY % local.holder.attrib "">
  <!ENTITY % holder.role.attrib "%role.attrib;">
  
<!ENTITY % holder.element "INCLUDE">
<![ %holder.element; [
<!ELEMENT Holder - - ((%docinfo.char.mix;)+)>
<!--end of holder.element-->]]>
  
<!ENTITY % holder.attlist "INCLUDE">
<![ %holder.attlist; [
<!ATTLIST Holder
		%common.attrib;
		%holder.role.attrib;
		%local.holder.attrib;
>
<!--end of holder.attlist-->]]>
  <!--end of holder.module-->]]>
<!--end of copyright.content.module-->]]>

<!-- CorpAuthor ....................... -->

<!ENTITY % corpauthor.module "INCLUDE">
<![ %corpauthor.module; [
<!ENTITY % local.corpauthor.attrib "">
<!ENTITY % corpauthor.role.attrib "%role.attrib;">

<!ENTITY % corpauthor.element "INCLUDE">
<![ %corpauthor.element; [
<!ELEMENT CorpAuthor - - ((%docinfo.char.mix;)+)>
<!--end of corpauthor.element-->]]>

<!ENTITY % corpauthor.attlist "INCLUDE">
<![ %corpauthor.attlist; [
<!ATTLIST CorpAuthor
		%common.attrib;
		%corpauthor.role.attrib;
		%local.corpauthor.attrib;
>
<!--end of corpauthor.attlist-->]]>
<!--end of corpauthor.module-->]]>

<!-- CorpName ......................... -->

<!ENTITY % corpname.module "INCLUDE">
<![ %corpname.module; [
<!ENTITY % local.corpname.attrib "">

<!ENTITY % corpname.element "INCLUDE">
<![ %corpname.element; [
<!ELEMENT CorpName - - ((%docinfo.char.mix;)+)>
<!--end of corpname.element-->]]>
<!ENTITY % corpname.role.attrib "%role.attrib;">

<!ENTITY % corpname.attlist "INCLUDE">
<![ %corpname.attlist; [
<!ATTLIST CorpName
		%common.attrib;
		%corpname.role.attrib;
		%local.corpname.attrib;
>
<!--end of corpname.attlist-->]]>
<!--end of corpname.module-->]]>

<!-- Date ............................. -->

<!ENTITY % date.module "INCLUDE">
<![ %date.module; [
<!ENTITY % local.date.attrib "">
<!ENTITY % date.role.attrib "%role.attrib;">

<!ENTITY % date.element "INCLUDE">
<![ %date.element; [
<!ELEMENT Date - - ((%docinfo.char.mix;)+)>
<!--end of date.element-->]]>

<!ENTITY % date.attlist "INCLUDE">
<![ %date.attlist; [
<!ATTLIST Date
		%common.attrib;
		%date.role.attrib;
		%local.date.attrib;
>
<!--end of date.attlist-->]]>
<!--end of date.module-->]]>

<!-- Edition .......................... -->

<!ENTITY % edition.module "INCLUDE">
<![ %edition.module; [
<!ENTITY % local.edition.attrib "">
<!ENTITY % edition.role.attrib "%role.attrib;">

<!ENTITY % edition.element "INCLUDE">
<![ %edition.element; [
<!ELEMENT Edition - - ((%docinfo.char.mix;)+)>
<!--end of edition.element-->]]>

<!ENTITY % edition.attlist "INCLUDE">
<![ %edition.attlist; [
<!ATTLIST Edition
		%common.attrib;
		%edition.role.attrib;
		%local.edition.attrib;
>
<!--end of edition.attlist-->]]>
<!--end of edition.module-->]]>

<!-- Editor ........................... -->

<!ENTITY % editor.module "INCLUDE">
<![ %editor.module; [
<!ENTITY % local.editor.attrib "">
<!ENTITY % editor.role.attrib "%role.attrib;">

<!ENTITY % editor.element "INCLUDE">
<![ %editor.element; [
<!ELEMENT Editor - - ((%person.ident.mix;)+)>
<!--end of editor.element-->]]>

<!ENTITY % editor.attlist "INCLUDE">
<![ %editor.attlist; [
<!ATTLIST Editor
		%common.attrib;
		%editor.role.attrib;
		%local.editor.attrib;
>
<!--end of editor.attlist-->]]>
  <!--(see "Personal identity elements" for %person.ident.mix;)-->
<!--end of editor.module-->]]>

<!-- ISBN ............................. -->

<!ENTITY % isbn.module "INCLUDE">
<![ %isbn.module; [
<!ENTITY % local.isbn.attrib "">
<!ENTITY % isbn.role.attrib "%role.attrib;">

<!ENTITY % isbn.element "INCLUDE">
<![ %isbn.element; [
<!ELEMENT ISBN - - ((%docinfo.char.mix;)+)>
<!--end of isbn.element-->]]>

<!ENTITY % isbn.attlist "INCLUDE">
<![ %isbn.attlist; [
<!ATTLIST ISBN
		%common.attrib;
		%isbn.role.attrib;
		%local.isbn.attrib;
>
<!--end of isbn.attlist-->]]>
<!--end of isbn.module-->]]>

<!-- ISSN ............................. -->

<!ENTITY % issn.module "INCLUDE">
<![ %issn.module; [
<!ENTITY % local.issn.attrib "">
<!ENTITY % issn.role.attrib "%role.attrib;">

<!ENTITY % issn.element "INCLUDE">
<![ %issn.element; [
<!ELEMENT ISSN - - ((%docinfo.char.mix;)+)>
<!--end of issn.element-->]]>

<!ENTITY % issn.attlist "INCLUDE">
<![ %issn.attlist; [
<!ATTLIST ISSN
		%common.attrib;
		%issn.role.attrib;
		%local.issn.attrib;
>
<!--end of issn.attlist-->]]>
<!--end of issn.module-->]]>

<!-- InvPartNumber .................... -->

<!ENTITY % invpartnumber.module "INCLUDE">
<![ %invpartnumber.module; [
<!ENTITY % local.invpartnumber.attrib "">
<!ENTITY % invpartnumber.role.attrib "%role.attrib;">

<!ENTITY % invpartnumber.element "INCLUDE">
<![ %invpartnumber.element; [
<!ELEMENT InvPartNumber - - ((%docinfo.char.mix;)+)>
<!--end of invpartnumber.element-->]]>

<!ENTITY % invpartnumber.attlist "INCLUDE">
<![ %invpartnumber.attlist; [
<!ATTLIST InvPartNumber
		%common.attrib;
		%invpartnumber.role.attrib;
		%local.invpartnumber.attrib;
>
<!--end of invpartnumber.attlist-->]]>
<!--end of invpartnumber.module-->]]>

<!-- IssueNum ......................... -->

<!ENTITY % issuenum.module "INCLUDE">
<![ %issuenum.module; [
<!ENTITY % local.issuenum.attrib "">
<!ENTITY % issuenum.role.attrib "%role.attrib;">

<!ENTITY % issuenum.element "INCLUDE">
<![ %issuenum.element; [
<!ELEMENT IssueNum - - ((%docinfo.char.mix;)+)>
<!--end of issuenum.element-->]]>

<!ENTITY % issuenum.attlist "INCLUDE">
<![ %issuenum.attlist; [
<!ATTLIST IssueNum
		%common.attrib;
		%issuenum.role.attrib;
		%local.issuenum.attrib;
>
<!--end of issuenum.attlist-->]]>
<!--end of issuenum.module-->]]>

<!-- LegalNotice ...................... -->

<!ENTITY % legalnotice.module "INCLUDE">
<![ %legalnotice.module; [
<!ENTITY % local.legalnotice.attrib "">
<!ENTITY % legalnotice.role.attrib "%role.attrib;">

<!ENTITY % legalnotice.element "INCLUDE">
<![ %legalnotice.element; [
<!ELEMENT LegalNotice - - (Title?, (%legalnotice.mix;)+) %formal.exclusion;>
<!--end of legalnotice.element-->]]>

<!ENTITY % legalnotice.attlist "INCLUDE">
<![ %legalnotice.attlist; [
<!ATTLIST LegalNotice
		%common.attrib;
		%legalnotice.role.attrib;
		%local.legalnotice.attrib;
>
<!--end of legalnotice.attlist-->]]>
<!--end of legalnotice.module-->]]>

<!-- ModeSpec ......................... -->

<!ENTITY % modespec.module "INCLUDE">
<![ %modespec.module; [
<!ENTITY % local.modespec.attrib "">
<!ENTITY % modespec.role.attrib "%role.attrib;">

<!ENTITY % modespec.element "INCLUDE">
<![ %modespec.element; [
<!ELEMENT ModeSpec - - ((%docinfo.char.mix;)+) %ubiq.exclusion;>
<!--end of modespec.element-->]]>

<!ENTITY % modespec.attlist "INCLUDE">
<![ %modespec.attlist; [
<!ATTLIST ModeSpec
		--
		Application: Type of action required for completion
		of the links to which the ModeSpec is relevant (e.g.,
		retrieval query)
		--
		Application	NOTATION
				(%notation.class;)	#IMPLIED
		%common.attrib;
		%modespec.role.attrib;
		%local.modespec.attrib;
>
<!--end of modespec.attlist-->]]>
<!--end of modespec.module-->]]>

<!-- OrgName .......................... -->

<!ENTITY % orgname.module "INCLUDE">
<![ %orgname.module; [
<!ENTITY % local.orgname.attrib "">
<!ENTITY % orgname.role.attrib "%role.attrib;">

<!ENTITY % orgname.element "INCLUDE">
<![ %orgname.element; [
<!ELEMENT OrgName - - ((%docinfo.char.mix;)+)>
<!--end of orgname.element-->]]>

<!ENTITY % orgname.attlist "INCLUDE">
<![ %orgname.attlist; [
<!ATTLIST OrgName
		%common.attrib;
		%orgname.role.attrib;
		%local.orgname.attrib;
>
<!--end of orgname.attlist-->]]>
<!--end of orgname.module-->]]>

<!-- OtherCredit ...................... -->

<!ENTITY % othercredit.module "INCLUDE">
<![ %othercredit.module; [
<!ENTITY % local.othercredit.attrib "">
<!ENTITY % othercredit.role.attrib "%role.attrib;">

<!ENTITY % othercredit.element "INCLUDE">
<![ %othercredit.element; [
<!ELEMENT OtherCredit - - ((%person.ident.mix;)+)>
<!--end of othercredit.element-->]]>

<!ENTITY % othercredit.attlist "INCLUDE">
<![ %othercredit.attlist; [
<!ATTLIST OtherCredit
		%common.attrib;
		%othercredit.role.attrib;
		%local.othercredit.attrib;
>
<!--end of othercredit.attlist-->]]>
  <!--(see "Personal identity elements" for %person.ident.mix;)-->
<!--end of othercredit.module-->]]>

<!-- PageNums ......................... -->

<!ENTITY % pagenums.module "INCLUDE">
<![ %pagenums.module; [
<!ENTITY % local.pagenums.attrib "">
<!ENTITY % pagenums.role.attrib "%role.attrib;">

<!ENTITY % pagenums.element "INCLUDE">
<![ %pagenums.element; [
<!ELEMENT PageNums - - ((%docinfo.char.mix;)+)>
<!--end of pagenums.element-->]]>

<!ENTITY % pagenums.attlist "INCLUDE">
<![ %pagenums.attlist; [
<!ATTLIST PageNums
		%common.attrib;
		%pagenums.role.attrib;
		%local.pagenums.attrib;
>
<!--end of pagenums.attlist-->]]>
<!--end of pagenums.module-->]]>

<!-- Personal identity elements ....... -->

<!-- These elements are used only within Author, Editor, and 
OtherCredit. -->

<!ENTITY % person.ident.module "INCLUDE">
<![ %person.ident.module; [
  <!ENTITY % contrib.module "INCLUDE">
  <![ %contrib.module; [
  <!ENTITY % local.contrib.attrib "">
  <!ENTITY % contrib.role.attrib "%role.attrib;">
  
<!ENTITY % contrib.element "INCLUDE">
<![ %contrib.element; [
<!ELEMENT Contrib - - ((%docinfo.char.mix;)+)>
<!--end of contrib.element-->]]>
  
<!ENTITY % contrib.attlist "INCLUDE">
<![ %contrib.attlist; [
<!ATTLIST Contrib
		%common.attrib;
		%contrib.role.attrib;
		%local.contrib.attrib;
>
<!--end of contrib.attlist-->]]>
  <!--end of contrib.module-->]]>

  <!ENTITY % firstname.module "INCLUDE">
  <![ %firstname.module; [
  <!ENTITY % local.firstname.attrib "">
  <!ENTITY % firstname.role.attrib "%role.attrib;">
  
<!ENTITY % firstname.element "INCLUDE">
<![ %firstname.element; [
<!ELEMENT FirstName - - ((%docinfo.char.mix;)+)>
<!--end of firstname.element-->]]>
  
<!ENTITY % firstname.attlist "INCLUDE">
<![ %firstname.attlist; [
<!ATTLIST FirstName
		%common.attrib;
		%firstname.role.attrib;
		%local.firstname.attrib;
>
<!--end of firstname.attlist-->]]>
  <!--end of firstname.module-->]]>

  <!ENTITY % honorific.module "INCLUDE">
  <![ %honorific.module; [
  <!ENTITY % local.honorific.attrib "">
  <!ENTITY % honorific.role.attrib "%role.attrib;">
  
<!ENTITY % honorific.element "INCLUDE">
<![ %honorific.element; [
<!ELEMENT Honorific - - ((%docinfo.char.mix;)+)>
<!--end of honorific.element-->]]>
  
<!ENTITY % honorific.attlist "INCLUDE">
<![ %honorific.attlist; [
<!ATTLIST Honorific
		%common.attrib;
		%honorific.role.attrib;
		%local.honorific.attrib;
>
<!--end of honorific.attlist-->]]>
  <!--end of honorific.module-->]]>

  <!ENTITY % lineage.module "INCLUDE">
  <![ %lineage.module; [
  <!ENTITY % local.lineage.attrib "">
  <!ENTITY % lineage.role.attrib "%role.attrib;">
  
<!ENTITY % lineage.element "INCLUDE">
<![ %lineage.element; [
<!ELEMENT Lineage - - ((%docinfo.char.mix;)+)>
<!--end of lineage.element-->]]>
  
<!ENTITY % lineage.attlist "INCLUDE">
<![ %lineage.attlist; [
<!ATTLIST Lineage
		%common.attrib;
		%lineage.role.attrib;
		%local.lineage.attrib;
>
<!--end of lineage.attlist-->]]>
  <!--end of lineage.module-->]]>

  <!ENTITY % othername.module "INCLUDE">
  <![ %othername.module; [
  <!ENTITY % local.othername.attrib "">
  <!ENTITY % othername.role.attrib "%role.attrib;">
  
<!ENTITY % othername.element "INCLUDE">
<![ %othername.element; [
<!ELEMENT OtherName - - ((%docinfo.char.mix;)+)>
<!--end of othername.element-->]]>
  
<!ENTITY % othername.attlist "INCLUDE">
<![ %othername.attlist; [
<!ATTLIST OtherName
		%common.attrib;
		%othername.role.attrib;
		%local.othername.attrib;
>
<!--end of othername.attlist-->]]>
  <!--end of othername.module-->]]>

  <!ENTITY % surname.module "INCLUDE">
  <![ %surname.module; [
  <!ENTITY % local.surname.attrib "">
  <!ENTITY % surname.role.attrib "%role.attrib;">
  
<!ENTITY % surname.element "INCLUDE">
<![ %surname.element; [
<!ELEMENT Surname - - ((%docinfo.char.mix;)+)>
<!--end of surname.element-->]]>
  
<!ENTITY % surname.attlist "INCLUDE">
<![ %surname.attlist; [
<!ATTLIST Surname
		%common.attrib;
		%surname.role.attrib;
		%local.surname.attrib;
>
<!--end of surname.attlist-->]]>
  <!--end of surname.module-->]]>
<!--end of person.ident.module-->]]>

<!-- PrintHistory ..................... -->

<!ENTITY % printhistory.module "INCLUDE">
<![ %printhistory.module; [
<!ENTITY % local.printhistory.attrib "">
<!ENTITY % printhistory.role.attrib "%role.attrib;">

<!ENTITY % printhistory.element "INCLUDE">
<![ %printhistory.element; [
<!ELEMENT PrintHistory - - ((%para.class;)+)>
<!--end of printhistory.element-->]]>

<!ENTITY % printhistory.attlist "INCLUDE">
<![ %printhistory.attlist; [
<!ATTLIST PrintHistory
		%common.attrib;
		%printhistory.role.attrib;
		%local.printhistory.attrib;
>
<!--end of printhistory.attlist-->]]>
<!--end of printhistory.module-->]]>

<!-- ProductName ...................... -->

<!ENTITY % productname.module "INCLUDE">
<![ %productname.module; [
<!ENTITY % local.productname.attrib "">
<!ENTITY % productname.role.attrib "%role.attrib;">

<!ENTITY % productname.element "INCLUDE">
<![ %productname.element; [
<!ELEMENT ProductName - - ((%para.char.mix;)+)>
<!--end of productname.element-->]]>

<!ENTITY % productname.attlist "INCLUDE">
<![ %productname.attlist; [
<!ATTLIST ProductName
		--
		Class: More precisely identifies the item the element names
		--
		Class		(Service
				|Trade
				|Registered
				|Copyright)	Trade
		%common.attrib;
		%productname.role.attrib;
		%local.productname.attrib;
>
<!--end of productname.attlist-->]]>
<!--end of productname.module-->]]>

<!-- ProductNumber .................... -->

<!ENTITY % productnumber.module "INCLUDE">
<![ %productnumber.module; [
<!ENTITY % local.productnumber.attrib "">
<!ENTITY % productnumber.role.attrib "%role.attrib;">

<!ENTITY % productnumber.element "INCLUDE">
<![ %productnumber.element; [
<!ELEMENT ProductNumber - - ((%docinfo.char.mix;)+)>
<!--end of productnumber.element-->]]>

<!ENTITY % productnumber.attlist "INCLUDE">
<![ %productnumber.attlist; [
<!ATTLIST ProductNumber
		%common.attrib;
		%productnumber.role.attrib;
		%local.productnumber.attrib;
>
<!--end of productnumber.attlist-->]]>
<!--end of productnumber.module-->]]>

<!-- PubDate .......................... -->

<!ENTITY % pubdate.module "INCLUDE">
<![ %pubdate.module; [
<!ENTITY % local.pubdate.attrib "">
<!ENTITY % pubdate.role.attrib "%role.attrib;">

<!ENTITY % pubdate.element "INCLUDE">
<![ %pubdate.element; [
<!ELEMENT PubDate - - ((%docinfo.char.mix;)+)>
<!--end of pubdate.element-->]]>

<!ENTITY % pubdate.attlist "INCLUDE">
<![ %pubdate.attlist; [
<!ATTLIST PubDate
		%common.attrib;
		%pubdate.role.attrib;
		%local.pubdate.attrib;
>
<!--end of pubdate.attlist-->]]>
<!--end of pubdate.module-->]]>

<!-- Publisher ........................ -->

<!ENTITY % publisher.content.module "INCLUDE">
<![ %publisher.content.module; [
<!ENTITY % publisher.module "INCLUDE">
<![ %publisher.module; [
<!ENTITY % local.publisher.attrib "">
<!ENTITY % publisher.role.attrib "%role.attrib;">

<!ENTITY % publisher.element "INCLUDE">
<![ %publisher.element; [
<!ELEMENT Publisher - - (PublisherName, Address*)>
<!--end of publisher.element-->]]>

<!ENTITY % publisher.attlist "INCLUDE">
<![ %publisher.attlist; [
<!ATTLIST Publisher
		%common.attrib;
		%publisher.role.attrib;
		%local.publisher.attrib;
>
<!--end of publisher.attlist-->]]>
<!--end of publisher.module-->]]>

  <!ENTITY % publishername.module "INCLUDE">
  <![ %publishername.module; [
  <!ENTITY % local.publishername.attrib "">
  <!ENTITY % publishername.role.attrib "%role.attrib;">
  
<!ENTITY % publishername.element "INCLUDE">
<![ %publishername.element; [
<!ELEMENT PublisherName - - ((%docinfo.char.mix;)+)>
<!--end of publishername.element-->]]>
  
<!ENTITY % publishername.attlist "INCLUDE">
<![ %publishername.attlist; [
<!ATTLIST PublisherName
		%common.attrib;
		%publishername.role.attrib;
		%local.publishername.attrib;
>
<!--end of publishername.attlist-->]]>
  <!--end of publishername.module-->]]>

  <!-- Address (defined elsewhere in this section)-->
<!--end of publisher.content.module-->]]>

<!-- PubsNumber ....................... -->

<!ENTITY % pubsnumber.module "INCLUDE">
<![ %pubsnumber.module; [
<!ENTITY % local.pubsnumber.attrib "">
<!ENTITY % pubsnumber.role.attrib "%role.attrib;">

<!ENTITY % pubsnumber.element "INCLUDE">
<![ %pubsnumber.element; [
<!ELEMENT PubsNumber - - ((%docinfo.char.mix;)+)>
<!--end of pubsnumber.element-->]]>

<!ENTITY % pubsnumber.attlist "INCLUDE">
<![ %pubsnumber.attlist; [
<!ATTLIST PubsNumber
		%common.attrib;
		%pubsnumber.role.attrib;
		%local.pubsnumber.attrib;
>
<!--end of pubsnumber.attlist-->]]>
<!--end of pubsnumber.module-->]]>

<!-- ReleaseInfo ...................... -->

<!ENTITY % releaseinfo.module "INCLUDE">
<![ %releaseinfo.module; [
<!ENTITY % local.releaseinfo.attrib "">
<!ENTITY % releaseinfo.role.attrib "%role.attrib;">

<!ENTITY % releaseinfo.element "INCLUDE">
<![ %releaseinfo.element; [
<!ELEMENT ReleaseInfo - - ((%docinfo.char.mix;)+)>
<!--end of releaseinfo.element-->]]>

<!ENTITY % releaseinfo.attlist "INCLUDE">
<![ %releaseinfo.attlist; [
<!ATTLIST ReleaseInfo
		%common.attrib;
		%releaseinfo.role.attrib;
		%local.releaseinfo.attrib;
>
<!--end of releaseinfo.attlist-->]]>
<!--end of releaseinfo.module-->]]>

<!-- RevHistory ....................... -->

<!ENTITY % revhistory.content.module "INCLUDE">
<![ %revhistory.content.module; [
<!ENTITY % revhistory.module "INCLUDE">
<![ %revhistory.module; [
<!ENTITY % local.revhistory.attrib "">
<!ENTITY % revhistory.role.attrib "%role.attrib;">

<!ENTITY % revhistory.element "INCLUDE">
<![ %revhistory.element; [
<!ELEMENT RevHistory - - (Revision+)>
<!--end of revhistory.element-->]]>

<!ENTITY % revhistory.attlist "INCLUDE">
<![ %revhistory.attlist; [
<!ATTLIST RevHistory
		%common.attrib;
		%revhistory.role.attrib;
		%local.revhistory.attrib;
>
<!--end of revhistory.attlist-->]]>
<!--end of revhistory.module-->]]>

  <!ENTITY % revision.module "INCLUDE">
  <![ %revision.module; [
  <!ENTITY % local.revision.attrib "">
  <!ENTITY % revision.role.attrib "%role.attrib;">
  
<!ENTITY % revision.element "INCLUDE">
<![ %revision.element; [
<!ELEMENT Revision - - (RevNumber, Date, AuthorInitials*, (RevRemark|RevDescription)?)>
<!--end of revision.element-->]]>
  
<!ENTITY % revision.attlist "INCLUDE">
<![ %revision.attlist; [
<!ATTLIST Revision
		%common.attrib;
		%revision.role.attrib;
		%local.revision.attrib;
>
<!--end of revision.attlist-->]]>
  <!--end of revision.module-->]]>

  <!ENTITY % revnumber.module "INCLUDE">
  <![ %revnumber.module; [
  <!ENTITY % local.revnumber.attrib "">
  <!ENTITY % revnumber.role.attrib "%role.attrib;">
  
<!ENTITY % revnumber.element "INCLUDE">
<![ %revnumber.element; [
<!ELEMENT RevNumber - - ((%docinfo.char.mix;)+)>
<!--end of revnumber.element-->]]>
  
<!ENTITY % revnumber.attlist "INCLUDE">
<![ %revnumber.attlist; [
<!ATTLIST RevNumber
		%common.attrib;
		%revnumber.role.attrib;
		%local.revnumber.attrib;
>
<!--end of revnumber.attlist-->]]>
<!--end of revnumber.module-->]]>

<!-- Date (defined elsewhere in this section)-->
<!-- AuthorInitials (defined elsewhere in this section)-->

<!ENTITY % revremark.module "INCLUDE">
<![ %revremark.module; [
<!ENTITY % local.revremark.attrib "">
<!ENTITY % revremark.role.attrib "%role.attrib;">

<!ENTITY % revremark.element "INCLUDE">
<![ %revremark.element; [
<!ELEMENT RevRemark - - ((%docinfo.char.mix;)+)>
<!--end of revremark.element-->]]>

<!ENTITY % revremark.attlist "INCLUDE">
<![ %revremark.attlist; [
<!ATTLIST RevRemark
		%common.attrib;
		%revremark.role.attrib;
		%local.revremark.attrib;
>
<!--end of revremark.attlist-->]]>
<!--end of revremark.module-->]]>

<!ENTITY % revdescription.module "INCLUDE">
<![ %revdescription.module; [
<!ENTITY % local.revdescription.attrib "">
<!ENTITY % revdescription.role.attrib "%role.attrib;">

<!ENTITY % revdescription.element "INCLUDE">
<![ %revdescription.element; [
<!ELEMENT RevDescription - - ((%revdescription.mix;)+)>
<!--end of revdescription.element-->]]>

<!ENTITY % revdescription.attlist "INCLUDE">
<![ %revdescription.attlist; [
<!ATTLIST RevDescription
		%common.attrib;
		%revdescription.role.attrib;
		%local.revdescription.attrib;
>
<!--end of revdescription.attlist-->]]>
<!--end of revdescription.module-->]]>
<!--end of revhistory.content.module-->]]>

<!-- SeriesVolNums .................... -->

<!ENTITY % seriesvolnums.module "INCLUDE">
<![ %seriesvolnums.module; [
<!ENTITY % local.seriesvolnums.attrib "">
<!ENTITY % seriesvolnums.role.attrib "%role.attrib;">

<!ENTITY % seriesvolnums.element "INCLUDE">
<![ %seriesvolnums.element; [
<!ELEMENT SeriesVolNums - - ((%docinfo.char.mix;)+)>
<!--end of seriesvolnums.element-->]]>

<!ENTITY % seriesvolnums.attlist "INCLUDE">
<![ %seriesvolnums.attlist; [
<!ATTLIST SeriesVolNums
		%common.attrib;
		%seriesvolnums.role.attrib;
		%local.seriesvolnums.attrib;
>
<!--end of seriesvolnums.attlist-->]]>
<!--end of seriesvolnums.module-->]]>

<!-- VolumeNum ........................ -->

<!ENTITY % volumenum.module "INCLUDE">
<![ %volumenum.module; [
<!ENTITY % local.volumenum.attrib "">
<!ENTITY % volumenum.role.attrib "%role.attrib;">

<!ENTITY % volumenum.element "INCLUDE">
<![ %volumenum.element; [
<!ELEMENT VolumeNum - - ((%docinfo.char.mix;)+)>
<!--end of volumenum.element-->]]>

<!ENTITY % volumenum.attlist "INCLUDE">
<![ %volumenum.attlist; [
<!ATTLIST VolumeNum
		%common.attrib;
		%volumenum.role.attrib;
		%local.volumenum.attrib;
>
<!--end of volumenum.attlist-->]]>
<!--end of volumenum.module-->]]>

<!-- .................................. -->

<!--end of docinfo.content.module-->]]>

<!-- ...................................................................... -->
<!-- Inline, link, and ubiquitous elements ................................ -->

<!-- Technical and computer terms ......................................... -->

<!ENTITY % accel.module "INCLUDE">
<![ %accel.module; [
<!ENTITY % local.accel.attrib "">
<!ENTITY % accel.role.attrib "%role.attrib;">

<!ENTITY % accel.element "INCLUDE">
<![ %accel.element; [
<!ELEMENT Accel - - ((%smallcptr.char.mix;)+)>
<!--end of accel.element-->]]>

<!ENTITY % accel.attlist "INCLUDE">
<![ %accel.attlist; [
<!ATTLIST Accel
		%common.attrib;
		%accel.role.attrib;
		%local.accel.attrib;
>
<!--end of accel.attlist-->]]>
<!--end of accel.module-->]]>

<!ENTITY % action.module "INCLUDE">
<![ %action.module; [
<!ENTITY % local.action.attrib "">
<!ENTITY % action.role.attrib "%role.attrib;">

<!ENTITY % action.element "INCLUDE">
<![ %action.element; [
<!ELEMENT Action - - ((%smallcptr.char.mix;)+)>
<!--end of action.element-->]]>

<!ENTITY % action.attlist "INCLUDE">
<![ %action.attlist; [
<!ATTLIST Action
		%moreinfo.attrib;
		%common.attrib;
		%action.role.attrib;
		%local.action.attrib;
>
<!--end of action.attlist-->]]>
<!--end of action.module-->]]>

<!ENTITY % application.module "INCLUDE">
<![ %application.module; [
<!ENTITY % local.application.attrib "">
<!ENTITY % application.role.attrib "%role.attrib;">

<!ENTITY % application.element "INCLUDE">
<![ %application.element; [
<!ELEMENT Application - - ((%para.char.mix;)+)>
<!--end of application.element-->]]>

<!ENTITY % application.attlist "INCLUDE">
<![ %application.attlist; [
<!ATTLIST Application
		Class 		(Hardware
				|Software)	#IMPLIED
		%moreinfo.attrib;
		%common.attrib;
		%application.role.attrib;
		%local.application.attrib;
>
<!--end of application.attlist-->]]>
<!--end of application.module-->]]>

<!ENTITY % classname.module "INCLUDE">
<![ %classname.module; [
<!ENTITY % local.classname.attrib "">
<!ENTITY % classname.role.attrib "%role.attrib;">

<!ENTITY % classname.element "INCLUDE">
<![ %classname.element; [
<!ELEMENT ClassName - - ((%smallcptr.char.mix;)+)>
<!--end of classname.element-->]]>

<!ENTITY % classname.attlist "INCLUDE">
<![ %classname.attlist; [
<!ATTLIST ClassName
		%common.attrib;
		%classname.role.attrib;
		%local.classname.attrib;
>
<!--end of classname.attlist-->]]>
<!--end of classname.module-->]]>

<!ENTITY % co.module "INCLUDE">
<![ %co.module; [
<!ENTITY % local.co.attrib "">
<!-- CO is a callout area of the LineColumn unit type (a single character 
     position); the position is directly indicated by the location of CO. -->
<!ENTITY % co.role.attrib "%role.attrib;">

<!ENTITY % co.element "INCLUDE">
<![ %co.element; [
<!ELEMENT CO - O EMPTY>
<!--end of co.element-->]]>

<!ENTITY % co.attlist "INCLUDE">
<![ %co.attlist; [
<!ATTLIST CO
		%label.attrib; --bug number/symbol override or initialization--
		%linkends.attrib; --to any related information--
		%idreq.common.attrib;
		%co.role.attrib;
		%local.co.attrib;
>
<!--end of co.attlist-->]]>
<!--end of co.module-->]]>

<!ENTITY % command.module "INCLUDE">
<![ %command.module; [
<!ENTITY % local.command.attrib "">
<!ENTITY % command.role.attrib "%role.attrib;">

<!ENTITY % command.element "INCLUDE">
<![ %command.element; [
<!ELEMENT Command - - ((%cptr.char.mix;)+)>
<!--end of command.element-->]]>

<!ENTITY % command.attlist "INCLUDE">
<![ %command.attlist; [
<!ATTLIST Command
		%moreinfo.attrib;
		%common.attrib;
		%command.role.attrib;
		%local.command.attrib;
>
<!--end of command.attlist-->]]>
<!--end of command.module-->]]>

<!ENTITY % computeroutput.module "INCLUDE">
<![ %computeroutput.module; [
<!ENTITY % local.computeroutput.attrib "">
<!ENTITY % computeroutput.role.attrib "%role.attrib;">

<!ENTITY % computeroutput.element "INCLUDE">
<![ %computeroutput.element; [
<!ELEMENT ComputerOutput - - ((%cptr.char.mix;)+)>
<!--end of computeroutput.element-->]]>

<!ENTITY % computeroutput.attlist "INCLUDE">
<![ %computeroutput.attlist; [
<!ATTLIST ComputerOutput
		%moreinfo.attrib;
		%common.attrib;
		%computeroutput.role.attrib;
		%local.computeroutput.attrib;
>
<!--end of computeroutput.attlist-->]]>
<!--end of computeroutput.module-->]]>

<!ENTITY % database.module "INCLUDE">
<![ %database.module; [
<!ENTITY % local.database.attrib "">
<!ENTITY % database.role.attrib "%role.attrib;">

<!ENTITY % database.element "INCLUDE">
<![ %database.element; [
<!ELEMENT Database - - ((%smallcptr.char.mix;)+)>
<!--end of database.element-->]]>

<!ENTITY % database.attlist "INCLUDE">
<![ %database.attlist; [
<!ATTLIST Database
		--
		Class: Type of database the element names; no default
		--
		Class 		(Name
				|Table
				|Field
				|Key1
				|Key2
				|Record)	#IMPLIED
		%moreinfo.attrib;
		%common.attrib;
		%database.role.attrib;
		%local.database.attrib;
>
<!--end of database.attlist-->]]>
<!--end of database.module-->]]>

<!ENTITY % email.module "INCLUDE">
<![ %email.module; [
<!ENTITY % local.email.attrib "">
<!ENTITY % email.role.attrib "%role.attrib;">

<!ENTITY % email.element "INCLUDE">
<![ %email.element; [
<!ELEMENT Email - - ((%docinfo.char.mix;)+)>
<!--end of email.element-->]]>

<!ENTITY % email.attlist "INCLUDE">
<![ %email.attlist; [
<!ATTLIST Email
		%common.attrib;
		%email.role.attrib;
		%local.email.attrib;
>
<!--end of email.attlist-->]]>
<!--end of email.module-->]]>

<!ENTITY % envar.module "INCLUDE">
<![ %envar.module; [
<!ENTITY % local.envar.attrib "">
<!ENTITY % envar.role.attrib "%role.attrib;">

<!ENTITY % envar.element "INCLUDE">
<![ %envar.element; [
<!ELEMENT EnVar - - ((%smallcptr.char.mix;)+)>
<!--end of envar.element-->]]>

<!ENTITY % envar.attlist "INCLUDE">
<![ %envar.attlist; [
<!ATTLIST EnVar
		%common.attrib;
		%envar.role.attrib;
		%local.envar.attrib;
>
<!--end of envar.attlist-->]]>
<!--end of envar.module-->]]>


<!ENTITY % errorcode.module "INCLUDE">
<![ %errorcode.module; [
<!ENTITY % local.errorcode.attrib "">
<!ENTITY % errorcode.role.attrib "%role.attrib;">

<!ENTITY % errorcode.element "INCLUDE">
<![ %errorcode.element; [
<!ELEMENT ErrorCode - - ((%smallcptr.char.mix;)+)>
<!--end of errorcode.element-->]]>

<!ENTITY % errorcode.attlist "INCLUDE">
<![ %errorcode.attlist; [
<!ATTLIST ErrorCode
		%moreinfo.attrib;
		%common.attrib;
		%errorcode.role.attrib;
		%local.errorcode.attrib;
>
<!--end of errorcode.attlist-->]]>
<!--end of errorcode.module-->]]>

<!ENTITY % errorname.module "INCLUDE">
<![ %errorname.module; [
<!ENTITY % local.errorname.attrib "">
<!ENTITY % errorname.role.attrib "%role.attrib;">

<!ENTITY % errorname.element "INCLUDE">
<![ %errorname.element; [
<!ELEMENT ErrorName - - ((%smallcptr.char.mix;)+)>
<!--end of errorname.element-->]]>

<!ENTITY % errorname.attlist "INCLUDE">
<![ %errorname.attlist; [
<!ATTLIST ErrorName
		%common.attrib;
		%errorname.role.attrib;
		%local.errorname.attrib;
>
<!--end of errorname.attlist-->]]>
<!--end of errorname.module-->]]>

<!ENTITY % errortype.module "INCLUDE">
<![ %errortype.module; [
<!ENTITY % local.errortype.attrib "">
<!ENTITY % errortype.role.attrib "%role.attrib;">

<!ENTITY % errortype.element "INCLUDE">
<![ %errortype.element; [
<!ELEMENT ErrorType - - ((%smallcptr.char.mix;)+)>
<!--end of errortype.element-->]]>

<!ENTITY % errortype.attlist "INCLUDE">
<![ %errortype.attlist; [
<!ATTLIST ErrorType
		%common.attrib;
		%errortype.role.attrib;
		%local.errortype.attrib;
>
<!--end of errortype.attlist-->]]>
<!--end of errortype.module-->]]>

<!ENTITY % filename.module "INCLUDE">
<![ %filename.module; [
<!ENTITY % local.filename.attrib "">
<!ENTITY % filename.role.attrib "%role.attrib;">

<!ENTITY % filename.element "INCLUDE">
<![ %filename.element; [
<!ELEMENT Filename - - ((%smallcptr.char.mix;)+)>
<!--end of filename.element-->]]>

<!ENTITY % filename.attlist "INCLUDE">
<![ %filename.attlist; [
<!ATTLIST Filename
		--
		Class: Type of filename the element names; no default
		--
		Class		(HeaderFile
				|DeviceFile
				|Directory
				|LibraryFile
				|SymLink)	#IMPLIED
		--
		Path: Search path (possibly system-specific) in which 
		file can be found
		--
		Path		CDATA		#IMPLIED
		%moreinfo.attrib;
		%common.attrib;
		%filename.role.attrib;
		%local.filename.attrib;
>
<!--end of filename.attlist-->]]>
<!--end of filename.module-->]]>

<!ENTITY % function.module "INCLUDE">
<![ %function.module; [
<!ENTITY % local.function.attrib "">
<!ENTITY % function.role.attrib "%role.attrib;">

<!ENTITY % function.element "INCLUDE">
<![ %function.element; [
<!ELEMENT Function - - ((%cptr.char.mix;)+)>
<!--end of function.element-->]]>

<!ENTITY % function.attlist "INCLUDE">
<![ %function.attlist; [
<!ATTLIST Function
		%moreinfo.attrib;
		%common.attrib;
		%function.role.attrib;
		%local.function.attrib;
>
<!--end of function.attlist-->]]>
<!--end of function.module-->]]>

<!ENTITY % guibutton.module "INCLUDE">
<![ %guibutton.module; [
<!ENTITY % local.guibutton.attrib "">
<!ENTITY % guibutton.role.attrib "%role.attrib;">

<!ENTITY % guibutton.element "INCLUDE">
<![ %guibutton.element; [
<!ELEMENT GUIButton - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guibutton.element-->]]>

<!ENTITY % guibutton.attlist "INCLUDE">
<![ %guibutton.attlist; [
<!ATTLIST GUIButton
		%moreinfo.attrib;
		%common.attrib;
		%guibutton.role.attrib;
		%local.guibutton.attrib;
>
<!--end of guibutton.attlist-->]]>
<!--end of guibutton.module-->]]>

<!ENTITY % guiicon.module "INCLUDE">
<![ %guiicon.module; [
<!ENTITY % local.guiicon.attrib "">
<!ENTITY % guiicon.role.attrib "%role.attrib;">

<!ENTITY % guiicon.element "INCLUDE">
<![ %guiicon.element; [
<!ELEMENT GUIIcon - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guiicon.element-->]]>

<!ENTITY % guiicon.attlist "INCLUDE">
<![ %guiicon.attlist; [
<!ATTLIST GUIIcon
		%moreinfo.attrib;
		%common.attrib;
		%guiicon.role.attrib;
		%local.guiicon.attrib;
>
<!--end of guiicon.attlist-->]]>
<!--end of guiicon.module-->]]>

<!ENTITY % guilabel.module "INCLUDE">
<![ %guilabel.module; [
<!ENTITY % local.guilabel.attrib "">
<!ENTITY % guilabel.role.attrib "%role.attrib;">

<!ENTITY % guilabel.element "INCLUDE">
<![ %guilabel.element; [
<!ELEMENT GUILabel - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guilabel.element-->]]>

<!ENTITY % guilabel.attlist "INCLUDE">
<![ %guilabel.attlist; [
<!ATTLIST GUILabel
		%moreinfo.attrib;
		%common.attrib;
		%guilabel.role.attrib;
		%local.guilabel.attrib;
>
<!--end of guilabel.attlist-->]]>
<!--end of guilabel.module-->]]>

<!ENTITY % guimenu.module "INCLUDE">
<![ %guimenu.module; [
<!ENTITY % local.guimenu.attrib "">
<!ENTITY % guimenu.role.attrib "%role.attrib;">

<!ENTITY % guimenu.element "INCLUDE">
<![ %guimenu.element; [
<!ELEMENT GUIMenu - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guimenu.element-->]]>

<!ENTITY % guimenu.attlist "INCLUDE">
<![ %guimenu.attlist; [
<!ATTLIST GUIMenu
		%moreinfo.attrib;
		%common.attrib;
		%guimenu.role.attrib;
		%local.guimenu.attrib;
>
<!--end of guimenu.attlist-->]]>
<!--end of guimenu.module-->]]>

<!ENTITY % guimenuitem.module "INCLUDE">
<![ %guimenuitem.module; [
<!ENTITY % local.guimenuitem.attrib "">
<!ENTITY % guimenuitem.role.attrib "%role.attrib;">

<!ENTITY % guimenuitem.element "INCLUDE">
<![ %guimenuitem.element; [
<!ELEMENT GUIMenuItem - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guimenuitem.element-->]]>

<!ENTITY % guimenuitem.attlist "INCLUDE">
<![ %guimenuitem.attlist; [
<!ATTLIST GUIMenuItem
		%moreinfo.attrib;
		%common.attrib;
		%guimenuitem.role.attrib;
		%local.guimenuitem.attrib;
>
<!--end of guimenuitem.attlist-->]]>
<!--end of guimenuitem.module-->]]>

<!ENTITY % guisubmenu.module "INCLUDE">
<![ %guisubmenu.module; [
<!ENTITY % local.guisubmenu.attrib "">
<!ENTITY % guisubmenu.role.attrib "%role.attrib;">

<!ENTITY % guisubmenu.element "INCLUDE">
<![ %guisubmenu.element; [
<!ELEMENT GUISubmenu - - ((%smallcptr.char.mix;|Accel)+)>
<!--end of guisubmenu.element-->]]>

<!ENTITY % guisubmenu.attlist "INCLUDE">
<![ %guisubmenu.attlist; [
<!ATTLIST GUISubmenu
		%moreinfo.attrib;
		%common.attrib;
		%guisubmenu.role.attrib;
		%local.guisubmenu.attrib;
>
<!--end of guisubmenu.attlist-->]]>
<!--end of guisubmenu.module-->]]>

<!ENTITY % hardware.module "INCLUDE">
<![ %hardware.module; [
<!ENTITY % local.hardware.attrib "">
<!ENTITY % hardware.role.attrib "%role.attrib;">

<!ENTITY % hardware.element "INCLUDE">
<![ %hardware.element; [
<!ELEMENT Hardware - - ((%smallcptr.char.mix;)+)>
<!--end of hardware.element-->]]>

<!ENTITY % hardware.attlist "INCLUDE">
<![ %hardware.attlist; [
<!ATTLIST Hardware
		%moreinfo.attrib;
		%common.attrib;
		%hardware.role.attrib;
		%local.hardware.attrib;
>
<!--end of hardware.attlist-->]]>
<!--end of hardware.module-->]]>

<!ENTITY % interface.module "INCLUDE">
<![ %interface.module; [
<!ENTITY % local.interface.attrib "">
<!ENTITY % interface.role.attrib "%role.attrib;">

<!ENTITY % interface.element "INCLUDE">
<![ %interface.element; [
<!ELEMENT Interface - - (%smallcptr.char.mix;|Accel)*>
<!--end of interface.element-->]]>

<!ENTITY % interface.attlist "INCLUDE">
<![ %interface.attlist; [
<!ATTLIST Interface
		%moreinfo.attrib;
		%common.attrib;
		%interface.role.attrib;
		%local.interface.attrib;
>
<!--end of interface.attlist-->]]>
<!--end of interface.module-->]]>

<!ENTITY % keycap.module "INCLUDE">
<![ %keycap.module; [
<!ENTITY % local.keycap.attrib "">
<!ENTITY % keycap.role.attrib "%role.attrib;">

<!ENTITY % keycap.element "INCLUDE">
<![ %keycap.element; [
<!ELEMENT KeyCap - - (%smallcptr.char.mix;)*>
<!--end of keycap.element-->]]>

<!ENTITY % keycap.attlist "INCLUDE">
<![ %keycap.attlist; [
<!ATTLIST KeyCap
		%moreinfo.attrib;
		%common.attrib;
		%keycap.role.attrib;
		%local.keycap.attrib;
>
<!--end of keycap.attlist-->]]>
<!--end of keycap.module-->]]>

<!ENTITY % keycode.module "INCLUDE">
<![ %keycode.module; [
<!ENTITY % local.keycode.attrib "">
<!ENTITY % keycode.role.attrib "%role.attrib;">

<!ENTITY % keycode.element "INCLUDE">
<![ %keycode.element; [
<!ELEMENT KeyCode - - ((%smallcptr.char.mix;)+)>
<!--end of keycode.element-->]]>

<!ENTITY % keycode.attlist "INCLUDE">
<![ %keycode.attlist; [
<!ATTLIST KeyCode
		%common.attrib;
		%keycode.role.attrib;
		%local.keycode.attrib;
>
<!--end of keycode.attlist-->]]>
<!--end of keycode.module-->]]>

<!ENTITY % keycombo.module "INCLUDE">
<![ %keycombo.module; [
<!ENTITY % local.keycombo.attrib "">
<!ENTITY % keycombo.role.attrib "%role.attrib;">

<!ENTITY % keycombo.element "INCLUDE">
<![ %keycombo.element; [
<!ELEMENT KeyCombo - - ((KeyCap|KeyCombo|KeySym|MouseButton)+)>
<!--end of keycombo.element-->]]>

<!ENTITY % keycombo.attlist "INCLUDE">
<![ %keycombo.attlist; [
<!ATTLIST KeyCombo
		%keyaction.attrib;
		%moreinfo.attrib;
		%common.attrib;
		%keycombo.role.attrib;
		%local.keycombo.attrib;
>
<!--end of keycombo.attlist-->]]>
<!--end of keycombo.module-->]]>

<!ENTITY % keysym.module "INCLUDE">
<![ %keysym.module; [
<!ENTITY % local.keysym.attrib "">
<!ENTITY % keysysm.role.attrib "%role.attrib;">

<!ENTITY % keysym.element "INCLUDE">
<![ %keysym.element; [
<!ELEMENT KeySym - - ((%smallcptr.char.mix;)+)>
<!--end of keysym.element-->]]>

<!ENTITY % keysym.attlist "INCLUDE">
<![ %keysym.attlist; [
<!ATTLIST KeySym
		%common.attrib;
		%keysysm.role.attrib;
		%local.keysym.attrib;
>
<!--end of keysym.attlist-->]]>
<!--end of keysym.module-->]]>

<!ENTITY % lineannotation.module "INCLUDE">
<![ %lineannotation.module; [
<!ENTITY % local.lineannotation.attrib "">
<!ENTITY % lineannotation.role.attrib "%role.attrib;">

<!ENTITY % lineannotation.element "INCLUDE">
<![ %lineannotation.element; [
<!ELEMENT LineAnnotation - - ((%para.char.mix;)+)>
<!--end of lineannotation.element-->]]>

<!ENTITY % lineannotation.attlist "INCLUDE">
<![ %lineannotation.attlist; [
<!ATTLIST LineAnnotation
		%common.attrib;
		%lineannotation.role.attrib;
		%local.lineannotation.attrib;
>
<!--end of lineannotation.attlist-->]]>
<!--end of lineannotation.module-->]]>

<!ENTITY % literal.module "INCLUDE">
<![ %literal.module; [
<!ENTITY % local.literal.attrib "">
<!ENTITY % literal.role.attrib "%role.attrib;">

<!ENTITY % literal.element "INCLUDE">
<![ %literal.element; [
<!ELEMENT Literal - - (%cptr.char.mix;)*>
<!--end of literal.element-->]]>

<!ENTITY % literal.attlist "INCLUDE">
<![ %literal.attlist; [
<!ATTLIST Literal
		%moreinfo.attrib;
		%common.attrib;
		%literal.role.attrib;
		%local.literal.attrib;
>
<!--end of literal.attlist-->]]>
<!--end of literal.module-->]]>

<!ENTITY % constant.module "INCLUDE">
<![ %constant.module; [
<!ENTITY % local.constant.attrib "">
<!ENTITY % constant.role.attrib "%role.attrib;">

<!ENTITY % constant.element "INCLUDE">
<![ %constant.element; [
<!ELEMENT Constant - - (%smallcptr.char.mix;)*>
<!--end of constant.element-->]]>

<!ENTITY % constant.attlist "INCLUDE">
<![ %constant.attlist; [
<!ATTLIST Constant
		%common.attrib;
		%constant.role.attrib;
		%local.constant.attrib;
		Class	(Limit)		#IMPLIED
>
<!--end of constant.attlist-->]]>
<!--end of constant.module-->]]>

<!ENTITY % varname.module "INCLUDE">
<![ %varname.module; [
<!ENTITY % local.varname.attrib "">
<!ENTITY % varname.role.attrib "%role.attrib;">

<!ENTITY % varname.element "INCLUDE">
<![ %varname.element; [
<!ELEMENT VarName - - (%smallcptr.char.mix;)*>
<!--end of varname.element-->]]>

<!ENTITY % varname.attlist "INCLUDE">
<![ %varname.attlist; [
<!ATTLIST VarName
		%common.attrib;
		%varname.role.attrib;
		%local.varname.attrib;
>
<!--end of varname.attlist-->]]>
<!--end of varname.module-->]]>

<!ENTITY % markup.module "INCLUDE">
<![ %markup.module; [
<!ENTITY % local.markup.attrib "">
<!ENTITY % markup.role.attrib "%role.attrib;">

<!ENTITY % markup.element "INCLUDE">
<![ %markup.element; [
<!ELEMENT Markup - - ((%smallcptr.char.mix;)+)>
<!--end of markup.element-->]]>

<!ENTITY % markup.attlist "INCLUDE">
<![ %markup.attlist; [
<!ATTLIST Markup
		%common.attrib;
		%markup.role.attrib;
		%local.markup.attrib;
>
<!--end of markup.attlist-->]]>
<!--end of markup.module-->]]>

<!ENTITY % medialabel.module "INCLUDE">
<![ %medialabel.module; [
<!ENTITY % local.medialabel.attrib "">
<!ENTITY % medialabel.role.attrib "%role.attrib;">

<!ENTITY % medialabel.element "INCLUDE">
<![ %medialabel.element; [
<!ELEMENT MediaLabel - - ((%smallcptr.char.mix;)+)>
<!--end of medialabel.element-->]]>

<!ENTITY % medialabel.attlist "INCLUDE">
<![ %medialabel.attlist; [
<!ATTLIST MediaLabel
		--
		Class: Type of medium named by the element; no default
		--
		Class 		(Cartridge
				|CDRom
				|Disk
				|Tape)		#IMPLIED
		%common.attrib;
		%medialabel.role.attrib;
		%local.medialabel.attrib;
>
<!--end of medialabel.attlist-->]]>
<!--end of medialabel.module-->]]>

<!ENTITY % menuchoice.content.module "INCLUDE">
<![ %menuchoice.content.module; [
<!ENTITY % menuchoice.module "INCLUDE">
<![ %menuchoice.module; [
<!ENTITY % local.menuchoice.attrib "">
<!ENTITY % menuchoice.role.attrib "%role.attrib;">

<!ENTITY % menuchoice.element "INCLUDE">
<![ %menuchoice.element; [
<!ELEMENT MenuChoice - - (Shortcut?, (GUIButton|GUIIcon|GUILabel
		|GUIMenu|GUIMenuItem|GUISubmenu|Interface)+)>
<!--end of menuchoice.element-->]]>

<!ENTITY % menuchoice.attlist "INCLUDE">
<![ %menuchoice.attlist; [
<!ATTLIST MenuChoice
		%moreinfo.attrib;
		%common.attrib;
		%menuchoice.role.attrib;
		%local.menuchoice.attrib;
>
<!--end of menuchoice.attlist-->]]>
<!--end of menuchoice.module-->]]>

<!ENTITY % shortcut.module "INCLUDE">
<![ %shortcut.module; [
<!-- See also KeyCombo -->
<!ENTITY % local.shortcut.attrib "">
<!ENTITY % shortcut.role.attrib "%role.attrib;">

<!ENTITY % shortcut.element "INCLUDE">
<![ %shortcut.element; [
<!ELEMENT Shortcut - - ((KeyCap|KeyCombo|KeySym|MouseButton)+)>
<!--end of shortcut.element-->]]>

<!ENTITY % shortcut.attlist "INCLUDE">
<![ %shortcut.attlist; [
<!ATTLIST Shortcut
		%keyaction.attrib;
		%moreinfo.attrib;
		%common.attrib;
		%shortcut.role.attrib;
		%local.shortcut.attrib;
>
<!--end of shortcut.attlist-->]]>
<!--end of shortcut.module-->]]>
<!--end of menuchoice.content.module-->]]>

<!ENTITY % mousebutton.module "INCLUDE">
<![ %mousebutton.module; [
<!ENTITY % local.mousebutton.attrib "">
<!ENTITY % mousebutton.role.attrib "%role.attrib;">

<!ENTITY % mousebutton.element "INCLUDE">
<![ %mousebutton.element; [
<!ELEMENT MouseButton - - ((%smallcptr.char.mix;)+)>
<!--end of mousebutton.element-->]]>

<!ENTITY % mousebutton.attlist "INCLUDE">
<![ %mousebutton.attlist; [
<!ATTLIST MouseButton
		%moreinfo.attrib;
		%common.attrib;
		%mousebutton.role.attrib;
		%local.mousebutton.attrib;
>
<!--end of mousebutton.attlist-->]]>
<!--end of mousebutton.module-->]]>

<!ENTITY % msgtext.module "INCLUDE">
<![ %msgtext.module; [
<!ENTITY % local.msgtext.attrib "">
<!ENTITY % msgtext.role.attrib "%role.attrib;">

<!ENTITY % msgtext.element "INCLUDE">
<![ %msgtext.element; [
<!--FUTURE USE (V5.0):
......................
The content model of MsgText will be reduced. It will be made
the same as %example.mix; although it may not use that PE.
......................
-->
<!ELEMENT MsgText - - ((%component.mix;)+)>
<!--end of msgtext.element-->]]>

<!ENTITY % msgtext.attlist "INCLUDE">
<![ %msgtext.attlist; [
<!ATTLIST MsgText
		%common.attrib;
		%msgtext.role.attrib;
		%local.msgtext.attrib;
>
<!--end of msgtext.attlist-->]]>
<!--end of msgtext.module-->]]>

<!ENTITY % option.module "INCLUDE">
<![ %option.module; [
<!ENTITY % local.option.attrib "">
<!ENTITY % option.role.attrib "%role.attrib;">

<!ENTITY % option.element "INCLUDE">
<![ %option.element; [
<!ELEMENT Option - - (%smallcptr.char.mix;)*>
<!--end of option.element-->]]>

<!ENTITY % option.attlist "INCLUDE">
<![ %option.attlist; [
<!ATTLIST Option
		%common.attrib;
		%option.role.attrib;
		%local.option.attrib;
>
<!--end of option.attlist-->]]>
<!--end of option.module-->]]>

<!ENTITY % optional.module "INCLUDE">
<![ %optional.module; [
<!ENTITY % local.optional.attrib "">
<!ENTITY % optional.role.attrib "%role.attrib;">

<!ENTITY % optional.element "INCLUDE">
<![ %optional.element; [
<!ELEMENT Optional - - ((%cptr.char.mix;)+)>
<!--end of optional.element-->]]>

<!ENTITY % optional.attlist "INCLUDE">
<![ %optional.attlist; [
<!ATTLIST Optional
		%common.attrib;
		%optional.role.attrib;
		%local.optional.attrib;
>
<!--end of optional.attlist-->]]>
<!--end of optional.module-->]]>

<!ENTITY % parameter.module "INCLUDE">
<![ %parameter.module; [
<!ENTITY % local.parameter.attrib "">
<!ENTITY % parameter.role.attrib "%role.attrib;">

<!ENTITY % parameter.element "INCLUDE">
<![ %parameter.element; [
<!ELEMENT Parameter - - (%smallcptr.char.mix;)*>
<!--end of parameter.element-->]]>

<!ENTITY % parameter.attlist "INCLUDE">
<![ %parameter.attlist; [
<!ATTLIST Parameter
		--
		Class: Type of the Parameter; no default
		--
		Class 		(Command
				|Function
				|Option)	#IMPLIED
		%moreinfo.attrib;
		%common.attrib;
		%parameter.role.attrib;
		%local.parameter.attrib;
>
<!--end of parameter.attlist-->]]>
<!--end of parameter.module-->]]>

<!ENTITY % prompt.module "INCLUDE">
<![ %prompt.module; [
<!ENTITY % local.prompt.attrib "">
<!ENTITY % prompt.role.attrib "%role.attrib;">

<!ENTITY % prompt.element "INCLUDE">
<![ %prompt.element; [
<!ELEMENT Prompt - - ((%smallcptr.char.mix;)+)>
<!--end of prompt.element-->]]>

<!ENTITY % prompt.attlist "INCLUDE">
<![ %prompt.attlist; [
<!ATTLIST Prompt
		%moreinfo.attrib;
		%common.attrib;
		%prompt.role.attrib;
		%local.prompt.attrib;
>
<!--end of prompt.attlist-->]]>
<!--end of prompt.module-->]]>

<!ENTITY % property.module "INCLUDE">
<![ %property.module; [
<!ENTITY % local.property.attrib "">
<!ENTITY % property.role.attrib "%role.attrib;">

<!ENTITY % property.element "INCLUDE">
<![ %property.element; [
<!ELEMENT Property - - (%smallcptr.char.mix;)*>
<!--end of property.element-->]]>

<!ENTITY % property.attlist "INCLUDE">
<![ %property.attlist; [
<!ATTLIST Property
		%moreinfo.attrib;
		%common.attrib;
		%property.role.attrib;
		%local.property.attrib;
>
<!--end of property.attlist-->]]>
<!--end of property.module-->]]>

<!ENTITY % replaceable.module "INCLUDE">
<![ %replaceable.module; [
<!ENTITY % local.replaceable.attrib "">
<!ENTITY % replaceable.role.attrib "%role.attrib;">

<!ENTITY % replaceable.element "INCLUDE">
<![ %replaceable.element; [
<!ELEMENT Replaceable - - ((#PCDATA 
		| %link.char.class; 
		| Optional
		| %base.char.class; 
		| %other.char.class; 
		| InlineGraphic
		| InlineMediaObject)+)>
<!--end of replaceable.element-->]]>

<!ENTITY % replaceable.attlist "INCLUDE">
<![ %replaceable.attlist; [
<!ATTLIST Replaceable
		--
		Class: Type of information the element represents; no
		default
		--
		Class		(Command
				|Function
				|Option
				|Parameter)	#IMPLIED
		%common.attrib;
		%replaceable.role.attrib;
		%local.replaceable.attrib;
>
<!--end of replaceable.attlist-->]]>
<!--end of replaceable.module-->]]>

<!ENTITY % returnvalue.module "INCLUDE">
<![ %returnvalue.module; [
<!ENTITY % local.returnvalue.attrib "">
<!ENTITY % returnvalue.role.attrib "%role.attrib;">

<!ENTITY % returnvalue.element "INCLUDE">
<![ %returnvalue.element; [
<!ELEMENT ReturnValue - - ((%smallcptr.char.mix;)+)>
<!--end of returnvalue.element-->]]>

<!ENTITY % returnvalue.attlist "INCLUDE">
<![ %returnvalue.attlist; [
<!ATTLIST ReturnValue
		%common.attrib;
		%returnvalue.role.attrib;
		%local.returnvalue.attrib;
>
<!--end of returnvalue.attlist-->]]>
<!--end of returnvalue.module-->]]>

<!ENTITY % sgmltag.module "INCLUDE">
<![ %sgmltag.module; [
<!ENTITY % local.sgmltag.attrib "">
<!ENTITY % sgmltag.role.attrib "%role.attrib;">

<!ENTITY % sgmltag.element "INCLUDE">
<![ %sgmltag.element; [
<!ELEMENT SGMLTag - - ((%smallcptr.char.mix;)+)>
<!--end of sgmltag.element-->]]>

<!ENTITY % sgmltag.attlist "INCLUDE">
<![ %sgmltag.attlist; [
<!ATTLIST SGMLTag
		--
		Class: Type of SGML construct the element names; no default
		--
		Class 		(Attribute
				|AttValue
				|Element
				|EndTag
				|EmptyTag
				|GenEntity
				|NumCharRef
				|ParamEntity
				|PI
				|XMLPI
				|StartTag
				|SGMLComment)	#IMPLIED
		%common.attrib;
		%sgmltag.role.attrib;
		%local.sgmltag.attrib;
>
<!--end of sgmltag.attlist-->]]>
<!--end of sgmltag.module-->]]>

<!ENTITY % structfield.module "INCLUDE">
<![ %structfield.module; [
<!ENTITY % local.structfield.attrib "">
<!ENTITY % structfield.role.attrib "%role.attrib;">

<!ENTITY % structfield.element "INCLUDE">
<![ %structfield.element; [
<!ELEMENT StructField - - ((%smallcptr.char.mix;)+)>
<!--end of structfield.element-->]]>

<!ENTITY % structfield.attlist "INCLUDE">
<![ %structfield.attlist; [
<!ATTLIST StructField
		%common.attrib;
		%structfield.role.attrib;
		%local.structfield.attrib;
>
<!--end of structfield.attlist-->]]>
<!--end of structfield.module-->]]>

<!ENTITY % structname.module "INCLUDE">
<![ %structname.module; [
<!ENTITY % local.structname.attrib "">
<!ENTITY % structname.role.attrib "%role.attrib;">

<!ENTITY % structname.element "INCLUDE">
<![ %structname.element; [
<!ELEMENT StructName - - ((%smallcptr.char.mix;)+)>
<!--end of structname.element-->]]>

<!ENTITY % structname.attlist "INCLUDE">
<![ %structname.attlist; [
<!ATTLIST StructName
		%common.attrib;
		%structname.role.attrib;
		%local.structname.attrib;
>
<!--end of structname.attlist-->]]>
<!--end of structname.module-->]]>

<!ENTITY % symbol.module "INCLUDE">
<![ %symbol.module; [
<!ENTITY % local.symbol.attrib "">
<!ENTITY % symbol.role.attrib "%role.attrib;">

<!ENTITY % symbol.element "INCLUDE">
<![ %symbol.element; [
<!ELEMENT Symbol - - ((%smallcptr.char.mix;)+)>
<!--end of symbol.element-->]]>

<!ENTITY % symbol.attlist "INCLUDE">
<![ %symbol.attlist; [
<!ATTLIST Symbol
		--
		Class: Type of symbol; no default
		--
		Class		(Limit)		#IMPLIED
		%common.attrib;
		%symbol.role.attrib;
		%local.symbol.attrib;
>
<!--end of symbol.attlist-->]]>
<!--end of symbol.module-->]]>

<!ENTITY % systemitem.module "INCLUDE">
<![ %systemitem.module; [
<!ENTITY % local.systemitem.attrib "">
<!ENTITY % systemitem.role.attrib "%role.attrib;">

<!ENTITY % systemitem.element "INCLUDE">
<![ %systemitem.element; [
<!ELEMENT SystemItem - - ((%smallcptr.char.mix; | Acronym)*)>
<!--end of systemitem.element-->]]>

<!ENTITY % systemitem.attlist "INCLUDE">
<![ %systemitem.attlist; [
<!ATTLIST SystemItem
		--
		Class: Type of system item the element names; no default
		--
		Class	(Constant
			|GroupName
			|Library
			|Macro
			|OSname
			|Resource
			|SystemName
			|UserName)	#IMPLIED
		%moreinfo.attrib;
		%common.attrib;
		%systemitem.role.attrib;
		%local.systemitem.attrib;
>
<!--end of systemitem.attlist-->]]>
<!--end of systemitem.module-->]]>


<!ENTITY % token.module "INCLUDE">
<![ %token.module; [
<!ENTITY % local.token.attrib "">
<!ENTITY % token.role.attrib "%role.attrib;">

<!ENTITY % token.element "INCLUDE">
<![ %token.element; [
<!ELEMENT Token - - ((%smallcptr.char.mix;)+)>
<!--end of token.element-->]]>

<!ENTITY % token.attlist "INCLUDE">
<![ %token.attlist; [
<!ATTLIST Token
		%common.attrib;
		%token.role.attrib;
		%local.token.attrib;
>
<!--end of token.attlist-->]]>
<!--end of token.module-->]]>

<!ENTITY % type.module "INCLUDE">
<![ %type.module; [
<!ENTITY % local.type.attrib "">
<!ENTITY % type.role.attrib "%role.attrib;">

<!ENTITY % type.element "INCLUDE">
<![ %type.element; [
<!ELEMENT Type - - ((%smallcptr.char.mix;)+)>
<!--end of type.element-->]]>

<!ENTITY % type.attlist "INCLUDE">
<![ %type.attlist; [
<!ATTLIST Type
		%common.attrib;
		%type.role.attrib;
		%local.type.attrib;
>
<!--end of type.attlist-->]]>
<!--end of type.module-->]]>

<!ENTITY % userinput.module "INCLUDE">
<![ %userinput.module; [
<!ENTITY % local.userinput.attrib "">
<!ENTITY % userinput.role.attrib "%role.attrib;">

<!ENTITY % userinput.element "INCLUDE">
<![ %userinput.element; [
<!ELEMENT UserInput - - ((%cptr.char.mix;)+)>
<!--end of userinput.element-->]]>

<!ENTITY % userinput.attlist "INCLUDE">
<![ %userinput.attlist; [
<!ATTLIST UserInput
		%moreinfo.attrib;
		%common.attrib;
		%userinput.role.attrib;
		%local.userinput.attrib;
>
<!--end of userinput.attlist-->]]>
<!--end of userinput.module-->]]>

<!-- General words and phrases ............................................ -->

<!ENTITY % abbrev.module "INCLUDE">
<![ %abbrev.module; [
<!ENTITY % local.abbrev.attrib "">
<!ENTITY % abbrev.role.attrib "%role.attrib;">

<!ENTITY % abbrev.element "INCLUDE">
<![ %abbrev.element; [
<!ELEMENT Abbrev - - ((%word.char.mix;)+)>
<!--end of abbrev.element-->]]>

<!ENTITY % abbrev.attlist "INCLUDE">
<![ %abbrev.attlist; [
<!ATTLIST Abbrev
		%common.attrib;
		%abbrev.role.attrib;
		%local.abbrev.attrib;
>
<!--end of abbrev.attlist-->]]>
<!--end of abbrev.module-->]]>

<!ENTITY % acronym.module "INCLUDE">
<![ %acronym.module; [
<!ENTITY % local.acronym.attrib "">
<!ENTITY % acronym.role.attrib "%role.attrib;">

<!ENTITY % acronym.element "INCLUDE">
<![ %acronym.element; [
<!ELEMENT Acronym - - ((%word.char.mix;)+) %acronym.exclusion;>
<!--end of acronym.element-->]]>

<!ENTITY % acronym.attlist "INCLUDE">
<![ %acronym.attlist; [
<!ATTLIST Acronym
		%common.attrib;
		%acronym.role.attrib;
		%local.acronym.attrib;
>
<!--end of acronym.attlist-->]]>
<!--end of acronym.module-->]]>

<!ENTITY % citation.module "INCLUDE">
<![ %citation.module; [
<!ENTITY % local.citation.attrib "">
<!ENTITY % citation.role.attrib "%role.attrib;">

<!ENTITY % citation.element "INCLUDE">
<![ %citation.element; [
<!ELEMENT Citation - - ((%para.char.mix;)+)>
<!--end of citation.element-->]]>

<!ENTITY % citation.attlist "INCLUDE">
<![ %citation.attlist; [
<!ATTLIST Citation
		%common.attrib;
		%citation.role.attrib;
		%local.citation.attrib;
>
<!--end of citation.attlist-->]]>
<!--end of citation.module-->]]>

<!ENTITY % citerefentry.module "INCLUDE">
<![ %citerefentry.module; [
<!ENTITY % local.citerefentry.attrib "">
<!ENTITY % citerefentry.role.attrib "%role.attrib;">

<!ENTITY % citerefentry.element "INCLUDE">
<![ %citerefentry.element; [
<!ELEMENT CiteRefEntry - - (RefEntryTitle, ManVolNum?)>
<!--end of citerefentry.element-->]]>

<!ENTITY % citerefentry.attlist "INCLUDE">
<![ %citerefentry.attlist; [
<!ATTLIST CiteRefEntry
		%common.attrib;
		%citerefentry.role.attrib;
		%local.citerefentry.attrib;
>
<!--end of citerefentry.attlist-->]]>
<!--end of citerefentry.module-->]]>

<!ENTITY % refentrytitle.module "INCLUDE">
<![ %refentrytitle.module; [
<!ENTITY % local.refentrytitle.attrib "">
<!ENTITY % refentrytitle.role.attrib "%role.attrib;">

<!ENTITY % refentrytitle.element "INCLUDE">
<![ %refentrytitle.element; [
<!ELEMENT RefEntryTitle - O ((%para.char.mix;)+)>
<!--end of refentrytitle.element-->]]>

<!ENTITY % refentrytitle.attlist "INCLUDE">
<![ %refentrytitle.attlist; [
<!ATTLIST RefEntryTitle
		%common.attrib;
		%refentrytitle.role.attrib;
		%local.refentrytitle.attrib;
>
<!--end of refentrytitle.attlist-->]]>
<!--end of refentrytitle.module-->]]>

<!ENTITY % manvolnum.module "INCLUDE">
<![ %manvolnum.module; [
<!ENTITY % local.manvolnum.attrib "">
<!ENTITY % namvolnum.role.attrib "%role.attrib;">

<!ENTITY % manvolnum.element "INCLUDE">
<![ %manvolnum.element; [
<!ELEMENT ManVolNum - O ((%word.char.mix;)+)>
<!--end of manvolnum.element-->]]>

<!ENTITY % manvolnum.attlist "INCLUDE">
<![ %manvolnum.attlist; [
<!ATTLIST ManVolNum
		%common.attrib;
		%namvolnum.role.attrib;
		%local.manvolnum.attrib;
>
<!--end of manvolnum.attlist-->]]>
<!--end of manvolnum.module-->]]>

<!ENTITY % citetitle.module "INCLUDE">
<![ %citetitle.module; [
<!ENTITY % local.citetitle.attrib "">
<!ENTITY % citetitle.role.attrib "%role.attrib;">

<!ENTITY % citetitle.element "INCLUDE">
<![ %citetitle.element; [
<!ELEMENT CiteTitle - - ((%para.char.mix;)+)>
<!--end of citetitle.element-->]]>

<!ENTITY % citetitle.attlist "INCLUDE">
<![ %citetitle.attlist; [
<!ATTLIST CiteTitle
		--
		Pubwork: Genre of published work cited; no default
		--
		Pubwork		(Article
				|Book
				|Chapter
				|Part
				|RefEntry
				|Section
				|Journal
				|Series
				|Set
				|Manuscript)	#IMPLIED
		%common.attrib;
		%citetitle.role.attrib;
		%local.citetitle.attrib;
>
<!--end of citetitle.attlist-->]]>
<!--end of citetitle.module-->]]>

<!ENTITY % emphasis.module "INCLUDE">
<![ %emphasis.module; [
<!ENTITY % local.emphasis.attrib "">
<!ENTITY % emphasis.role.attrib "%role.attrib;">

<!ENTITY % emphasis.element "INCLUDE">
<![ %emphasis.element; [
<!ELEMENT Emphasis - - ((%para.char.mix;)+)>
<!--end of emphasis.element-->]]>

<!ENTITY % emphasis.attlist "INCLUDE">
<![ %emphasis.attlist; [
<!ATTLIST Emphasis
		%common.attrib;
		%emphasis.role.attrib;
		%local.emphasis.attrib;
>
<!--end of emphasis.attlist-->]]>
<!--end of emphasis.module-->]]>

<!ENTITY % firstterm.module "INCLUDE">
<![ %firstterm.module; [
<!ENTITY % local.firstterm.attrib "">
<!ENTITY % firstterm.role.attrib "%role.attrib;">

<!ENTITY % firstterm.element "INCLUDE">
<![ %firstterm.element; [
<!ELEMENT FirstTerm - - ((%word.char.mix;)+)>
<!--end of firstterm.element-->]]>

<!ENTITY % firstterm.attlist "INCLUDE">
<![ %firstterm.attlist; [
<!ATTLIST FirstTerm
		%linkend.attrib; --to GlossEntry or other explanation--
		%common.attrib;
		%firstterm.role.attrib;
		%local.firstterm.attrib;
>
<!--end of firstterm.attlist-->]]>
<!--end of firstterm.module-->]]>

<!ENTITY % foreignphrase.module "INCLUDE">
<![ %foreignphrase.module; [
<!ENTITY % local.foreignphrase.attrib "">
<!ENTITY % foreignphrase.role.attrib "%role.attrib;">

<!ENTITY % foreignphrase.element "INCLUDE">
<![ %foreignphrase.element; [
<!ELEMENT ForeignPhrase - - ((%para.char.mix;)+)>
<!--end of foreignphrase.element-->]]>

<!ENTITY % foreignphrase.attlist "INCLUDE">
<![ %foreignphrase.attlist; [
<!ATTLIST ForeignPhrase
		%common.attrib;
		%foreignphrase.role.attrib;
		%local.foreignphrase.attrib;
>
<!--end of foreignphrase.attlist-->]]>
<!--end of foreignphrase.module-->]]>

<!ENTITY % glossterm.module "INCLUDE">
<![ %glossterm.module; [
<!ENTITY % local.glossterm.attrib "">
<!ENTITY % glossterm.role.attrib "%role.attrib;">

<!ENTITY % glossterm.element "INCLUDE">
<![ %glossterm.element; [
<!ELEMENT GlossTerm - O ((%para.char.mix;)+) %glossterm.exclusion;>
<!--end of glossterm.element-->]]>

<!ENTITY % glossterm.attlist "INCLUDE">
<![ %glossterm.attlist; [
<!ATTLIST GlossTerm
		%linkend.attrib; --to GlossEntry if Glossterm used in text--
		--
		BaseForm: Provides the form of GlossTerm to be used
		for indexing
		--
		BaseForm	CDATA		#IMPLIED
		%common.attrib;
		%glossterm.role.attrib;
		%local.glossterm.attrib;
>
<!--end of glossterm.attlist-->]]>
<!--end of glossterm.module-->]]>

<!ENTITY % phrase.module "INCLUDE">
<![ %phrase.module; [
<!ENTITY % local.phrase.attrib "">
<!ENTITY % phrase.role.attrib "%role.attrib;">

<!ENTITY % phrase.element "INCLUDE">
<![ %phrase.element; [
<!ELEMENT Phrase - - ((%para.char.mix;)+)>
<!--end of phrase.element-->]]>

<!ENTITY % phrase.attlist "INCLUDE">
<![ %phrase.attlist; [
<!ATTLIST Phrase
		%common.attrib;
		%phrase.role.attrib;
		%local.phrase.attrib;
>
<!--end of phrase.attlist-->]]>
<!--end of phrase.module-->]]>

<!ENTITY % quote.module "INCLUDE">
<![ %quote.module; [
<!ENTITY % local.quote.attrib "">
<!ENTITY % quote.role.attrib "%role.attrib;">

<!ENTITY % quote.element "INCLUDE">
<![ %quote.element; [
<!ELEMENT Quote - - ((%para.char.mix;)+)>
<!--end of quote.element-->]]>

<!ENTITY % quote.attlist "INCLUDE">
<![ %quote.attlist; [
<!ATTLIST Quote
		%common.attrib;
		%quote.role.attrib;
		%local.quote.attrib;
>
<!--end of quote.attlist-->]]>
<!--end of quote.module-->]]>

<!ENTITY % ssscript.module "INCLUDE">
<![ %ssscript.module; [
<!ENTITY % local.ssscript.attrib "">
<!ENTITY % ssscript.role.attrib "%role.attrib;">

<!ENTITY % ssscript.elements "INCLUDE">
<![ %ssscript.elements [
<!ELEMENT (Subscript | Superscript) - - ((#PCDATA 
		| %link.char.class;
		| Emphasis
		| Replaceable 
		| Symbol 
		| InlineGraphic 
		| InlineMediaObject
		| %base.char.class; 
		| %other.char.class;)+)
		%ubiq.exclusion;>
<!--end of ssscript.elements-->]]>

<!ENTITY % ssscript.attlists "INCLUDE">
<![ %ssscript.attlists; [
<!ATTLIST (Subscript | Superscript)
		%common.attrib;
		%ssscript.role.attrib;
		%local.ssscript.attrib;
>
<!--end of ssscript.attlists-->]]>
<!--end of ssscript.module-->]]>

<!ENTITY % trademark.module "INCLUDE">
<![ %trademark.module; [
<!ENTITY % local.trademark.attrib "">
<!ENTITY % trademark.role.attrib "%role.attrib;">

<!ENTITY % trademark.element "INCLUDE">
<![ %trademark.element; [
<!ELEMENT Trademark - - ((#PCDATA 
		| %link.char.class; 
		| %tech.char.class;
		| %base.char.class; 
		| %other.char.class; 
		| InlineGraphic
		| InlineMediaObject
		| Emphasis)+)>
<!--end of trademark.element-->]]>

<!ENTITY % trademark.attlist "INCLUDE">
<![ %trademark.attlist; [
<!ATTLIST Trademark
		--
		Class: More precisely identifies the item the element names
		--
		Class		(Service
				|Trade
				|Registered
				|Copyright)	Trade
		%common.attrib;
		%trademark.role.attrib;
		%local.trademark.attrib;
>
<!--end of trademark.attlist-->]]>
<!--end of trademark.module-->]]>

<!ENTITY % wordasword.module "INCLUDE">
<![ %wordasword.module; [
<!ENTITY % local.wordasword.attrib "">
<!ENTITY % wordasword.role.attrib "%role.attrib;">

<!ENTITY % wordasword.element "INCLUDE">
<![ %wordasword.element; [
<!ELEMENT WordAsWord - - ((%word.char.mix;)+)>
<!--end of wordasword.element-->]]>

<!ENTITY % wordasword.attlist "INCLUDE">
<![ %wordasword.attlist; [
<!ATTLIST WordAsWord
		%common.attrib;
		%wordasword.role.attrib;
		%local.wordasword.attrib;
>
<!--end of wordasword.attlist-->]]>
<!--end of wordasword.module-->]]>

<!-- Links and cross-references ........................................... -->

<!ENTITY % link.module "INCLUDE">
<![ %link.module; [
<!ENTITY % local.link.attrib "">
<!ENTITY % link.role.attrib "%role.attrib;">

<!ENTITY % link.element "INCLUDE">
<![ %link.element; [
<!ELEMENT Link - - ((%para.char.mix;)+) %links.exclusion;>
<!--end of link.element-->]]>

<!ENTITY % link.attlist "INCLUDE">
<![ %link.attlist; [
<!ATTLIST Link
		--
		Endterm: ID of element containing text that is to be
		fetched from elsewhere in the document to appear as
		the content of this element
		--
		Endterm		IDREF		#IMPLIED
		%linkendreq.attrib; --to linked-to object--
		--
		Type: Freely assignable parameter
		--
		Type		CDATA		#IMPLIED
		%common.attrib;
		%link.role.attrib;
		%local.link.attrib;
>
<!--end of link.attlist-->]]>
<!--end of link.module-->]]>

<!ENTITY % olink.module "INCLUDE">
<![ %olink.module; [
<!ENTITY % local.olink.attrib "">
<!ENTITY % olink.role.attrib "%role.attrib;">

<!ENTITY % olink.element "INCLUDE">
<![ %olink.element; [
<!ELEMENT OLink - - ((%para.char.mix;)+) %links.exclusion;>
<!--end of olink.element-->]]>

<!ENTITY % olink.attlist "INCLUDE">
<![ %olink.attlist; [
<!ATTLIST OLink
		--
		TargetDocEnt: Name of an entity to be the target of the link
		--
		TargetDocEnt	ENTITY 		#IMPLIED
		--
		LinkMode: ID of a ModeSpec containing instructions for
		operating on the entity named by TargetDocEnt
		--
		LinkMode	IDREF		#IMPLIED
		--
		LocalInfo: Information that may be passed to ModeSpec
		--
		LocalInfo 	CDATA		#IMPLIED
		--
		Type: Freely assignable parameter
		--
		Type		CDATA		#IMPLIED
		%common.attrib;
		%olink.role.attrib;
		%local.olink.attrib;
>
<!--end of olink.attlist-->]]>
<!--end of olink.module-->]]>

<!ENTITY % ulink.module "INCLUDE">
<![ %ulink.module; [
<!ENTITY % local.ulink.attrib "">
<!ENTITY % ulink.role.attrib "%role.attrib;">

<!ENTITY % ulink.element "INCLUDE">
<![ %ulink.element; [
<!ELEMENT ULink - - ((%para.char.mix;)+) %links.exclusion;>
<!--end of ulink.element-->]]>

<!ENTITY % ulink.attlist "INCLUDE">
<![ %ulink.attlist; [
<!ATTLIST ULink
		--
		URL: uniform resource locator; the target of the ULink
		--
		URL		CDATA		#REQUIRED
		--
		Type: Freely assignable parameter
		--
		Type		CDATA		#IMPLIED
		%common.attrib;
		%ulink.role.attrib;
		%local.ulink.attrib;
>
<!--end of ulink.attlist-->]]>
<!--end of ulink.module-->]]>

<!ENTITY % footnoteref.module "INCLUDE">
<![ %footnoteref.module; [
<!ENTITY % local.footnoteref.attrib "">
<!ENTITY % footnoteref.role.attrib "%role.attrib;">

<!ENTITY % footnoteref.element "INCLUDE">
<![ %footnoteref.element; [
<!ELEMENT FootnoteRef - O EMPTY>
<!--end of footnoteref.element-->]]>

<!ENTITY % footnoteref.attlist "INCLUDE">
<![ %footnoteref.attlist; [
<!ATTLIST FootnoteRef
		%linkendreq.attrib; --to footnote content supplied elsewhere--
		%label.attrib;
		%common.attrib;
		%footnoteref.role.attrib;
		%local.footnoteref.attrib;
>
<!--end of footnoteref.attlist-->]]>
<!--end of footnoteref.module-->]]>

<!ENTITY % xref.module "INCLUDE">
<![ %xref.module; [
<!ENTITY % local.xref.attrib "">
<!ENTITY % xref.role.attrib "%role.attrib;">

<!ENTITY % xref.element "INCLUDE">
<![ %xref.element; [
<!ELEMENT XRef - O EMPTY>
<!--end of xref.element-->]]>

<!ENTITY % xref.attlist "INCLUDE">
<![ %xref.attlist; [
<!ATTLIST XRef
		--
		Endterm: ID of element containing text that is to be
		fetched from elsewhere in the document to appear as
		the content of this element
		--
		Endterm		IDREF		#IMPLIED
		%linkendreq.attrib; --to linked-to object--
		%common.attrib;
		%xref.role.attrib;
		%local.xref.attrib;
>
<!--end of xref.attlist-->]]>
<!--end of xref.module-->]]>

<!-- Ubiquitous elements .................................................. -->

<!ENTITY % anchor.module "INCLUDE">
<![ %anchor.module; [
<!ENTITY % local.anchor.attrib "">
<!ENTITY % anchor.role.attrib "%role.attrib;">

<!ENTITY % anchor.element "INCLUDE">
<![ %anchor.element; [
<!ELEMENT Anchor - O EMPTY>
<!--end of anchor.element-->]]>

<!ENTITY % anchor.attlist "INCLUDE">
<![ %anchor.attlist; [
<!ATTLIST Anchor
		%idreq.attrib; -- required --
		%pagenum.attrib; --replaces Lang --
		%remap.attrib;
		%xreflabel.attrib;
		%revisionflag.attrib;
		%effectivity.attrib;
		%anchor.role.attrib;
		%local.anchor.attrib;
>
<!--end of anchor.attlist-->]]>
<!--end of anchor.module-->]]>

<!ENTITY % beginpage.module "INCLUDE">
<![ %beginpage.module; [
<!ENTITY % local.beginpage.attrib "">
<!ENTITY % beginpage.role.attrib "%role.attrib;">

<!ENTITY % beginpage.element "INCLUDE">
<![ %beginpage.element; [
<!ELEMENT BeginPage - O EMPTY>
<!--end of beginpage.element-->]]>

<!ENTITY % beginpage.attlist "INCLUDE">
<![ %beginpage.attlist; [
<!ATTLIST BeginPage
		--
		PageNum: Number of page that begins at this point
		--
		%pagenum.attrib;
		%common.attrib;
		%beginpage.role.attrib;
		%local.beginpage.attrib;
>
<!--end of beginpage.attlist-->]]>
<!--end of beginpage.module-->]]>

<!-- IndexTerms appear in the text flow for generating or linking an
     index. -->

<!ENTITY % indexterm.content.module "INCLUDE">
<![ %indexterm.content.module; [
<!ENTITY % indexterm.module "INCLUDE">
<![ %indexterm.module; [
<!ENTITY % local.indexterm.attrib "">
<!ENTITY % indexterm.role.attrib "%role.attrib;">

<!ENTITY % indexterm.element "INCLUDE">
<![ %indexterm.element; [
<!ELEMENT IndexTerm - O (Primary, ((Secondary, ((Tertiary, (See|SeeAlso+)?)
		| See | SeeAlso+)?) | See | SeeAlso+)?) %ubiq.exclusion;>
<!--end of indexterm.element-->]]>

<!ENTITY % indexterm.attlist "INCLUDE">
<![ %indexterm.attlist; [
<!ATTLIST IndexTerm
		%pagenum.attrib;
		--
		Scope: Indicates which generated indices the IndexTerm
		should appear in: Global (whole document set), Local (this
		document only), or All (both)
		--
		Scope		(All
				|Global
				|Local)		#IMPLIED
		--
		Significance: Whether this IndexTerm is the most pertinent
		of its series (Preferred) or not (Normal, the default)
		--
		Significance	(Preferred
				|Normal)	Normal
		--
		Class: Indicates type of IndexTerm; default is Singular, 
		or EndOfRange if StartRef is supplied; StartOfRange value 
		must be supplied explicitly on starts of ranges
		--
		Class		(Singular
				|StartOfRange
				|EndOfRange)	#IMPLIED
		--
		StartRef: ID of the IndexTerm that starts the indexing 
		range ended by this IndexTerm
		--
		StartRef		IDREF		#CONREF
		--
		Zone: IDs of the elements to which the IndexTerm applies,
		and indicates that the IndexTerm applies to those entire
		elements rather than the point at which the IndexTerm
		occurs
		--
		Zone			IDREFS		#IMPLIED
		%common.attrib;
		%indexterm.role.attrib;
		%local.indexterm.attrib;
>
<!--end of indexterm.attlist-->]]>
<!--end of indexterm.module-->]]>

<!ENTITY % primsecter.module "INCLUDE">
<![ %primsecter.module; [
<!ENTITY % local.primsecter.attrib "">
<!ENTITY % primsecter.role.attrib "%role.attrib;">

<!ENTITY % primsecter.elements "INCLUDE">
<![ %primsecter.elements; [
<!ELEMENT (Primary | Secondary | Tertiary) - O ((%ndxterm.char.mix;)+)>
<!--end of primsecter.elements-->]]>

<!ENTITY % primsecter.attlists "INCLUDE">
<![ %primsecter.attlists; [
<!ENTITY % containing.attlist "INCLUDE">
<![ %containing.attlist; [
<!ATTLIST (Primary | Secondary | Tertiary)
		--
		SortAs: Alternate sort string for index sorting, e.g.,
		"fourteen" for an element containing "14"
		--
		SortAs		CDATA		#IMPLIED
		%common.attrib;
		%primsecter.role.attrib;
		%local.primsecter.attrib;
>
<!--end of containing.attlist-->]]>
<!--end of primsecter.attlist-->]]>
<!--end of primsecter.module-->]]>

<!ENTITY % seeseealso.module "INCLUDE">
<![ %seeseealso.module; [
<!ENTITY % local.seeseealso.attrib "">
<!ENTITY % seeseealso.role.attrib "%role.attrib;">

<!ENTITY % seeseealso.elements "INCLUDE">
<![ %seeseealso.elements [
<!ELEMENT (See | SeeAlso) - O ((%ndxterm.char.mix;)+)>
<!--end of seeseealso.elements-->]]>

<!ENTITY % seeseealso.attlists "INCLUDE">
<![ %seeseealso.attlists [
<!ATTLIST (See | SeeAlso)
		%common.attrib;
		%seeseealso.role.attrib;
		%local.seeseealso.attrib;
>
<!--end of seeseealso.attlists-->]]>
<!--end of seeseealso.module-->]]>
<!--end of indexterm.content.module-->]]>

<!-- End of DocBook information pool module V4.1 .......................... -->
<!-- ...................................................................... -->
