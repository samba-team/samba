<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: vars.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $		
|- #############################################################################
|	$Author: jelmer $
|
|   PURPOSE: User and stylesheets XSL variables 
+ ############################################################################## -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <doc:reference id="vars" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: vars.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
	    </releaseinfo>
	    <authorgroup>
		<author><surname>Casellas</surname><firstname>Ramon</firstname></author>
		<author><surname>Devenish</surname><firstname>James</firstname></author>
	    </authorgroup>
	    <copyright>
		<year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>XSL Variables and Parameters</title>

	<partintro>
	    <section><title>Introduction</title>

		<para>This is technical reference documentation for the DocBook XSL
		    Stylesheets. It documents (some of) the parameters, templates, and
		    other elements of the stylesheets.</para>
	    </section>
	</partintro>
    </doc:reference>


    <!--############################################################################# 
    |  COMMON VARIABLES
    |- #############################################################################
    |	$Author: jelmer $
    |
    + ############################################################################## -->
    <xsl:variable name="default-classsynopsis-language">java</xsl:variable>

    <xsl:variable name="author.othername.in.middle" select="1"/>
    <xsl:variable name="refentry.xref.manvolnum" select="1"/>
    <xsl:variable name="funcsynopsis.style">kr</xsl:variable>
    <xsl:variable name="funcsynopsis.decoration" select="1"/>
    <xsl:variable name="function.parens">0</xsl:variable>
    <xsl:variable name="refentry.generate.name" select="1"/>

	<doc:param name="show.comments" xmlns="">
	<refpurpose> Display <sgmltag class="element">comment</sgmltag> elements? </refpurpose>
	<refdescription>
		<para>Control the display of <sgmltag class="element">comment</sgmltag>s and <sgmltag class="element">remark</sgmltag>s.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="show.comments" select="1"/>

    <xsl:variable name="section.autolabel" select="1"/>
    <xsl:variable name="section.label.includes.component.label" select="0"/>
    <xsl:variable name="chapter.autolabel" select="1"/>
    <xsl:variable name="preface.autolabel" select="0"/>
    <xsl:variable name="part.autolabel" select="1"/>
    <xsl:variable name="qandadiv.autolabel" select="1"/>
    <xsl:variable name="autotoc.label.separator" select="'. '"/>
    <xsl:variable name="qanda.inherit.numeration" select="1"/>
    <xsl:variable name="qanda.defaultlabel">number</xsl:variable>
    <xsl:param name="biblioentry.item.separator">, </xsl:param>
	<doc:param name="toc.section.depth" xmlns="">
	<refpurpose> Cull table-of-contents entries that are deeply nested </refpurpose>
	<refdescription>
		<para>Specifies the maximum depth before sections are omitted from the table of contents.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="toc.section.depth">4</xsl:param>

	<doc:param name="section.depth" xmlns="">
	<refpurpose> Control the automatic numbering of section, parts, and chapters </refpurpose>
	<refdescription>
		<para>
		Specifies the maximum depth before sections cease to be uniquely numbered.
		This is passed to LaTeX using the <literal>secnumdepth</literal> counter.
		Therefore, it is possible to use a value of <quote>0</quote> (zero) to disable section numbering.
		A value of <quote>-1</quote> will disable the numbering of parts and chapters, too.
		</para>
	</refdescription>
	</doc:param>
    <xsl:param name="section.depth">4</xsl:param>
    <xsl:variable name="graphic.default.extension"></xsl:variable>
    <xsl:variable name="check.idref">1</xsl:variable>
    <!--
    <xsl:variable name="link.mailto.url"></xsl:variable>
    <xsl:variable name="toc.list.type">dl</xsl:variable>
    -->

	<doc:param name="use.role.for.mediaobject" xmlns="">
	<refpurpose> Control <sgmltag class="element">mediaobject</sgmltag> selection methods </refpurpose>
	<refdescription>
		<para>This controls how DB2LaTeX behaves when a <sgmltag class="element">figure</sgmltag> contains
		multiple <sgmltag class="element">mediaobject</sgmltag>s. When enabled, DB2LaTeX will choose
		the mediaobject with the "LaTeX" or "TeX" role, if present. Otherwise, the first mediaobject
		is chosen.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="use.role.for.mediaobject">1</xsl:param>

	<doc:param name="preferred.mediaobject.role" xmlns="">
	<refpurpose> Control <sgmltag class="element">mediaobject</sgmltag> selection methods </refpurpose>
	<refdescription>
		<para>When <xref linkend="param.use.role.for.mediaobject"/> is enabled, this variable
		can be used to specify the mediaobject role that your document uses for LaTeX output.
		DB2LaTeX will try to use this role before using the "LaTeX" or "TeX" roles.
		For example, some authors may choose to set this to "PDF".</para>
	</refdescription>
	</doc:param>
	<xsl:param name="preferred.mediaobject.role"></xsl:param>

	<doc:param name="formal.title.placement" xmlns="">
	<refpurpose> Specifies where formal object titles should occur </refpurpose>
	<refdescription>
		<para>
			Titles for the formal object types (figure, example, quation, table, and procedure)
			can be placed before or after those objects. The keyword <quote>before</quote>
			is recognised. All other strings qualify as <quote>after</quote>.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="formal.title.placement">
		figure not_before
		example before
		equation not_before
		table before
		procedure before
	</xsl:param>

	<doc:param name="insert.xref.page.number" xmlns="">
	<refpurpose> Control the appearance of page numbers in cross references </refpurpose>
	<refdescription>
		<para>
			When enabled, <sgmltag class="element">xref</sgmltag>s will include page
			numbers after their generated cross-reference text.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="insert.xref.page.number">0</xsl:param>

	<doc:param name="ulink.show" xmlns="">
	<refpurpose> Control the display of URLs after ulinks </refpurpose>
	<refdescription>
		<para>
		When this option is enabled, and a ulink has a URL that is different
		from the displayed content, the URL will be typeset after the content.
		If the URL and content are identical, only one of them will appear.
		Otherwise, the URL is hyperlinked and the content is not.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="ulink.show">0</xsl:param>

	<doc:param name="ulink.footnotes" xmlns="">
	<refpurpose> Control the generation of footnotes for ulinks </refpurpose>
	<refdescription>
		<para>
		When this option is enabled, a ulink that has content different to its
		URL will have an associated footnote. The contents of the footnote
		will be the URL. If the ulink is within a footnote, the URL is shown
		after the content.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="ulink.footnotes">0</xsl:param>

    <!--############################################################################# 
    | 	LaTeX VARIABLES
    |- #############################################################################
    |	$Author: jelmer $
    |
    |   PURPOSE: User and stylesheets XSL variables 
    + ############################################################################## -->

	<doc:param name="latex.override" xmlns="">
	<refpurpose> Override DB2LaTeX's preamble with a custom preamble. </refpurpose>
	<refdescription>
		<para>
		When this variable is set, the entire DB2LaTeX premable will be superseded.
		<emphasis>You should not normally need or want to use this.</emphasis>
		It may cause LaTeX typesetting problems. This is a last resort or
		<quote>expert</quote> feature.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.override"></xsl:param>

	<!--
	<doc:variable name="latex.figure.position" xmlns="">
	<refpurpose> How to place floats. </refpurpose>
	<refdescription>
		<para>
		This variable is used as the positioning argument for floats.
		In future, this may be replaced by a dynamic mechanism that can
		honour DocBook placement attributes.
		</para>
	</refdescription>
	</doc:variable>
    <xsl:variable name="latex.figure.position">[hbt]</xsl:variable>
	-->

	<doc:param name="latex.apply.title.templates" xmlns="">
	<refpurpose> Whether to apply templates for section titles. </refpurpose>
	<refdescription>
		<para>
		Controls whether section titles will be generated by
		applying templates or by conversion to string values.
		When enabled, templates will be applied. This enables template
		expression in titles but may have problematic side-effects such
		as nested links.
		</para>
		<note>
			<para>
				This variable does not influence all <sgmltag class="element">title</sgmltag>
				elements. Some may have their own variables or not be configurable.
			</para>
		</note>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.apply.title.templates">1</xsl:param>





	<doc:param name="latex.apply.title.templates.admonitions" xmlns="">
	<refpurpose> Whether to apply templates for admonition titles. </refpurpose>
	<refdescription>
		<para>
		Controls whether admonition titles will be generated by
		applying templates or by conversion to string values.
		When enabled, templates will be applied.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.apply.title.templates.admonitions">1</xsl:param>






	<doc:param name="latex.graphics.formats" xmlns="">
	<refpurpose> Control <sgmltag class="element">imagedata</sgmltag> selection. </refpurpose>
	<refdescription>
		<para>This controls how DB2LaTeX behaves when a <sgmltag class="element">mediaobject</sgmltag> contains
		multiple <sgmltag class="element">imagedata</sgmltag>. When non-empty, DB2LaTeX will exclude
		imagedata that have a format no listed within this variable.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.graphics.formats"></xsl:param>






	<doc:param name="latex.caption.swapskip" xmlns="">
	<refpurpose> Improved typesetting of captions  </refpurpose>
	<refdescription>
		<para>
		DB2LaTeX supports <link linkend="param.formal.title.placement">$formal.title.placement</link>
		as a mechanism for choosing whether captions will appear above or below the objects they describe.
		<!--
		($formal.title.placement is described in the <ulink
		url="http://docbook.sourceforge.net/release/xsl/current/doc/html/formal.title.placement.html">DocBook
		XSL Stylesheet HTML Parameter Reference</ulink>.)
		-->
		However, LaTeX will often produce an ugly result when captions occur
		above their corresponding content. This usually arises because of
		unsuitable \abovecaptionskip and \belowcaptionskip.
		</para>
		<para>
		This variable, when set to '1', authorises DB2LaTeX to swap the caption
		'skip' lengths when a caption is placed <emphasis>above</emphasis> its
		corresponding content. This is enabled by default.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.caption.swapskip">1</xsl:param>





	<doc:param name="latex.titlepage.file" xmlns="">
	<refpurpose> DB2LaTeX allows using an (externally generated) cover page  </refpurpose>
	<refdescription>
		<para>
		You may supply a LaTeX file that will supersede DB2LaTeX's default
		cover page or title. If the value of this variable is non-empty, the
		generated LaTeX code includes \input{filename}. Otherwise, it uses the
		\maketitle command.
		</para>
		<warning><para>
			Bear in mind that using an external cover page breaks the
			"encapsulation" of DocBook. Further revisions of these stylesheets
			will add chunking support, and the automation of the cover file
			generation.
		</para></warning>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.titlepage.file">title</xsl:param>




	<doc:param name="latex.documentclass" xmlns="">
	<refpurpose> DB2LaTeX document class </refpurpose>
	<refdescription>
		<para>
		This variable is normally empty and the stylesheets will determine
		the correct document class according to whether the document is a
		book or an article. If you wish to use your own document class,
		put its non-empty value in this variable. It will apply for both
		books and articles.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass"></xsl:param>

	<doc:param name="latex.documentclass.common" xmlns="">
	<refpurpose> DB2LaTeX document class options  </refpurpose>
	<refdescription>
		<para>
		These are the first options to be passed to <literal>\documentclass</literal>
		The common options are set to <literal>french,english</literal> by default.
		They will be augmented or superseded by article/book options (see $latex.documentclass.article and $latex.documentclass.book) and pdftex/dvips options (see $latex.documentclass.pdftex and $latex.documentclass.dvips).
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass.common">french,english</xsl:param>

	<doc:param name="latex.documentclass.article" xmlns="">
	<refpurpose> DB2LaTeX document class options for articles</refpurpose>
	<refdescription>
		<para>
		The article options are set to <literal>a4paper,10pt,twoside,twocolumn</literal> by default.
		These are the intermediate options to be passed to <literal>\documentclass</literal>,
		between the common options and the pdftex/dvips options.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass.article">a4paper,10pt,twoside,twocolumn</xsl:param>

	<doc:param name="latex.documentclass.book" xmlns="">
	<refpurpose> DB2LaTeX document class options for books</refpurpose>
	<refdescription>
		<para>
		The book options are set to <literal>a4paper,10pt,twoside,openright</literal> by default.
		These are the intermediate options to be passed to <literal>\documentclass</literal>,
		between the common options and the pdftex/dvips options.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass.book">a4paper,10pt,twoside,openright</xsl:param>

	<doc:param name="latex.documentclass.pdftex" xmlns="">
	<refpurpose> DB2LaTeX document class options for pdfTeX output</refpurpose>
	<refdescription>
		<para>
		The pdfTeX options are empty by default.
		These are the last options to be passed to <literal>\documentclass</literal>
		and override the common/article/book options.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass.pdftex"></xsl:param>

	<doc:param name="latex.documentclass.dvips" xmlns="">
	<refpurpose> DB2LaTeX document class options for dvips output</refpurpose>
	<refdescription>
		<para>
		The dvips options are empty by default.
		These are the last options to be passed to <literal>\documentclass</literal>
		and override the common/article/book options.
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.documentclass.dvips"></xsl:param>

	<doc:param name="latex.admonition.path" xmlns="">
	<refpurpose> LaTeX location for admonition graphics </refpurpose>
	<refdescription>
		<para>The file path that will be passed to LaTeX in order to find admonition graphics.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.admonition.path">figures</xsl:param>


	<doc:param name="latex.admonition.imagesize" xmlns="">
	<refpurpose> DB2LaTeX graphics admonitions size</refpurpose>
	<refdescription>
		<para>
			Is passed as an optional parameter for <literal>\includegraphics</literal> and
			can take on any such legal values (or be empty).
		</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.admonition.imagesize">width=1cm</xsl:param>


	<!--
	<xsl:param name="latex.chapter.label">1</xsl:param>

    <doc:param name="latex.chapter.hypertarget" xmlns="">
	<refpurpose> Hypertarget Chapters  </refpurpose>
	<refdescription>
	    <para>
	    </para>
	</refdescription>
    </doc:param>
    <xsl:param name="latex.chapter.hypertarget">1</xsl:param>
	-->


	<doc:param name="latex.biblio.output" xmlns="">
	<refpurpose> Control which references are cited in the bibliography </refpurpose>
	<refdescription>
		<para>
		The DB2LaTeX generated bibliography (bibitems) may either
		include all biblioentries found in the document, or only thee ones explicitly
		cited with <sgmltag class="element">citation</sgmltag>.
		</para>
	    <para>Two values are possible: <quote>all</quote> or <quote>cited</quote>.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.biblio.output">all</xsl:param>


	<doc:param name="latex.bibfiles" xmlns="">
	<refpurpose>
		Control the output of the \bibliography{.bib}.
	</refpurpose>
	<refdescription>
		<para>The value of this parameter is output.</para>
		<para>An example is <quote><filename>citations.bib</filename></quote>,
		if your BibTeX file has that name.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.bibfiles"></xsl:param>


	<doc:param name="latex.bibwidelabel" xmlns="">
	<refpurpose> Adjust bibliography formatting </refpurpose>
	<refdescription>
		<para>The environment bibliography accepts a parameter that indicates
		the widest label, which is used to correctly format the bibliography
		output. The value of this parameter is output inside the
		<literal>\begin{thebibliography[]}</literal> LaTeX command.</para>
	</refdescription>
	</doc:param>
	<xsl:param name="latex.bibwidelabel">WIDELABEL</xsl:param>

	<!--
	<xsl:variable name="latex.dont.label">0</xsl:variable>
	<xsl:variable name="latex.dont.hypertarget">0</xsl:variable>
	-->

	<doc:param name="latex.babel.language" xmlns="">
		<refpurpose>Select the optional parameter for the <productname>babel</productname> LaTeX package</refpurpose>
		<refdescription><para>See the <productname>babel</productname> documentation for details.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.babel.language">french</xsl:param>

	<doc:param name="latex.use.isolatin1" xmlns="">
		<refpurpose>Toggle the use of the <productname>isolatin1</productname> LaTeX package</refpurpose>
	</doc:param>
	<xsl:variable name="latex.use.isolatin1">1</xsl:variable>

	<doc:param name="latex.use.hyperref" xmlns="">
		<refpurpose>Toggle the use of the <productname>hyperref</productname> LaTeX package</refpurpose>
		<refdescription><para>This is used extensively for hyperlinking within documents.</para></refdescription>
	</doc:param>
	<xsl:variable name="latex.use.hyperref">1</xsl:variable>

	<doc:param name="latex.use.fancybox" xmlns="">
		<refpurpose>Toggle the use of the <productname>fancybox</productname> LaTeX package</refpurpose>
		<refdescription><para>This is essential for admonitions.</para></refdescription>
	</doc:param>
	<xsl:variable name="latex.use.fancybox">1</xsl:variable>

	<doc:param name="latex.use.fancyvrb" xmlns="">
		<refpurpose>Toggle the use of the <productname>fancyvrb</productname> LaTeX package</refpurpose>
		<refdescription><para>Provides support for tabbed whitespace in verbatim environments.
		See also <xref linkend="param.latex.fancyvrb.tabsize"/>.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.fancyvrb">1</xsl:param>

	<doc:param name="latex.fancyvrb.tabsize" xmlns="">
		<refpurpose>Choose indentation for tabs in verbatim environments</refpurpose>
		<refdescription><para>When <xref linkend="param.latex.use.fancyvrb"/> is enabled,
		this variable sets the width of a tab in terms of an equivalent number of spaces.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.fancyvrb.tabsize">3</xsl:param>

	<doc:param name="latex.use.fancyhdr" xmlns="">
		<refpurpose>Toggle the use of the <productname>fancyhdr</productname> LaTeX package</refpurpose>
		<refdescription><para>Provides page headers and footers. Disabling support for
		this package will make headers and footer go away.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.fancyhdr">1</xsl:param>

	<doc:param name="latex.use.parskip" xmlns="">
		<refpurpose>Toggle the use of the <productname>parskip</productname> LaTeX package</refpurpose>
		<refdescription><para>Support a <quote>block</quote> paragraph style as opposed to
		<quote>indented</quote>.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.parskip">0</xsl:param>

	<doc:param name="latex.use.subfigure" xmlns="">
		<refpurpose>Toggle the use of the <productname>subfigure</productname> LaTeX package</refpurpose>
		<refdescription><para>Used to provide nice layout of multiple mediaobjects in figures.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.subfigure">1</xsl:param>

	<doc:param name="latex.use.rotating" xmlns="">
		<refpurpose>Toggle the use of the <productname>rotating</productname> LaTeX package</refpurpose>
	</doc:param>
	<xsl:param name="latex.use.rotating">1</xsl:param>

	<doc:param name="latex.use.tabularx" xmlns="">
		<refpurpose>Toggle the use of the <productname>tabularx</productname> LaTeX package</refpurpose>
		<refdescription><para>Used to provide certain table features. Has some incompatabilities
		with packages, but also solves some conflicts that the regular tabular
		environment has.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.tabularx">1</xsl:param>

	<doc:param name="latex.use.umoline" xmlns="">
		<refpurpose>Toggle the use of the <productname>umoline</productname> LaTeX package</refpurpose>
		<refdescription><para>Provide underlining.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.umoline">0</xsl:param>

	<doc:param name="latex.use.url" xmlns="">
		<refpurpose>Toggle the use of the <productname>url</productname> LaTeX package</refpurpose>
		<refdescription><para>Provide partial support for hyperlinks.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.url">1</xsl:param>

	<doc:param name="latex.use.makeidx" xmlns="">
		<refpurpose>Toggle the use of the <productname>makeidx</productname> LaTeX package</refpurpose>
		<refdescription><para>Support index generation.</para></refdescription>
	</doc:param>
	<xsl:param name="latex.use.makeidx">1</xsl:param>

	<doc:param name="latex.hyphenation.tttricks" xmlns="">
	<refpurpose> DB2LaTeX hyphenation linebreak tricks </refpurpose>
	<refdescription>
		<para>
		Usually, LaTeX does not perform hyphenation in <quote>teletype</quote> (monospace)
		text. This can lead to formatting problems. But certain monospace texts, such as
		URLs and filenames, have <quote>natural</quote> breakpoints such as full stops
		and slashes. DB2LaTeX's <quote>tttricks</quote> exploit a hyphenation trick in
		order to provide line wrapping in the middle of monospace text. Set this to '1'
		to enable these tricks (they are not enabled by default). See also the FAQ.
		</para>
	</refdescription>
	</doc:param>
    <xsl:variable name="latex.hyphenation.tttricks">0</xsl:variable>

	<doc:param name="latex.hyperref.param.common" xmlns="">
	<refpurpose> DB2LaTeX hyperref options</refpurpose>
	<refdescription>
		<para>
		The hyperref options are set to <literal>bookmarksnumbered,colorlinks,backref, bookmarks, breaklinks, linktocpage</literal> by default.
		You may wish to specify additional options using <literal>latex.hyperref.param.pdftex</literal>
		or <literal>latex.hyperref.param.dvips</literal>.
		</para>
	</refdescription>
	</doc:param>
    <xsl:variable name="latex.hyperref.param.common">bookmarksnumbered,colorlinks,backref, bookmarks, breaklinks, linktocpage</xsl:variable>

	<doc:param name="latex.hyperref.param.pdftex" xmlns="">
	<refpurpose> DB2LaTeX hyperref options for pdfTeX output</refpurpose>
	<refdescription>
		<para>
		This variable is empty by default. See the hyperref documentation for further information.
		</para>
	</refdescription>
	</doc:param>
	<xsl:variable name="latex.hyperref.param.pdftex"></xsl:variable>

	<doc:param name="latex.hyperref.param.dvips" xmlns="">
	<refpurpose> DB2LaTeX hyperref options for dvips output</refpurpose>
	<refdescription>
		<para>
		This variable is empty by default. See the hyperref documentation for further information.
		</para>
	</refdescription>
	</doc:param>
	<xsl:variable name="latex.hyperref.param.dvips"></xsl:variable>

    <xsl:variable name="latex.fancyhdr.lh">Left Header</xsl:variable>
    <xsl:variable name="latex.fancyhdr.ch">Center Header</xsl:variable>
    <xsl:variable name="latex.fancyhdr.rh">Right Header</xsl:variable>
    <xsl:variable name="latex.fancyhdr.lf">Left Footer</xsl:variable>
    <xsl:variable name="latex.fancyhdr.cf">Center Footer</xsl:variable>
    <xsl:variable name="latex.fancyhdr.rf">Right Footer</xsl:variable>
	
    <doc:param name="latex.step.title.style" xmlns="">
	<refpurpose> Control the style of step titles  </refpurpose>
	<refdescription>
	    <para>Step titles are typeset in small caps but if
		this option is set to a LaTeX command, such as <literal>\itshape{}</literal>, then
		that command will precede the title and it will be typeset accordingly.</para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.step.title.style">\sc</xsl:variable>

    <doc:param name="latex.pagestyle" xmlns="">
	<refpurpose> Override DB2LaTeX's choice of LaTeX page numbering style </refpurpose>
	<refdescription>
	    <para>By default, DB2LaTeX will choose the 'plain' or 'fancy' page styles,
		depending on <xref linkend="param.latex.use.fancyhdr"/>. If non-empty, this
		variable overrides the automatic selection. An example would be the literal
		string 'empty', to eliminate headers and page numbers.</para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.pagestyle"></xsl:variable>

    <doc:param name="latex.procedure.title.style" xmlns="">
	<refpurpose> Control the style of procedure titles  </refpurpose>
	<refdescription>
	    <para>Procedure titles are typeset in small caps but if
		this option is set to a LaTeX command, such as <literal>\itshape{}</literal>, then
		that command will precede the title and it will be typeset accordingly.</para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.procedure.title.style">\sc</xsl:variable>

    <doc:param name="latex.figure.title.style" xmlns="">
	<refpurpose> Control the style of figure titles  </refpurpose>
	<refdescription>
	    <para>Figure titles are typeset in the default typeface (usually 'roman') but if
		this option is set to a LaTeX command, such as <literal>\itshape{}</literal>, then
		that command will precede the title and it will be typeset accordingly.</para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.figure.title.style"></xsl:variable>

    <doc:param name="latex.pdf.support" xmlns="">
	<refpurpose> Controls the output of LaTeX commands to support the generation 
	    of PDF files.</refpurpose>
	<refdescription>
	    <para>If this parameter is set to 1, the stylesheets generate code to 
		detect if it is either <literal>latex</literal> or <literal>pdflatex</literal>
		the shell command that is being used to compile the LaTeX text file. Some
		packages (<literal>graphicx</literal>, <literal>hyperref</literal>) are used
		with the right parameters. Finally, the graphic extensions declared, to use in
		<literal>\includegraphics</literal> commands depends also on which command is
		being used. If this parameter is set to zero, such code is not generated (which 
		does not mean that the file cannot compile with pdflatex, but some strange issues 
		may appear). <emphasis>DEFAULT: 1</emphasis> Only more code is generated. 
	    </para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.pdf.support">1</xsl:variable>



    <doc:param name="latex.thead.row.entry" xmlns="">
	<refpurpose> Format the output of tabular headings. </refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:template name="latex.thead.row.entry">
	<xsl:apply-templates/>
	</xsl:template>



    <doc:param name="latex.math.support" xmlns="">
	<refpurpose> Controls the output of LaTeX packages and commands to support 
	    documents with math commands and environments..</refpurpose>
	<refdescription>
	    <para>If this parameter is set to 1, the stylesheets generate code to 
		<emphasis>DEFAULT: 1</emphasis> Only more code is generated. 
	    </para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.math.support">1</xsl:variable>



    <doc:param name="latex.output.revhistory" xmlns="">
	<refpurpose> Controls  if the revision history table is generated as the first document 
	    table.
	</refpurpose>
	<refdescription>
	    <para>If this parameter is set to 1, the stylesheets generate code to 
		<emphasis>DEFAULT: 1</emphasis> Only more code is generated. 
	    </para>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.output.revhistory">1</xsl:variable>




    <xsl:variable name="latex.book.preamble.pre">
    </xsl:variable>

    <xsl:variable name="latex.book.preamble.post">
    </xsl:variable>

    <doc:param name="latex.book.varsets" xmlns="">
	<refpurpose> 
	    All purpose commands to change text width, height, counters, etc.
		Defaults to a two-sided margin layout.
	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.book.varsets">
	<xsl:text>\usepackage{anysize}&#10;</xsl:text>
	<xsl:text>\marginsize{3cm}{2cm}{1.25cm}{1.25cm}&#10;</xsl:text>
    </xsl:variable>

    <doc:param name="latex.book.begindocument" xmlns="">
	<refpurpose> 
	    Begin document command
	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.book.begindocument">
	<xsl:text>\begin{document}&#10;</xsl:text>
    </xsl:variable>





    <doc:param name="latex.book.afterauthor" xmlns="">
	<refpurpose> 
	    LaTeX code that is output after the author (e.g. 
	    <literal>\makeindex, \makeglossary</literal>
	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.book.afterauthor">
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\makeindex&#10;</xsl:text>
	<xsl:text>\makeglossary&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
    </xsl:variable>




    <doc:param name="latex.book.end" xmlns="">
	<refpurpose> 
	    LaTeX code that is output  at the end of the document
	    <literal>\end{document}</literal>
	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.book.end">
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% End of document&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\end{document}&#10;</xsl:text>
    </xsl:variable>



    <!--############################################################################# 
    | 	XSL VARIABLES FOR ARTICLES	
    |- #############################################################################
    |	$Author: jelmer $
    |
    + ############################################################################## -->



    <xsl:variable name="latex.article.preamble.pre">
    </xsl:variable>

    <xsl:variable name="latex.article.preamble.post">
    </xsl:variable>

    <doc:param name="latex.article.begindocument" xmlns="">
	<refpurpose> The begin document </refpurpose>
	<refdescription>The value of this variable is output from the article template
	    <xref linkend="template.article"/> after the author command. The default value
	    (shown below) is just the begin document command. Users of the XSL LaTeX
	    stylesheet may override this parameter in order to output what they want.
	</refdescription>
	<refreturn><literal>\begin{document}</literal></refreturn>
    </doc:param>
    <xsl:variable name="latex.article.begindocument">
	<xsl:text>\begin{document}&#10;</xsl:text>
    </xsl:variable>


    <doc:param name="latex.article.varsets" xmlns="">
	<refpurpose> Controls what is output after the LaTeX preamble. Basically the <literal>\maketitle</literal>
	</refpurpose>
	<refdescription>
	    <para>Default Values</para>
	    <screen><![CDATA[
		\setlength{\textwidth}{16.5cm}
		\setlength{\textheight}{22.2cm}
		\setlength{\hoffset}{-2cm}
		\setlength{\voffset}{-.9in}
		\renewcommand\floatpagefraction{.9}
		\renewcommand\topfraction{.9}
		\renewcommand\bottomfraction{.9}
		\renewcommand\textfraction{.1}
		]]></screen>
	</refdescription>
    </doc:param>

    <xsl:variable name="latex.article.varsets">
	<xsl:text>
	    \setlength{\textwidth}{16.5cm}
	    \setlength{\textheight}{22.2cm}
	    \setlength{\hoffset}{-2cm}
	    \setlength{\voffset}{-.9in}
	    \renewcommand\floatpagefraction{.9}
	    \renewcommand\topfraction{.9}
	    \renewcommand\bottomfraction{.9}
	    \renewcommand\textfraction{.1}
	</xsl:text>
    </xsl:variable>




    <doc:param name="latex.article.maketitle" xmlns="">
	<refpurpose> Controls what is output after the LaTeX preamble. Basically the <literal>\maketitle</literal>
	</refpurpose>
	<refdescription>
	    <para>Default Values</para>
	    <screen><![CDATA[
		\maketitle
		]]></screen>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.article.maketitle">
	<xsl:text>&#10;</xsl:text>
	<xsl:text>\maketitle&#10;</xsl:text>
    </xsl:variable>


    <doc:param name="latex.article.end" xmlns="">
	<refpurpose> Controls what is output at the end of the article. Basically the <literal>\end{document}</literal>
	    command, with some markup comments.	</refpurpose>
	<refdescription>
	</refdescription>
    </doc:param>
    <xsl:variable name="latex.article.end">
	<xsl:text>&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>% End of document&#10;</xsl:text>
	<xsl:text>% --------------------------------------------&#10;</xsl:text>
	<xsl:text>\end{document}&#10;</xsl:text>
    </xsl:variable>



</xsl:stylesheet>

