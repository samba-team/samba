<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: book-article.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $												
|														
|   PURPOSE:
|	This template matches a book / article
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="book-article" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: book-article.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
	    </releaseinfo>
	    <authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	    </authorgroup>
	    <copyright>
		<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Books and Articles <filename>book-article.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>









    <!--############################################################################# -->
    <!-- DOCUMENTATION -->
    <doc:template match="book" xmlns="">
	<refpurpose>Book XSL Template</refpurpose>
	<refdescription>
	    <para> Most DocBook documents are either articles or books, so the book 
		XSL template <xref linkend="template.book"/> is one classical entry point 
		when processign docbook documents.</para>

	    <formalpara><title>Tasks</title>
		<itemizedlist>
		    <listitem><para></para></listitem>
		</itemizedlist>
	    </formalpara>

	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
	<refparameter>
	    <variablelist>
		<varlistentry>
		    <term>colwidth</term>
		    <listitem>
			<para>The CALS column width specification.</para>
		    </listitem>
		</varlistentry>
	    </variablelist>
	</refparameter>
	<refreturn>
	    :<para>Outputs the LaTeX Code corresponding to a book.</para>
	</refreturn>
    </doc:template>




    <!--############################################################################# -->
    <!-- XSL TEMPLATE book                                                            -->
    <!--                                                                              -->
	<!-- Main entry point for a DocBook "book"                                        -->
    <!--############################################################################# -->
    <xsl:template match="book">
	<!-- book:1: generate.latex.book.preamble -->
	<xsl:call-template name="generate.latex.book.preamble"/>
	<!-- book:2: output title information     -->
	<xsl:text>\title{</xsl:text>
	<xsl:choose>
		<xsl:when test="./title">
		<xsl:apply-templates select="title" mode="maketitle.mode"/>
		<xsl:apply-templates select="subtitle" mode="maketitle.mode"/>
		</xsl:when>
		<xsl:otherwise>
		<xsl:apply-templates select="bookinfo/title" mode="maketitle.mode"/>
		<xsl:apply-templates select="bookinfo/subtitle" mode="maketitle.mode"/>
		</xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<!-- book:3: output author information     -->
	<xsl:text>\author{</xsl:text>
	<xsl:choose>
	    <xsl:when test="bookinfo/authorgroup">
			<xsl:apply-templates select="bookinfo/authorgroup"/>
	    </xsl:when>
	    <xsl:otherwise>
		        <xsl:for-each select="bookinfo/author">
            			<xsl:apply-templates select="."/>
            			<xsl:if test="not(position()=last())">
                			<xsl:text> \and </xsl:text>
            			</xsl:if>
        		</xsl:for-each>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<!-- book:4: dump any preamble after author  -->
	<xsl:value-of select="$latex.book.afterauthor"/>
	<!-- book:5: set some counters  -->
	<xsl:text>&#10;\setcounter{tocdepth}{</xsl:text><xsl:value-of select="$toc.section.depth"/><xsl:text>}&#10;</xsl:text>
	<xsl:text>&#10;\setcounter{secnumdepth}{</xsl:text><xsl:value-of select="$section.depth"/><xsl:text>}&#10;</xsl:text>
	<!-- book:6: dump the begin document command  -->
	<xsl:value-of select="$latex.book.begindocument"/>

	<!-- book:7: include external Cover page if specified -->
	<xsl:if test="$latex.titlepage.file != ''">
			<xsl:text>&#10;\InputIfFileExists{</xsl:text><xsl:value-of select="$latex.titlepage.file"/>
			<xsl:text>}{\typeout{WARNING: Using cover page</xsl:text>
			<xsl:value-of select="$latex.titlepage.file"/>
			<xsl:text>}}</xsl:text>
	</xsl:if>

	<!-- book:7b: maketitle and set up pagestyle -->
	<xsl:value-of select="$latex.maketitle"/>
	<!-- book:8: - APPLY TEMPLATES -->
	<xsl:apply-templates/>
	<!-- book:9:  call map.end -->
	<xsl:call-template name="map.end"/>
    </xsl:template>


    <!-- Titles/subtitles -->
	<!-- Empty templates  -->

	<xsl:template match="book/title"/>
	<xsl:template match="book/subtitle"/>
	<xsl:template match="book/titleabbrev"/>
	<xsl:template match="book/bookinfo/title"/>
	<xsl:template match="book/bookinfo/subtitle"/>
	<xsl:template match="book/bookinfo/titleabbrev"/>

	<xsl:template match="book/title" mode="maketitle.mode">\bfseries <xsl:apply-templates /></xsl:template>
	<xsl:template match="book/subtitle" mode="maketitle.mode">\\[12pt]\normalsize <xsl:apply-templates /></xsl:template>
	<xsl:template match="book/bookinfo/title" mode="maketitle.mode">\bfseries <xsl:apply-templates /></xsl:template>
	<xsl:template match="book/bookinfo/subtitle" mode="maketitle.mode">\\[12pt]\normalsize <xsl:apply-templates /></xsl:template>

    <xsl:template match="book/bookinfo">
	<xsl:apply-templates select="revhistory" />
	<xsl:apply-templates select="abstract" />
	<xsl:apply-templates select="keywordset" />
	<xsl:apply-templates select="copyright" />
	<xsl:apply-templates select="legalnotice" />
    </xsl:template>



    <!--############################################################################# 
    |   Template : article 
    +   ############################################################################# -->

    <!-- DOCUMENTATION -->
    <doc:template match="article" xmlns="">
	<refpurpose>Article XSL Template</refpurpose>
	<refdescription>
	    <para> Most DocBook documents are either articles or books, so the article
		XSL template <xref linkend="template.article"/> is one classical entry point 
		when processign docbook documents.</para>

	    <formalpara><title>Tasks</title>
		<itemizedlist>
		    <listitem><para>Calls <literal>generate.latex.article.preamble</literal>.</para></listitem>
		    <listitem><para>Outputs \title, \author, \date, getting the information from its children.</para></listitem>
		    <listitem><para>Calls <literal>latex.article.begindocument</literal>.</para></listitem>
		    <listitem><para>Calls <literal>latex.article.maketitle.</literal></para></listitem>
		    <listitem><para>Applies templates.</para></listitem>
		    <listitem><para>Calls <literal>latex.article.end</literal> template.</para></listitem>
		</itemizedlist>
	    </formalpara>

	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		    <listitem><para> EMPTY templates: article/title and article/subtitle</para></listitem>
		</itemizedlist>
	    </formalpara>
	</refdescription>
	<refparameter>
	    <variablelist>
		<varlistentry>
		    <term>colwidth</term>
		    <listitem>
			<para>The CALS column width specification.</para>
		    </listitem>
		</varlistentry>
	    </variablelist>
	</refparameter>
	<refreturn>
	    <para>Outputs the LaTeX Code corresponding to an article.</para>
	</refreturn>
    </doc:template>
    <!--############################################################################# -->


    <xsl:template match="book/article">
	<xsl:text>&#10;\makeatletter\if@openright\cleardoublepage\else\clearpage\fi</xsl:text>
	<xsl:call-template name="generate.latex.pagestyle"/>
	<xsl:text>\makeatother&#10;</xsl:text>	
	<!-- Get and output article title -->
	<xsl:variable name="article.title">
	    <xsl:choose>
			<xsl:when test="./title"> 
				<xsl:apply-templates select="./title"/>
			</xsl:when>
			<xsl:when test="./articleinfo/title">
				<xsl:apply-templates select="./articleinfo/title"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:apply-templates select="./artheader/title"/>
			</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>\begin{center}{</xsl:text>
	<xsl:value-of select="$latex.book.article.title.style"/>
	<xsl:text>{</xsl:text>
	<xsl:value-of select="$article.title"/>
	<xsl:text>}}\par&#10;</xsl:text>
	<!-- Display author information --> 
	<xsl:choose>
	    <xsl:when test="artheader/author">		
			<xsl:text>\textsf{</xsl:text>
			<xsl:for-each select="artheader/author">
				<xsl:apply-templates select="."/>
				<xsl:if test="not(position()=last())">
					<xsl:text> \and </xsl:text>
				</xsl:if>
			</xsl:for-each>
			<xsl:text>}\par&#10;</xsl:text>
		</xsl:when>
	    <xsl:when test="artheader/authorgroup">
			<xsl:text>\textsf{</xsl:text>
			<xsl:apply-templates select="artheader/authorgroup"/>
			<xsl:text>}\par&#10;</xsl:text>
		</xsl:when>
	    <xsl:when test="articleinfo/author">
			<xsl:text>\textsf{</xsl:text>
			<xsl:for-each select="articleinfo/author">
				<xsl:apply-templates select="."/>
				<xsl:if test="not(position()=last())">
					<xsl:text> \and </xsl:text>
				</xsl:if>
			</xsl:for-each>
			<xsl:text>}\par&#10;</xsl:text>
		</xsl:when>
	    <xsl:when test="articleinfo/authorgroup">
			<xsl:text>\textsf{</xsl:text>
			<xsl:apply-templates select="articleinfo/authorgroup"/>
			<xsl:text>}\par&#10;</xsl:text>
		</xsl:when>
	    <xsl:when test="author">
			<xsl:text>\textsf{</xsl:text>
			<xsl:for-each select="author">
				<xsl:apply-templates select="."/>
				<xsl:if test="not(position()=last())">
					<xsl:text> \and </xsl:text>
				</xsl:if>
			</xsl:for-each>
			<xsl:text>}\par&#10;</xsl:text>
		</xsl:when>
	</xsl:choose>
	<xsl:apply-templates select="artheader|articleinfo" mode="article.within.book"/>
	<xsl:text>\end{center}&#10;</xsl:text>
	<xsl:apply-templates select="*[not(self::title)]"/>
	</xsl:template>

	<xsl:template match="artheader|articleinfo" mode="article.within.book">
		<xsl:value-of select="."/>
	</xsl:template>



    <!-- ARTICLE TEMPLATE -->
    <xsl:template match="article">
	<!-- Output LaTeX preamble -->
	<xsl:call-template name="generate.latex.article.preamble"/>
	<!-- Get and output article title -->
	<xsl:variable name="article.title">
	    <xsl:choose>
			<xsl:when test="./title"> 
				<xsl:apply-templates select="./title"/>
			</xsl:when>
			<xsl:when test="./articleinfo/title">
				<xsl:apply-templates select="./articleinfo/title"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:apply-templates select="./artheader/title"/>
			</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>\title{</xsl:text>
	<xsl:value-of select="$latex.article.title.style"/>
	<xsl:text>{</xsl:text>
	<xsl:value-of select="$article.title"/>
	<xsl:text>}}&#10;</xsl:text>
	<!-- Display date and author information --> 
	<xsl:variable name="article.date">
		<xsl:apply-templates select="./artheader/date|./articleinfo/date"/>
	</xsl:variable>
	<xsl:if test="$article.date!=''">
		<xsl:text>\date{</xsl:text>
		<xsl:value-of select="$article.date"/>
		<xsl:text>}&#10;</xsl:text>
	</xsl:if>
	<xsl:text>\author{</xsl:text>
	<xsl:choose>
	    <xsl:when test="artheader/authorgroup">
			<xsl:apply-templates select="artheader/authorgroup"/>
		</xsl:when>
	    <xsl:when test="articleinfo/authorgroup">
			<xsl:apply-templates select="articleinfo/authorgroup"/>
		</xsl:when>
	    <xsl:when test="artheader/author">		
		<xsl:for-each select="artheader/author">
			<xsl:apply-templates select="."/>
			<xsl:if test="not(position()=last())">
				<xsl:text> \and </xsl:text>
			</xsl:if>
		</xsl:for-each>
		</xsl:when>
	    <xsl:when test="articleinfo/author">
		<xsl:for-each select="articleinfo/author">
			<xsl:apply-templates select="."/>
			<xsl:if test="not(position()=last())">
				<xsl:text> \and </xsl:text>
			</xsl:if>
		</xsl:for-each>
		</xsl:when>
	    <xsl:otherwise>
		<xsl:for-each select="author">
			<xsl:apply-templates select="."/>
			<xsl:if test="not(position()=last())">
				<xsl:text> \and </xsl:text>
			</xsl:if>
		</xsl:for-each>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:text>}&#10;</xsl:text>
	<!-- Display  begindocument command -->
	<xsl:value-of select="$latex.article.begindocument"/>
	<xsl:value-of select="$latex.maketitle"/>
	<xsl:apply-templates select="*[not(self::title)]"/>
	<xsl:value-of select="$latex.article.end"/>
    </xsl:template>


    <xsl:template match="article/title|articleinfo/title|articleinfo/date|artheader/date">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="article/artheader|article/articleinfo">
	<xsl:apply-templates select="legalnotice" />
	<xsl:apply-templates select="abstract"/>
    </xsl:template>

    <!-- EMPTY TEMPLATES -->
    <xsl:template match="article/subtitle"/>



	
    <!--############################################################################# 
    |   Template: copyright
    |-  ############################################################################# -->
	<xsl:template match="copyright">
		<xsl:call-template name="gentext.element.name"/>
		<xsl:call-template name='gentext.space'/>
		<xsl:call-template name="dingbat">
			<xsl:with-param name="dingbat">copyright</xsl:with-param>
		</xsl:call-template>
		<xsl:call-template name='gentext.space'/>
		<xsl:apply-templates select="year"/>
		<xsl:call-template name='gentext.space'/>
		<xsl:apply-templates select="holder"/>
	</xsl:template>

	<xsl:template match="copyright/holder">
		<xsl:apply-templates />
	</xsl:template>
	<xsl:template match="copyright/year[position()&lt;last()-1]">
		<xsl:apply-templates />
		<xsl:text>, </xsl:text>
	</xsl:template>

	<!-- RCAS 2003/03/11 FIXME : "and" -->
	<xsl:template match="copyright/year[position()=last()-1]">
		<xsl:apply-templates />
		<xsl:text>, </xsl:text>
	</xsl:template>
	
	<xsl:template match="copyright/year[position()=last()]">
		<xsl:apply-templates />
	</xsl:template>




    <!--############################################################################# 
    |   Template: name legalnotice.caption
    |-  ############################################################################# -->
	<xsl:template name="legalnotice.caption">
	<xsl:choose>
		<xsl:when test="./title">
			<xsl:apply-templates select="./title"/>
		</xsl:when>
		<xsl:otherwise>
    		<xsl:call-template name="gentext">
        		<xsl:with-param name="key">legalnotice</xsl:with-param>
    		</xsl:call-template>
		</xsl:otherwise>
	</xsl:choose>
	</xsl:template>



    <!--############################################################################# 
    |   Template: legalnotice 
    |-  ############################################################################# -->
<xsl:template match="legalnotice">
 	<!-- Support for legalnotice. -->
    <xsl:text>\vspace{-.3em}&#10;</xsl:text>
    <xsl:text>\if@twocolumn&#10;</xsl:text>
    <xsl:text>\noindent\small{\itshape &#10;</xsl:text>
	<xsl:call-template name="legalnotice.caption"/>
    <xsl:text>}\/\bfseries---$\!$%&#10;</xsl:text>
    <xsl:text>\else&#10;</xsl:text>
    <xsl:text>\noindent\begin{center}\small\bfseries &#10;</xsl:text>
	<xsl:call-template name="legalnotice.caption"/>
    <xsl:text>\end{center}\quotation\small&#10;</xsl:text>
    <xsl:text>\fi&#10;</xsl:text>
	<xsl:apply-templates select="*[not(self::title)]"/>
    <xsl:text>\vspace{0.6em}\par\if@twocolumn\else\endquotation\fi&#10;</xsl:text>
    <xsl:text>\normalsize\rmfamily&#10;</xsl:text>
</xsl:template>


	<xsl:template match="legalnotice/title">
		<xsl:apply-templates/>
	</xsl:template>



    <!--############################################################################# 
    |	$Id: book-article.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
    |- #############################################################################
    |	$Author: ab $
    |														
    |   PURPOSE: Table of Contents, Figures, ...
    + ############################################################################## -->

    <xsl:template match="toc">
	<xsl:text>&#10;</xsl:text>
	<xsl:text>\tableofcontents&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="lot">
	<xsl:choose>
		<xsl:when test="@label">
			<xsl:choose>
				<xsl:when test="@label='figures'">
					<xsl:text>\listoffigures&#10;</xsl:text>
				</xsl:when>
				<xsl:when test="@label='tables'">
					<xsl:text>\listoftables&#10;</xsl:text>
				</xsl:when>
				<xsl:otherwise>
					<xsl:text>\listoffigures&#10;</xsl:text>
					<xsl:text>\listoftables&#10;</xsl:text>
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>\listoffigures&#10;</xsl:text>
			<xsl:text>\listoftables&#10;</xsl:text>
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>


    <xsl:template match="lotentry">
    </xsl:template>

    <xsl:template match="lotentry"/>
    <xsl:template match="tocpart|tocchap|tocfront|tocback|tocentry"/>
    <xsl:template match="toclevel1|toclevel2|toclevel3|toclevel4|toclevel5"/>

    <doc:template name="generate.latex.pagestyle" xmlns="">
	<refpurpose> Choose the preferred page style for document body </refpurpose>
	<refdescription>
		<para>
			If no page style is preferred by the user, the defaults will be
			"empty" for articles, "plain" for books, or "fancy" (if the
			fancyhdr packages is permitted).
		</para>
		<formalpara><title>Pertinent Variables</title>
		<itemizedlist>
			<listitem><simpara><xref linkend="param.pagestyle"/></simpara></listitem>
			<listitem><simpara><xref linkend="param.use.fancyhdr"/></simpara></listitem>
		</itemizedlist>
		</formalpara>
	</refdescription>
    </doc:template>
	<xsl:template name="generate.latex.pagestyle">
		<xsl:text>\pagestyle{</xsl:text>
		<xsl:choose>
			<xsl:when test="$latex.pagestyle!=''"><xsl:value-of select="$latex.pagestyle"/></xsl:when>
			<xsl:when test="count(//book)&gt;0">
				<xsl:choose>
					<xsl:when test="$latex.use.fancyhdr=1"><xsl:text>fancy</xsl:text></xsl:when>
					<xsl:otherwise><xsl:text>plain</xsl:text></xsl:otherwise>
				</xsl:choose>
			</xsl:when>
			<xsl:otherwise><xsl:text>empty</xsl:text></xsl:otherwise>
		</xsl:choose>
		<xsl:text>}</xsl:text>
	</xsl:template>
	
</xsl:stylesheet>

