<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: biblio.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $												
|														
|   PURPOSE: Manage Bibliography.
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="biblio" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: biblio.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
	    </releaseinfo>
	    <authorgroup>
	    <author> <firstname>Ramon</firstname> <surname>Casellas</surname> </author>
	    <author> <firstname>James</firstname> <surname>Devenish</surname> </author>
	    </authorgroup>
	    <copyright>
		<year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>

	<title>Bibliography related XSL Variables and Templates <filename>biblio.mod.xsl</filename></title>

	<partintro>
	    <section><title>Introduction</title>
		<para>This reference describes the templates and parameters relevant
		    to formatting DocBook bibliography markup.</para>
	    </section>
	    <section><title>All Vs. Cited mode</title>
		<para> Using this option, only the biblioentries that have been 
		    cited somewhere in the document are output. Otherwise (in All mode)
		    all bibentries found are output (as the HTML stylesheets do).</para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->



    <!--############################################################################# 
    |	BIBLIOGRAPHY	
    |- #############################################################################
    |	
    |														
    |   
    + ############################################################################## -->

    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="bibliography" xmlns="">
	<refpurpose> bibliography XSL template </refpurpose>
	<refdescription>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="bibliography">
	<xsl:message>DB2LaTeX: Processing BIBLIOGRAPHY</xsl:message>
	<xsl:message>DB2LaTeX: Output Mode :  <xsl:value-of select="$latex.biblio.output"/></xsl:message>
	<xsl:text>% ------------------------------------------- &#10;</xsl:text>
	<xsl:text>%	&#10;</xsl:text>
	<xsl:text>%  Bibliography&#10;</xsl:text>
	<xsl:text>%	&#10;</xsl:text>
	<xsl:text>% -------------------------------------------	&#10;</xsl:text>
	<xsl:text>\bibliography{</xsl:text><xsl:value-of select="$latex.bibfiles"/><xsl:text>}&#10;</xsl:text>
	<xsl:if test="biblioentry or bibliodiv">
	<xsl:text>\begin{thebibliography}{</xsl:text>
	<xsl:value-of select="$latex.bibwidelabel"/>
	<xsl:text>}&#10;</xsl:text>
	<xsl:choose>
	    <xsl:when test="$latex.biblio.output ='cited'">
		<xsl:apply-templates select="biblioentry" mode="bibliography.cited">
		    <xsl:sort select="./abbrev"/>
		    <xsl:sort select="./@xreflabel"/>
		    <xsl:sort select="./@id"/>
		</xsl:apply-templates>
	    </xsl:when>
	    <xsl:when test="$latex.biblio.output ='all'">
		<xsl:apply-templates select="biblioentry" mode="bibliography.all">
		    <xsl:sort select="./abbrev"/>
		    <xsl:sort select="./@xreflabel"/>
		    <xsl:sort select="./@id"/>
		</xsl:apply-templates>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:apply-templates select="biblioentry">
		    <xsl:sort select="./abbrev"/>
		    <xsl:sort select="./@xreflabel"/>
		    <xsl:sort select="./@id"/>
		</xsl:apply-templates>
	    </xsl:otherwise>
	</xsl:choose>
	<!-- <xsl:apply-templates select="child::*[name(.)!='biblioentry']"/>  -->
	<xsl:apply-templates select="bibliodiv"/> 
	<xsl:text>&#10;\end{thebibliography}&#10;</xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template match="bibliography/title"/>
    <xsl:template match="bibliography/subtitle"/>
    <xsl:template match="bibliography/titleabbrev"/>



    <!--############################################################################# 
    |	BIBLIODIV
    |- #############################################################################
    |	
    |														
    |   
    + ############################################################################## -->

    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="bibliodiv" xmlns="">
	<refpurpose> bibliography XSL template </refpurpose>
	<refdescription>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="bibliodiv">
	<xsl:message>DB2LaTeX: Processing BIBLIOGRAPHY - BIBLIODIV</xsl:message>
	<!--
	<xsl:call-template name="label.id"/>
	<xsl:text>&#10;</xsl:text>
	<xsl:text>\vspace{1cm}</xsl:text>
	<xsl:text>\noindent{\Large {\sc </xsl:text><xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> </xsl:call-template>
	<xsl:text>}}\\&#10;&#10;</xsl:text>
	-->
	<xsl:choose>
	    <xsl:when test="$latex.biblio.output ='cited'">
		<xsl:apply-templates select="biblioentry" mode="bibliography.cited">
		    <xsl:sort select="./abbrev"/>
		    <xsl:sort select="./@xreflabel"/>
		    <xsl:sort select="./@id"/>
		</xsl:apply-templates>
	    </xsl:when>
	    <xsl:when test="$latex.biblio.output ='all'">
		<xsl:apply-templates select="biblioentry">
		    <xsl:sort select="./abbrev"/>
		    <xsl:sort select="./@xreflabel"/>
		    <xsl:sort select="./@id"/>
		</xsl:apply-templates>
	    </xsl:when>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="bibliodiv/title"/>



    <!--############################################################################# 
    |	BIBLIOENTRY
    - #############################################################################
    |	
    |														
    |   
    + ############################################################################## -->


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="biblioentry" mode="bibliography.cited" xmlns="">
	<refpurpose> bibliography XSL template </refpurpose>
	<refdescription>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="biblioentry" mode="bibliography.cited">
	<xsl:param name="bibid" select="@id"/>
	<xsl:param name="ab" select="abbrev"/>
	<xsl:variable name="nx" select="//xref[@linkend=$bibid]"/>
	<xsl:variable name="nc" select="//citation[text()=$ab]"/>
	<xsl:if test="count($nx) &gt; 0 or count($nc) &gt; 0">
	    <xsl:call-template name="biblioentry.output"/>
	</xsl:if>
    </xsl:template>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="biblioentry"  mode="bibliography.all" xmlns="">
	<refpurpose> bibliography XSL template </refpurpose>
	<refdescription>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		</itemizedlist>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <xsl:template match="biblioentry" mode="bibliography.all">
	<xsl:call-template name="biblioentry.output"/>
    </xsl:template>

    <xsl:template match="biblioentry">
	<xsl:call-template name="biblioentry.output"/>
    </xsl:template>

    <xsl:template name="biblioentry.output">
	<xsl:variable name="biblioentry.label">
	    <xsl:choose>
		<xsl:when test="@xreflabel">
		    <xsl:value-of select="normalize-space(@xreflabel)"/> 
		</xsl:when>
		<xsl:when test="abbrev">
		    <xsl:apply-templates select="abbrev" mode="bibliography.mode"/> 
		</xsl:when>
		<xsl:when test="@id">
		    <xsl:value-of select="normalize-space(@id)"/> 
		</xsl:when>
		<xsl:otherwise>
		</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:variable name="biblioentry.id">
	    <xsl:choose>
		<xsl:when test="abbrev">
		    <xsl:apply-templates select="abbrev" mode="bibliography.mode"/> 
		</xsl:when>
		<xsl:otherwise>
			<xsl:call-template name="generate.label.id"/>
		</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>&#10;</xsl:text>
	<xsl:text>% -------------- biblioentry &#10;</xsl:text>
	<xsl:choose>
		<xsl:when test="$biblioentry.label=''">
			<xsl:text>\bibitem</xsl:text> 
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>\bibitem[</xsl:text>
			<xsl:call-template name="normalize-scape">
				<xsl:with-param name="string" select="$biblioentry.label"/>
			</xsl:call-template>
			<xsl:text>]</xsl:text> 
		</xsl:otherwise>
	</xsl:choose>
	<xsl:text>{</xsl:text>
	<xsl:value-of select="$biblioentry.id"/>
	<xsl:text>}\docbooktolatexbibaux{</xsl:text> 
	<xsl:call-template name="generate.label.id"/> 
	<xsl:text>}{</xsl:text> 
	<xsl:value-of select="$biblioentry.id"/>
	<xsl:text>}&#10;\hypertarget{</xsl:text> 
	<xsl:call-template name="generate.label.id"/> 
	<xsl:text>}{\emph{</xsl:text> <xsl:apply-templates select="title" mode="bibliography.mode"/> <xsl:text>}}</xsl:text>
	<xsl:value-of select="$biblioentry.item.separator"/>
	<xsl:apply-templates select="author|authorgroup" mode="bibliography.mode"/>
	<xsl:for-each select="child::copyright|child::publisher|child::pubdate|child::pagenums|child::isbn|child::editor|child::releaseinfo">
	    <xsl:value-of select="$biblioentry.item.separator"/>
	    <xsl:apply-templates select="." mode="bibliography.mode"/> 
	</xsl:for-each>
	<xsl:text>.</xsl:text>
	<xsl:text>&#10;&#10;</xsl:text>
    </xsl:template>

    <!-- EMPTY templates -->
    <xsl:template match="abstract" mode="bibliography.mode"/>
    <xsl:template match="authorblurb" mode="bibliography.mode"/>



    <xsl:template match="abbrev" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="address" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="affiliation" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="shortaffil" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="jobtitle" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="artheader" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="artpagenums" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="author" mode="bibliography.mode">
	<xsl:variable name="authorsstring">
	    <xsl:call-template name="person.name"/>
	</xsl:variable>
	<xsl:value-of select="normalize-space($authorsstring)"/>
    </xsl:template>



    <xsl:template match="author[position()=last()]" mode="bibliography.mode">
	<xsl:variable name="authorsstring">
	    <xsl:call-template name="person.name"/>
	</xsl:variable>
	<xsl:value-of select="normalize-space($authorsstring)"/>
    </xsl:template>


    <!-- 
    Authorgroup
    calls person.name.list in ../common/common.xsl in order to get a
    formatted string. We need to return to "normalized-space(.) of it 
    -->

    <xsl:template match="authorgroup" mode="bibliography.mode">
	<xsl:variable name="authorsstring">
	    <xsl:call-template name="person.name.list"/>
	</xsl:variable>
	<xsl:value-of select="normalize-space($authorsstring)"/>
    </xsl:template>

    <xsl:template match="authorinitials" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="bibliomisc" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="bibliomset" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="bibliomixed" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>







    <xsl:template match="biblioset" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="biblioset/title|biblioset/citetitle" 
	mode="bibliography.mode">
	<xsl:variable name="relation" select="../@relation"/>
	<xsl:choose>
	    <xsl:when test="$relation='article'">
		<xsl:call-template name="dingbat">
		    <xsl:with-param name="dingbat">ldquo</xsl:with-param>
		</xsl:call-template>
		<xsl:apply-templates/>
		<xsl:call-template name="dingbat">
		    <xsl:with-param name="dingbat">rdquo</xsl:with-param>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:apply-templates/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="bookbiblio" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="citetitle" mode="bibliography.mode">
	<I><xsl:apply-templates mode="bibliography.mode"/></I>
    </xsl:template>

    <xsl:template match="collab" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="collabname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="confgroup" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="confdates" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="conftitle" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="confnum" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="confsponsor" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="contractnum" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="contractsponsor" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="contrib" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="copyright" mode="bibliography.mode">
	<xsl:call-template name="gentext.element.name"/>
	<xsl:call-template name="gentext.space"/>
	<xsl:call-template name="dingbat">
	    <xsl:with-param name="dingbat">copyright</xsl:with-param>
	</xsl:call-template>
	<xsl:call-template name="gentext.space"/>
	<xsl:apply-templates select="year" mode="bibliography.mode"/>
	<xsl:call-template name="gentext.space"/>
	<xsl:apply-templates select="holder" mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="year" mode="bibliography.mode">
	<xsl:apply-templates/><xsl:text>, </xsl:text>
    </xsl:template>

    <xsl:template match="year[position()=last()]" mode="bibliography.mode">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="holder" mode="bibliography.mode">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="corpauthor" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="corpname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="date" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="edition" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="editor" mode="bibliography.mode">
	<xsl:call-template name="person.name"/>
    </xsl:template>

    <xsl:template match="firstname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="honorific" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="indexterm" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="invpartnumber" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="isbn" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="issn" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="issuenum" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="lineage" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="orgname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="orgdiv" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="othercredit" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="othername" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="pagenums" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="printhistory" mode="bibliography.mode">
	<!-- suppressed -->
    </xsl:template>

    <xsl:template match="productname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="productnumber" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="pubdate" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="publisher" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="publishername" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="pubsnumber" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="releaseinfo" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="revhistory" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="seriesinfo" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="seriesvolnums" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="subtitle" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="surname" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="title" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="titleabbrev" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="volumenum" mode="bibliography.mode">
	<xsl:apply-templates mode="bibliography.mode"/>
    </xsl:template>

    <xsl:template match="*" mode="bibliography.mode">
	<xsl:apply-templates select="."/>
    </xsl:template>

</xsl:stylesheet>
