<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: inline.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
|- #############################################################################
|	$Author: ab $
|														
|   PURPOSE:
+ ############################################################################## -->
<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>


    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="inline" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: inline.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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
	<title>Inline <filename>inline.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>
    <!--############################################################################# -->




    <xsl:template name="inline.charseq">
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:copy-of select="$content"/>
    </xsl:template>

    <xsl:template name="inline.monoseq">
	<xsl:param name="hyphenation">\docbookhyphenatedot</xsl:param>
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>{\texttt{</xsl:text>
	<xsl:if test="$latex.hyphenation.tttricks='1'"><xsl:value-of select="$hyphenation" /></xsl:if>
	<xsl:text>{</xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}}}</xsl:text>
    </xsl:template>

    <xsl:template name="inline.boldseq">
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>{\bfseries </xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}</xsl:text>
    </xsl:template>

    <xsl:template name="inline.italicseq">
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>{\em </xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}</xsl:text>
    </xsl:template>

    <xsl:template name="inline.boldmonoseq">
	<xsl:param name="hyphenation">\docbookhyphenatedot</xsl:param>
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>{\texttt\bfseries{</xsl:text>
	<xsl:if test="$latex.hyphenation.tttricks='1'"><xsl:value-of select="$hyphenation" /></xsl:if>
	<xsl:text>{</xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}}}</xsl:text>
    </xsl:template>

    <xsl:template name="inline.italicmonoseq">
	<xsl:param name="hyphenation">\docbookhyphenatedot</xsl:param>
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>{\texttt\itshape{</xsl:text>
	<xsl:if test="$latex.hyphenation.tttricks='1'"><xsl:value-of select="$hyphenation" /></xsl:if>
	<xsl:text>{</xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}}}</xsl:text>
    </xsl:template>

    <xsl:template name="inline.superscriptseq">
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>$^\text{</xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}$</xsl:text>
    </xsl:template>

    <xsl:template name="inline.subscriptseq">
	<xsl:param name="content">
	    <xsl:apply-templates/>
	</xsl:param>
	<xsl:text>$_\text{</xsl:text>
	<xsl:copy-of select="$content"/>
	<xsl:text>}$</xsl:text>
    </xsl:template>






    <!-- ==================================================================== -->
    <!-- some special cases -->

    <xsl:template match="author">
	<xsl:call-template name="person.name"/>
    </xsl:template>

    <xsl:template match="editor">
	<xsl:call-template name="person.name"/>
    </xsl:template>

    <xsl:template match="othercredit">
	<xsl:call-template name="person.name"/>
    </xsl:template>

    <xsl:template match="authorinitials">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="accel">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="action">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="application">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="classname">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="exceptionname">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="interfacename">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="methodname">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="command">
	<xsl:call-template name="inline.boldseq"/>
    </xsl:template>

    <xsl:template match="computeroutput">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="constant">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="database">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="errorcode">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="errorname">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="errortype">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="envar">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="filename">
	<xsl:call-template name="inline.monoseq"><xsl:with-param name="hyphenation">\docbookhyphenatefilename</xsl:with-param></xsl:call-template>
    </xsl:template>



    <xsl:template match="function">
	<xsl:choose>
	    <xsl:when test="$function.parens != '0'
		or parameter or function or replaceable"> <xsl:variable name="nodes" select="text()|*"/>
		<xsl:call-template name="inline.monoseq">
		    <xsl:with-param name="content">
			<xsl:apply-templates select="$nodes[1]"/>
		    </xsl:with-param>
		</xsl:call-template>
		<xsl:text>(</xsl:text>
		<xsl:apply-templates select="$nodes[position()>1]"/>
		<xsl:text>)</xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:call-template name="inline.monoseq"/>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="function/parameter" priority="2">
	<xsl:call-template name="inline.italicmonoseq"/>
	<xsl:if test="following-sibling::*">
	    <xsl:text>, </xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template match="function/replaceable" priority="2">
	<xsl:call-template name="inline.italicmonoseq"/>
	<xsl:if test="following-sibling::*">
	    <xsl:text>, </xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template match="guibutton|guiicon|guilabel|guimenu|guimenuitem|guisubmenu|interface">
	<xsl:text>{\sffamily \bfseries </xsl:text>
	<xsl:call-template name="inline.charseq" />
	<xsl:text>}</xsl:text>
    </xsl:template>

    <xsl:template match="hardware">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="interfacedefinition">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="keycap|keysym">
	<xsl:call-template name="inline.boldseq" />
    </xsl:template>

    <xsl:template match="keycode">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="literal">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="medialabel">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="shortcut">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="mousebutton">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="option">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="parameter" priority="1">
	<xsl:call-template name="inline.italicmonoseq"/>
    </xsl:template>

    <xsl:template match="property">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="prompt">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="replaceable" priority="1">
	<xsl:call-template name="inline.italicmonoseq"/>
    </xsl:template>

    <xsl:template match="returnvalue">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="structfield">
	<xsl:call-template name="inline.italicmonoseq"/>
    </xsl:template>

    <xsl:template match="structname">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="symbol">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="systemitem">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="token">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="type">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="userinput">
	<xsl:call-template name="inline.boldmonoseq"/>
    </xsl:template>

    <xsl:template match="abbrev">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="acronym">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="citerefentry">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="citetitle">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="emphasis">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="emphasis[@role='bold']">
	<xsl:call-template name="inline.boldseq"/>
    </xsl:template>

    <xsl:template match="foreignphrase">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="markup">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

	<doc:template match="phrase">
		<refpurpose> A span of text </refpurpose>
		<refdescription><para>
			This is a regular inline sequence.
			However, if the role attribute is 'tex' or 'latex', the content
			will be output without LaTeX active-character escaping.
		</para></refdescription>
	</doc:template>
    <xsl:template match="phrase">
	<xsl:choose>
		<xsl:when test="@role='tex' or @role='latex'">
			<xsl:value-of select="."/>
		</xsl:when>
		<xsl:otherwise>
			<xsl:call-template name="inline.charseq"/>
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <xsl:template match="quote">
	<xsl:call-template name="gentext.nestedstartquote"/>
	<xsl:call-template name="inline.charseq"/>
	<xsl:call-template name="gentext.nestedendquote"/>
    </xsl:template>

    <xsl:template match="varname">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

    <xsl:template match="wordasword">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="lineannotation">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="superscript">
	<xsl:call-template name="inline.superscriptseq"/>
    </xsl:template>

    <xsl:template match="subscript">
	<xsl:call-template name="inline.subscriptseq"/>
    </xsl:template>

    <xsl:template match="trademark">
	<xsl:call-template name="inline.charseq"/>
	<xsl:call-template name="dingbat">
	    <xsl:with-param name="dingbat">trademark</xsl:with-param>
	</xsl:call-template>
    </xsl:template>

    <xsl:template match="firstterm">
	<xsl:call-template name="inline.italicseq"/>
    </xsl:template>

    <xsl:template match="glossterm">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="keycombo">
	<xsl:variable name="action" select="@action"/>
	<xsl:variable name="joinchar">
	    <xsl:choose>
		<xsl:when test="$action='seq'"><xsl:text> </xsl:text></xsl:when>
		<xsl:when test="$action='simul'">+</xsl:when>
		<xsl:when test="$action='press'">--</xsl:when>
		<xsl:when test="$action='click'">--</xsl:when>
		<xsl:when test="$action='double-click'">--</xsl:when>
		<xsl:when test="$action='other'"></xsl:when>
		<xsl:otherwise>--</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:for-each select="./*">
	    <xsl:if test="position()>1"><xsl:value-of select="$joinchar"/></xsl:if>
	    <xsl:apply-templates select="."/>
	</xsl:for-each>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="menuchoice">
	<xsl:variable name="shortcut" select="./shortcut"/>
	<xsl:call-template name="process.menuchoice"/>
	<xsl:if test="$shortcut">
	    <xsl:text> (</xsl:text>
	    <xsl:apply-templates select="$shortcut"/>
	    <xsl:text>)</xsl:text>
	</xsl:if>
    </xsl:template>

    <xsl:template name="process.menuchoice">
	<xsl:param name="nodelist" select="guibutton|guiicon|guilabel|guimenu|guimenuitem|guisubmenu|interface"/><!-- not(shortcut) -->
	<xsl:param name="count" select="1"/>

	<xsl:choose>
	    <xsl:when test="$count>count($nodelist)"></xsl:when>
	    <xsl:when test="$count=1">
		<xsl:apply-templates select="$nodelist[$count=position()]"/>
		<xsl:call-template name="process.menuchoice">
		    <xsl:with-param name="nodelist" select="$nodelist"/>
		    <xsl:with-param name="count" select="$count+1"/>
		</xsl:call-template>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:variable name="node" select="$nodelist[$count=position()]"/>
		<xsl:choose>
		    <xsl:when test="name($node)='guimenuitem'
			or name($node)='guisubmenu'">
			<xsl:text> $\to$ </xsl:text>
		    </xsl:when>
		    <xsl:otherwise>+</xsl:otherwise>
		</xsl:choose>
		<xsl:apply-templates select="$node"/>
		<xsl:call-template name="process.menuchoice">
		    <xsl:with-param name="nodelist" select="$nodelist"/>
		    <xsl:with-param name="count" select="$count+1"/>
		</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="optional">
	<xsl:value-of select="$arg.choice.opt.open.str"/>
	<xsl:call-template name="inline.charseq"/>
	<xsl:value-of select="$arg.choice.opt.close.str"/>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="comment|remark">
	<xsl:if test="$show.comments != 0">
	    <i><xsl:call-template name="inline.charseq"/></i>
	</xsl:if>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="productname">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <xsl:template match="productnumber">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <!-- ==================================================================== -->

    <xsl:template match="pob|street|city|state|postcode|country|phone|fax|otheraddr">
	<xsl:call-template name="inline.charseq"/>
    </xsl:template>

    <!-- ==================================================================== -->

</xsl:stylesheet>

