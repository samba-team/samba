<?xml version='1.0'?>
<!--############################################################################# 
|   PURPOSE: 
| 	This is the "parent" stylesheet. The used "modules" are included here.
|	output encoding text in ISO-8859-1 indented.
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    xmlns:exsl="http://exslt.org/common" 
    extension-element-prefixes="exsl"
    exclude-result-prefixes="doc" version='1.0'>

    <xsl:output method="text" encoding="ISO-8859-1" indent="yes"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/common/l10n.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/common/common.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/VERSION.xml"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/vars.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/latex.mapping.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/preamble.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/font.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/labelid.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/book-article.mod.xsl"/>

<!--
    ## commented out to prevent breaking the build  - jerry
    <xsl:include href="http://db2latex.sourceforge.net/xsl/dedication.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/preface.mod.xsl"/>
-->

    <xsl:include href="http://db2latex.sourceforge.net/xsl/part-chap-app.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/sections.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/bridgehead.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/abstract.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/biblio.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/revision.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/admonition.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/verbatim.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/email.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/sgmltag.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/citation.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/qandaset.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/procedure.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/lists.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/callout.mod.xsl"/>


    <xsl:include href="http://db2latex.sourceforge.net/xsl/figure.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/graphic.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mediaobject.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/index.mod.xsl"/>


    <xsl:include href="http://db2latex.sourceforge.net/xsl/xref.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/formal.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/example.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/table.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/inline.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/authorgroup.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/dingbat.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/info.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/keywords.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/refentry.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/component.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/glossary.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/block.mod.xsl"/>


    <xsl:include href="http://db2latex.sourceforge.net/xsl/synop-oop.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/synop-struct.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/pi.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/footnote.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/texmath.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathelem.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.presentation.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.content.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.content.token.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.content.functions.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/mathml/mathml.content.constsymb.mod.xsl"/>

    <xsl:include href="http://db2latex.sourceforge.net/xsl/para.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/msgset.mod.xsl"/>
    <xsl:include href="http://db2latex.sourceforge.net/xsl/errors.mod.xsl"/>

    <xsl:include href="normalize-scape.mod.xsl"/>


    <xsl:template match="/">
	<xsl:variable name="xsl-vendor" select="system-property('xsl:vendor')"/>
	<xsl:message>################################################################################</xsl:message>
	<xsl:message> XSLT stylesheets DocBook - LaTeX 2e                                            </xsl:message>
	<xsl:message> Reqs: LaTeX 2e installation common packages                                    </xsl:message>
	<xsl:message>################################################################################</xsl:message>
	<xsl:message> RELEASE : <xsl:value-of select="$VERSION"/>                                    </xsl:message>
	<xsl:message> VERSION : <xsl:value-of select="$CVSVERSION"/>                                 </xsl:message>
	<xsl:message>     TAG : <xsl:value-of select="$TAG"/>                                        </xsl:message>
	<xsl:message>     WWW : http://db2latex.sourceforge.net                                      </xsl:message>
	<xsl:message> SUMMARY : http://www.sourceforge.net/projects/db2latex                         </xsl:message>
	<xsl:message>  AUTHOR : Ramon Casellas   casellas@infres.enst.fr                             </xsl:message>
	<xsl:message>  AUTHOR : James Devenish   j-devenish@users.sf.net                             </xsl:message>
	<xsl:message>   USING : <xsl:call-template name="set-vendor"/>                               </xsl:message>
	<xsl:message>################################################################################</xsl:message>
	<xsl:apply-templates/>
    </xsl:template>


    <!--############################################################################# -->
    <!-- XSL Processor Vendor                                                         -->
    <!-- XSL Mailing Lists http://www.dpawson.co.uk/xsl/N10378.html                   -->
    <!--############################################################################# -->
    <xsl:template name="set-vendor">
	<xsl:variable name="xsl-vendor" select="system-property('xsl:vendor')"/>
	<xsl:choose>
	    <xsl:when test="contains($xsl-vendor, 'SAXON 6.4')">
		<xsl:text>SAXON 6.4.X</xsl:text>
	    </xsl:when>
	    <xsl:when test="contains($xsl-vendor, 'SAXON 6.2')">
		<xsl:text>SAXON 6.2.X</xsl:text>
	    </xsl:when>
	    <xsl:when test="starts-with($xsl-vendor,'SAXON')">
		<xsl:text>SAXON</xsl:text>
	    </xsl:when>
	    <xsl:when test="contains($xsl-vendor,'Apache')">
		<xsl:text>XALAN</xsl:text>
	    </xsl:when>
	    <xsl:when test="contains($xsl-vendor,'Xalan')">
		<xsl:text>XALAN</xsl:text>
	    </xsl:when>
	    <xsl:when test="contains($xsl-vendor,'libxslt')">
		<xsl:text>libxslt/xsltproc</xsl:text>
	    </xsl:when>
	    <xsl:when test="contains($xsl-vendor,'Clark')">
		<xsl:text>XT</xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>UNKNOWN</xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>


</xsl:stylesheet>
