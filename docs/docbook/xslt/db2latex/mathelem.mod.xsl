<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: mathelem.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $		
|- #############################################################################
|	$Author: ab $												
|														
|   PURPOSE: Math Elements as theorems, lemmas, propositions, etc.
|	Note: these elements are not part of the DocBook DTD. I have extended
|    the docbook DTD in order to support this tags, so that's why I have these 
|	templates here.
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="mathelems" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: mathelem.mod.xsl,v 1.1 2003/04/30 21:39:49 ab Exp $
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

	<title>Math Elements <filename>mathelems.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>




    <xsl:template match="mathelement">
	<xsl:apply-templates/>
    </xsl:template>


    <!--
    ##########################################
    #
    #  \begin{hypothesis}[title]
    #
    #  \end{hypothesis}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathhypothesis">
	<xsl:text>\begin{hypothesis}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{rem}&#10;</xsl:text>
    </xsl:template>

    <!--
    ##########################################
    #
    #  \begin{rem}[title]
    #
    #  \end{rem}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathremark">
	<xsl:text>\begin{rem}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{rem}&#10;</xsl:text>
    </xsl:template>


    <!--
    ##########################################
    #
    #  \begin{exm}[title]
    #
    #  \end{exm}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathexample">
	<xsl:text>\begin{exm}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{exm}&#10;</xsl:text>
    </xsl:template>


    <!--
    ##########################################
    #
    #  \begin{prop}[title]
    #
    #  \end{prop}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathproposition">
	<xsl:text>\begin{prop}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{prop}&#10;</xsl:text>
    </xsl:template>


    <!--
    ##########################################
    #
    #  \begin{thm}[title]
    #
    #  \end{thm}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/maththeorem">
	<xsl:text>\begin{thm}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{thm}&#10;</xsl:text>
    </xsl:template>



    <!--
    ##########################################
    #
    #  \begin{defn}[definition title]
    #
    #  \end{defn}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathdefinition">
	<xsl:text>\begin{defn}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{defn}&#10;</xsl:text>
    </xsl:template>



    <!--
    ##########################################
    #
    #  \begin{lem}[lemma title]
    #
    #  \end{lem}
    #
    ##########################################
    -->
    <xsl:template match="mathelement/mathlemma">
	<xsl:text>\begin{lem}[</xsl:text>
	<xsl:call-template name="normalize-scape">
	    <xsl:with-param name="string" select="title"/> 
	</xsl:call-template>
	<xsl:text>]&#10;</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{lem}&#10;</xsl:text>
    </xsl:template>


    <!--
    ##########################################
    #
    #  \begin{proof}
    #
    #  \end{proof}
    #
    ##########################################
    -->
    <xsl:template match="mathproof">
	<xsl:text>\begin{proof}</xsl:text>
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:apply-templates/>
	<xsl:text>\end{proof}&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="mathphrase|mathcondition|mathassertion">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="mathelement/*/title">
    </xsl:template>

</xsl:stylesheet>
