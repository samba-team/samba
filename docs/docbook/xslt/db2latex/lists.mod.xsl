<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: lists.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
|- #############################################################################
|	$Author: jelmer $
|														
|   PURPOSE:
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:reference id="lists" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: lists.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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

	<title>Lists <filename>lists.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para></para>
	    </section>
	</partintro>
    </doc:reference>



    <xsl:template match="variablelist/title| orderedlist/title | itemizedlist/title | simplelist/title">
	<xsl:text>&#10;{\sc </xsl:text>
	<xsl:apply-templates/>
	<xsl:text>}&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="itemizedlist">
	<xsl:if test="title"> <xsl:apply-templates select="title"/></xsl:if>
	<xsl:text>\begin{itemize}&#10;</xsl:text>
	<xsl:apply-templates select="listitem"/>
	<xsl:text>\end{itemize}&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="orderedlist">
	<!-- PARAM numeration : -->
	<xsl:param name="numeration">
	    <xsl:choose>
		<xsl:when test="@numeration">
		    <xsl:value-of select="@numeration"/>
		</xsl:when>
		<xsl:otherwise>
		    <xsl:value-of select="arabic"/>
		</xsl:otherwise>
	    </xsl:choose>
	</xsl:param>
	<xsl:if test="title"> <xsl:apply-templates select="title"/></xsl:if>
	<xsl:text>\begin{enumerate}</xsl:text>
	<xsl:if test="@numeration">
	    <xsl:choose>
		<xsl:when test="@numeration='arabic'"> 	<xsl:text>[1]</xsl:text>&#10;</xsl:when>
		<xsl:when test="@numeration='upperalpha'"><xsl:text>[A]</xsl:text>&#10;</xsl:when>
		<xsl:when test="@numeration='loweralpha'"><xsl:text>[a]</xsl:text>&#10;</xsl:when>
		<xsl:when test="@numeration='upperroman'"><xsl:text>[I]</xsl:text>&#10;</xsl:when>
		<xsl:when test="@numeration='lowerroman'"><xsl:text>[i]</xsl:text>&#10;</xsl:when>
	    </xsl:choose>
	</xsl:if>
	<xsl:apply-templates select="listitem"/>
	\end{enumerate}&#10;
    </xsl:template>



    <xsl:template match="variablelist">
	<xsl:if test="title"> <xsl:apply-templates select="title"/></xsl:if>
	<xsl:text>&#10;\noindent&#10;</xsl:text> 
	\begin{description}
	<xsl:apply-templates select="varlistentry"/>
	\end{description}
    </xsl:template>


    <xsl:template match="listitem">
	\item <xsl:apply-templates/><xsl:text>&#10;</xsl:text>
    </xsl:template>


    <xsl:template match="varlistentry">
	<xsl:variable name="id"> <xsl:call-template name="label.id"/> </xsl:variable>
	<xsl:text>\item[</xsl:text><xsl:apply-templates select="term"/><xsl:text>] </xsl:text>
	<xsl:apply-templates select="listitem"/>
    </xsl:template>

    <xsl:template match="varlistentry/term">
	<xsl:apply-templates/><xsl:text>, </xsl:text>
    </xsl:template>

    <xsl:template match="varlistentry/term[position()=last()]">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="varlistentry/listitem">
	<xsl:apply-templates/>
    </xsl:template>


    <xsl:template name="tabular.string">
	<xsl:param name="cols" select="1"/>
	<xsl:param name="i" select="1"/>
	<xsl:choose>
	    <xsl:when test="$i > $cols"></xsl:when>
	    <xsl:otherwise>
		<xsl:text>l</xsl:text>
		<xsl:call-template name="tabular.string">
		    <xsl:with-param name="i" select="$i+1"/>
		    <xsl:with-param name="cols" select="$cols"/>
		</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>


    <!--========================================================================== 
    | Inline simplelist. It is rendered as a list of comma separated values.
    | We make the difference between the last member and the rest. XSL easily
    | allows this.
    +============================================================================-->

    <xsl:template match="simplelist[@type='inline']">
	<xsl:apply-templates/>
    </xsl:template>
    <xsl:template match="simplelist[@type='inline']/member">
	<xsl:apply-templates/>
	<xsl:text>, </xsl:text>
    </xsl:template>
    <xsl:template match="simplelist[@type='inline']/member[position()=last()]">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="simplelist[@type='horiz']">
	<xsl:variable name="cols">
	    <xsl:choose>
		<xsl:when test="@columns">
		    <xsl:value-of select="@columns"/>
		</xsl:when>
		<xsl:otherwise>1</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>&#10;</xsl:text>
	<xsl:text>\begin{tabular*}{\linewidth}{</xsl:text>
	<xsl:call-template name="tabular.string">
	    <xsl:with-param name="cols" select="$cols"/>
	</xsl:call-template>
	<xsl:text>} </xsl:text> 
	<xsl:call-template name="simplelist.horiz">
	    <xsl:with-param name="cols" select="$cols"/>
	</xsl:call-template>
	<xsl:text>&#10;\end{tabular*}&#10;</xsl:text>
    </xsl:template>




    <xsl:template name="simplelist.horiz">
	<xsl:param name="cols">1</xsl:param>
	<xsl:param name="cell">1</xsl:param>
	<xsl:param name="members" select="./member"/>
	<xsl:if test="$cell &lt;= count($members)">
	    <xsl:text>&#10;</xsl:text> 
	    <xsl:call-template name="simplelist.horiz.row">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="cell" select="$cell"/>
		<xsl:with-param name="members" select="$members"/>
	    </xsl:call-template>
	    <xsl:text> \\</xsl:text> 
	    <xsl:call-template name="simplelist.horiz">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="cell" select="$cell + $cols"/>
		<xsl:with-param name="members" select="$members"/>
	    </xsl:call-template>
	</xsl:if>
    </xsl:template>

    <xsl:template name="simplelist.horiz.row">
	<xsl:param name="cols">1</xsl:param>
	<xsl:param name="cell">1</xsl:param>
	<xsl:param name="members" select="./member"/>
	<xsl:param name="curcol">1</xsl:param>
	<xsl:if test="$curcol &lt;= $cols">
	    <xsl:choose>
		<xsl:when test="$members[position()=$cell]">
		    <xsl:apply-templates select="$members[position()=$cell]"/>
		    <xsl:text> </xsl:text> 
		    <xsl:if test="$curcol &lt; $cols">
			<xsl:text>&amp; </xsl:text> 
		    </xsl:if>
		</xsl:when>
	    </xsl:choose>
	    <xsl:call-template name="simplelist.horiz.row">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="cell" select="$cell+1"/>
		<xsl:with-param name="members" select="$members"/>
		<xsl:with-param name="curcol" select="$curcol+1"/>
	    </xsl:call-template>
	</xsl:if>
    </xsl:template>











    <xsl:template match="simplelist|simplelist[@type='vert']">
	<xsl:variable name="cols">
	    <xsl:choose>
		<xsl:when test="@columns">
		    <xsl:value-of select="@columns"/>
		</xsl:when>
		<xsl:otherwise>1</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>&#10;</xsl:text>
	<!--<xsl:text>\vspace{1cm}&#10;</xsl:text>-->
	<xsl:text>\begin{tabular*}{\linewidth}{</xsl:text>
	<xsl:call-template name="tabular.string">
	    <xsl:with-param name="i" select="1"/>
	    <xsl:with-param name="cols" select="$cols"/>
	</xsl:call-template>
	<xsl:text>}</xsl:text> 
	<xsl:call-template name="simplelist.vert">
	    <xsl:with-param name="cols" select="$cols"/>
	</xsl:call-template>
	<xsl:text>&#10;\end{tabular*}&#10;</xsl:text>
	<!--<xsl:text>\vspace{1cm}&#10;</xsl:text>-->
    </xsl:template>



    <xsl:template name="simplelist.vert">
	<xsl:param name="cols">1</xsl:param>
	<xsl:param name="cell">1</xsl:param>
	<xsl:param name="members" select="./member"/>
	<xsl:param name="rows" select="floor((count($members)+$cols - 1) div $cols)"/>
	<xsl:if test="$cell &lt;= $rows">
	    <xsl:text>&#10;</xsl:text> 
	    <xsl:call-template name="simplelist.vert.row">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="rows" select="$rows"/>
		<xsl:with-param name="cell" select="$cell"/>
		<xsl:with-param name="members" select="$members"/>
	    </xsl:call-template>
	    <xsl:text> \\</xsl:text> 
	    <xsl:call-template name="simplelist.vert">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="cell" select="$cell+1"/>
		<xsl:with-param name="members" select="$members"/>
		<xsl:with-param name="rows" select="$rows"/>
	    </xsl:call-template>
	</xsl:if>
    </xsl:template>



    <xsl:template name="simplelist.vert.row">
	<xsl:param name="cols">1</xsl:param>
	<xsl:param name="rows">1</xsl:param>
	<xsl:param name="cell">1</xsl:param>
	<xsl:param name="members" select="./member"/>
	<xsl:param name="curcol">1</xsl:param>
	<xsl:if test="$curcol &lt;= $cols">
	    <xsl:choose>
		<xsl:when test="$members[position()=$cell]">
		    <xsl:apply-templates select="$members[position()=$cell]"/>
		    <xsl:text> </xsl:text> 
		    <xsl:if test="$curcol &lt; $cols">
			<xsl:text>&amp; </xsl:text> 
		    </xsl:if>
		</xsl:when>
		<xsl:otherwise>
		</xsl:otherwise>
	    </xsl:choose>
	    <xsl:call-template name="simplelist.vert.row">
		<xsl:with-param name="cols" select="$cols"/>
		<xsl:with-param name="rows" select="$rows"/>
		<xsl:with-param name="cell" select="$cell+$rows"/>
		<xsl:with-param name="members" select="$members"/>
		<xsl:with-param name="curcol" select="$curcol+1"/>
	    </xsl:call-template>
	</xsl:if>
    </xsl:template>


    <xsl:template match="member">
	<xsl:apply-templates/>
    </xsl:template>




    <xsl:template match="segmentedlist">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="segmentedlist/title">
	<xsl:text>&#10;{\sc </xsl:text>
	<xsl:apply-templates/>
	<xsl:text>} \\&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="segtitle">
    </xsl:template>

    <xsl:template match="segtitle" mode="segtitle-in-seg">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="seglistitem">
	<xsl:apply-templates/>
	<xsl:choose>
		<xsl:when test="position()=last()"><xsl:text>&#10;&#10;</xsl:text></xsl:when>
		<xsl:otherwise><xsl:text> \\&#10;</xsl:text></xsl:otherwise>
	</xsl:choose>
    </xsl:template>




    <xsl:template match="seg">
	<xsl:variable name="segnum" select="position()"/>
	<xsl:variable name="seglist" select="ancestor::segmentedlist"/>
	<xsl:variable name="segtitles" select="$seglist/segtitle"/>

	<!--
	Note: segtitle is only going to be the right thing in a well formed
	SegmentedList.  If there are too many Segs or too few SegTitles,
	you'll get something odd...maybe an error
	-->

	<xsl:text>{ \em </xsl:text>
	<xsl:apply-templates select="$segtitles[$segnum=position()]" mode="segtitle-in-seg"/>
	<xsl:text>:} </xsl:text>
	<xsl:apply-templates/>
    </xsl:template>










    <!-- ==================================================================== -->

    <xsl:template match="calloutlist">
	<xsl:if test="./title">
	    <xsl:apply-templates select="./title" mode="calloutlist.title.mode"/>
	</xsl:if>
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="calloutlist/title">
    </xsl:template>

    <xsl:template match="calloutlist/title" mode="calloutlist.title.mode">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="callout">
	<dt>
	    <xsl:call-template name="callout.arearefs">
		<xsl:with-param name="arearefs" select="@arearefs"/>
	    </xsl:call-template>
	</dt>
	<dl><xsl:apply-templates/></dl>
    </xsl:template>

    <xsl:template name="callout.arearefs">
	<xsl:param name="arearefs"></xsl:param>
	<xsl:if test="$arearefs!=''">
	    <xsl:choose>
		<xsl:when test="substring-before($arearefs,' ')=''">
		    <xsl:call-template name="callout.arearef">
			<xsl:with-param name="arearef" select="$arearefs"/>
		    </xsl:call-template>
		</xsl:when>
		<xsl:otherwise>
		    <xsl:call-template name="callout.arearef">
			<xsl:with-param name="arearef"
			    select="substring-before($arearefs,' ')"/>
		    </xsl:call-template>
		</xsl:otherwise>
	    </xsl:choose>
	    <xsl:call-template name="callout.arearefs">
		<xsl:with-param name="arearefs"
		    select="substring-after($arearefs,' ')"/>
	    </xsl:call-template>
	</xsl:if>
    </xsl:template>





    <xsl:template name="callout.arearef">
	<xsl:param name="arearef"></xsl:param>
	<xsl:variable name="targets" select="//node()[@id=$arearef]"/>
	<xsl:variable name="target" select="$targets[1]"/>
	<xsl:choose>
	    <xsl:when test="count($target)=0">
		<xsl:value-of select="$arearef"/>
		<xsl:text>callout ???</xsl:text>
	    </xsl:when>
	    <xsl:when test="local-name($target)='co'">
		<!-- FIXME -->
		<xsl:text>\href{ </xsl:text>
		<xsl:value-of select="$target/@id"/> 
		<xsl:text>}{</xsl:text>
		<xsl:value-of select="$target/@id"/><xsl:text>} </xsl:text>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>callout ???</xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>


</xsl:stylesheet>
