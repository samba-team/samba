<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: xref.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
|- #############################################################################
|	$Author: jelmer $
|														
|   PURPOSE: Manage XREFs
+ ############################################################################## -->

<xsl:stylesheet 
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:doc="http://nwalsh.com/xsl/documentation/1.0"
    exclude-result-prefixes="doc" version='1.0'>



<!--############################################################################# -->
<!-- DOCUMENTATION                                                                -->
<doc:reference id="xref" xmlns="">
<referenceinfo> 
<releaseinfo role="meta">
$Id: xref.mod.xsl,v 1.1.2.1 2003/05/01 14:06:15 jelmer Exp $
</releaseinfo>
<authorgroup>
<author> <surname>Casellas</surname><firstname>Ramon</firstname> </author>
<author> <surname>James</surname><firstname>Devenish</firstname> </author>
</authorgroup>
<copyright> 
	<year>2000</year> <year>2001</year> <year>2002</year> <year>2003</year>
	<holder>Ramon Casellas</holder>
</copyright>
</referenceinfo>

<title>Xref, Cross References <filename>xref.mod.xsl</filename></title>
<partintro>
<section><title>Introduction</title>
<para></para>
</section>
</partintro>
</doc:reference>




<!--############################################################################# -->
<doc:template match="anchor" xmlns="">
  <refpurpose>Anchor XSL template</refpurpose>
  <refdescription>
    <para>The <sgmltag>anchor</sgmltag> element 
    The DB2LaTeX processing of the element is quite straightforward :
	Map to a <literal>\label</literal>.</para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template match="anchor">
		<xsl:text>\hypertarget{</xsl:text>
		<xsl:value-of select="@id"/>
		<xsl:text>}{}</xsl:text>
    </xsl:template>





<!--############################################################################# -->
<doc:template name="id.is.xrefed" xmlns="">
  <refpurpose>Auxiliary named template</refpurpose>
  <refdescription>
    <para>This template returns 1 if there exists somewhere an xref
    whose linkend is the target's id.</para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template name="id.is.xrefed">
	<xsl:param name="i" select="1"/>
	<xsl:param name="target" select="."/>
	<xsl:param name="xrefs" select="//xref"/>
	<xsl:choose>
	    <xsl:when test="xrefs[i]/@linkend = 'target/@id'">
		<xsl:value-of select="1"/>
	    </xsl:when>
	    <xsl:when test="i = count(xrefs)">
		<xsl:value-of select="0"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:call-template name="id.is.xrefed">
		    <xsl:with-param name="i" select="i+1"/>
		</xsl:call-template>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>





<!--############################################################################# -->
<doc:template name="xref.xreflabel" xmlns="">
  <refpurpose>Auxiliary named template</refpurpose>
  <refdescription>
    <para> Called to process an xreflabel...you might use this to make 
     xreflabels come out in the right font for different targets, 
	 for example.</para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template name="xref.xreflabel">
	<xsl:param name="target" select="."/>
	<xsl:value-of select="$target/@xreflabel"/>
    </xsl:template>






<!--############################################################################# -->
<doc:template match="xref|link" xmlns="">
  <refpurpose>Xref and Link XSL Template</refpurpose>
  <refdescription>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template match="xref|link">
	<xsl:variable name="targets" select="id(@linkend)"/>
	<xsl:variable name="target" select="$targets[1]"/>
	<xsl:variable name="refelem" select="local-name($target)"/>
	<xsl:call-template name="check.id.unique"><xsl:with-param name="linkend" select="@linkend"/></xsl:call-template>
	<xsl:choose>
	    <xsl:when test="$refelem=''">
		<xsl:message><xsl:text>XRef to nonexistent id: </xsl:text><xsl:value-of select="@linkend"/></xsl:message>
		<xsl:text>XrefId[?</xsl:text>
		<xsl:if test="local-name(.)='link'"><xsl:apply-templates/></xsl:if>
		<xsl:text>?]</xsl:text>
	    </xsl:when>

	    <!-- This is a link with content ... -->
		<xsl:when test="local-name(.)='link' and .!=''">
		<xsl:call-template name="generate.hyperlink">
			<xsl:with-param name="target" select="$target"/>
			<xsl:with-param name="text"><xsl:apply-templates/></xsl:with-param>
		</xsl:call-template>
		</xsl:when>
		
	    <xsl:otherwise>
		<xsl:choose>
		    <xsl:when test="@endterm">
			<xsl:variable name="etargets" select="id(@endterm)"/>
			<xsl:variable name="etarget" select="$etargets[1]"/>
			<xsl:choose>
			    <xsl:when test="count($etarget) = 0">
				<xsl:message>
				    <xsl:value-of select="count($etargets)"/>
				    <xsl:text>Endterm points to nonexistent ID: </xsl:text>
				    <xsl:value-of select="@endterm"/>
				</xsl:message>
				<xsl:text>[NONEXISTENT ID]</xsl:text>
			    </xsl:when>
			    <xsl:otherwise>
				<xsl:call-template name="generate.hyperlink">
					<xsl:with-param name="target" select="$target"/>
					<xsl:with-param name="text"><xsl:apply-templates select="$etarget" mode="xref.text"/></xsl:with-param>
				</xsl:call-template>
			    </xsl:otherwise>
			</xsl:choose>
		    </xsl:when>
			<!-- If an xreflabel has been specified for the target ... -->
			<xsl:when test="local-name(.)='xref' and $target/@xreflabel">
			<xsl:call-template name="generate.hyperlink">
				<xsl:with-param name="target" select="$target"/>
				<xsl:with-param name="text">
					<xsl:text>{[</xsl:text>
					<xsl:call-template name="xref.xreflabel">
						<xsl:with-param name="target" select="$target"/>
					</xsl:call-template>
					<xsl:text>]}</xsl:text>
				</xsl:with-param>
			</xsl:call-template>
			</xsl:when>
		    <xsl:otherwise>
				<xsl:call-template name="generate.hyperlink">
					<xsl:with-param name="target" select="$target"/>
					<xsl:with-param name="text"><xsl:apply-templates select="$target" mode="xref-to"/></xsl:with-param>
				</xsl:call-template>
		    </xsl:otherwise>
		</xsl:choose>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:if test="$insert.xref.page.number=1 and $refelem!='' and local-name(.)='xref'">
		<xsl:call-template name="xref.p.subst">
			<xsl:with-param name="string">
				<xsl:call-template name="gentext.xref.text">
				<xsl:with-param name="element.name" select="'page.citation'"/>
				<xsl:with-param name="default"> [%p]</xsl:with-param>
				</xsl:call-template>
			</xsl:with-param>
			<xsl:with-param name="target" select="$target"/>
		</xsl:call-template>
	</xsl:if>
    </xsl:template>

	<doc:template name="generate.hyperlink" xmlns="">
	<refpurpose> Choose hyperlink syntax </refpurpose>
	<refdescription>
		<para>Will use hyperref, if it is available. Otherwise, just outputs
		unlinked text. If the destination is a citation, a backreference is
		emitted (even though it is technically a hyperlink, not a citation).
		If the 'text' arises from an @endterm, then the 'optional argument'
		syntax of <literal>\cite</literal> is used.</para>
	</refdescription>
	</doc:template>
	<xsl:template name="generate.hyperlink">
		<xsl:param name="target"/>
		<xsl:param name="text"/>
		<xsl:variable name="element" select="local-name($target)"/>
		<xsl:variable name="citation" select="$element='biblioentry' or $element='bibliomixed'"/>
		<xsl:choose>
			<xsl:when test="$citation and @endterm!=''">
				<xsl:text>\docbooktolatexcite</xsl:text>
				<xsl:text>{</xsl:text>
				<xsl:value-of select="$target/@id"/>
				<xsl:text>}{</xsl:text>
				<xsl:call-template name="scape-optionalarg">
					<xsl:with-param name="string" select="$text"/>
				</xsl:call-template>
				<xsl:text>}</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:if test="$latex.use.hyperref=1">
					<xsl:text>\hyperlink{</xsl:text>
					<xsl:value-of select="$target/@id"/>
					<xsl:text>}</xsl:text>
				</xsl:if>
				<xsl:text>{</xsl:text>
				<xsl:if test="$citation">
					<xsl:text>\docbooktolatexbackcite{</xsl:text>
					<xsl:value-of select="$target/@id"/>
					<xsl:text>}</xsl:text>
				</xsl:if>
				<xsl:value-of select="$text"/>
				<xsl:text>}</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<doc:template name="xref.p.subst" xmlns="">
		<refpurpose>Insert page number into xrefs</refpurpose>
		<refdescription><para></para></refdescription>
	</doc:template>
	<xsl:template name="xref.p.subst">
		<xsl:param name="string"></xsl:param>
		<xsl:param name="target" select="."/>
		<xsl:variable name="subst">%p</xsl:variable>
		<xsl:choose>
			<xsl:when test="contains($string, $subst)">
				<xsl:value-of select="substring-before($string, $subst)"/>
				<xsl:text>\pageref*{</xsl:text>
				<xsl:value-of select="$target/@id"/>
				<xsl:text>}</xsl:text>
				<xsl:value-of select="substring-after($string, $subst)"/>
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="$string"/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>







<!--############################################################################# -->
<doc:template name="number.xref" xmlns="">
  <refpurpose>Numbering template</refpurpose>
  <refdescription>
  	<para>
    Let LaTeX manage the numbering. Otherwise sty files that 
    do specify another numberic (e.g I,II) get messed
	</para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template name="number.xref">
		<xsl:text>{\ref*{</xsl:text><xsl:value-of select="@id"/><xsl:text>}}</xsl:text>
    </xsl:template>








<!--############################################################################# -->
<doc:template name="cross-reference" xmlns="">
  <refpurpose>FIXME</refpurpose>
  <refdescription>
  	<para>
	FIXME
	</para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template name="cross-reference">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:param name="xref.text">
	    <xsl:call-template name="gentext.xref.text">
		<xsl:with-param name="element.name" select="$refelem"/>
		<xsl:with-param name="default">%g %n</xsl:with-param>
	    </xsl:call-template>
	</xsl:param>
	<xsl:call-template name="subst.xref.text">
	    <xsl:with-param name="xref.text" select="$xref.text"/>
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>





    <xsl:template match="*" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:message>
	    <xsl:text>[Don't know what gentext to create for xref to: "</xsl:text>
	    <xsl:value-of select="$refelem"/>
	    <xsl:text>"]</xsl:text>
	</xsl:message>
	<xsl:text>UNKGENTEXT</xsl:text><xsl:value-of select="$refelem"/>
    </xsl:template>





    <xsl:template match="formalpara" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>


    <xsl:template match="figure|example|table|equation" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>


    <xsl:template match="dedication|preface|part|chapter|appendix" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>

    <xsl:template match="cmdsynopsis" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:variable name="command" select="($target//command)[1]"/>
	<xsl:apply-templates select="$command" mode="xref"/>
    </xsl:template>

    <xsl:template match="funcsynopsis" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:variable name="func" select="($target//function)[1]"/>
	<xsl:apply-templates select="$func" mode="xref"/>
    </xsl:template>


    <xsl:template match="biblioentry" mode="xref-to">
	<!-- handles both biblioentry and bibliomixed -->
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:text>[</xsl:text>
	<xsl:choose>
	    <xsl:when test="local-name($target/*[1]) = 'abbrev'">
		<xsl:apply-templates select="$target/*[1]"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:value-of select="@id"/>
	    </xsl:otherwise>
	</xsl:choose>
	<xsl:text>]</xsl:text>
    </xsl:template>



    <xsl:template match="bibliography|glossary|index" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>


    <xsl:template match="section|simplesect
	|sect1|sect2|sect3|sect4|sect5
	|refsect1|refsect2|refsect3" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>

    <xsl:template match="question|answer" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>

    <xsl:template match="reference" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:call-template name="cross-reference">
	    <xsl:with-param name="target" select="$target"/>
	</xsl:call-template>
    </xsl:template>

    <xsl:template match="co" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:apply-templates select="$target" mode="callout-bug"/>
    </xsl:template>

    <xsl:template match="co" mode="conumber">
	<xsl:number from="literallayout|programlisting|screen|synopsis"
	    level="single"
	    format="1"/>
    </xsl:template>


    <xsl:template match="book" mode="xref-to">
	<xsl:param name="target" select="."/>
	<xsl:param name="refelem" select="local-name($target)"/>
	<xsl:variable name="title">
	    <xsl:choose>
		<xsl:when test="$target/title">
		    <xsl:apply-templates select="$target/title" mode="xref"/>
		</xsl:when>
		<xsl:otherwise>
		    <xsl:apply-templates select="$target/bookinfo/title" mode="xref"/>
		</xsl:otherwise>
	    </xsl:choose>
	</xsl:variable>
	<xsl:text>{\em </xsl:text> <xsl:copy-of select="$title"/> <xsl:text>}</xsl:text>
    </xsl:template>


    <xsl:template match="command" mode="xref">
	<xsl:call-template name="inline.boldseq"/>
    </xsl:template>

    <xsl:template match="function" mode="xref">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>




<!--############################################################################# -->
<doc:template match="ulink" xmlns="">
  <refpurpose>A link that addresses its target by means of a URL (Uniform Resource Locator)</refpurpose>
  <refdescription>
  	<formalpara>
		<title>Pertinent Variables</title>
		<itemizedlist>
			<listitem><simpara><xref linkend="param.ulink.show"/></simpara></listitem>
			<listitem><simpara><xref linkend="param.ulink.footnotes"/></simpara></listitem>
			<listitem><simpara><xref linkend="latex.hyphenation.tttricks"/></simpara></listitem>
		</itemizedlist>
	</formalpara>
  </refdescription>
</doc:template>
<!--############################################################################# -->


    <xsl:template match="ulink" name="ulink">
	<xsl:param name="hyphenation">\docbookhyphenateurl</xsl:param>
	<xsl:param name="url" select="@url"/>
	<xsl:choose>
		<xsl:when test=". = '' or . = $url">
			<xsl:call-template name="generate.typeset.url">
				<xsl:with-param name="hyphenation" select="$hyphenation"/>
				<xsl:with-param name="url" select="$url"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="$latex.use.tabularx=1 and count(ancestor::table)&gt;0">
			<xsl:apply-templates/>
			<xsl:text> </xsl:text>
			<xsl:call-template name="generate.typeset.url">
				<xsl:with-param name="hyphenation" select="$hyphenation"/>
				<xsl:with-param name="url" select="$url"/>
			</xsl:call-template>
		</xsl:when>
		<xsl:when test="$ulink.footnotes='1' or $ulink.show='1'">
			<xsl:apply-templates/>
			<xsl:if test="$ulink.footnotes='1' and count(ancestor::footnote)=0">
				<xsl:call-template name="footnote">
					<xsl:with-param name="hyphenation" select="$hyphenation"/>
					<xsl:with-param name="url" select="$url"/>
				</xsl:call-template>
			</xsl:if>
			<xsl:if test="$ulink.show='1' or ($ulink.footnotes='1' and ancestor::footnote)">
				<xsl:text> </xsl:text>
				<xsl:call-template name="generate.typeset.url">
					<xsl:with-param name="hyphenation" select="$hyphenation"/>
					<xsl:with-param name="url" select="$url"/>
				</xsl:call-template>
			</xsl:if>
		</xsl:when>
		<xsl:otherwise>
			<xsl:text>\href{</xsl:text>
				<xsl:call-template name="scape-href">
					<xsl:with-param name="string" select="$url"/>
				</xsl:call-template>
			<xsl:text>}</xsl:text>
			<xsl:text>{</xsl:text>
				<xsl:apply-templates/>
			<xsl:text>}</xsl:text><!-- End Of second argument of \href -->
		</xsl:otherwise>
	</xsl:choose>
    </xsl:template>




<!--############################################################################# -->
<doc:template match="olink" xmlns="">
  <refpurpose>OLink XSL template</refpurpose>
  <refdescription>
  <para></para>
  </refdescription>
</doc:template>
<!--############################################################################# -->

    <xsl:template match="olink">
		<xsl:apply-templates/>
    </xsl:template>







<!--############################################################################# -->
    <xsl:template name="title.xref">
	<xsl:param name="target" select="."/>
	<xsl:choose>
	    <xsl:when test="name($target) = 'figure'
		or name($target) = 'example'
		or name($target) = 'equation'
		or name($target) = 'table'
		or name($target) = 'dedication'
		or name($target) = 'preface'
		or name($target) = 'bibliography'
		or name($target) = 'glossary'
		or name($target) = 'index'
		or name($target) = 'setindex'
		or name($target) = 'colophon'">
		<xsl:call-template name="gentext.startquote"/>
		<xsl:apply-templates select="$target" mode="title.content"/>
		<xsl:call-template name="gentext.endquote"/>
	    </xsl:when>
	    <xsl:otherwise>
		<xsl:text>{\em </xsl:text><xsl:apply-templates select="$target" mode="title.content"/><xsl:text>}</xsl:text>
	    </xsl:otherwise>
	</xsl:choose>
    </xsl:template>


<!--############################################################################# -->
    <xsl:template match="title" mode="xref">
	<xsl:apply-templates/>
    </xsl:template>

    <xsl:template match="command" mode="xref">
	<xsl:call-template name="inline.boldseq"/>
    </xsl:template>

    <xsl:template match="function" mode="xref">
	<xsl:call-template name="inline.monoseq"/>
    </xsl:template>

	<xsl:template name="generate.typeset.url">
		<xsl:param name="hyphenation"/>
		<xsl:param name="url" select="@url"/>
		<xsl:choose>
			<xsl:when test="$latex.use.url='1'">
				<xsl:text>\url{</xsl:text>
				<xsl:value-of select="$url"/>
				<xsl:text>}</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<xsl:text>\href{</xsl:text>
				<xsl:call-template name="scape-href">
					<xsl:with-param name="string" select="$url"/>
				</xsl:call-template>
				<xsl:text>}{\texttt{</xsl:text>
				<xsl:call-template name="generate.string.url">
					<xsl:with-param name="hyphenation" select="$hyphenation"/>
					<xsl:with-param name="string" select="$url"/>
				</xsl:call-template>
				<xsl:text>}}</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

<!--############################################################################# -->
	<doc:template name="generate.string.url" xmlns="">
		<refpurpose>Escape and hyphenate a string as a teletype URL.</refpurpose>
		<refdescription>
		<para>
		This template typsets teletype text using slash.hyphen if
		$latex.hyphenation.tttricks is disabled.
		Has two parameters: 'hyphenation' and 'string'.
		</para>
		</refdescription>
	</doc:template>
<!--############################################################################# -->
	<xsl:template name="generate.string.url">
		<xsl:param name="hyphenation" />
		<xsl:param name="string" />
		<xsl:param name="url" select="$string"/>
		<xsl:choose>
			<xsl:when test="$latex.hyphenation.tttricks=1">
				<xsl:value-of select="$hyphenation" />
				<xsl:text>{</xsl:text>
				<xsl:call-template name="normalize-scape"><xsl:with-param name="string" select="$string"/></xsl:call-template>
				<xsl:text>}</xsl:text>
			</xsl:when>
			<xsl:otherwise>
				<!-- LaTeX chars are scaped. Each / except the :// is mapped to a /\- -->
				<xsl:call-template name="scape.slash.hyphen"><xsl:with-param name="string" select="$url"/></xsl:call-template>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

</xsl:stylesheet>
