<?xml version='1.0'?>
<!--############################################################################# 
|	$Id: abstract.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
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
    <doc:reference id="abstract" xmlns="">
	<referenceinfo>
	    <releaseinfo role="meta">
		$Id: abstract.mod.xsl,v 1.1.2.3 2003/08/12 18:22:39 jelmer Exp $
	    </releaseinfo>
	    <authorgroup>
	    	<author><firstname>Ramon</firstname> <surname>Casellas</surname></author>
		<author><firstname>James</firstname> <surname>Devenish</surname></author>
	    </authorgroup>
	    <copyright>
		<year>2000</year><year>2001</year><year>2002</year><year>2003</year>
		<holder>Ramon Casellas</holder>
	    </copyright>
	</referenceinfo>
	<title>Abstract <filename>abstract.mod.xsl</filename></title>
	<partintro>
	    <section><title>Introduction</title>
		<para>This file <filename>abstract.mod.xsl</filename> contains a single
		XSL template for <sgmltag>abstract</sgmltag>.</para>
		<itemizedlist>
		<listitem><para>Calls <literal>map.begin</literal>.</para></listitem>
		<listitem><para>Processes children with <sgmltag>xsl:apply-templates</sgmltag>.</para></listitem>
		<listitem><para>Calls <literal>map.end</literal></para></listitem>
		<listitem><para>The abstract/title template is empty.</para></listitem>
		</itemizedlist>
	    </section>
	</partintro>
    </doc:reference>






    <!--############################################################################# -->
    <!-- DOCUMENTATION                                                                -->
    <doc:template match="abstract" xmlns="">
	<refpurpose> Abstract XSL template.  </refpurpose>
	<refdescription>
	    <para>Calls template <xref linkend="map.begin"/>(<literal>map.begin</literal>),
		to output the opening command (by default):</para>
	    <screen>
		% --------------------------------------------
		% Abstract 
		% --------------------------------------------
		\begin{abstract}
	    </screen>
	    <para> Calls "apply-templates" for all the children, and call template
		<xref linkend="map.end"/>(<literal>map.end</literal>) to output the closing
		command.</para>
	    <formalpara><title>Remarks and Bugs</title>
		<itemizedlist>
		    <listitem><para> The title of the abstract is lost.</para></listitem>
		    <listitem><para> The template for abstract/title is defined EMPTY.</para></listitem>
		</itemizedlist>
	    </formalpara>

	    <formalpara><title>Default Behaviour</title>
		<screen>
		    Fill	
		</screen>
	    </formalpara>
	</refdescription>
    </doc:template>
    <!--############################################################################# -->

    <!-- TEMPLATE -->
    <xsl:template match="abstract">
	<xsl:call-template name="map.begin"/>
	<xsl:apply-templates/>
	<xsl:call-template name="map.end"/>
    </xsl:template>

    <xsl:template match="abstract/title"/>

</xsl:stylesheet>


