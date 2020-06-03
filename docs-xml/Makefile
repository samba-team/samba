#################################################################
# Makefile for Samba Documentation
# Authors:	
# 		James Moore <jmoore@php.net>
# 		Gerald Carter <jerry@samba.org>
# 		Jelmer Vernooij <jelmer@samba.org>
include Makefile.settings

export XML_CATALOG_FILES := $(XML_CATALOG_FILES) /etc/xml/catalog  $(shell pwd)/build/catalog.xml

# Docs to build
MAIN_DOCS = $(patsubst %/index.xml,%,$(wildcard */index.xml))
MANPAGES = $(sort $(wildcard $(MANPAGEDIR)/*.?.xml))

# Lists of files to process
DBLATEX_OPTIONS = -p xslt/latex.xsl -i xslt/latex

DATETIME := $(shell date +%Y%m%d%H%M%S)

XSLTPROC_DEPS = build/catalog.xml build/DTD/samba.build.version

ifeq ($(PROFILE), Y)
XSLTPROC += --profile --load-trace --timing
endif

ifndef OUTPUTDIR
Makefile.settings: configure
	./configure

configure: configure.ac
	autoreconf
endif

help: 
	@echo "Supported make targets:"
	@echo " release - Build the docs needed for a Samba release"
	@echo " all - Build all docs that can be build using the utilities found by configure"
	@echo " everything - Build all of the above"
	@echo " pdf,tex,ps,manpages,htmlhelp - Build specific output format"
	@echo " html - Build multi-file HTML versions"
	@echo " html-single - Build single-file HTML versions"
	@echo " htmlman - Build HTML version of manpages"

$(PDFDIR)/Samba3-Developers-Guide.pdf $(PSDIR)/Samba3-Developers-Guide.ps $(DOCBOOKDIR)/Samba3-Developers-Guide.xml Samba3-Developers-Guide.tex: $(wildcard Samba3-Developers-Guide/*.xml) Samba3-Developers-Guide-attributions.xml

# Pseudo targets 
all:: $(TARGETS)
everything:: manpages pdf html-single html htmlman ps fo htmlhelp
release:: manpages htmlman html pdf
clean::
	@echo "Cleaning up..." 
	rm -rf $(OUTPUTDIR)/* $(DOCBOOKDIR)
	rm -f *-attributions.xml
	rm -f *-attributions.xml *.d *.tpt *.tex *.loc *.toc *.lof *.glo *.idx *.aux
	rm -f *-images-html*
	rm -f *-images-latex-* $(LATEX_FIGURES)
	rm -f xslt/figures/*pdf
	rm -f $(SMBDOTCONFDOC)/parameters.*.xml
	rm -f build/catalog.xml

# Output format targets
pdf:: $(patsubst %,$(PDFDIR)/%.pdf,$(MAIN_DOCS))
ps:: $(patsubst %,$(PSDIR)/%.ps,$(MAIN_DOCS))
tex:: $(addsuffix .tex,$(MAIN_DOCS))
manpages:: $(patsubst $(MANPAGEDIR)/%.xml,$(OUTPUTDIR)/manpages/%,$(MANPAGES))
htmlman:: $(patsubst $(MANPAGEDIR)/%.xml,$(HTMLDIR)/manpages/%.html,$(MANPAGES)) $(HTMLDIR)/manpages/index.html
html-single:: $(patsubst %,$(HTMLDIR)/%.html,$(MAIN_DOCS))
html:: $(patsubst %,$(HTMLDIR)/%/index.html,$(MAIN_DOCS)) $(HTMLDIR)/index.html
htmlhelp:: $(addprefix $(HTMLHELPDIR)/,$(MAIN_DOCS))
validate:: $(addsuffix -validate,$(MAIN_DOCS))

test:: validate
check:: validate

.PHONY: test check validate manpages

# Intermediate docbook docs
#
$(DOCBOOKDIR)/%.xml: %/index.xml xslt/expand-sambadoc.xsl $(XSLTPROC_DEPS)
	@echo "Converting Samba-specific tags for $*..."
	@mkdir -p $(@D)
	@$(XSLTPROC) --stringparam latex.imagebasedir "$*/"  --stringparam noreference 0  --xinclude --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/manpages/%.xml: $(MANPAGEDIR)/%.xml xslt/expand-sambadoc.xsl Makefile.settings $(XSLTPROC_DEPS)
	@mkdir -p $(@D)
	$(XSLTPROC) --xinclude --stringparam noreference 0 --output $@ xslt/expand-sambadoc.xsl $<

$(DOCBOOKDIR)/manpages/index.xml: $(MANPAGES) xslt/manpage-summary.xsl $(XSLTPROC_DEPS)
	@mkdir -p $(@D)
	echo "<article><variablelist>" > $@
	$(XSLTPROC) xslt/manpage-summary.xsl $(MANPAGES) >> $@
	@echo "</variablelist></article>" >> $@

# HTML docs
$(HTMLDIR)/index.html: htmldocs.html
	@mkdir -p $(@D)
	cp $< $@

$(HTMLDIR)/%/index.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/%/samba.css xslt/html-chunk.xsl %-images-html-chunks $(XSLTPROC_DEPS)
	@mkdir -p $(@D)
	$(XSLTPROC) --stringparam base.dir "$(HTMLDIR)/$*/" xslt/html-chunk.xsl $<

# Single large HTML files
$(OUTPUTDIR)/%/samba.css: xslt/html/samba.css $(XSLTPROC_DEPS)
	@mkdir -p $(@D)
	cp $< $@

$(patsubst %,$(HTMLDIR)/%.html,$(MAIN_DOCS)): $(HTMLDIR)/%.html: %-images-html-single

$(HTMLDIR)/%.html: $(DOCBOOKDIR)/%.xml $(HTMLDIR)/samba.css xslt/html.xsl $(XSLTPROC_DEPS)
	$(XSLTPROC) --output $@ xslt/html.xsl $<

# Attributions
%-attributions.xml: $(XSLTPROC_DEPS)
	@echo "Generating attributions file $@ from $*/"
	@cp -f templates/attributions.xml $@
	@$(XSLTPROC) --xinclude -o $@ xslt/generate-attributions.xsl $*/index.xml 

# Tex files
%.tex: %/index.xml xslt/latex.xsl
	@echo "Generating $@..."
	@mkdir -p $(@D)
	@$(DBLATEX) $(DBLATEX_OPTIONS) -t tex -o $@ $<

# Dependency files
%.d: $(DOCBOOKDIR)/%.xml xslt/generate-dependencies.xsl $(XSLTPROC_DEPS)
	@echo "Generating dependency file for $*" 
	@$(XSLTPROC) --novalid \
		--stringparam target "$*" \
		-o $@ xslt/generate-dependencies.xsl $<
	@echo "$*-images-latex-eps: \$$(addsuffix .eps, \$$($*-images-latex))" >> $@

	@echo >> $@
	@echo "\$$(HTMLDIR)/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "\$$(HTMLDIR)/$*/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "\$$(HTMLHELPDIR)/$*/%: $*/%" >> $@
	@echo "	@mkdir -p \$$(@D)" >> $@
	@echo "	@cp \$$< \$$@" >> $@
	@echo >> $@
	@echo "$*-images-html-single: \$$(addprefix \$$(HTMLDIR)/, \$$($*-images-html))" >> $@
	@echo "$*-images-html-chunks: \$$(addprefix \$$(HTMLDIR)/$*/, \$$($*-images-html))" >> $@
	@echo "$*-images-htmlhelp: \$$(addprefix \$$(HTMLHELPDIR)/$*/, \$$($*-images-html))" >> $@

ifdef OUTPUTDIR 
ifneq ($(MAKECMDGOALS),clobber)
-include $(addsuffix .d,$(MAIN_DOCS))
endif
endif

# Adobe PDF files  
$(PDFDIR)/%.pdf: %/index.xml $(PDFDIR) xslt/latex.xsl %-images-latex-png %-images-latex-pdf
	$(DBLATEX) $(DBLATEX_OPTIONS) -I $*/images -t pdf -o $@ $<

# PostScript files
$(PSDIR)/%.ps: %/index.xml $(PSDIR) xslt/latex.xsl %-images-latex-eps
	$(DBLATEX) $(DBLATEX_OPTIONS) -I $*/images -t ps -o $@ $<

%.eps: %.png
	$(PNGTOPNM) $< | $(PNMTOPS) > $@

$(HTMLHELPDIR)/%: $(DOCBOOKDIR)/%.xml %-images-htmlhelp $(XSLTPROC_DEPS)
	$(XSLTPROC) --stringparam htmlhelp.chm $*.chm \
				--stringparam manifest.in.base.dir "$@/" \
				--stringparam base.dir "$@/" \
	http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl $<

# Manpages
$(MANPAGEDIR)/smb.conf.5.xml: parameters

# The phony parameters target exists in order to always create the
# the parameters xml files. Otherwise, when parameters.*.xml does not exist
# yet, the parameters are not generated when smb.conf.5.xml is newer than
# any smbdotconf/*/*.xml file ...
.PHONY: parameters

parameters: $(SMBDOTCONFDOC)/parameters.all.xml

$(SMBDOTCONFDOC)/parameters.all.xml: $(wildcard $(SMBDOTCONFDOC)/*/*.xml) $(SMBDOTCONFDOC)/generate-file-list.sh
	$(SMBDOTCONFDOC)/generate-file-list.sh $(SMBDOTCONFDOC) > $@

$(OUTPUTDIR):
	test -d $@ || mkdir $@

$(OUTPUTDIR)/%: $(DOCBOOKDIR)/%.xml xslt/man.xsl
	@mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/man.xsl $<

# Individual smb.conf parameters
smb.conf-chunks: $(patsubst $(SMBDOTCONFDOC)/%.xml,$(HTMLDIR)/smb.conf/%.html,$(wildcard $(SMBDOTCONFDOC)/*/*.xml))

$(HTMLDIR)/smb.conf/%.html: $(SMBDOTCONFDOC)/%.xml
	@mkdir -p $(@D)
	$(XSLTPROC) --output $@ xslt/smb.conf-html.xsl $<

# Validation verification
%-validate: %/index.xml
	cd $(<D) && $(XMLLINT) --xinclude --noent --postvalid --noout $(<F)

build/catalog.xml: build/catalog.xml.in
	sed -e "s|@abs_top_srcdir@|`pwd`|g;s|@abs_top_builddir@|`pwd`|g" < build/catalog.xml.in > build/catalog.xml

# XSL scripts
xslt/html.xsl: xslt/html-common.xsl 
xslt/html-chunk.xsl: xslt/html-common.xsl 
xslt/latex.xsl: 
xslt/expand-sambadoc.xsl: 
xslt/generate-attributions.xsl: 
xslt/man.xsl:

distclean clobber:: clean
	rm -f Makefile.settings config.status config.log

realdistclean:: distclean
	rm -f configure
	rm -rf autom4te.cache
	rm -rf output

# Always keep intermediate files if we can
.SECONDARY:
.PHONY: clean clobber release everything all 
