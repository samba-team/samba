%
% $Id: sambadoc.cls,v 1.4 2003/12/11 19:30:50 jelmer Exp $
%

% phstyle.cls -- Macros for formatting Prentice-Hall Books
%               -- Compiled by J.K. Shultis, Dec. 1993
% 		-- Modified and enhanced for LaTeX2e mdh/rlm 1997/02
%       -- Style Modifications Lori Hughes June 2002 

\NeedsTeXFormat{LaTeX2e}%
\ProvidesClass{sambadoc}[1997/02/20 Prentice Hall Book Class, February 1997]

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}

\ProcessOptions%

%  Base everything on the default class 'article'.
\LoadClass{report}%


%================================================================================
% 1. Page layout dimensions
% 3. Define new fonts for headings
% 4. Define LaTeX logos (usually ot needed)
% 5. Redefines the way "figure" amd "table" are formated in a \caption
% 6. Defines a \capt macro which defines (1) \captwidth, (2) \captsize
%    and \beforetableskip.
% 7. New Environemnts:  Eqnarray, reflist, exerlist
% 8. Defines and modifies FANCYHDS.STY for headers and foots
% 9. Change sectioning headings to bold sans serif fonts
%10. Turn off leader dots in Table of Contents
%======================================================================

%====================== Page Layout
% \oddsidemargin 0.750in   \evensidemargin 0.750in  \textwidth 5.00in
% \topmargin     0.625in    \headheight     0.3in    \headsep  0.2in
% \textheight    7.3in     %\footheight .2in        
% \footskip      0.3in
% \parskip       0ex       \marginparwidth 1.00in  \marginparsep 0.5in
%\setlength\arraycolsep{1pt}

\textwidth 5.00in

%====================== Define special fonts
\newfont{\BIG}{cminch}                             %--- One-inch font
\newfont{\sfbHuge}{cmssbx10 scaled\magstep5}       %-- 25pt sans serif bold
\newfont{\sfblarge}{cmssbx10 scaled\magstep1}      %-- 12pt sans serif bold
\newfont{\sfbeleven}{cmssbx10 scaled\magstephalf}  %-- 11pt sans serif bold
\newfont{\sfb}{cmssbx10}                           %-- 10pt sans serif bold
\newfont{\sfeight}{cmss8}                          %-- 8pt sans serif
\newfont{\sfnine}{cmss8 at 9pt}                     %-- 9pt sans serif

\newfont{\defnem}{cmbxti10}                    %-- 10pt sans serif bold
\def\spacingset#1{\def\baselinestretch{#1}\small\normalsize}

%-----------Change section heading font sizes here----
\newfont{\sfbsection}{cmssbx10 at 13pt}
\newfont{\sfbsubsec}{cmssbx10 at 12pt}
\newfont{\sfbsubsub}{cmssbx10 at 11pt}
\newfont{\sfbpara}{cmssbx10}
%---------------------------------------------------


%===================== LaTeX and TeX type logos
\newcount\TestCount
\def\La{\TestCount=\the\fam \leavevmode L\raise.42ex
         \hbox{$\fam\TestCount\scriptstyle\kern-.3em A$}}
\def\LaTeX{\La\kern-.15em\TeX}
\def\AllTeX{{(\La)\TeX}}

%
% Theorem hack
%

\def\@begintheorem#1#2{\trivlist
   \item[\hskip \labelsep{\bfseries #1\ #2:}]\itshape}

%===================== Redefine the \@makecaption command
   \long\def\@makecaption#1#2{\vskip 10\p@
%% \setbox\@tempboxa\hbox{#1: #2}%         %% original label definition
   \setbox\@tempboxa\hbox{\textbf{ \small #1.} \small #2}%   %% bold and . instead of :
   \ifdim \wd\@tempboxa >\hsize
%%     #1: #2\par                   %% original definition
       \textbf{ \small #1.} \small #2\par             %% bold and . instead of :
   \else
    \hbox to\hsize{\hfil\box\@tempboxa\hfil}%   %% original
%%      \hbox to\hsize{\box\@tempboxa\hfil}%             %% no centering
   \fi}

%===================== New caption macro
\newlength{\captsize}         \let\captsize=\footnotesize
\newlength{\captwidth}        \setlength{\captwidth}{\textwidth}
\newlength{\beforetableskip}  \setlength{\beforetableskip}{.5\baselineskip}
\newcommand{\capt}[1]{\begin{minipage}{\captwidth}
          \let\normalsize=\captsize
          \caption[#1]{#1}
          \end{minipage}\\ \vspace{\beforetableskip}}
		  

%---------- Change Figure Label
\newcommand{\thefigurename}{Figure}   %-- set default: Figure
\def\fnum@figure{\thefigurename\ \thefigure}

%       This is to get the equation numbers in the form (section.equation),
%       and to have the equation counter reset every time the section 
%       counter is incremented.

\def\theequation{\thechapter.\arabic{equation}}
\@addtoreset{equation}{chapter}


%===================== New Environments

%------ Reference List Macro
\newenvironment{reflist}{\begin{list}{}{\leftmargin 1em \labelwidth 0in
\labelsep 0in \itemsep 0ex  \rightmargin 0in}}{\end{list}}
\newcommand{\refitem}{\item \hspace*{-1em}}   %--- item for ref list
\newcommand{\SC}{\scriptsize}  %--- small capitals for reference lists


%------ New environment for better spacing in Eqnarray
\def\eqnarray{%
   \stepcounter{equation}%
   \def\@currentlabel{\p@equation\theequation}%
   \global\@eqnswtrue
   \m@th
   \global\@eqcnt\z@
   \tabskip\@centering
   \let\\\@eqncr
   $$\everycr{}\halign to\displaywidth\bgroup
       \hskip\@centering$\displaystyle\tabskip\z@skip{##}$\@eqnsel
      &\global\@eqcnt\@ne\hskip \arraycolsep \hfil${##}$\hfil
      &\global\@eqcnt\tw@ \hskip \arraycolsep
         $\displaystyle{##}$\hfil\tabskip\@centering
      &\global\@eqcnt\thr@@ \hb@xt@\z@\bgroup\hss##\egroup
         \tabskip\z@skip
      \cr
}





%\newenvironment{Eqnarray}{\arraycolsep 0.14em\begin{eqnarray}}{\end{eqnarray}}

% The hangitem environment -- like description, but text lines up with 
%    the item descriptor.  You give an additional argument containing text
%    of the width that you want indentations.
%
\def\hangitem#1{\list{}{\settowidth\labelwidth{#1}
        \leftmargin\labelwidth\advance\leftmargin\labelsep }}
\let\endhangitem\endlist

%------ Problem List Macro
\newcounter{probnum}
\newenvironment{exerlist}%
  {\begin{list}{\bf \theprobnum.}%
  {\usecounter{probnum} \itemsep 1ex  \leftmargin 2.0em \labelsep 0.5em
   \rightmargin 0in}}{\end{list}}




%===================== Define FANCYHDS.STY
% fancyheadings.sty version 1.1
% Fancy headers and footers.
% Piet van Oostrum, Dept of Computer Science, University of Utrecht
% Padualaan 14, P.O. Box 80.089, 3508 TB Utrecht, The Netherlands
% Telephone: +31-30-531806. piet@cs.ruu.nl (mcvax!hp4nl!ruuinf!piet)
% Sep 23, 1992.

\def\lhead{\@ifnextchar[{\@xlhead}{\@ylhead}}
\def\@xlhead[#1]#2{\gdef\@elhead{#1}\gdef\@olhead{#2}}
\def\@ylhead#1{\gdef\@elhead{#1}\gdef\@olhead{#1}}

\def\chead{\@ifnextchar[{\@xchead}{\@ychead}}
\def\@xchead[#1]#2{\gdef\@echead{#1}\gdef\@ochead{#2}}
\def\@ychead#1{\gdef\@echead{#1}\gdef\@ochead{#1}}

\def\rhead{\@ifnextchar[{\@xrhead}{\@yrhead}}
\def\@xrhead[#1]#2{\gdef\@erhead{#1}\gdef\@orhead{#2}}
\def\@yrhead#1{\gdef\@erhead{#1}\gdef\@orhead{#1}}

\def\lfoot{\@ifnextchar[{\@xlfoot}{\@ylfoot}}
\def\@xlfoot[#1]#2{\gdef\@elfoot{#1}\gdef\@olfoot{#2}}
\def\@ylfoot#1{\gdef\@elfoot{#1}\gdef\@olfoot{#1}}

\def\cfoot{\@ifnextchar[{\@xcfoot}{\@ycfoot}}
\def\@xcfoot[#1]#2{\gdef\@ecfoot{#1}\gdef\@ocfoot{#2}}
\def\@ycfoot#1{\gdef\@ecfoot{#1}\gdef\@ocfoot{#1}}

\def\rfoot{\@ifnextchar[{\@xrfoot}{\@yrfoot}}
\def\@xrfoot[#1]#2{\gdef\@erfoot{#1}\gdef\@orfoot{#2}}
\def\@yrfoot#1{\gdef\@erfoot{#1}\gdef\@orfoot{#1}}

\newdimen\headrulewidth
\newdimen\footrulewidth
\newdimen\plainheadrulewidth
\newdimen\plainfootrulewidth
\newdimen\headwidth
\newif\if@fancyplain \@fancyplainfalse
\def\fancyplain#1#2{\if@fancyplain#1\else#2\fi}

% Initialization of the head and foot text.

\headrulewidth 0.4pt
\footrulewidth\z@
\plainheadrulewidth\z@
\plainfootrulewidth\z@

\lhead[\fancyplain{}{\sl\rightmark}]{\fancyplain{}{\sl\leftmark}}
%  i.e. empty on ``plain'' pages \rightmark on even, \leftmark on odd pages
\chead{}
\rhead[\fancyplain{}{\sl\leftmark}]{\fancyplain{}{\sl\rightmark}}
%  i.e. empty on ``plain'' pages \leftmark on even, \rightmark on odd pages
\lfoot{}
\cfoot{\rm\thepage} % page number
\rfoot{}

% Put together a header or footer given the left, center and
% right text, fillers at left and right and a rule.
% The \lap commands put the text into an hbox of zero size,
% so overlapping text does not generate an errormessage.

\def\@fancyhead#1#2#3#4#5{#1\hbox to\headwidth{\vbox{\hbox
{\rlap{\parbox[b]{\headwidth}{\raggedright#2\strut}}\hfill
\parbox[b]{\headwidth}{\centering#3\strut}\hfill
\llap{\parbox[b]{\headwidth}{\raggedleft#4\strut}}}\headrule}}#5}


\def\@fancyfoot#1#2#3#4#5{#1\hbox to\headwidth{\vbox{\footrule
\hbox{\rlap{\parbox[t]{\headwidth}{\raggedright#2\strut}}\hfill
\parbox[t]{\headwidth}{\centering#3\strut}\hfill
\llap{\parbox[t]{\headwidth}{\raggedleft#4\strut}}}}}#5}

\def\headrule{{\if@fancyplain\headrulewidth\plainheadrulewidth\fi
\hrule\@height\headrulewidth\@width\headwidth \vskip-\headrulewidth}}

\def\footrule{{\if@fancyplain\footrulewidth\plainfootrulewidth\fi
\vskip-0.3\normalbaselineskip\vskip-\footrulewidth
\hrule\@width\headwidth\@height\footrulewidth\vskip-0.3\normalbaselineskip}}

\def\ps@fancy{
\let\@mkboth\markboth
\@ifundefined{chapter}{\def\sectionmark##1{\markboth
{{\ifnum \c@secnumdepth>\z@ %MEUH
 \thesection\hskip 1em\relax \fi ##1}}{}}
\def\subsectionmark##1{\markright {\ifnum \c@secnumdepth >\@ne
 \thesubsection\hskip 1em\relax \fi ##1}}}
%
{\def\chaptermark##1{\markboth {{\ifnum \c@secnumdepth>\m@ne %MEUH
 \@chapapp\ \thechapter. \ \fi ##1}}{}}
\def\sectionmark##1{\markright{{\ifnum \c@secnumdepth >\z@ %MEUH
 \thesection. \ \fi ##1}}}}
\ps@@fancy
\headwidth\textwidth}
\def\ps@fancyplain{\ps@fancy \let\ps@plain\ps@plain@fancy}
\def\ps@plain@fancy{\@fancyplaintrue\ps@@fancy}
\def\ps@@fancy{
\def\@oddhead{\@fancyhead\relax\@olhead\@ochead\@orhead\hss}
\def\@oddfoot{\@fancyfoot\relax\@olfoot\@ocfoot\@orfoot\hss}
\def\@evenhead{\@fancyhead\hss\@elhead\@echead\@erhead\relax}
\def\@evenfoot{\@fancyfoot\hss\@elfoot\@ecfoot\@erfoot\relax}
}
%------------------- Modify Headers for Prentice-Hall Book Style
%---------- Setup headers and footers
\pagestyle{fancyplain}
\plainfootrulewidth 0pt             %---- no foot rule for chapter page
\footrulewidth 0pt                  %---- no rule for foot


%10.5pt fonts
\usepackage{type1cm}
\renewcommand\normalsize{%
   \@setfontsize\normalsize{10.5pt}{12pt}
   \abovedisplayskip 10\p@ \@plus2\p@ \@minus5\p@
   \abovedisplayshortskip \z@ \@plus3\p@
   \belowdisplayshortskip 6\p@ \@plus3\p@ \@minus3\p@
   \belowdisplayskip \abovedisplayskip
\let\@listi\@listI}
\normalsize   
%

%--- Redefine Headers
\renewcommand{\sectionmark}[1]{\markright{\thesection\ #1}}
%
\lhead[\fancyplain{}{\bf\thepage}]{\fancyplain{}{\sfnine\rightmark}}
%
%\rhead[\fancyplain{}{\footnotesize\sf\CHHEAD}]{\fancyplain{}{\bf\thepage}}
 \rhead[\fancyplain{}{\sfnine \leftmark}]{\fancyplain{}{\bf\thepage}}
%--- Empty footers on every page (except initial chapter page which has
%--- page number) and optionally a small date stamp
\cfoot[\fancyplain{}{}]{\fancyplain{}{}}
\rfoot[\fancyplain{}{}]{\fancyplain{\hspace{\fill}\\ \bf\thepage}{}}
\lfoot[\fancyplain{\hspace{\fill}\\ \bf\thepage}{}]{\fancyplain{}{}}
%-- replace the two lines above with the two below for a date stamp footer
%\rfoot[\fancyplain{\scriptsize \today}{\scriptsize \today}]{\fancyplain{\bf\thepage}{}}
%\lfoot[\fancyplain{\bf\thepage}{}]{\fancyplain{\scriptsize \today}{\scriptsize \today}}
%--- Change format of section header
%
% rlm added chaptermark 10/11/96
\def\sectionmark#1{\markright{\ifnum \c@secnumdepth >\z@
  {\sfeight Section}~\thesection.\quad \fi #1}}
\def\sectionsmark#1{\markright{#1}{#1}}
%
\def\chaptermark#1{\markboth{#1 \quad \@chapapp{}~\thechapter}{}}
\def\chaptersmark#1{\markboth{#1}{#1}}




%===================== Change Section Heads to Bold Sans Serif
% Create bolds sans serif sectioning headings.  Also the headings have
% been reduced in size with less space before and after the heading.
% Modified from macros given in BK10.STY
%
%----------------------------- part ---------------------------------
\def\@part[#1]#2{%
	\thispagestyle{empty}
	\ifodd\c@page\hbox{}\else\clearpage\fi
	\addtocounter{page}{-2}
	\thispagestyle{empty}
	\ifnum \c@secnumdepth >-2\relax
		\refstepcounter{part}%
		\addcontentsline{toc}{part}{Part \thepart\hspace{1em}#1}%
	\else
		\addcontentsline{toc}{part}{Part #1}%
	\fi
	{\centering
		\interlinepenalty \@M
			\normalfont
			\ifnum \c@secnumdepth >-2\relax
				\huge\bfseries \partname\nobreakspace\thepart
				\par
				\vskip 20\p@
			\fi
			\Huge \bfseries #2\par}%
	\@endpart}

%------------------------- appendix -----------------------------------

\let\oldappendix\appendix
\def\appendix{\oldappendix\def\addchaptertoloe{}}

%------------------------- chapter -----------------------------------
\def\addchaptertoloe{%
	\addtocontents{loe}{\protect\addvspace{14pt}}%
	\addtocontents{loe}{\noindent {\bfseries Chapter~\thechapter}\protect\par}%
	\addtocontents{loe}{\protect\addvspace{10pt}}%
}

\def\chapter{\clearpage \thispagestyle{plain} \global\@topnum\z@
\@afterindentfalse \secdef\@chapter\@schapter} 
\def\@chapter[#1]#2{\ifnum \c@secnumdepth >\m@ne
 \refstepcounter{chapter}
 \typeout{\@chapapp\space\thechapter.}
 \addcontentsline{toc}{chapter}{Chapter~\protect
 \numberline{\thechapter}\uppercase{#1}}\else
 \addcontentsline{toc}{chapter}{Chapter~\uppercase{#1}}\fi
 \chaptermark{#1}
 \addchaptertoloe
 \addtocontents{lof}{\protect\addvspace{10pt}}
\addtocontents{lot}{\protect\addvspace{10pt}} \if@twocolumn
\@topnewpage[\@makechapterhead{#2}] 
 \else \@makechapterhead{#2}
 \@afterheading \fi} 
%
\def\@schapter#1{\if@twocolumn \@topnewpage[\@makeschapterhead{#1}]
 \else \@makeschapterhead{#1}\chaptersmark{#1}
 \@afterheading\fi\addcontentsline{toc}{chapter}{\uppercase{#1}}}



\def\@makechapterhead#1{\vspace*{-20pt}{\parindent0pt\raggedright
\ifnum\c@secnumdepth>\m@ne\LARGE\sf\@chapapp{}~\thechapter\par
\vskip3pt\hrule\vskip3pt\hrule
\vskip30pt\fi\raggedright\Huge\sfbHuge\uppercase{#1}\par
\nobreak\vskip70pt}}%\chaptermark{#1}}

\def\@makeschapterhead#1{\vspace*{4pt}{\parindent0pt
\vskip3pt\hrule\vskip3pt\hrule
\vskip36pt\raggedright\Huge\sfbHuge\uppercase{#1}\par
\nobreak\vskip70pt}}%\chaptersmark{#1}}

%------------------------ section -----------------------------------
\def\section{\@startsection{section}{1}{\z@}{-3.5ex plus-1ex
  minus -.2ex}{1.8ex}{\sfbsection}}

%--------------------- subsection -----------------------------------
\def\subsection{\@startsection{subsection}{2}{\z@}{-2.75ex plus -1ex
    minus -.2ex}{1.2ex}{\sfbsubsec}}

%-------------------- subsubsection --------------------------------
\def\subsubsection{\@startsection{subsubsection}{3}{\z@}{-2.75ex
  plus -1ex minus -.2ex}{1.2ex}{\sfbsubsub}}

%----------------------- paragraph ----------------------------------
\def\paragraph{\@startsection{paragraph}{4}{\z@}{1.25ex plus
     1ex minus .2ex}{-1em}{\sfbpara}}

%---------------------- subparagraph --------------------------------
\def\subparagraph{\@startsection{subparagraph}{4}{\parindent}{1.25ex
     plus 1ex minus .2ex}{-1em}{\normalsize\sfb}}



%====================== Turn off leader dots in Table of Contents
\renewcommand{\@dotsep}{500}

\def\tableofcontents{\markboth{}{}\@restonecolfalse\if@twocolumn\@restonecoltrue\onecolumn
 \fi\thispagestyle{plain} \@makeschapterhead{Contents} 
 \@afterheading
 \chaptersmark{Contents}
 \sectionsmark{Contents}
 \@starttoc{toc}\if@restonecol\twocolumn\fi}


\def\thebibliography#1{\chapter*{Bibliography}\list
% \addcontentsline{toc}{chapter}{Bibliography}
 {[\arabic{enumi}]}{\settowidth\labelwidth{2em}\leftmargin\labelwidth
% \advance\leftmargin\labelsep
 \usecounter{enumi}}
 \def\newblock{\hskip .11em plus .33em minus .07em}
 \sloppy\clubpenalty4000\widowpenalty4000
 \sfcode`\.=1000\relax}
\let\endthebibliography=\endlist


%% BIBLIOGRAPHY
%
%% separate citations with "], ["
\def\@citex[#1]#2{\if@filesw\immediate\write\@auxout{\string\citation{#2}}\fi
\def\@citea{}\@cite{\@for\@citeb:=#2\do {\@citea\def\@citea{],
[}\@ifundefined {b@\@citeb}{{\bf ?}\@warning {Citation `\@citeb' on
page \thepage \space undefined}}%
{\csname b@\@citeb\endcsname}}}{#1}}
 
\def\@cite#1#2{[{#1\if@tempswa, #2\fi}]}


%% index

%\def\theindex{\@restonecoltrue\if@twocolumn\@restonecolfalse\fi
%\columnseprule \z@
%\columnsep 35pt\twocolumn[\@makeschapterhead{Subject Index}]
% \addcontentsline{toc}{chapter}{SUBJECT INDEX}
% \thispagestyle{plain}\parindent\z@
% \parskip\z@ plus .3pt\relax\let\item\@idxitem}

\def\theindex{\cleardoublepage\@restonecoltrue\if@twocolumn\@restonecolfalse\fi
\columnseprule \z@
\columnsep 35pt\twocolumn[\@makeschapterhead{Subject Index}]
  \chaptersmark{Subject Index}%
 \addcontentsline{toc}{chapter}{SUBJECT INDEX}
 \thispagestyle{plain}\parindent\z@
 \parskip\z@ plus .3pt\relax\let\item\@idxitem}


\renewcommand{\cleardoublepage}{\clearpage\if@twoside \ifodd\c@page\else
\hbox{}\thispagestyle{empty}\newpage\if@twocolumn\hbox{}\newpage\fi\fi\fi}

\renewcommand{\numberline}[1]{\sbox\@tempboxa{#1\hspace{2pt}}%
	                \ifdim\wd\@tempboxa>\@tempdima \else \wd\@tempboxa\@tempdima\fi
						                           \box\@tempboxa}

\def\listofexamples{\@restonecolfalse\if@twocolumn\@restonecoltrue\onecolumn
  \fi\chapter*{List of Examples}
  \renewcommand\@pnumwidth{0em}
  \@starttoc{loe}\if@restonecol
  \twocolumn\fi}

\def\l@example{\noindent\@dottedtocline{1}{0em}{3.5em}}

\parskip 1.5ex
\parindent 0pt

\renewcommand\listfigurename{\uppercase{List Of Figures}}
\renewcommand\listtablename{\uppercase{List Of Tables}}

\setlength{\emergencystretch}{0cm}
\cleardoublepage
\pagenumbering{roman}

\setcounter{page}{2}
\setcounter{totalnumber}{8}
\setcounter{bottomnumber}{3}
\setcounter{topnumber}{3}
\renewcommand{\textfraction}{0.1}
\renewcommand{\topfraction}{1.0}
\renewcommand{\bottomfraction}{1.0}

\usepackage[twoside]{geometry}

\geometry{%
paperwidth=7in,
paperheight=9.25in,
lmargin=.75in,
rmargin=.75in,
bmargin=.625in,
tmargin=.625in,
width=5.5in,
height=7.525in, %7.3
marginparwidth=0.35in,
headheight=0.2in,
headsep=.25in,
footskip=.025in}

\setlength{\headwidth}{\textwidth}

% smb.conf syntax highlighting
\usepackage{listings}
\usepackage{xcolor}

\lstdefinelanguage{smbconf}{
	morecomment=[l]{\#},
}

\newcommand{\linebreaksign}{\hbox{\ensuremath\hookleftarrow}}

\lstdefinestyle{smbconfblock}
{
	breaklines=true,
	backgroundcolor=\color{lightgray},
	frame=single,
	frameround=tttt,
	prebreak={\space\linebreaksign}
}

\newcommand{\smbconfsection}[1]{\emph{#1}}
\newcommand{\smbconfoption}[1]{\index{#1}\emph{#1}}
