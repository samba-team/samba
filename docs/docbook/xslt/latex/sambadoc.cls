%%---------------------------------------------------
%%-- RC Thesis 
%%---------------------------------------------------
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{sambadoc}

%%---------------------------------------------------
%%-- Load the base class and modify current macros.
%%---------------------------------------------------

\newif\if@usecppsyntax \@usecppsyntaxfalse

\DeclareOption{cpp}{\@usecppsyntaxtrue}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{scrreprt}}
\ProcessOptions

\LoadClass{scrreprt}

%%--Set the section number depth.
\setcounter{secnumdepth}{3}
\setcounter{tocdepth}{4}

%\setcounter{page}{2}

%%--Create a vertical skip for the distance between the title and
%%--the first line of text on the prolog pages.
\newskip\thesisvskip
\thesisvskip 36pt

%%--Set the margins. %\headheight6pt \headsep12pt
\usepackage[margin=20pt,head=20pt,headsep=20pt,foot=20pt]{geometry}

%%--Use typehtml for better specification of tables
\usepackage{typehtml}

%%--Change the marginpar.
\reversemarginpar
\let\old@marginpar=\marginpar
\def\marginpar#1{
	\old@marginpar{\def\baselinestretch{1}\em\small #1}}

\renewcommand*{\scr@parskip}{%
    \setlength{\parskip}{\baselineskip}%
    \addtolength{\parskip}{\z@ \@plus .5\baselineskip}}

\setlength\parindent{0pt}

%%--Parameters that can be set by the user.
\def\samba@listtables{y}
\def\samba@listfigures{y}

\newcommand{\notablelist}{\gdef\samba@listtables{n}}
\newcommand{\nofigurelist}{\gdef\samba@listfigures{n}}


%%--Modify behavior of the figure and table environment.
\def\fps@figure{hbt}
\def\fnum@figure{{\bf \figurename~\thefigure}}
\def\fps@table{htb}
\def\fnum@table{{\bf \tablename~\thetable}}

\def\mathfigure{\thesisfiguretrue\figure}
\def\endmathfigure{\endfigure\thesisfigurefalse}



%%-----------------------------------------------
%%-- Modify the displayed math environments.
%%-----------------------------------------------

\newif\ifthesisfigure
\thesisfigurefalse



%%--------------------------------------------
%%-- Miscellaneous commands.
%%--------------------------------------------

%%--Commands to simplify font changing.
\newcommand{\sfup}{\sffamily\mdseries\upshape}
\newcommand{\sfsc}{\ttfamily\mdseries\scshape}
\newcommand{\sfit}{\sffamily\mdseries\itshape}
\newcommand{\rmup}{\rmfamily\mdseries\upshape}
\newcommand{\rmbf}{\rmfamily\bfseries\upshape}
\newcommand{\rmit}{\rmfamily\mdseries\itshape}
\newcommand{\ttup}{\ttfamily\mdseries\upshape}


\endinput

%%--The \tableofcontents.
\renewcommand\tableofcontents{%
   \renewcommand{\contentsname}{Table of Contents}
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \oldchapter*{\contentsname
        \@mkboth{\uppercase{\contentsname}}{\uppercase{\contentsname}}}%
    \@starttoc{toc}%
    \if@restonecol\twocolumn\fi}

%%--The \listoffigures command.
\renewcommand\listoffigures{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \oldchapter*{\listfigurename
      \@mkboth{\uppercase{\listfigurename}}{\uppercase{\listfigurename}}}%
    \@starttoc{lof}%
    \if@restonecol\twocolumn\fi}

%%--The \listoftables command.
\renewcommand\listoftables{%
    \if@twocolumn%
      \@restonecoltrue\onecolumn%
    \else%
      \@restonecolfalse%
    \fi%
    \oldchapter*{\listtablename%
      \@mkboth{\uppercase{\listtablename}}{\uppercase{\listtablename}}}%
    \@starttoc{lot}%
    \if@restonecol\twocolumn\fi}

\endinput
