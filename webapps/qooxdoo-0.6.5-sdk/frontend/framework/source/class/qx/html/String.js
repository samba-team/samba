/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

#require(qx.lang.Object)

************************************************************************ */

/**
 * A Collection of utility functions to escape and unescape strings.
 */
qx.OO.defineClass("qx.html.String");


/**
 * Escapes the characters in a <code>String</code> using HTML entities.
 *
 * For example: <tt>"bread" & "butter"</tt> => <tt>&amp;quot;bread&amp;quot; &amp;amp; &amp;quot;butter&amp;quot;</tt>.
 * Supports all known HTML 4.0 entities, including funky accents.
 *
 * * <a href="http://www.w3.org/TR/REC-html32#latin1">HTML 3.2 Character Entities for ISO Latin-1</a>
 * * <a href="http://www.w3.org/TR/REC-html40/sgml/entities.html">HTML 4.0 Character entity references</a>
 * * <a href="http://www.w3.org/TR/html401/charset.html#h-5.3">HTML 4.01 Character References</a>
 * * <a href="http://www.w3.org/TR/html401/charset.html#code-position">HTML 4.01 Code positions</a>
 *
 * @see #unescape
 *
 * @param str {String} the String to escape
 * @return {String} a new escaped String
 */
qx.Class.escape = function(str) {
  return qx.dom.String.escapeEntities(
    str,
    qx.html.Entity.FROM_CHARCODE
  );
};


/**
 * Unescapes a string containing entity escapes to a string
 * containing the actual Unicode characters corresponding to the
 * escapes. Supports HTML 4.0 entities.
 *
 * For example, the string "&amp;lt;Fran&amp;ccedil;ais&amp;gt;"
 * will become "&lt;Fran&ccedil;ais&gt;"
 *
 * If an entity is unrecognized, it is left alone, and inserted
 * verbatim into the result string. e.g. "&amp;gt;&amp;zzzz;x" will
 * become "&gt;&amp;zzzz;x".
 *
 * @see #escape
 *
 * @param str {String} the String to unescape, may be null
 * @return a new unescaped String
 */
qx.Class.unescape = function(str) {
  return qx.dom.String.unescapeEntities(
    str,
    qx.html.Entity.TO_CHARCODE
  );
};


/**
 * Converts a plain text string into HTML.
 * This is similar to {@link #escape} but converts new lines to
 * <tt>&lt:br&gt:</tt> and preserves whitespaces.
 *
 * @see #escape
 *
 * @param str {String} the String to convert
 * @return {String} a new converted String
 */
qx.Class.fromText = function(str) {
  return qx.html.String.escape(str).replace(/(  |\n)/g, function(chr) {
    var map = {
      "  ": " &nbsp;",
      "\n": "<br>"
    }
    return map[chr] || chr;
  });
}


/**
 * Converts HTML to plain text.
 *
 * * Strips all HTML tags
 * * converts <tt>&lt:br&gt:</tt> to new line
 * * unescapes HTML entities
 *
 * @param str {String} HTML string to converts
 * @return {String} plain text representaion of the HTML string
 */
qx.Class.toText = function(str) {
  return qx.html.String.unescape(str.replace(/\s+|<([^>])+>/gi, function(chr) {
    if (/\s+/.test(chr)) {
      return " ";
    }
    else if (/^<BR|^<br/gi.test(chr)) {
      return "\n";
    } else {
      return "";
    }
  }));
};
