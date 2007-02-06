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
 * Escaping and unescaping of XML strings.
 */
qx.OO.defineClass("qx.xml.String");


/**
 * Escapes the characters in a <code>String</code> using XML entities.
 *
 * For example: <tt>"bread" & "butter"</tt> =>
 * <tt>&amp;quot;bread&amp;quot; &amp;amp; &amp;quot;butter&amp;quot;</tt>.
 *
 * Supports only the four basic XML entities (gt, lt, quot, amp).
 * Does not support DTDs or external entities.
 * Note that unicode characters greater than 0x7f are currently escaped to their numerical \\u equivalent.
 *
 * @see #unescape
 *
 * @param str {String} the string to be escaped
 * @return {String} the escaped string
 */
qx.Class.escape = function(str) {
  return qx.dom.String.escapeEntities(
    str,
    qx.xml.Entity.FROM_CHARCODE
  );
};


/**
 * Unescapes a string containing XML entity escapes to a string
 * containing the actual Unicode characters corresponding to the
 * escapes.
 *
 * Supports only the four basic XML entities (gt, lt, quot, amp).
 * Does not support DTDs or external entities.
 *
 * @see #escape
 *
 * @param str {String} the string to be unescaped
 * @return {String} the unescaped string
 */
qx.Class.unescape = function(str) {
  return qx.dom.String.unescapeEntities(
    str,
    qx.xml.Entity.TO_CHARCODE
  );
};
