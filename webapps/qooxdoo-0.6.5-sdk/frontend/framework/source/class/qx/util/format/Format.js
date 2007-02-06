/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

/**
 * Superclass for formatters and parsers.
 */
qx.OO.defineClass("qx.util.format.Format", qx.core.Object,
function() {
  qx.core.Object.call(this);
});


/**
 * Formats an object.
 *
 * @param obj {var} The object to format.
 * @return {String} the formatted object.
 */
qx.Proto.format = function(obj) {
  throw new Error("format is abstract");
}


/**
 * Parses an object.
 *
 * @param str {String} the string to parse.
 * @return {var} the parsed object.
 */
qx.Proto.parse = function(str) {
  throw new Error("parse is abstract");
}
