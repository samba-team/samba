/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by STZ-IDA, Germany, http://www.stz-ida.de

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

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
 * @return {string} the formatted object.
 */
qx.Proto.format = function(obj) {
  throw new Error("format is abstract");
}


/**
 * Parses an object.
 *
 * @param str {string} the string to parse.
 * @return {var} the parsed object.
 */
qx.Proto.parse = function(str) {
  throw new Error("parse is abstract");
}
