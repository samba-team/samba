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
 * Generic escaping and unescaping of DOM strings.
 *
 * {@link qx.html.String} for (un)escaping of HTML strings.
 *
 * {@link qx.xml.String} for (un)escaping of XML strings.
 */
qx.OO.defineClass("qx.dom.String");


/**
 * generic escaping method
 *
 * @param str {String} string to escape
 * @param charcodeToEntities {Map} entity to charcode map
 */
qx.Class.escapeEntities = function(str, charcodeToEntities) {
  var result = [];
  for (var i=0; i<str.length; i++) {
    var chr = str.charAt(i);
    var code = chr.charCodeAt(0)
    if (charcodeToEntities[code]) {
        var entity = "&" + charcodeToEntities[code] + ";";
    } else {
      if (code > 0x7F) {
        entity = "&#" + code + ";";
      } else {
        entity = chr;
      }
    }
    result.push(entity);
  }
  return result.join("");
};


/**
 * generic unescaping method
 *
 * @param str {String} string to unescape
 * @param entitiesToCharCode {Map} charcode to entity map
 */
qx.Class.unescapeEntities = function(str, entitiesToCharCode) {
  return str.replace(/&[#\w]+;/gi, function(entity) {
    var chr = entity;
    var entity = entity.substring(1, entity.length-1);
    var code = entitiesToCharCode[entity];
    if (code) {
      chr = String.fromCharCode(code);
    } else {
      if (entity.charAt(0) == '#') {
        if (entity.charAt(1).toUpperCase() == 'X') {
          var code = entity.substring(2);
          // match hex number
          if (code.match(/^[0-9A-Fa-f]+$/gi)) {
            chr = String.fromCharCode(parseInt("0x" + code));
          }
        } else {
        var code = entity.substring(1);
          // match integer
          if (code.match(/^\d+$/gi)) {
            chr = String.fromCharCode(parseInt(code));
          }
        }
      }
    }
    return chr;
  });
};


/**
 * Remove HTML/XML tags from a string
 * Example:
 * <pre>qx.dom.String.stripTags("&lt;h1>Hello&lt;/h1>") == "Hello"</pre>
 *
 * @param str {String} string containing tags
 * @return {String} the string with stripped tags
 */
qx.Class.stripTags = function(str) {
  return str.replace(/<\/?[^>]+>/gi, "");
};


