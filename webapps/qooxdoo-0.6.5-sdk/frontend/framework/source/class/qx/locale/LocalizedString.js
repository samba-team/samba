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
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/**
 * Create a new instance of qx.locale.LocalizedString
 *
 * @see qx.lang.String.format
 *
 * @param messageId {String} message id (may contain format strings)
 * @param args {Object[]} array of objects, which are inserted into the format string.
 * @param locale {String} optional locale to be used for translation
 */
qx.OO.defineClass("qx.locale.LocalizedString", qx.core.Object,
function(messageId, args, locale) {
  qx.core.Object.call(this);

  this.setId(messageId);
  this._locale = locale;

  var storedArguments = [];
  for (var i=0; i<args.length; i++)
  {
    var arg = args[i];
    if (arg instanceof qx.locale.LocalizedString) {
      // defer conversion to string
      storedArguments.push(arg);
    } else {
      // force conversion to string
      storedArguments.push(arg + "");
    }
  }

  this.setArgs(storedArguments);
});


/** message id */
qx.OO.addProperty({ name: "id"});

/** list of arguments to be applied to the format string */
qx.OO.addProperty({ name: "args"});


/**
 * Return translation of the string using the current locale
 *
 * @return {String} translation using the current locale
 */
qx.Proto.toString = function () {
  return qx.locale.Manager.getInstance().translate(this.getId(), this.getArgs(), this._locale);
};

