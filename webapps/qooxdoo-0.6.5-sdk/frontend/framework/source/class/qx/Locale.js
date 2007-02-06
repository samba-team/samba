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

************************************************************************ */

/* ************************************************************************

#module(core)

************************************************************************ */

qx.OO.defineClass("qx.Locale",
{
  /** {var} TODOC */
  _registry : {},

  /**
   * Locale definition
   *
   * Example:
   * <pre><code>
   * qx.Locale.define("fullname",
   * {
   *   "msgId": "msgText",
   *   ...
   * });
   * </code></pre>
   *
   * @type static
   * @name define
   * @access public
   * @param fullname {String} name of the mixin
   * @param definition {Map} definition structure
   * @return {void}
   */
  define : function(fullname, definition)
  {
    var vSplitName = fullname.split(".");
    var vLength = vSplitName.length;
    var vParentPackage = window;
    var vPartName = vSplitName[0];

    for (var i=0, l=vSplitName.length - 1; i<l; i++)
    {
      if (!vParentPackage[vPartName]) {
        vParentPackage[vPartName] = {};
      }

      vParentPackage = vParentPackage[vPartName];
      vPartName = vSplitName[i + 1];
    }

    vParentPackage[vPartName] = definition;
    qx.locale.Manager.getInstance().addTranslation(vPartName, definition);

    qx.Locale._registry[fullname] = definition;
  },

  /**
   * Returns a locale by name
   *
   * @type static
   * @name byName
   * @access public
   * @param fullname {String} locale name to check
   * @return {Object ? void} locale object
   */
  byName : function(fullname) {
    return qx.Locale._registry[fullname];
  },

  /**
   * Determine if locale exists
   *
   * @type static
   * @name isDefined
   * @access public
   * @param fullname {String} locale name to check
   * @return {Boolean} true if locale exists
   */
  isDefined : function(fullname) {
    return qx.Locale.byName(fullname) !== undefined;
  }
});
