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


************************************************************************ */

/**
 * Extend the native JavaScript types Number, String and Array with the
 * feature additions of {@link qx.lang.Number}, {@link qx.lang.String} and
 * {@link qx.lang.Array}, respectively.
 *
 * Important: It is not recommended to modify the native types, as this
 * may lead to incompatibilities with non-qooxdoo code or libraries.
 * Therefore this feature is disabled by default (see default setting
 * "enable"). All classes and features contributed to qooxdoo
 * should work without this feature enabled!
 */
qx.OO.defineClass("qx.lang.Prototypes");



/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("enable", false);





/*
---------------------------------------------------------------------------
  PROTOTYPES MAPPER
---------------------------------------------------------------------------
*/

/**
 * Augment the prototype of the native JavaScript objects "String",
 * "Number" and "Array" with the methods defined in the corresponding
 * static classes.
 *
 * @see qx.lang.String
 * @see qx.lang.Number
 * @see qx.lang.Array
 */
qx.lang.Prototypes.init = function()
{
  var key, obj;
  var objs = [ "String", "Number", "Array" ];

  for (var i=0, len=objs.length; i<len; i++)
  {
    obj = objs[i];

    for (key in qx.lang[obj])
    {
      window[obj].prototype[key] = (function(key, obj)
      {
        return function() {
          return qx.lang[obj][key].apply(null, Array.prototype.concat.call([this], Array.prototype.slice.call(arguments, 0)));
        }
      })(key, obj);
    }
  }
}

if (qx.Settings.getValueOfClass("qx.lang.Prototypes", "enable")) {
  qx.lang.Prototypes.init();
}
