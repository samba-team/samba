/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

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

if (qx.Settings.getValueOfClass("qx.lang.Generics", "enable")) {
  qx.lang.Prototypes.init();
}
