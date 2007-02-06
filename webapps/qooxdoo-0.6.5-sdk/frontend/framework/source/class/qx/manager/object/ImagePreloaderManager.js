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

#module(ui_core)

************************************************************************ */

/*!
  This singleton manage all qx.io.image.Preloader instances.
*/
qx.OO.defineClass("qx.manager.object.ImagePreloaderManager", qx.manager.object.ObjectManager,
function() {
  qx.manager.object.ObjectManager.call(this);
});





/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.add = function(vObject) {
  this._objects[vObject.getUri()] = vObject;
}

qx.Proto.remove = function(vObject) {
  delete this._objects[vObject.getUri()];
}

qx.Proto.has = function(vSource) {
  return this._objects[vSource] != null;
}

qx.Proto.get = function(vSource) {
  return this._objects[vSource];
}

qx.Proto.create = function(vSource)
{
  if (this._objects[vSource]) {
    return this._objects[vSource];
  }

  return new qx.io.image.Preloader(vSource);
}






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
