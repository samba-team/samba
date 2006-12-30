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

#module(core)

************************************************************************ */

qx.OO.defineClass("qx.component.init.AbstractInitComponent", qx.component.AbstractComponent,
function() {
  qx.component.AbstractComponent.call(this);
});



/*!
  Run initialisation part of component creation.
*/
qx.Proto.initialize = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().initialize(e);
}

/*!
  Run main  part of component creation.
*/
qx.Proto.main = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().main(e);
}

/*!
  Run finalization part of component creation.
*/
qx.Proto.finalize = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().finalize(e);
}

/*!
  Terminate this component.
*/
qx.Proto.close = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().close(e);
}

/*!
  Terminate this component.
*/
qx.Proto.terminate = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().terminate(e);
}
