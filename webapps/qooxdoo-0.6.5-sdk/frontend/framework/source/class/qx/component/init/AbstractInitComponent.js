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

/**
 * Abstract application initializer
 */
qx.OO.defineClass("qx.component.init.AbstractInitComponent", qx.component.AbstractComponent,
function() {
  qx.component.AbstractComponent.call(this);
});



/**
 * Run initialisation part of component creation.
 *
 * @param e {Event} event object
 */
qx.Proto.initialize = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().initialize(e);
};


/**
 * Run main  part of component creation.
 *
 * @param e {Event} event object
 */
qx.Proto.main = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().main(e);
};


/**
 * Run finalization part of component creation.
 *
 * @param e {Event} event object
 */
qx.Proto.finalize = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().finalize(e);
};


/**
 * Terminate this component.
 *
 * @param e {Event} event object
 */
qx.Proto.close = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().close(e);
};


/**
 * Terminate this component.
 *
 * @param e {Event} event object
 */
qx.Proto.terminate = function(e) {
  return qx.core.Init.getInstance().getApplicationInstance().terminate(e);
};
