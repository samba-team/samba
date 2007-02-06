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

/**
 * Appearance Theme
 *
 * @param vTitle {String} anme of the appearance
 */
qx.OO.defineClass("qx.renderer.theme.AppearanceTheme", qx.core.Object,
function(vTitle)
{
  qx.core.Object.call(this);

  this.setTitle(vTitle);
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/** name of the theme */
qx.OO.addProperty({ name : "title", type : "string", allowNull : false, defaultValue : "" });





/*
---------------------------------------------------------------------------
  DATA
---------------------------------------------------------------------------
*/

qx.Proto._appearances = {};





/*
---------------------------------------------------------------------------
  CORE METHODS
---------------------------------------------------------------------------
*/

/**
 * Register an appearance for a given id
 *
 * vData has the following structure:
 * <pre>
 * {
 *   setup : function() {}
 *   initial : function(vTheme) {}
 *   state : function(vTheme, vStates) {}
 * }
 * </pre>
 * @param vId {String} id of the apperance (e.g. "button", "label", ...)
 * @param vData {Map}
 */
qx.Proto.registerAppearance = function(vId, vData) {
  this._appearances[vId] = vData;
};


/**
 * Return the apperance object for a specific apperance id.
 *
 * @param vId {String} id of the apperance (e.g. "button", "label", ...)
 * @return {Object} appearance map
 */
qx.Proto.getAppearance = function(vId) {
  return this._appearances[vId];
}


/**
 * Call the "setup" function of the apperance
 *
 * @param vAppearance {Object} appearance map
 */
qx.Proto.setupAppearance = function(vAppearance)
{
  if (!vAppearance._setupDone)
  {
    if (vAppearance.setup) {
      vAppearance.setup(this);
    }

    vAppearance._setupDone = true;
  }
};








/*
---------------------------------------------------------------------------
  WIDGET METHODS
---------------------------------------------------------------------------
*/

/**
 * Get the result of the "initial" function for a given id
 *
 * @param vId {String} id of the apperance (e.g. "button", "label", ...)
 * @return {Map} map of widget properties as returned by the "initial" function
 */
qx.Proto.initialFrom = function(vId)
{
  var vAppearance = this.getAppearance(vId);
  if (vAppearance)
  {
    this.setupAppearance(vAppearance);

    try
    {
      return vAppearance.initial ? vAppearance.initial(this) : {}
    }
    catch(ex)
    {
      this.error("Couldn't apply initial appearance", ex);
    }
  }
  else
  {
    return this.error("Missing appearance: " + vId);
  }
};


/**
 * Get the result of the "state" function for a given id and states
 *
 * @param vId {String} id of the apperance (e.g. "button", "label", ...)
 * @param vStates {Map} hash map defining the set states
 * @return {Map} map of widget properties as returned by the "state" function
 */
qx.Proto.stateFrom = function(vId, vStates)
{
  var vAppearance = this.getAppearance(vId);
  if (vAppearance)
  {
    this.setupAppearance(vAppearance);

    try
    {
      return vAppearance.state ? vAppearance.state(this, vStates) : {}
    }
    catch(ex)
    {
      this.error("Couldn't apply state appearance", ex);
    }
  }
  else
  {
    return this.error("Missing appearance: " + vId);
  }
}







/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

/**
 * Disposer
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._appearances = null;

  return qx.core.Object.prototype.dispose.call(this);
}
