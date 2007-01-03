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

#module(ui_core)

************************************************************************ */

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

qx.Proto.registerAppearance = function(vId, vData) {
  this._appearances[vId] = vData;
}

qx.Proto.getAppearance = function(vId) {
  return this._appearances[vId];
}

qx.Proto.setupAppearance = function(vAppearance)
{
  if (!vAppearance._setupDone)
  {
    if (vAppearance.setup) {
      vAppearance.setup(this);
    }

    vAppearance._setupDone = true;
  }
}








/*
---------------------------------------------------------------------------
  WIDGET METHODS
---------------------------------------------------------------------------
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
}

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

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  this._appearances = null;

  return qx.core.Object.prototype.dispose.call(this);
}
