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

#module(ui_buttonview)

************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.buttonview.Bar", qx.ui.pageview.AbstractBar,
function() {
  qx.ui.pageview.AbstractBar.call(this);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "bar-view-bar" });




/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto.getWheelDelta = function(e)
{
  var vWheelDelta = e.getWheelDelta();

  switch(this.getParent().getBarPosition())
  {
    case "left":
    case "right":
      vWheelDelta *= -1;
  }

  return vWheelDelta;
}





/*
---------------------------------------------------------------------------
  APPEARANCE ADDITIONS
---------------------------------------------------------------------------
*/

qx.Proto._applyStateAppearance = function()
{
  var vPos = this.getParent().getBarPosition();

  this._states.barLeft = vPos === "left";
  this._states.barRight = vPos === "right";
  this._states.barTop = vPos === "top";
  this._states.barBottom = vPos === "bottom";

  qx.ui.pageview.AbstractButton.prototype._applyStateAppearance.call(this);
}
