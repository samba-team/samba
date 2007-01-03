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

/*!
  One of the widgets which could be used to structurize the interface.

  qx.ui.pageview.buttonview.ButtonView creates the typical apple-like tabview-replacements which could also
  be found in more modern versions of the settings dialog in Mozilla Firefox.
*/
qx.OO.defineClass("qx.ui.pageview.buttonview.ButtonView", qx.ui.pageview.AbstractPageView,
function()
{
  qx.ui.pageview.AbstractPageView.call(this, qx.ui.pageview.buttonview.Bar, qx.ui.pageview.buttonview.Pane);

  this.setOrientation("vertical");
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "barPosition", type : "string", defaultValue : "top", possibleValues : [ "top", "right", "bottom", "left" ] });

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "bar-view" });





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyBarPosition = function(propValue, propOldValue, propData)
{
  var vBar = this._bar;

  // move bar around and change orientation
  switch(propValue)
  {
    case "top":
      vBar.moveSelfToBegin();
      this.setOrientation("vertical");
      break;

    case "bottom":
      vBar.moveSelfToEnd();
      this.setOrientation("vertical");
      break;

    case "left":
      vBar.moveSelfToBegin();
      this.setOrientation("horizontal");
      break;

    case "right":
      vBar.moveSelfToEnd();
      this.setOrientation("horizontal");
      break;
  }

  // force re-apply of states for bar and pane
  this._addChildrenToStateQueue();

  // force re-apply of states for all tabs
  vBar._addChildrenToStateQueue();

  return true;
}
