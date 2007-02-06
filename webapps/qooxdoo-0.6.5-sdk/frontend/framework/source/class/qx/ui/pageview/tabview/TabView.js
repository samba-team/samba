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

#module(ui_tabview)

************************************************************************ */

qx.OO.defineClass("qx.ui.pageview.tabview.TabView", qx.ui.pageview.AbstractPageView,
function() {
  qx.ui.pageview.AbstractPageView.call(this, qx.ui.pageview.tabview.Bar, qx.ui.pageview.tabview.Pane);
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "tab-view" });

qx.OO.addProperty({ name : "alignTabsToLeft", type : "boolean", defaultValue : true });
qx.OO.addProperty({ name : "placeBarOnTop", type : "boolean", defaultValue : true });






/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyAlignTabsToLeft = function(propValue, propOldValue, propData)
{
  var vBar = this._bar;

  vBar.setHorizontalChildrenAlign(propValue ? "left" : "right");

  // force re-apply of states for all tabs
  vBar._addChildrenToStateQueue();

  return true;
}

qx.Proto._modifyPlaceBarOnTop = function(propValue, propOldValue, propData)
{
  // This does not work if we use flexible zones
  // this.setReverseChildrenOrder(!propValue);

  var vBar = this._bar;

  // move bar around
  if (propValue) {
    vBar.moveSelfToBegin();
  } else {
    vBar.moveSelfToEnd();
  }

  // force re-apply of states for all tabs
  vBar._addChildrenToStateQueue();

  return true;
}
