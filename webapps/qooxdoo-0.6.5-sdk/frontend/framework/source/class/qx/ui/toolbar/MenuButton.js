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

#module(ui_toolbar)
#module(ui_menu)

************************************************************************ */

qx.OO.defineClass("qx.ui.toolbar.MenuButton", qx.ui.toolbar.Button,
function(vText, vMenu, vIcon, vIconWidth, vIconHeight, vFlash)
{
  qx.ui.toolbar.Button.call(this, vText, vIcon, vIconWidth, vIconHeight, vFlash);

  if (vMenu != null) {
    this.setMenu(vMenu);
  }
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "menu", type : "object", instance : "qx.ui.menu.Menu" });
qx.OO.addProperty({ name : "direction", type : "string", allowNull : false, possibleValues : [ "up", "down" ], defaultValue : "down" });




/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getParentToolBar = function()
{
  var vParent = this.getParent();

  if (vParent instanceof qx.ui.toolbar.Part) {
    vParent = vParent.getParent();
  }

  return vParent instanceof qx.ui.toolbar.ToolBar ? vParent : null;
}

qx.Proto._showMenu = function(vFromKeyEvent)
{
  var vMenu = this.getMenu();

  if (vMenu)
  {
    // Caching common stuff
    var vMenuParent = vMenu.getParent();
    var vMenuParentElement = vMenuParent.getElement();
    var vButtonElement = this.getElement();
    var vButtonHeight = qx.html.Dimension.getBoxHeight(vButtonElement);

    // Apply X-Location
    var vMenuParentLeft = qx.html.Location.getPageBoxLeft(vMenuParentElement);
    var vButtonLeft = qx.html.Location.getPageBoxLeft(vButtonElement);

    vMenu.setLeft(vButtonLeft - vMenuParentLeft);

    // Apply Y-Location
    switch(this.getDirection())
    {
      case "up":
        var vBodyHeight = qx.html.Dimension.getInnerHeight(document.body);
        var vMenuParentBottom = qx.html.Location.getPageBoxBottom(vMenuParentElement);
        var vButtonBottom = qx.html.Location.getPageBoxBottom(vButtonElement);

        vMenu.setBottom(vButtonHeight + (vBodyHeight - vButtonBottom) - (vBodyHeight - vMenuParentBottom));
        vMenu.setTop(null);
        break;

      case "down":
        var vButtonTop = qx.html.Location.getPageBoxTop(vButtonElement);

        vMenu.setTop(vButtonTop + vButtonHeight);
        vMenu.setBottom(null);
        break;
    }

    this.addState("pressed");

    // If this show is called from a key event occured, we want to highlight
    // the first menubutton inside.
    if (vFromKeyEvent) {
      vMenu.setHoverItem(vMenu.getFirstActiveChild());
    }

    vMenu.show();
  }
}

qx.Proto._hideMenu = function()
{
  var vMenu = this.getMenu();

  if (vMenu) {
    vMenu.hide();
  }
}





/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyMenu = function(propValue, propOldValue, propData)
{
  if (propOldValue)
  {
    propOldValue.setOpener(null);

    propOldValue.removeEventListener("appear", this._onmenuappear, this);
    propOldValue.removeEventListener("disappear", this._onmenudisappear, this);
  }

  if (propValue)
  {
    propValue.setOpener(this);

    propValue.addEventListener("appear", this._onmenuappear, this);
    propValue.addEventListener("disappear", this._onmenudisappear, this);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  EVENTS: MOUSE
---------------------------------------------------------------------------
*/

qx.Proto._onmousedown = function(e)
{
  if (e.getTarget() != this || !e.isLeftButtonPressed()) {
    return;
  }

  this.hasState("pressed") ? this._hideMenu() : this._showMenu();
}

qx.Proto._onmouseup = function(e) {}

qx.Proto._onmouseout = function(e)
{
  if (e.getTarget() != this) {
    return;
  }

  this.removeState("over");
}

qx.Proto._onmouseover = function(e)
{
  var vToolBar = this.getParentToolBar();

  if (vToolBar)
  {
    var vMenu = this.getMenu();

    switch(vToolBar.getOpenMenu())
    {
      case null:
      case vMenu:
        break;

      default:
        // hide other menus
        qx.manager.object.MenuManager.getInstance().update();

        // show this menu
        this._showMenu();
    }
  }

  return qx.ui.toolbar.Button.prototype._onmouseover.call(this, e);
}






/*
---------------------------------------------------------------------------
  EVENTS: MENU
---------------------------------------------------------------------------
*/

qx.Proto._onmenuappear = function(e)
{
  var vToolBar = this.getParentToolBar();

  if (!vToolBar) {
    return;
  }

  var vMenu = this.getMenu();

  vToolBar.setOpenMenu(vMenu);
}

qx.Proto._onmenudisappear = function(e)
{
  var vToolBar = this.getParentToolBar();

  if (!vToolBar) {
    return;
  }

  var vMenu = this.getMenu();

  if (vToolBar.getOpenMenu() == vMenu) {
    vToolBar.setOpenMenu(null);
  }
}
