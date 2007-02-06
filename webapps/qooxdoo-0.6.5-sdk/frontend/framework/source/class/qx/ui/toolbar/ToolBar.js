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

************************************************************************ */

qx.OO.defineClass("qx.ui.toolbar.ToolBar", qx.ui.layout.HorizontalBoxLayout,
function()
{
  qx.ui.layout.HorizontalBoxLayout.call(this);

  this.addEventListener("keypress", this._onkeypress);
});



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "openMenu", type : "object", instance : "qx.ui.menu.Menu" });

/*!
  Appearance of the widget
*/
qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "toolbar" });









/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getAllButtons = function()
{
  var vChildren = this.getChildren();
  var vLength = vChildren.length;
  var vDeepChildren = [];
  var vCurrent;

  for (var i=0; i<vLength; i++)
  {
    vCurrent = vChildren[i];

    if (vCurrent instanceof qx.ui.toolbar.MenuButton)
    {
      vDeepChildren.push(vCurrent);
    }
    else if (vCurrent instanceof qx.ui.toolbar.Part)
    {
      vDeepChildren = vDeepChildren.concat(vCurrent.getChildren());
    }
  }

  return vDeepChildren;
}







/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

/*!
  Wraps key events to target functions
*/
qx.Proto._onkeypress = function(e)
{
  switch(e.getKeyIdentifier())
  {
    case "Left":
      return this._onkeypress_left();

    case "Right":
      return this._onkeypress_right();
  }
}

qx.Proto._onkeypress_left = function()
{
  var vMenu = this.getOpenMenu();
  if (!vMenu) {
    return;
  }

  var vOpener = vMenu.getOpener();
  if (!vOpener) {
    return;
  }

  var vChildren = this.getAllButtons();
  var vChildrenLength = vChildren.length;
  var vIndex = vChildren.indexOf(vOpener);
  var vCurrent;
  var vPrevButton = null;

  for (var i=vIndex-1; i>=0; i--)
  {
    vCurrent = vChildren[i];

    if (vCurrent instanceof qx.ui.toolbar.MenuButton && vCurrent.getEnabled())
    {
      vPrevButton = vCurrent;
      break;
    }
  }

  // If none found, try again from the begin (looping)
  if (!vPrevButton)
  {
    for (var i=vChildrenLength-1; i>vIndex; i--)
    {
      vCurrent = vChildren[i];

      if (vCurrent instanceof qx.ui.toolbar.MenuButton && vCurrent.getEnabled())
      {
        vPrevButton = vCurrent;
        break;
      }
    }
  }

  if (vPrevButton)
  {
    // hide other menus
    qx.manager.object.MenuManager.getInstance().update();

    // show previous menu
    vPrevButton._showMenu(true);
  }
}

qx.Proto._onkeypress_right = function()
{
  var vMenu = this.getOpenMenu();
  if (!vMenu) {
    return;
  }

  var vOpener = vMenu.getOpener();
  if (!vOpener) {
    return;
  }

  var vChildren = this.getAllButtons();
  var vChildrenLength = vChildren.length;
  var vIndex = vChildren.indexOf(vOpener);
  var vCurrent;
  var vNextButton = null;

  for (var i=vIndex+1; i<vChildrenLength; i++)
  {
    vCurrent = vChildren[i];

    if (vCurrent instanceof qx.ui.toolbar.MenuButton && vCurrent.getEnabled())
    {
      vNextButton = vCurrent;
      break;
    }
  }

  // If none found, try again from the begin (looping)
  if (!vNextButton)
  {
    for (var i=0; i<vIndex; i++)
    {
      vCurrent = vChildren[i];

      if (vCurrent instanceof qx.ui.toolbar.MenuButton && vCurrent.getEnabled())
      {
        vNextButton = vCurrent;
        break;
      }
    }
  }

  if (vNextButton)
  {
    // hide other menus
    qx.manager.object.MenuManager.getInstance().update();

    // show next menu
    vNextButton._showMenu(true);
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

  this.removeEventListener("keypress", this._onkeypress);

  return qx.ui.layout.HorizontalBoxLayout.prototype.dispose.call(this);
}
