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

#module(ui_menu)

************************************************************************ */

qx.OO.defineClass("qx.ui.menu.Separator", qx.ui.layout.CanvasLayout,
function()
{
  qx.ui.layout.CanvasLayout.call(this);

  // Fix IE Styling Issues
  this.setStyleProperty("fontSize", "0");
  this.setStyleProperty("lineHeight", "0");

  // ************************************************************************
  //   LINE
  // ************************************************************************

  this._line = new qx.ui.basic.Terminator;
  this._line.setAnonymous(true);
  this._line.setAppearance("menu-separator-line");
  this.add(this._line);


  // ************************************************************************
  //   EVENTS
  // ************************************************************************

  // needed to stop the event, and keep the menu showing
  this.addEventListener("mousedown", this._onmousedown);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "menu-separator" });

qx.Proto.hasIcon = qx.lang.Function.returnFalse;
qx.Proto.hasLabel = qx.lang.Function.returnFalse;
qx.Proto.hasShortcut = qx.lang.Function.returnFalse;
qx.Proto.hasMenu = qx.lang.Function.returnFalse;

qx.Proto._onmousedown = function(e) {
  e.stopPropagation();
}

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._line)
  {
    this._line.dispose();
    this._line = null;
  }

  return qx.ui.layout.CanvasLayout.prototype.dispose.call(this);
}
