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

#module(ui_popup)

************************************************************************ */

qx.OO.defineClass("qx.ui.popup.PopupAtom", qx.ui.popup.Popup,
function(vLabel, vIcon)
{
  qx.ui.popup.Popup.call(this);

  this._atom = new qx.ui.basic.Atom(vLabel, vIcon);
  this._atom.setParent(this);
});

qx.Proto.getAtom = function() {
  return this._atom;
}

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._atom)
  {
    this._atom.dispose();
    this._atom = null;
  }

  return qx.ui.popup.Popup.prototype.dispose.call(this);
}
