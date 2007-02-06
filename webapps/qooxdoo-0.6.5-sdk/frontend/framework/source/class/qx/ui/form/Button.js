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

#module(ui_form)

************************************************************************ */
/**
 * A button.
 *
 * @state {abandoned}
 * @state {over}
 * @state {pressed}
 */
qx.OO.defineClass("qx.ui.form.Button", qx.ui.basic.Atom,
function(vText, vIcon, vIconWidth, vIconHeight, vFlash)
{
  // ************************************************************************
  //   INIT
  // ************************************************************************
  qx.ui.basic.Atom.call(this, vText, vIcon, vIconWidth, vIconHeight, vFlash);

  // Make focusable
  this.setTabIndex(1);


  // ************************************************************************
  //   MOUSE EVENTS
  // ************************************************************************
  this.addEventListener("mouseover", this._onmouseover);
  this.addEventListener("mouseout", this._onmouseout);
  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);


  // ************************************************************************
  //   KEY EVENTS
  // ************************************************************************
  this.addEventListener("keydown", this._onkeydown);
  this.addEventListener("keyup", this._onkeyup);
});

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "button" });



/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onmouseover = function(e)
{
  if (e.getTarget() != this) {
    return;
  }

  if (this.hasState("abandoned"))
  {
    this.removeState("abandoned");
    this.addState("pressed");
  }

  this.addState("over");
}

qx.Proto._onmouseout = function(e)
{
  if (e.getTarget() != this) {
    return;
  }

  this.removeState("over");

  if (this.hasState("pressed"))
  {
    // Activate capturing if the button get a mouseout while
    // the button is pressed.
    this.setCapture(true);

    this.removeState("pressed");
    this.addState("abandoned");
  }
}

qx.Proto._onmousedown = function(e)
{
  if (e.getTarget() != this || !e.isLeftButtonPressed()) {
    return;
  }

  this.removeState("abandoned");
  this.addState("pressed");
}

qx.Proto._onmouseup = function(e)
{
  this.setCapture(false);

  // We must remove the states before executing the command
  // because in cases were the window lost the focus while
  // executing we get the capture phase back (mouseout).
  var hasPressed = this.hasState("pressed");
  var hasAbandoned = this.hasState("abandoned");

  if (hasPressed) {
    this.removeState("pressed");
  }

  if (hasAbandoned) {
    this.removeState("abandoned");
  }

  if (!hasAbandoned)
  {
    this.addState("over");

    if (hasPressed) {
      this.execute();
    }
  }
}

qx.Proto._onkeydown = function(e)
{
  switch(e.getKeyIdentifier())
  {
    case "Enter":
    case "Space":
      this.removeState("abandoned");
      this.addState("pressed");
  }
}

qx.Proto._onkeyup = function(e)
{
  switch(e.getKeyIdentifier())
  {
    case "Enter":
    case "Space":
      if (this.hasState("pressed"))
      {
        this.removeState("abandoned");
        this.removeState("pressed");
        this.execute();
      }
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

  // ************************************************************************
  //   MOUSE EVENTS
  // ************************************************************************
  this.removeEventListener("mouseover", this._onmouseover, this);
  this.removeEventListener("mouseout", this._onmouseout, this);
  this.removeEventListener("mousedown", this._onmousedown, this);
  this.removeEventListener("mouseup", this._onmouseup, this);


  // ************************************************************************
  //   KEY EVENTS
  // ************************************************************************
  this.removeEventListener("keydown", this._onkeydown, this);
  this.removeEventListener("keyup", this._onkeyup, this);


  // ************************************************************************
  //   SUPER CLASS
  // ************************************************************************
  return qx.ui.basic.Atom.prototype.dispose.call(this);
}
