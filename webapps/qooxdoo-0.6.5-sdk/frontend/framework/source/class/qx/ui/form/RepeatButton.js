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
 * @event execute {qx.event.type.Event}
 */
qx.OO.defineClass("qx.ui.form.RepeatButton", qx.ui.form.Button,
function(vText, vIcon, vIconWidth, vIconHeight, vFlash)
{
  qx.ui.form.Button.call(this, vText, vIcon, vIconWidth, vIconHeight, vFlash);

  this._timer = new qx.client.Timer;
  this._timer.setInterval(this.getInterval());
  this._timer.addEventListener("interval", this._oninterval, this);
});


/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "interval", type : "number", defaultValue : 100 });
qx.OO.addProperty({ name : "firstInterval", type : "number", defaultValue : 500 });





/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onmousedown = function(e)
{
  if (e.getTarget() != this || !e.isLeftButtonPressed()) {
    return;
  }

  this._executed = false;

  this._timer.setInterval(this.getFirstInterval());
  this._timer.start();

  this.removeState("abandoned");
  this.addState("pressed");
}

qx.Proto._onmouseup = function(e)
{
  this.setCapture(false);

  if (!this.hasState("abandoned"))
  {
    this.addState("over");

    if (this.hasState("pressed") && !this._executed) {
      this.execute();
    }
  }

  this._timer.stop();

  this.removeState("abandoned");
  this.removeState("pressed");
}

qx.Proto._oninterval = function(e)
{
  this._timer.stop();
  this._timer.setInterval(this.getInterval());
  this._timer.start();

  this._executed = true;
  this.createDispatchEvent("execute");
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._timer)
  {
    this._timer.stop();
    this._timer.dispose();
    this._timer = null;
  }

  return qx.ui.form.Button.prototype.dispose.call(this);
}
