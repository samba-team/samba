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
#load(qx.manager.object.ToolTipManager)

************************************************************************ */

qx.OO.defineClass("qx.ui.popup.ToolTip", qx.ui.popup.PopupAtom,
function(vLabel, vIcon)
{
  // ************************************************************************
  //   INIT
  // ************************************************************************

  qx.ui.popup.PopupAtom.call(this, vLabel, vIcon);

  // Apply shadow
  this.setStyleProperty("filter", "progid:DXImageTransform.Microsoft.Shadow(color='Gray', Direction=135, Strength=4)");


  // ************************************************************************
  //   TIMER
  // ************************************************************************

  this._showTimer = new qx.client.Timer(this.getShowInterval());
  this._showTimer.addEventListener("interval", this._onshowtimer, this);

  this._hideTimer = new qx.client.Timer(this.getHideInterval());
  this._hideTimer.addEventListener("interval", this._onhidetimer, this);


  // ************************************************************************
  //   EVENTS
  // ************************************************************************
  this.addEventListener("mouseover", this._onmouseover);
  this.addEventListener("mouseout", this._onmouseover);
});

qx.Proto._minZIndex = 1e7;


/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "tool-tip" });

qx.OO.addProperty({ name : "hideOnHover", type : "boolean", defaultValue : true });

qx.OO.addProperty({ name : "mousePointerOffsetX", type : "number", defaultValue : 1 });
qx.OO.addProperty({ name : "mousePointerOffsetY", type : "number", defaultValue : 20 });

qx.OO.addProperty({ name : "showInterval", type : "number", defaultValue : 1000 });
qx.OO.addProperty({ name : "hideInterval", type : "number", defaultValue : 4000 });

qx.OO.addProperty({ name : "boundToWidget", type : "object", instance : "qx.ui.core.Widget" });








/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyHideInterval = function(propValue, propOldValue, propData)
{
  this._hideTimer.setInterval(propValue);
  return true;
}

qx.Proto._modifyShowInterval = function(propValue, propOldValue, propData)
{
  this._showTimer.setInterval(propValue);
  return true;
}

qx.Proto._modifyBoundToWidget = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    this.setParent(propValue.getTopLevelWidget());
  }
  else if (propOldValue)
  {
    this.setParent(null);
  }

  return true;
}






/*
---------------------------------------------------------------------------
  APPEAR/DISAPPEAR
---------------------------------------------------------------------------
*/

qx.Proto._beforeAppear = function()
{
  qx.ui.popup.PopupAtom.prototype._beforeAppear.call(this);

  this._stopShowTimer();
  this._startHideTimer();
}

qx.Proto._beforeDisappear = function() {
  qx.ui.popup.PopupAtom.prototype._beforeDisappear.call(this);

  this._stopHideTimer();
}






/*
---------------------------------------------------------------------------
  TIMER
---------------------------------------------------------------------------
*/

qx.Proto._startShowTimer = function()
{
  if(!this._showTimer.getEnabled()) {
    this._showTimer.start();
  }
}

qx.Proto._startHideTimer = function()
{
  if(!this._hideTimer.getEnabled()) {
    this._hideTimer.start();
  }
}

qx.Proto._stopShowTimer = function()
{
  if(this._showTimer.getEnabled()) {
    this._showTimer.stop();
  }
}

qx.Proto._stopHideTimer = function()
{
  if(this._hideTimer.getEnabled()) {
    this._hideTimer.stop();
  }
}







/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onmouseover = function(e)
{
  if(this.getHideOnHover()) {
    this.hide();
  }
}

qx.Proto._onshowtimer = function(e)
{
  this.setLeft(qx.event.type.MouseEvent.getPageX() + this.getMousePointerOffsetX());
  this.setTop(qx.event.type.MouseEvent.getPageY() + this.getMousePointerOffsetY());

  this.show();

  // we need a manual flushing because it could be that
  // there is currently no event which do this for us
  // and so show the tooltip.
  qx.ui.core.Widget.flushGlobalQueues();

  return true;
}

qx.Proto._onhidetimer = function(e) {
  return this.hide();
}







/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  this.removeEventListener("mouseover", this._onmouseover);
  this.removeEventListener("mouseout", this._onmouseover);

  if (this._showTimer)
  {
    this._showTimer.removeEventListener("interval", this._onshowtimer, this);
    this._showTimer.dispose();
    this._showTimer = null;
  }

  if (this._hideTimer)
  {
    this._hideTimer.removeEventListener("interval", this._onhidetimer, this);
    this._hideTimer.dispose();
    this._hideTimer = null;
  }

  return qx.ui.popup.PopupAtom.prototype.dispose.call(this);
}
