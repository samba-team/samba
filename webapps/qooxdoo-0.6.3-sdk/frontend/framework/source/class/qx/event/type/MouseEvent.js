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

#module(ui_core)

************************************************************************ */

/*!
  A mouse event instance contains all data for each occured mouse event
*/
qx.OO.defineClass("qx.event.type.MouseEvent", qx.event.type.DomEvent,
function(vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget, vRelatedTarget)
{
  qx.event.type.DomEvent.call(this, vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget);

  if (vRelatedTarget) {
    this.setRelatedTarget(vRelatedTarget);
  }
});

qx.Class.C_BUTTON_LEFT = "left";
qx.Class.C_BUTTON_MIDDLE = "middle";
qx.Class.C_BUTTON_RIGHT = "right";
qx.Class.C_BUTTON_NONE = "none";



/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  CLASS PROPERTIES AND METHODS
---------------------------------------------------------------------------
*/

qx.event.type.MouseEvent._screenX = qx.event.type.MouseEvent._screenY = qx.event.type.MouseEvent._clientX = qx.event.type.MouseEvent._clientY = qx.event.type.MouseEvent._pageX = qx.event.type.MouseEvent._pageY = 0;
qx.event.type.MouseEvent._button = null;

qx.event.type.MouseEvent._storeEventState = function(e)
{
  qx.event.type.MouseEvent._screenX = e.getScreenX();
  qx.event.type.MouseEvent._screenY = e.getScreenY();
  qx.event.type.MouseEvent._clientX = e.getClientX();
  qx.event.type.MouseEvent._clientY = e.getClientY();
  qx.event.type.MouseEvent._pageX   = e.getPageX();
  qx.event.type.MouseEvent._pageY   = e.getPageY();
  qx.event.type.MouseEvent._button  = e.getButton();
}

qx.event.type.MouseEvent.getScreenX = function() { return qx.event.type.MouseEvent._screenX; }
qx.event.type.MouseEvent.getScreenY = function() { return qx.event.type.MouseEvent._screenY; }
qx.event.type.MouseEvent.getClientX = function() { return qx.event.type.MouseEvent._clientX; }
qx.event.type.MouseEvent.getClientY = function() { return qx.event.type.MouseEvent._clientY; }
qx.event.type.MouseEvent.getPageX   = function() { return qx.event.type.MouseEvent._pageX;   }
qx.event.type.MouseEvent.getPageY   = function() { return qx.event.type.MouseEvent._pageY;   }
qx.event.type.MouseEvent.getButton  = function() { return qx.event.type.MouseEvent._button;  }

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.event.type.MouseEvent.buttons = { left : 1, right : 2, middle : 4 }
}
else
{
  qx.event.type.MouseEvent.buttons = { left : 0, right : 2, middle : 1 }
}






/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  SCREEN COORDINATES SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.getScreenX = function() {
  return this.getDomEvent().screenX;
}

qx.Proto.getScreenY = function() {
  return this.getDomEvent().screenY;
}








/*
---------------------------------------------------------------------------
  PAGE COORDINATES SUPPORT
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
qx.OO.addFastProperty({ name : "pageX", readOnly : true });
qx.OO.addFastProperty({ name : "pageY", readOnly : true });

  if (qx.sys.Client.getInstance().isInQuirksMode())
  {
    qx.Proto._computePageX = function() {
      return this.getDomEvent().clientX + document.documentElement.scrollLeft;
    }

    qx.Proto._computePageY = function() {
      return this.getDomEvent().clientY + document.documentElement.scrollTop;
    }
  }
  else
  {
    qx.Proto._computePageX = function() {
      return this.getDomEvent().clientX + document.body.scrollLeft;
    }

    qx.Proto._computePageY = function() {
      return this.getDomEvent().clientY + document.body.scrollTop;
    }
  }
}
else if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto.getPageX = function() {
    return this.getDomEvent().pageX;
  }

  qx.Proto.getPageY = function() {
    return this.getDomEvent().pageY;
  }
}
else
{
  qx.Proto.getPageX = function() {
    return this.getDomEvent().clientX;
  }

  qx.Proto.getPageY = function() {
    return this.getDomEvent().clientY;
  }
}







/*
---------------------------------------------------------------------------
  CLIENT COORDINATES SUPPORT
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml() || qx.sys.Client.getInstance().isGecko())
{
  qx.Proto.getClientX = function() {
    return this.getDomEvent().clientX;
  }

  qx.Proto.getClientY = function() {
    return this.getDomEvent().clientY;
  }
}
else
{
qx.OO.addFastProperty({ name : "clientX", readOnly : true });
qx.OO.addFastProperty({ name : "clientY", readOnly : true });

  qx.Proto._computeClientX = function() {
    return this.getDomEvent().clientX + (document.body && document.body.scrollLeft != null ? document.body.scrollLeft : 0);
  }

  qx.Proto._computeClientY = function() {
    return this.getDomEvent().clientY + (document.body && document.body.scrollTop != null ? document.body.scrollTop : 0);
  }
}







/*
---------------------------------------------------------------------------
  BUTTON SUPPORT
---------------------------------------------------------------------------
*/

qx.OO.addFastProperty({ name : "button", readOnly : true });

// IE does not set e.button in click events
if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto.isLeftButtonPressed = function() {
    if (this.getType() == "click") {
      return true;
    } else {
      return this.getButton() === qx.event.type.MouseEvent.C_BUTTON_LEFT;
    }
  }
}
else
{
  qx.Proto.isLeftButtonPressed = function() {
    return this.getButton() === qx.event.type.MouseEvent.C_BUTTON_LEFT;
  }
}

qx.Proto.isMiddleButtonPressed = function() {
  return this.getButton() === qx.event.type.MouseEvent.C_BUTTON_MIDDLE;
}

qx.Proto.isRightButtonPressed = function() {
  return this.getButton() === qx.event.type.MouseEvent.C_BUTTON_RIGHT;
}

qx.Proto._computeButton = function() {
  var e = this.getDomEvent();
  if (e.which) {
    switch (e.which) {
      case 1:
        return qx.event.type.MouseEvent.C_BUTTON_LEFT;

      case 3:
        return qx.event.type.MouseEvent.C_BUTTON_RIGHT;

      case 2:
        return qx.event.type.MouseEvent.C_BUTTON_MIDDLE;

      default:
        return qx.event.type.MouseEvent.C_BUTTON_NONE;

    }
  } else {
    switch(e.button) {
      case 1:
        return qx.event.type.MouseEvent.C_BUTTON_LEFT;

      case 2:
        return qx.event.type.MouseEvent.C_BUTTON_RIGHT;

      case 4:
        return qx.event.type.MouseEvent.C_BUTTON_MIDDLE;

      default:
        return qx.event.type.MouseEvent.C_BUTTON_NONE;
    }
  }
}




/*
---------------------------------------------------------------------------
  WHEEL SUPPORT
---------------------------------------------------------------------------
*/

// Implementation differences: http://ajaxian.com/archives/javascript-and-mouse-wheels

qx.OO.addFastProperty({ name : "wheelDelta", readOnly : true });

if(qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._computeWheelDelta = function() {
    return this.getDomEvent().wheelDelta / 120;
  }
}
else if(qx.sys.Client.getInstance().isOpera())
{
  qx.Proto._computeWheelDelta = function() {
    return -this.getDomEvent().wheelDelta / 120;
  }
}
else
{
  qx.Proto._computeWheelDelta = function() {
    return -this.getDomEvent().detail / 3;
  }
}
