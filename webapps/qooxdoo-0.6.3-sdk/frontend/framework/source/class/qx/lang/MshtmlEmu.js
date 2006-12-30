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

#require(qx.sys.Client)

************************************************************************ */

qx.OO.defineClass("qx.lang.MshtmlEmu");

/*
  Parts are based on:
  moz-behaviors.xml - version 1.1.1 (2005-08-19)
  Copyright 2004-2005, Dean Edwards
  License: http://creativecommons.org/licenses/LGPL/2.1/
  Thanks to Erik Arvidsson (http://webfx.eae.net/dhtml/ieemu/)
*/

/*
  We're going to mess about with some of mozilla's interfaces to
  make them more explorer-like
*/

/*
  Note:
  In my comments where i say support/mimic a property:

  * support = exactly the same as explorer
  * mimic = close enough
*/

if (qx.sys.Client.getInstance().isGecko())
{
  /*
  --------------------------------------------------------------------------------
    CSS STYLES: FLOAT
  --------------------------------------------------------------------------------
  */

  /*
    Support microsoft's styleFloat
  */

  CSSStyleDeclaration.prototype.__defineGetter__("styleFloat", function() {
    return this.cssFloat;
  });

  CSSStyleDeclaration.prototype.__defineSetter__("styleFloat", function(vValue) {
    this.cssFloat = vValue;
  });





  /*
  --------------------------------------------------------------------------------
    CSS STYLES: DIMENSIONS
  --------------------------------------------------------------------------------
  */

  /*
    Mimic microsoft's pixel representations of left/top/width/height
    the getters only work for values that are already pixels
  */

  CSSStyleDeclaration.prototype.__defineGetter__("pixelLeft", function() {
    return parseInt(this.left) || 0;
  });

  CSSStyleDeclaration.prototype.__defineSetter__("pixelLeft", function(vValue) {
    this.left = vValue + "px";
  });

  CSSStyleDeclaration.prototype.__defineGetter__("pixelTop", function() {
    return parseInt(this.top) || 0;
  });

  CSSStyleDeclaration.prototype.__defineSetter__("pixelTop", function(vValue) {
    this.top = vValue + "px";
  });

  CSSStyleDeclaration.prototype.__defineGetter__("pixelWidth", function() {
    return parseInt(this.width) || 0;
  });

  CSSStyleDeclaration.prototype.__defineSetter__("pixelWidth", function(vValue) {
    this.width = vValue + "px";
  });

  CSSStyleDeclaration.prototype.__defineGetter__("pixelHeight", function() {
    return parseInt(this.height) || 0;
  });

  CSSStyleDeclaration.prototype.__defineSetter__("pixelHeight", function(vValue) {
    this.height = vValue + "px";
  });





  /*
  --------------------------------------------------------------------------------
    HTML DOCUMENT EXTENSIONS
  --------------------------------------------------------------------------------
  */

  /*
    Support Microsoft's "all" property
  */
  HTMLDocument.prototype.__defineGetter__("all", function() {
    return this.getElementsByTagName("*");
  });

  /*
    Mimic the "createEventObject" method for the document object
  */
  HTMLDocument.prototype.createEventObject = function() {
    return document.createEvent("Events");
  }






  /*
  --------------------------------------------------------------------------------
    HTML ELEMENT EXTENSIONS
  --------------------------------------------------------------------------------
  */

  /*
    Mimic Microsoft's "all" property
  */
  HTMLElement.prototype.__defineGetter__("all", function() {
    return this.getElementsByTagName("*");
  });

  /*
    Support "parentElement"
  */
  HTMLElement.prototype.__defineGetter__("parentElement", function() {
    return (this.parentNode == this.ownerDocument) ? null : this.parentNode;
  });

  /*
    Support "uniqueID"
  */
  HTMLElement.prototype.__defineGetter__("uniqueID", function()
  {
    // a global counter is stored privately as a property of this getter function.
    // initialise the counter
    if (!arguments.callee.count) {
      arguments.callee.count = 0;
    }

    // create the id and increment the counter
    var vUniqueID = "moz_id" + arguments.callee.count++;

    // creating a unique id, creates a global reference
    window[vUniqueID] = this;

    // we don't want to increment next time, so redefine the getter
    this.__defineGetter__("uniqueID", function(){return vUniqueID;});

    return vUniqueID;
  });

  /*
    Mimic Microsoft's "currentStyle"
  */
  HTMLElement.prototype.__defineGetter__("currentStyle", function() {
    return getComputedStyle(this, null);
  });

  /*
    Mimic Microsoft's "runtimeStyle"
  */
  HTMLElement.prototype.__defineGetter__("runtimeStyle", function()
  {
    /*
      this doesn't work yet (https://bugzilla.mozilla.org/show_bug.cgi?id=45424)
      return this.ownerDocument.defaultView.getOverrideStyle(this, null);
    */

    return this.style;
  });

  /*
    Support "innerText"
  */
  HTMLElement.prototype.__defineGetter__("innerText", function() {
    return this.textContent;
  });

  HTMLElement.prototype.__defineSetter__("innerText", function(vValue) {
    this.textContent = vValue;
  });

  /*
    Mimic the "attachEvent" method
  */
  HTMLElement.prototype.attachEvent = function(vName, vHandler) {
    this.addEventListener(vName.slice(2), vHandler, false);
  }

  /*
    Mimic the "removeEvent" method
  */
  HTMLElement.prototype.removeEvent = function(vName, vHandler) {
    this.removeEventListener(vName.slice(2), vHandler, false);
  }

  /*
    Mimic the "createEventObject" method
  */
  HTMLElement.prototype.createEventObject = function() {
    return this.ownerDocument.createEventObject();
  }

  /*
    Mimic the "fireEvent" method
  */
  HTMLElement.prototype.fireEvent = function(vName, vEvent)
  {
    if (!vEvent) {
      vEvent = this.ownerDocument.createEventObject();
    }

    vEvent.initEvent(vName.slice(2), false, false);

    this.dispatchEvent(vEvent);

    // not sure that this should be here??
    if (typeof this[vName] === "function")
    {
      this[vName]();
    }
    else if (this.getAttribute(vName))
    {
      eval(this.getAttribute(vName));
    }
  }

  /*
    Support the "contains" method
  */
  HTMLElement.prototype.contains = function(vElement) {
    return Boolean(vElement == this || (vElement && this.contains(vElement.parentElement)));
  }





  /*
  --------------------------------------------------------------------------------
    EVENT EXTENSIONS
  --------------------------------------------------------------------------------
  */

  /*
    Support Microsoft's proprietary event properties
  */
  Event.prototype.__defineGetter__("srcElement", function() {
    return (this.target.nodeType == Node.ELEMENT_NODE) ? this.target : this.target.parentNode;
  });

  Event.prototype.__defineGetter__("fromElement",function() {
    return (this.type == "mouseover") ? this.relatedTarget : (this.type == "mouseout") ? this.srcElement : null;
  });

  Event.prototype.__defineGetter__("toElement", function() {
    return (this.type == "mouseout") ? this.relatedTarget : (this.type == "mouseover") ? this.srcElement : null;
  });

  /*
    Convert w3c button id's to Microsoft's
    Breaks with qooxdoo's internal event handling!!!
  */
  /*
  Event.prototype.__defineGetter__("button", function() {
    return (this.which == 1) ? 1 : (this.which == 2) ? 4 : 2;
  });
  */


  /*
    Mimic "returnValue" (default is "true")
    Breaks with qooxdoo's internal event handling!!!
  */
  /*
  Event.prototype.__defineGetter__("returnValue", function() {
    return true;
  });

  Event.prototype.__defineSetter__("returnValue", function(vValue)
  {
    if (this.cancelable && !vValue)
    {
      // this can't be undone!
      this.preventDefault();

      this.__defineGetter__("returnValue", function() {
        return false;
      });
    }
  });
  */

  /*
    Mozilla already supports the read-only "cancelBubble"
    so we only need to define the setter
  */
  Event.prototype.__defineSetter__("cancelBubble", function(vValue)
  {
    // this can't be undone!
    if (vValue) {
      this.stopPropagation();
    }
  });

  Event.prototype.__defineGetter__("offsetX", function() {
    return this.layerX;
  });

  Event.prototype.__defineGetter__("offsetY", function() {
    return this.layerY;
  });
}
