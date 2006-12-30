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
#require(qx.dom.StyleSheet)
#require(qx.event.handler.EventHandler)
#optional(qx.client.NativeWindow)
#optional(qx.ui.window.Window)
#optional(qx.manager.object.PopupManager)

************************************************************************ */

/**
 * This is the basic widget of all qooxdoo applications.
 *
 * qx.ui.core.ClientDocument is the parent of all children inside your application. It
 * also handles their resizing and focus navigation.
 *
 * @event windowblur {qx.event.type.Event} Fired when the window looses the
 *        focus. (Fired by {@link qx.event.handler.EventHandler})
 * @event windowfocus {qx.event.type.Event} Fired when the window gets the
 *        focus. (Fired by {@link qx.event.handler.EventHandler})
 * @event windowresize {qx.event.type.Event} Fired when the window has been
 *        resized. (Fired by {@link qx.event.handler.EventHandler})
 */
qx.OO.defineClass("qx.ui.core.ClientDocument", qx.ui.layout.CanvasLayout,
function()
{
  this._window = window;
  this._document = window.document;

  // Init element
  this.setElement(this._document.body);

  // Needed hard-coded because otherwise the client document
  // would not be added initially to the state queue
  this.addToStateQueue();

  qx.ui.layout.CanvasLayout.call(this);

  // Don't use widget styles
  this._styleProperties = {};

  // Configure as focus root
  this.activateFocusRoot();

  // Cache current size
  this._cachedInnerWidth = this._document.body.offsetWidth;
  this._cachedInnerHeight = this._document.body.offsetHeight;

  // Add Resize Handler
  this.addEventListener("windowresize", this._onwindowresize);

  // Dialog Support
  this._modalWidgets = [];
  this._modalNativeWindow = null;

  // Register as focus root
  qx.event.handler.EventHandler.getInstance().setFocusRoot(this);


  // Init Resize Helper
  /*
  if (qx.sys.Client.getInstance().isGecko())
  {
    var o = this;
    this._resizeHelper = window.setInterval(function() { o._onresizehelper() }, 100);
  }
  */
});

qx.OO.addProperty({ name : "globalCursor", type : "string" });

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "client-document" });



/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("enableApplicationLayout", true);
qx.Settings.setDefault("boxModelCorrection", true);






/*
---------------------------------------------------------------------------
  OVERWRITE WIDGET FUNCTIONS/PROPERTIES
---------------------------------------------------------------------------
*/

qx.Proto._modifyParent = qx.util.Return.returnTrue;
qx.Proto._modifyVisible = qx.util.Return.returnTrue;

qx.Proto._modifyElement = function(propValue, propOldValue, propData)
{
  this._isCreated = qx.util.Validation.isValidElement(propValue);

  if (propOldValue)
  {
    propOldValue.qx_Widget = null;
  }

  if (propValue)
  {
    // add reference to widget instance
    propValue.qx_Widget = this;

    // link element and style reference
    this._element = propValue;
    this._style = propValue.style;
  }
  else
  {
    this._element = null;
    this._style = null;
  }

  return true;
}

qx.Proto.getTopLevelWidget = qx.util.Return.returnThis;
qx.Proto.getWindowElement = function() { return this._window; }
qx.Proto.getDocumentElement = function() { return this._document; }

qx.Proto.getParent = qx.Proto.getToolTip = qx.util.Return.returnNull;
qx.Proto.isMaterialized = qx.Proto.isSeeable = qx.util.Return.returnTrue;

qx.Proto._isDisplayable = true;
qx.Proto._hasParent = false;
qx.Proto._initialLayoutDone = true;









/*
---------------------------------------------------------------------------
  BLOCKER AND DIALOG SUPPORT
---------------------------------------------------------------------------
*/

/**
 * Returns the blocker widget if already created; otherwise create it first
 *
 * @return {ClientDocumentBlocker} the blocker widget.
 */
qx.Proto._getBlocker = function()
{
  if (!this._blocker)
  {
    // Create blocker instance
    this._blocker = new qx.ui.core.ClientDocumentBlocker;

    // Add blocker events
    this._blocker.addEventListener("mousedown", this.blockHelper, this);
    this._blocker.addEventListener("mouseup", this.blockHelper, this);

    // Add blocker to client document
    this.add(this._blocker);
  }

  return this._blocker;
};

qx.Proto.blockHelper = function(e)
{
  if (this._modalNativeWindow)
  {
    try
    {
      this._modalNativeWindow._window.focus();
    }
    catch(ex)
    {
      this.debug("Window seems to be closed already! => Releasing Blocker: (" + e.getType() + ")", ex);
      this.release(this._modalNativeWindow);
    }
  }
}

qx.Proto.block = function(vActiveChild)
{
  // this.debug("BLOCK: " + vActiveChild.toHashCode());

  this._getBlocker().show();

  if (qx.OO.isAvailable("qx.ui.window.Window") && vActiveChild instanceof qx.ui.window.Window)
  {
    this._modalWidgets.push(vActiveChild);

    var vOrigIndex = vActiveChild.getZIndex();
    this._getBlocker().setZIndex(vOrigIndex);
    vActiveChild.setZIndex(vOrigIndex+1);
  }
  else if (qx.OO.isAvailable("qx.client.NativeWindow") && vActiveChild instanceof qx.client.NativeWindow)
  {
    this._modalNativeWindow = vActiveChild;
    this._getBlocker().setZIndex(1e7);
  }
}

qx.Proto.release = function(vActiveChild)
{
  // this.debug("RELEASE: " + vActiveChild.toHashCode());

  if (vActiveChild)
  {
    if (qx.OO.isAvailable("qx.client.NativeWindow") && vActiveChild instanceof qx.client.NativeWindow)
    {
      this._modalNativeWindow = null;
    }
    else
    {
      qx.lang.Array.remove(this._modalWidgets, vActiveChild);
    }
  }

  var l = this._modalWidgets.length;
  if (l == 0)
  {
    this._getBlocker().hide();
  }
  else
  {
    var oldActiveChild = this._modalWidgets[l-1];

    var o = oldActiveChild.getZIndex();
    this._getBlocker().setZIndex(o);
    oldActiveChild.setZIndex(o+1);
  }
}








/*
---------------------------------------------------------------------------
  CSS API
---------------------------------------------------------------------------
*/

qx.Proto.createStyleElement = function(vCssText) {
  return qx.dom.StyleSheet.createElement(vCssText);
}

qx.Proto.addCssRule = function(vSheet, vSelector, vStyle) {
  return qx.dom.StyleSheet.addRule(vSheet, vSelector, vStyle);
}

qx.Proto.removeCssRule = function(vSheet, vSelector) {
  return qx.dom.StyleSheet.removeRule(vSheet, vSelector);
}

qx.Proto.removeAllCssRules = function(vSheet) {
  return qx.dom.StyleSheet.removeAllRules(vSheet);
}






/*
---------------------------------------------------------------------------
  CSS FIX
---------------------------------------------------------------------------
*/
if (qx.Settings.getValueOfClass("qx.ui.core.ClientDocument", "boxModelCorrection")) {
  qx.dom.StyleSheet.createElement("html,body{margin:0;border:0;padding:0;}" +
    " html{border:0 none;} *{" + qx.sys.Client.getInstance().getEngineBoxSizingAttribute() +
    ":border-box;} img{" + qx.sys.Client.getInstance().getEngineBoxSizingAttribute() +
    ":content-box;}");
}
if (qx.Settings.getValueOfClass("qx.ui.core.ClientDocument", "enableApplicationLayout")) {
  qx.dom.StyleSheet.createElement("html,body{width:100%;height:100%;overflow:hidden;}");
}





/*
---------------------------------------------------------------------------
  GLOBAL CURSOR SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto._modifyGlobalCursor = function(propValue, propOldValue, propData)
{
  if (!this._globalCursorStyleSheet) {
    this._globalCursorStyleSheet = this.createStyleElement();
  }

  // Selector based remove does not work with the "*" selector in mshtml
  // this.removeCssRule(this._globalCursorStyleSheet, "*");

  this.removeAllCssRules(this._globalCursorStyleSheet);

  if (propValue) {
    this.addCssRule(this._globalCursorStyleSheet, "*", "cursor:" + propValue + " !important");
  }

  return true;
}





/*
---------------------------------------------------------------------------
  WINDOW RESIZE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._onwindowresize = function(e)
{
  // Hide popups, tooltips, ...
  if (qx.OO.isAvailable("qx.manager.object.PopupManager")) {
    qx.manager.object.PopupManager.getInstance().update();
  }

  // Update children
  this._recomputeInnerWidth();
  this._recomputeInnerHeight();

  // Flush queues
  qx.ui.core.Widget.flushGlobalQueues();
}

// This was an idea to allow mozilla more realtime document resize updates
// but it seems so, that mozilla stops javascript execution while the user
// resize windows. Bad.

/*
qx.Proto._onwindowresizehelper = function()
{
  // Test for changes
  var t1 = this._recomputeInnerWidth();
  var t2 = this._recomputeInnerHeight();

  // Flush queues
  if (t1 || t2) {
    qx.ui.core.Widget.flushGlobalQueues();
  }
}
*/

qx.Proto._computeInnerWidth = function() {
  return this._document.body.offsetWidth;
}

qx.Proto._computeInnerHeight = function() {
  return this._document.body.offsetHeight;
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

  delete this._document;
  delete this._modalWidgets;
  delete this._modalNativeWindow;

  // Remove Resize Handler
  this.removeEventListener("windowresize", this._onwindowresize);

  this._globalCursorStyleSheet = null;

  if (this._blocker)
  {
    this._blocker.removeEventListener("mousedown", this.blockHelper, this);
    this._blocker.removeEventListener("mouseup", this.blockHelper, this);

    this._blocker.dispose();
    this._blocker = null;
  }

  /*
  if (this._resizeHelper)
  {
    window.clearInterval(this._resizeHelper);
    this._resizeHelper = null;
  }
  */

  return qx.ui.layout.CanvasLayout.prototype.dispose.call(this);
}






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
