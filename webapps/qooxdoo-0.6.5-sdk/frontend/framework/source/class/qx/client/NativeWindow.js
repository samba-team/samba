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

#require(qx.html.Window)

************************************************************************ */

qx.OO.defineClass("qx.client.NativeWindow", qx.core.Target,
function(vUrl, vName)
{
  qx.core.Target.call(this);


  // ************************************************************************
  //   TIMER
  // ************************************************************************

  this._timer = new qx.client.Timer(100);
  this._timer.addEventListener("interval", this._oninterval, this);


  // ************************************************************************
  //   INITIAL PROPERTIES
  // ************************************************************************

  if (vUrl != null) {
    this.setUrl(vUrl);
  }

  if (vName != null) {
    this.setName(vName);
  }
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  If the window is open or closed
*/
qx.OO.addProperty({ name : "open", type : "boolean", defaultValue : false });

/*!
  The outer width of the window.
*/
qx.OO.addProperty({ name : "width", type : "number", defaultValue : 400, impl : "dimension" });

/*!
  The outer height of the window.
*/
qx.OO.addProperty({ name : "height", type : "number", defaultValue : 250, impl : "dimension" });

/*!
  The left screen coordinate of the window.
*/
qx.OO.addProperty({ name : "left", type : "number", defaultValue : 100, impl : "position" });

/*!
  The top screen coordinate of the window.
*/
qx.OO.addProperty({ name : "top", type : "number", defaultValue : 200, impl : "position" });

/*!
  Should be window be modal
*/
qx.OO.addProperty({ name : "modal", type : "boolean", defaultValue : false });

/*!
  Should be window be dependent on this application window
*/
qx.OO.addProperty({ name : "dependent", type : "boolean", defaultValue : true });

/*!
  The url
*/
qx.OO.addProperty({ name : "url", type : "string" });

/*!
  The window name
*/
qx.OO.addProperty({ name : "name", type : "string" });

/*!
  The text of the statusbar
*/
qx.OO.addProperty({ name : "status", type : "string", defaultValue : "Ready" });

/*!
  Should the statusbar be shown
*/
qx.OO.addProperty({ name : "showStatusbar", type : "boolean", defaultValue : false });

/*!
  Should the menubar be shown
*/
qx.OO.addProperty({ name : "showMenubar", type : "boolean", defaultValue : false });

/*!
  Should the location(bar) be shown
*/
qx.OO.addProperty({ name : "showLocation", type : "boolean", defaultValue : false });

/*!
  Should the toolbar be shown
*/
qx.OO.addProperty({ name : "showToolbar", type : "boolean", defaultValue : false });

/*!
  If the window is resizeable
*/
qx.OO.addProperty({ name : "resizeable", type : "boolean", defaultValue : true });

/*!
  If the window is able to scroll and has visible scrollbars if needed
*/
qx.OO.addProperty({ name : "allowScrollbars", type : "boolean", defaultValue : true });



/*
---------------------------------------------------------------------------
  STATE
---------------------------------------------------------------------------
*/

qx.Proto._loaded = false;




/*
---------------------------------------------------------------------------
  PROPERTY GROUPS
---------------------------------------------------------------------------
*/

qx.OO.addPropertyGroup({ name : "location", members : [ "left", "top" ]});
qx.OO.addPropertyGroup({ name : "dimension", members : [ "width", "height" ]});




/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyPosition = function(propValue, propOldValue, propName)
{
  /*
    http://www.microsoft.com/technet/prodtechnol/winxppro/maintain/sp2brows.mspx
    Changes to Functionality in Microsoft Windows XP Service Pack 2
    Part 5: Enhanced Browsing Security
    URLACTION_FEATURE_WINDOW_RESTRICTIONS
    Allow script-initiated windows without size or position constraints
    Code: 2102
  */

  if (!this.isClosed())
  {
    try
    {
      this._window.moveTo(this.getLeft(), this.getTop());
    }
    catch(ex)
    {
      this.error("Cross-Domain Scripting problem: Could not move window!", ex);
    }
  }

  return true;
}

qx.Proto._modifyDimension = function(propValue, propOldValue, propName)
{
  /*
    http://www.microsoft.com/technet/prodtechnol/winxppro/maintain/sp2brows.mspx
    Changes to Functionality in Microsoft Windows XP Service Pack 2
    Part 5: Enhanced Browsing Security
    URLACTION_FEATURE_WINDOW_RESTRICTIONS
    Allow script-initiated windows without size or position constraints
    Code: 2102
  */

  if (!this.isClosed())
  {
    try
    {
      this._window.resizeTo(this.getWidth(), this.getHeight());
    }
    catch(ex)
    {
      this.error("Cross-Domain Scripting problem: Could not resize window!", ex);
    }
  }

  return true;
}

qx.Proto._modifyName = function(propValue, propOldValue, propName)
{
  if (!this.isClosed()) {
    this._window.name = propValue;
  }

  return true;
}

qx.Proto._modifyUrl = function(propValue, propOldValue, propName)
{
  // String hack needed for old compressor (compile.py)
  if(!this.isClosed()) {
    this._window.location.replace(propValue != null ? propValue : ("javascript:/" + "/"));
  }

  return true;
}

qx.Proto._modifyOpen = function(propValue, propOldValue, propData)
{
  propValue ? this._open() : this._close();
  return true;
}






/*
---------------------------------------------------------------------------
  NAME
---------------------------------------------------------------------------
*/

qx.Proto.getName = function()
{
  if (!this.isClosed())
  {
    try
    {
      var vName = this._window.name;
    }
    catch(ex)
    {
      return this._valueName;
    }

    if (vName == this._valueName)
    {
      return vName;
    }
    else
    {
      throw new Error("window name and name property are not identical");
    }
  }
  else
  {
    return this._valueName;
  }
}






/*
---------------------------------------------------------------------------
  UTILITY
---------------------------------------------------------------------------
*/

qx.Proto.isClosed = function()
{
  var vClosed = true;

  if (this._window)
  {
    try {
      vClosed = this._window.closed;
    } catch(ex) {}
  }

  return vClosed;
}

qx.Proto.open = function() {
  this.setOpen(true);
}

qx.Proto.close = function() {
  this.setOpen(false);
}

qx.Proto.isLoaded = function() {
  return this._loaded;
}







/*
---------------------------------------------------------------------------
  OPEN METHOD
---------------------------------------------------------------------------
*/

qx.Proto._open = function()
{
  var vConf = [];


  /*
  ------------------------------------------------------------------------------
    PRE CONFIGURE WINDOW
  ------------------------------------------------------------------------------
  */

  if (this.getWidth() != null)
  {
    vConf.push("width");
    vConf.push("=");
    vConf.push(this.getWidth());
    vConf.push(",");
  }

  if (this.getHeight() != null)
  {
    vConf.push("height");
    vConf.push("=");
    vConf.push(this.getHeight());
    vConf.push(",");
  }

  if (this.getLeft() != null)
  {
    vConf.push("left");
    vConf.push("=");
    vConf.push(this.getLeft());
    vConf.push(",");
  }

  if (this.getTop() != null)
  {
    vConf.push("top");
    vConf.push("=");
    vConf.push(this.getTop());
    vConf.push(",");
  }



  vConf.push("dependent");
  vConf.push("=");
  vConf.push(this.getDependent() ? "yes" : "no");
  vConf.push(",");

  vConf.push("resizable");
  vConf.push("=");
  vConf.push(this.getResizeable() ? "yes" : "no");
  vConf.push(",");

  vConf.push("status");
  vConf.push("=");
  vConf.push(this.getShowStatusbar() ? "yes" : "no");
  vConf.push(",");

  vConf.push("location");
  vConf.push("=");
  vConf.push(this.getShowLocation() ? "yes" : "no");
  vConf.push(",");

  vConf.push("menubar");
  vConf.push("=");
  vConf.push(this.getShowMenubar() ? "yes" : "no");
  vConf.push(",");

  vConf.push("toolbar");
  vConf.push("=");
  vConf.push(this.getShowToolbar() ? "yes" : "no");
  vConf.push(",");

  vConf.push("scrollbars");
  vConf.push("=");
  vConf.push(this.getAllowScrollbars() ? "yes" : "no");
  vConf.push(",");

  vConf.push("modal");
  vConf.push("=");
  vConf.push(this.getModal() ? "yes" : "no");
  vConf.push(",");






  /*
  ------------------------------------------------------------------------------
    OPEN WINDOW
  ------------------------------------------------------------------------------
  */

  if (this.getName() != null) {
    this.setName("qx_NativeWindow" + this.toHashCode());
  }

  this._window = window.open(this.getUrl(), this.getName(), vConf.join(""));

  if (this.isClosed())
  {
    this.error("Window could not be opened. It seems, there is a popup blocker active!");
  }
  else
  {
    // This try-catch is needed because of cross domain issues (access rights)
    try
    {
      this._window._native = this;
      this._window.onload = this._onload;
    }
    catch(ex) {}

    // start timer for close detection
    this._timer.start();

    // block original document
    if (this.getModal()) {
      qx.ui.core.ClientDocument.getInstance().block(this);
    }
  }
}

qx.Proto._close = function()
{
  if (!this._window) {
    return;
  }

  // stop timer for close detection
  this._timer.stop();

  // release window again
  if (this.getModal()){
    qx.ui.core.ClientDocument.getInstance().release(this);
  }

  // finally close window
  if (!this.isClosed()) {
    this._window.close();
  }

  try
  {
    this._window._native = null;
    this._window.onload = null;
  }
  catch(ex) {};

  this._window = null;
  this._loaded = false;

  this.createDispatchEvent("close");
}






/*
---------------------------------------------------------------------------
  CENTER SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.centerToScreen = function() {
  return this._centerHelper((screen.width - this.getWidth()) / 2, (screen.height - this.getHeight()) / 2);
}

qx.Proto.centerToScreenArea = function() {
  return this._centerHelper((screen.availWidth - this.getWidth()) / 2, (screen.availHeight - this.getHeight()) / 2);
}

qx.Proto.centerToOpener = function() {
  return this._centerHelper(((qx.html.Window.getInnerWidth(window) - this.getWidth()) / 2) + qx.html.Location.getScreenBoxLeft(window.document.body), ((qx.html.Window.getInnerHeight(window) - this.getHeight()) / 2) + qx.html.Location.getScreenBoxTop(window.document.body));
}

qx.Proto._centerHelper = function(l, t)
{
  // set new values
  this.setLeft(l);
  this.setTop(t);

  // focus window if opened
  if (!this.isClosed()) {
    this.focus();
  }
}






/*
---------------------------------------------------------------------------
  FOCUS HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.focus = function()
{
  if (!this.isClosed()) {
    this._window.focus();
  }
}

qx.Proto.blur = function()
{
  if (!this.isClosed()) {
    this._window.blur();
  }
}







/*
---------------------------------------------------------------------------
  EVENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._oninterval = function(e)
{
  if (this.isClosed()) {
    this.setOpen(false);
  }
  else if (!this._loaded)
  {
    // This try-catch is needed because of cross domain issues (access rights)
    try
    {
      if (this._window.document && this._window.document.readyState == "complete")
      {
        this._loaded = true;
        this.createDispatchEvent("load");
      }
    }
    catch(ex) {};
  }
}

qx.Proto._onload = function(e)
{
  var obj = this._native;

  if (!obj._loaded)
  {
    obj._loaded = true;
    obj.createDispatchEvent("load");
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

  if (this.getDependent()) {
    this.close();
  }

  if (this._timer)
  {
    this._timer.stop();
    this._timer = null;
  }

  if (this._window)
  {
    try
    {
      this._window._native = null;
      this._window.onload = null;
    }
    catch(ex) {};

    this._window = null;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
