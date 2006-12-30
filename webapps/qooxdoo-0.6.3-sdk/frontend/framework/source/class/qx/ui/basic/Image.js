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

#module(ui_basic)
#resource(core:static/image)

************************************************************************ */

/**
 * This widget is for all images in qooxdoo projects.
 *
 * @event error {qx.event.type.Event}
 */
qx.OO.defineClass("qx.ui.basic.Image", qx.ui.basic.Terminator,
function(vSource, vWidth, vHeight)
{
  qx.ui.basic.Terminator.call(this);

  // Reset Alt and Title
  this.setHtmlProperty("alt", "");
  this.setHtmlProperty("title", "");

  // Apply constructor arguments
  this.setSource(qx.util.Validation.isValid(vSource) ? vSource : "static/image/blank.gif");

  // Dimensions
  this.setWidth(qx.util.Validation.isValid(vWidth) ? vWidth : "auto");
  this.setHeight(qx.util.Validation.isValid(vHeight) ? vHeight : "auto");

  // Prohibit selection
  this.setSelectable(false);
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The source uri of the image.
*/
qx.OO.addProperty({ name : "source", type : "string" });

/*!
  The assigned preloader instance of the image.
*/
qx.OO.addProperty({ name : "preloader", type : "object" });

/*!
  The loading status.

  True if the image is loaded correctly. False if no image is loaded
  or the one that should be loaded is currently loading or not available.
*/
qx.OO.addProperty({ name : "loaded", type : "boolean", defaultValue : false });

/*!
  Should the image be maxified in it's own container?
*/
qx.OO.addProperty({ name : "resizeToInner", type : "boolean", defaultValue : false });

/*!
  Appearance of the widget
*/
qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "image" });





/*
---------------------------------------------------------------------------
  EVENT MAPPERS
---------------------------------------------------------------------------
*/

qx.Proto._onload = function() {
  this.setLoaded(true);
}

qx.Proto._onerror = function()
{
  this.debug("Could not load: " + this.getSource());

  this.setLoaded(false);

  if (this.hasEventListeners("error")) {
    this.dispatchEvent(new qx.event.type.Event("error"), true);
  }
}





/*
---------------------------------------------------------------------------
  DISPLAYBLE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._beforeAppear = function()
{
  var vSource = this.getSource();

  if (qx.util.Validation.isValidString(vSource)) {
    qx.manager.object.ImageManager.getInstance()._sources[vSource]++;
  }

  return qx.ui.basic.Terminator.prototype._beforeAppear.call(this);
}

qx.Proto._beforeDisappear = function()
{
  var vSource = this.getSource();

  if (qx.util.Validation.isValidString(vSource))
  {
    if (qx.manager.object.ImageManager.getInstance()._sources[vSource] <= 1)
    {
      delete qx.manager.object.ImageManager.getInstance()._sources[vSource];
    }
    else
    {
      qx.manager.object.ImageManager.getInstance()._sources[vSource]--;
    }
  }

  return qx.ui.basic.Terminator.prototype._beforeDisappear.call(this);
}





/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifySource = function(propValue, propOldValue, propData)
{
  if (propValue && typeof qx.manager.object.ImageManager.getInstance()._sources[propValue] === "undefined") {
    qx.manager.object.ImageManager.getInstance()._sources[propValue] = 0;
  }

  if (propOldValue)
  {
    if (qx.manager.object.ImageManager.getInstance()._sources[propOldValue] <= 1)
    {
      delete qx.manager.object.ImageManager.getInstance()._sources[propOldValue];
    }
    else
    {
      qx.manager.object.ImageManager.getInstance()._sources[propOldValue]--;
    }
  }

  if (this.isCreated())
  {
    if (propValue)
    {
      this.setPreloader(qx.manager.object.ImagePreloaderManager.getInstance().create(qx.manager.object.AliasManager.getInstance().resolvePath(propValue)));
    }
    else if (propOldValue)
    {
      this._resetContent();
      this.setPreloader(null);
    }
  }

  return true;
}

qx.Proto._modifyPreloader = function(propValue, propOldValue, propData)
{
  if (propOldValue)
  {
    // remove event connection
    propOldValue.removeEventListener("load", this._onload, this);
    propOldValue.removeEventListener("error", this._onerror, this);
  }

  if (propValue)
  {
    // Register to image manager
    qx.manager.object.ImageManager.getInstance().add(this);

    // Omit  here, otherwise the later setLoaded(true)
    // will not be executed (prevent recursion)

    // Changed: Use forceLoaded instead of setLoaded => should be faster
    this.forceLoaded(false);

    if (propValue.isErroneous())
    {
      this._onerror();
    }
    else if (propValue.isLoaded())
    {
      this.setLoaded(true);
    }
    else
    {
      propValue.addEventListener("load", this._onload, this);
      propValue.addEventListener("error", this._onerror, this);
    }
  }
  else
  {
    // Remove from image manager
    qx.manager.object.ImageManager.getInstance().remove(this);

    this.setLoaded(false);
  }

  return true;
}

qx.Proto._modifyLoaded = function(propValue, propOldValue, propData)
{
  if (propValue && this.isCreated())
  {
    this._applyContent();
  }
  else if (!propValue)
  {
    this._invalidatePreferredInnerWidth();
    this._invalidatePreferredInnerHeight();
  }

  return true;
}

qx.Proto._modifyElement = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    if (!this._image)
    {
      try
      {
        // Create Image-Node
        // Webkit has problems with "new Image". Maybe related to "new Function" with
        // is also not working correctly.
        if (qx.sys.Client.getInstance().isWebkit())
        {
          this._image = document.createElement("img");
        }
        else
        {
          this._image = new Image;
        }

        // Possible alternative for MSHTML for PNG images
        // But it seems not to be faster
        // this._image = document.createElement("div");

        // this costs much performance, move setup to blank gif to error handling
        // is this SSL save?
        // this._image.src = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");

        this._image.style.border = "0 none";
        this._image.style.verticalAlign = "top";
      }
      catch(ex)
      {
        this.error("Failed while creating image #1", ex);
      }

      if (!qx.sys.Client.getInstance().isMshtml()) {
        this._applyEnabled();
      }
    }

    propValue.appendChild(this._image);
  }

  // call widget implmentation
  qx.ui.basic.Terminator.prototype._modifyElement.call(this, propValue, propOldValue, propData);

  if (propValue)
  {
    try
    {
      // initialisize preloader
      var vSource = this.getSource();
      if (qx.util.Validation.isValidString(vSource)) {
        this.setPreloader(qx.manager.object.ImagePreloaderManager.getInstance().create(qx.manager.object.AliasManager.getInstance().resolvePath(vSource)));
      }
    }
    catch(ex)
    {
      this.error("Failed while creating image #2", ex);
    }
  }

  return true;
}





/*
---------------------------------------------------------------------------
  CLIENT OPTIMIZED MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._postApply = function()
{
  if (!this.getLoaded()) {
    this._updateContent(qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif"));
    return;
  }

  this._postApplyDimensions();
  this._updateContent();
}

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
  {
    if (this._image) {
      this._applyEnabled();
    }

    return qx.ui.basic.Terminator.prototype._modifyEnabled.call(this, propValue, propOldValue, propData);
  }

  qx.Proto._updateContent = function(vSource)
  {
    var i = this._image;
    var pl = this.getPreloader();

    if (pl.getIsPng() && this.getEnabled())
    {
      i.src = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
      i.style.filter = "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='" + (vSource || pl.getSource()) + "',sizingMethod='scale')";
    }
    else
    {
      i.src = vSource || pl.getSource();
      i.style.filter = this.getEnabled() ? "" : "Gray() Alpha(Opacity=30)";
    }
  }

  qx.Proto._resetContent = function()
  {
    var i = this._image;

    i.src = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
    i.style.filter = "";
  }

  qx.Proto._applyEnabled = qx.Proto._postApply;
}
else
{
  qx.Proto._updateContent = function(vSource) {
    this._image.src = vSource || this.getPreloader().getSource();
  }

  qx.Proto._resetContent = function() {
    this._image.src = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
  }

  qx.Proto._applyEnabled = function()
  {
    if (this._image)
    {
      var o = this.getEnabled() ? "" : 0.3;
      var s = this._image.style;

      s.opacity = s.KhtmlOpacity = s.MozOpacity = o;
    }
  }

  qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
  {
    if (this._image) {
      this._applyEnabled();
    }

    return qx.ui.basic.Terminator.prototype._modifyEnabled.call(this, propValue, propOldValue, propData);
  }
}







/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS: INNER
---------------------------------------------------------------------------
*/

qx.Proto._computePreferredInnerWidth = function()
{
  if (this.getLoaded())
  {
    return this.getPreloader().getWidth();
  }
  else if (qx.util.Validation.isValidString(this.getSource()))
  {
    var vPreloader = qx.manager.object.ImagePreloaderManager.getInstance().get(qx.manager.object.AliasManager.getInstance().resolvePath(this.getSource()));

    if (vPreloader && vPreloader.isLoaded()) {
      return vPreloader.getWidth();
    }
  }

  return 0;
}

qx.Proto._computePreferredInnerHeight = function()
{
  if (this.getLoaded())
  {
    return this.getPreloader().getHeight();
  }
  else if (qx.util.Validation.isValidString(this.getSource()))
  {
    var vPreloader = qx.manager.object.ImagePreloaderManager.getInstance().get(qx.manager.object.AliasManager.getInstance().resolvePath(this.getSource()));

    if (vPreloader && vPreloader.isLoaded()) {
      return vPreloader.getHeight();
    }
  }

  return 0;
}







/*
---------------------------------------------------------------------------
  APPLY
---------------------------------------------------------------------------
*/

qx.Proto._applyContent = function()
{
  qx.ui.basic.Terminator.prototype._applyContent.call(this);

  // Images load asyncron, so we need to force flushing here
  // to get an up-to-date view when an image is loaded.
  qx.ui.core.Widget.flushGlobalQueues();
}

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._postApplyDimensions = function()
  {
    try
    {
      var vImageStyle = this._image.style;

      if (this.getResizeToInner())
      {
        vImageStyle.pixelWidth = this.getInnerWidth();
        vImageStyle.pixelHeight = this.getInnerHeight();
      }
      else
      {
        vImageStyle.pixelWidth = this.getPreferredInnerWidth();
        vImageStyle.pixelHeight = this.getPreferredInnerHeight();
      }
    }
    catch(ex)
    {
      this.error("postApplyDimensions failed", ex);
    }
  }
}
else
{
  qx.Proto._postApplyDimensions = function()
  {
    try
    {
      var vImageNode = this._image;

      if (this.getResizeToInner())
      {
        vImageNode.width = this.getInnerWidth();
        vImageNode.height = this.getInnerHeight();
      }
      else
      {
        vImageNode.width = this.getPreferredInnerWidth();
        vImageNode.height = this.getPreferredInnerHeight();
      }
    }
    catch(ex)
    {
      this.error("postApplyDimensions failed", ex);
    }
  }
}




/*
---------------------------------------------------------------------------
  CHANGES IN DIMENSIONS
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._changeInnerWidth = function(vNew, vOld)
  {
    if (this.getResizeToInner()) {
      this._image.style.pixelWidth = vNew;
    }
  }

  qx.Proto._changeInnerHeight = function(vNew, vOld)
  {
    if (this.getResizeToInner()) {
      this._image.style.pixelHeight = vNew;
    }
  }
}
else
{
  qx.Proto._changeInnerWidth = function(vNew, vOld)
  {
    if (this.getResizeToInner()) {
      this._image.width = vNew;
    }
  }

  qx.Proto._changeInnerHeight = function(vNew, vOld)
  {
    if (this.getResizeToInner()) {
      this._image.height = vNew;
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
    return true;
  }

  var vPreloader = this.getPreloader();
  if (vPreloader)
  {
    // remove event connection
    vPreloader.removeEventListener("load", this._onload, this);
    vPreloader.removeEventListener("error", this._onerror, this);

    this.forcePreloader(null);
  }

  if (this._image)
  {
    // Remove leaking filter attribute before leaving page
    this._image.style.filter = "";
    this._image = null;
  }

  qx.manager.object.ImageManager.getInstance().remove(this);

  return qx.ui.basic.Terminator.prototype.dispose.call(this);
}
