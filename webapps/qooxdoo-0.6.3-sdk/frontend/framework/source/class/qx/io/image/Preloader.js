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

/**
 * This is the preloader used from qx.ui.basic.Image instances.
 *
 * @event load {qx.event.type.Event}
 * @event error {qx.event.type.Event}
 */
qx.OO.defineClass("qx.io.image.Preloader", qx.core.Target,
function(vSource)
{
  if(qx.manager.object.ImagePreloaderManager.getInstance().has(vSource))
  {
    this.debug("Reuse qx.io.image.Preloader in old-style!");
    this.debug("Please use qx.manager.object.ImagePreloaderManager.getInstance().create(source) instead!");

    return qx.manager.object.ImagePreloaderManager.getInstance().get(vSource);
  }

  qx.core.Target.call(this);

  // Create Image-Node
  // Does not work with document.createElement("img") in Webkit. Interesting.
  // Compare this to the bug in qx.ui.basic.Image.
  this._element = new Image;

  // This is needed for wrapping event to the object
  this._element.qx_ImagePreloader = this;

  // Define handler if image events occurs
  if (qx.sys.Client.getInstance().isWebkit())
  {
    // Webkit as of version 41xxx
    // does not get the target right. We need to help out a bit
    // ugly closure!
    var self = this;
    this._element.onload = function(e) {
      return self._onload(e);
    };
    this._element.onerror = function(e) {
      return self._onerror(e);
    };
  }
  else
  {
    this._element.onload = qx.io.image.Preloader.__onload;
    this._element.onerror = qx.io.image.Preloader.__onerror;
  }

  // Set Source
  this._source = vSource;
  this._element.src = vSource;

  // Set PNG State
  if (qx.sys.Client.getInstance().isMshtml()) {
    this._isPng = /\.png$/i.test(this._element.nameProp);
  }

  qx.manager.object.ImagePreloaderManager.getInstance().add(this);
});




/*
---------------------------------------------------------------------------
  STATE MANAGERS
---------------------------------------------------------------------------
*/

qx.Proto._source = null;
qx.Proto._isLoaded = false;
qx.Proto._isErroneous = false;





/*
---------------------------------------------------------------------------
  CROSSBROWSER GETTERS
---------------------------------------------------------------------------
*/

qx.Proto.getUri = function() { return this._source; };
qx.Proto.getSource = function() { return this._source; };
qx.Proto.isLoaded = function() { return this._isLoaded; };
qx.Proto.isErroneous = function() { return this._isErroneous; };

// only used in mshtml: true when the image format is in png
qx.Proto._isPng = false;
qx.Proto.getIsPng = function() { return this._isPng; };

if(qx.sys.Client.getInstance().isGecko())
{
  qx.Proto.getWidth = function() { return this._element.naturalWidth; };
  qx.Proto.getHeight = function() { return this._element.naturalHeight; };
}
else
{
  qx.Proto.getWidth = function() { return this._element.width; };
  qx.Proto.getHeight = function() { return this._element.height; };
}





/*
---------------------------------------------------------------------------
  EVENT MAPPING
---------------------------------------------------------------------------
*/

qx.io.image.Preloader.__onload = function(e) { this.qx_ImagePreloader._onload(); };
qx.io.image.Preloader.__onerror = function(e) { this.qx_ImagePreloader._onerror(); };

qx.Proto._onload = function()
{
  if (this._isLoaded || this._isErroneous) {
    return;
  }

  this._isLoaded = true;
  this._isErroneous = false;

  if (this.hasEventListeners("load")) {
    this.dispatchEvent(new qx.event.type.Event("load"), true);
  }
}

qx.Proto._onerror = function()
{
  if (this._isLoaded || this._isErroneous) {
    return;
  }

  this.debug("Could not load: " + this._source);

  this._isLoaded = false;
  this._isErroneous = true;

  if (this.hasEventListeners("error")) {
    this.dispatchEvent(new qx.event.type.Event("error"), true);
  }
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

  if (this._element)
  {
    this._element.onload = this._element.onerror = null;
    this._element.qx_ImagePreloader = null;
    this._element = null;
  }

  this._isLoaded = this._isErroneous = this._isPng = false;

  return qx.core.Target.prototype.dispose.call(this);
}
