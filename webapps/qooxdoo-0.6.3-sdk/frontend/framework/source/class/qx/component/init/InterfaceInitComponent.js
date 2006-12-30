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

qx.OO.defineClass("qx.component.init.InterfaceInitComponent", qx.component.init.BasicInitComponent,
function() {
  qx.component.init.BasicInitComponent.call(this);
});





/*
---------------------------------------------------------------------------
  READY STATE
---------------------------------------------------------------------------
*/

qx.Proto._uiReady = false;

qx.Proto.isUiReady = function() {
  return this._uiReady;
}






/*
---------------------------------------------------------------------------
  STATE MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto.initialize = function()
{
  // Force creation of event handler
  qx.event.handler.EventHandler.getInstance();

  // Force creation of client document
  qx.ui.core.ClientDocument.getInstance();

  // Start real initialisation
  var start = (new Date).valueOf();
  qx.component.init.BasicInitComponent.prototype.initialize.call(this);
  this.info("initialize runtime: " + ((new Date).valueOf() - start) + "ms");
};

qx.Proto.main = function()
{
  // Start real main process
  var start = (new Date).valueOf();
  qx.component.init.BasicInitComponent.prototype.main.call(this);
  this.info("main runtime: " + ((new Date).valueOf() - start) + "ms");

  this.debug("preloading visible images...");
  new qx.io.image.PreloaderSystem(qx.manager.object.ImageManager.getInstance().getPreloadImageList(), this.finalize, this);
};


qx.Proto.finalize = function()
{
  var start = (new Date).valueOf();

  this._printPreloadComplete();
  this._uiReady = true;

  // Show initial widgets
  qx.ui.core.Widget.flushGlobalQueues();

  // Finally attach event to make the GUI ready for the user
  qx.event.handler.EventHandler.getInstance().attachEvents();

  qx.component.init.BasicInitComponent.prototype.finalize.call(this);

  this.info("finalize runtime: " + ((new Date).valueOf() - start) + "ms");
};

qx.Proto.close = function()
{
  var start = (new Date).valueOf();
  qx.component.init.BasicInitComponent.prototype.close.call(this);

  this.info("close runtime: " + ((new Date).valueOf() - start) + "ms");
};

qx.Proto.terminate = function()
{
  var start = (new Date).valueOf();
  qx.component.init.BasicInitComponent.prototype.terminate.call(this);

  this.info("terminate runtime: " + ((new Date).valueOf() - start) + "ms");
};





/*
---------------------------------------------------------------------------
  PRELOAD UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.preload = function()
{
  if (!this._preloadDone)
  {
    this.debug("preloading hidden images...");
    new qx.io.image.PreloaderSystem(qx.manager.object.ImageManager.getInstance().getPostPreloadImageList(), this._printPreloadComplete, this);
    this._preloadDone = true;
  }
}

qx.Proto._printPreloadComplete = function() {
  this.debug("preloading complete");
}






/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onload = function(e)
{
  this.initialize();
  this.main();

  // Note: finalize will be called through image preloader
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

  this._preloadDone = null;
  this._uiReady = null;

  return qx.component.init.BasicInitComponent.prototype.dispose.call(this);
}
