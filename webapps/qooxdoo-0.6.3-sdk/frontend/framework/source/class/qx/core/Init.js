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

#module(core)
#require(qx.dom.EventRegistration)
#optional(qx.component.init.InterfaceInitComponent)

************************************************************************ */

/**
 * Initialize qooxdoo.
 *
 * Attaches qooxdoo callbacks to the load events (onload, onunload, onbeforeunload)
 * and initializes the qooxdoo application. The initializations starts automatically.
 *
 * Make shure you set the application to your application before the load event is fired:
 * <pre>qx.core.Init.getInstance().setApplication(YourApplication)</pre>
 */
qx.OO.defineClass("qx.core.Init", qx.core.Target,
function()
{
  qx.core.Target.call(this, false);

  // Object Wrapper to Events (Needed for DOM-Events)
  var o = this;

  /**
   * private
   * @param e {Object}
   */
  this.__onload = function(e) { return o._onload(e); }
  /**
   * private
   * @param e {Object}
   */
  this.__onbeforeunload = function(e) { return o._onbeforeunload(e); }
  /**
   * private
   * @param e {Object}
   */
  this.__onunload = function(e) { return o._onunload(e); }

  // Attach events
  qx.dom.EventRegistration.addEventListener(window, "load", this.__onload);
  qx.dom.EventRegistration.addEventListener(window, "beforeunload", this.__onbeforeunload);
  qx.dom.EventRegistration.addEventListener(window, "unload", this.__onunload);
});





/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("component", "qx.component.init.InterfaceInitComponent");






/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/**
 * Instance of the component initializer.
 */
qx.OO.addProperty({ name : "component", type : "object", instance : "qx.component.init.BasicInitComponent" });

/**
 * Reference to the constructor of the main application.
 *
 * Set this before the onload event is fired.
 */
qx.OO.addProperty({ name : "application", type : "function" });







/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyApplication = function(propValue, propOldValue, propData)
{
  if (propValue) {
    this._applicationInstance = new propValue;
  }

  return true;
};






/*
---------------------------------------------------------------------------
  INTERNAL PROPERTIES
---------------------------------------------------------------------------
*/

/**
 * Rreturns an instance of the current qooxdoo Application
 *
 * @return {qx.component.AbstractApplication} instance of the current qooxdoo application
 */
qx.Proto.getApplicationInstance = function()
{
  if (!this.getApplication()) {
    this.setApplication(qx.component.DummyApplication);
  }

  return this._applicationInstance;
};






/*
---------------------------------------------------------------------------
  COMPONENT BINDING
---------------------------------------------------------------------------
*/

/**
 * define the initialisation function
 * Don't use this method directly. Use setApplication instead!
 *
 * @param vFunc {Function} callback function
 */
qx.Proto.defineInitialize = function(vFunc) {
  this.getApplicationInstance().initialize = vFunc;
}

/**
 * define the main function
 * Don't use this method directly. Use setApplication instead!
 *
 * @param vFunc {Function} callback function
 */
qx.Proto.defineMain = function(vFunc) {
  this.getApplicationInstance().main = vFunc;
}

/**
 * define the finalize function
 * Don't use this method directly. Use setApplication instead!
 *
 * @param vFunc {Function} callback function
 */
qx.Proto.defineFinalize = function(vFunc) {
  this.getApplicationInstance().finalize = vFunc;
}

/**
 * define the close function
 * Don't use this method directly. Use setApplication instead!
 *
 * @param vFunc {Function} callback function
 */
qx.Proto.defineClose = function(vFunc) {
  this.getApplicationInstance().close = vFunc;
}

/**
 * define the terminate function
 * Don't use this method directly. Use setApplication instead!
 *
 * @param vFunc {Function} callback function
 */
qx.Proto.defineTerminate = function(vFunc) {
  this.getApplicationInstance().terminate = vFunc;
}







/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

/**
 * load event handler
 *
 * @param e {Object}
 */
qx.Proto._onload = function(e)
{
  this.debug("qooxdoo " + qx.core.Version.toString());

  // Print out class information
  this.debug("loaded " + qx.lang.Object.getLength(qx.OO.classes) + " classes");

  // Print browser information
  var cl = qx.sys.Client.getInstance();
  this.debug("client: " + cl.getEngine() + "-" + cl.getMajor() + "."
    + cl.getMinor() + "/" + cl.getPlatform() + "/" + cl.getLocale());

  if (cl.isMshtml() && !cl.isInQuirksMode()) {
    this.warn("Wrong box sizing: Please modify the document's DOCTYPE!");
  }

  // Init component from settings
  this.setComponent(new qx.OO.classes[this.getSetting("component")](this));

  // Send onload
  return this.getComponent()._onload(e);
}


/**
 * beforeunload event handler
 *
 * @param e {Object}
 */
qx.Proto._onbeforeunload = function(e)
{
  // Send onbeforeunload event (can be cancelled)
  return this.getComponent()._onbeforeunload(e);
}


/**
 * unload event handler
 *
 * @param e {Object}
 */
qx.Proto._onunload = function(e)
{
  // Send onunload event (last event)
  this.getComponent()._onunload(e);

  // Dispose all qooxdoo objects
  qx.core.Object.dispose();
}







/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

/**
 * Destructor
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  // Detach Events
  qx.dom.EventRegistration.removeEventListener(window, "load", this.__onload);
  qx.dom.EventRegistration.removeEventListener(window, "beforeunload", this.__onbeforeunload);
  qx.dom.EventRegistration.removeEventListener(window, "unload", this.__onunload);

  // Reset inline functions
  this.__onload = this.__onbeforeunload = this.__onunload = null;

  if (this._applicationInstance) {
    this._applicationInstance.dispose();
    this._applicationInstance = null;
  }

  qx.core.Target.prototype.dispose.call(this);
}




/*
---------------------------------------------------------------------------
  DIRECT SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;

// Force direct creation
qx.Class.getInstance();
