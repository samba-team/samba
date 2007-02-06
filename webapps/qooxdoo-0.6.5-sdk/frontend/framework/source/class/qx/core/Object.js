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

#module(core)
#load(qx.core.Init)
#resource(static:static)

************************************************************************ */

/**
 * The qooxdoo root class. All other classes are direct or indirect subclasses of this one.
 *
 * This class contains methods for:
 * <ul>
 *   <li> object management (creation and destruction) </li>
 *   <li> logging & debugging </li>
 *   <li> generic getter/setter </li>
 *   <li> user data </li>
 *   <li> settings </li>
 *   <li> internationalization </li>
 * </ul>
 *
 * @param vAutoDispose {Boolean ? true} whether the object should be automatically disposed
 */
qx.OO.defineClass("qx.core.Object", Object,
function(vAutoDispose)
{
  this._hashCode = qx.core.Object._availableHashCode++;

  if (vAutoDispose !== false)
  {
    this._dbKey = qx.core.Object._db.length;
    qx.core.Object._db.push(this);
  }
});


/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("enableDisposerDebug", false);





/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

qx.Class._availableHashCode = 0;
qx.Class._db = [];
qx.Class._disposeAll = false;


/**
 * Returns an unique identifier for the given object. If such an identifier
 * does not yet exist, create it.
 *
 * @param o {Object} the Object to get the hashcode for
 * @return {Integer} unique identifier for the given object
 */
qx.Class.toHashCode = function(o)
{
  if(o._hashCode != null) {
    return o._hashCode;
  }

  return o._hashCode = qx.core.Object._availableHashCode++;
}


/**
 * Destructor. This method is called by qooxdoo on object destruction.
 *
 * Any class that holds resources like links to DOM nodes must overwrite
 * this method and free these resources.
 */
qx.Class.dispose = function()
{
  // var logger = qx.log.Logger.getClassLogger(qx.core.Object);
  // logger.debug("Disposing Application");

  // var vStart = (new Date).valueOf();
  qx.core.Object._disposeAll = true;
  var vObject;

  for (var i=qx.core.Object._db.length-1; i>=0; i--)
  {
    vObject = qx.core.Object._db[i];

    if (vObject && vObject._disposed === false)
    {
      // logger.debug("Disposing: " + vObject);
      vObject.dispose();
    }
  }

  // logger.debug("Done in: " + ((new Date).valueOf() - vStart) + "ms");
}


/**
 * Summary of allocated objects
 *
 * @return {String} summary of allocated objects.
 */
qx.Class.summary = function()
{
  var vData = {};
  var vCounter = 0;
  var vObject;

  for (var i=qx.core.Object._db.length-1; i>=0; i--)
  {
    vObject = qx.core.Object._db[i];

    if (vObject && vObject._disposed === false)
    {
      if (vData[vObject.classname] == null)
      {
        vData[vObject.classname] = 1;
      }
      else
      {
        vData[vObject.classname]++;
      }

      vCounter++;
    }
  }

  var vArrData = [];

  for (var vClassName in vData) {
    vArrData.push({ classname : vClassName, number : vData[vClassName] });
  }

  vArrData.sort(function(a, b) {
    return b.number - a.number;
  });

  var vMsg = "Summary: (" + vCounter + " Objects)\n\n";

  for (var i=0; i<vArrData.length; i++) {
    vMsg += vArrData[i].number + ": " + vArrData[i].classname + "\n";
  }

  alert(vMsg);
};

/**
 * Enable or disable the Object.
 *
 * The actual semantic of this property depends on concrete subclass of qx.core.Object.
 */
qx.OO.addProperty({ name : "enabled", type : "boolean", defaultValue : true, getAlias : "isEnabled" });






/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

/**
 * Returns a string represantation of the qooxdoo object.
 *
 * @return {String} string representation of the object
 */
qx.Proto.toString = function()
{
  if(this.classname) {
    return "[object " + this.classname + "]";
  }

  return "[object Object]";
}


/**
 * Return unique hash code of object
 *
 * @return {Integer} unique hash code of the object
 */
qx.Proto.toHashCode = function() {
  return this._hashCode;
}


/**
 * Returns true if the object is disposed.
 *
 * @return {Boolean} wether the object has been disposed
 */
qx.Proto.getDisposed = function() {
  return this._disposed;
}


/**
 * Returns true if the object is disposed.
 *
 * @return {Boolean} wether the object has been disposed
 */
qx.Proto.isDisposed = function() {
  return this._disposed;
}


/**
 * Returns a settings from global setting definition
 *
 * @param vKey {String} the key
 * @return {Object} value of the global setting
 */
qx.Proto.getSetting = function(vKey) {
  return qx.Settings.getValueOfClass(this.classname, vKey);
}


/*
---------------------------------------------------------------------------
  I18N INTERFACE
---------------------------------------------------------------------------
*/

/**
 * Translate a message
 * Mark the message for translation.
 * @see qx.lang.String.format
 *
 * @param messageId {String} message id (may contain format strings)
 * @param varargs {Object} variable number of argumes applied to the format string
 * @return {qx.locale.LocalizedString}
 */
qx.Proto.tr = function(messageId, varargs) {
  var nlsManager = qx.locale.Manager;
  return nlsManager.tr.apply(nlsManager, arguments);
};


/**
 * Translate a plural message
 * Mark the messages for translation.
 *
 * Depending on the third argument the plursl or the singular form is chosen.
 *
 * @see qx.lang.String.format
 *
 * @param singularMessageId {String} message id of the singular form (may contain format strings)
 * @param pluralMessageId {String} message id of the plural form (may contain format strings)
 * @param count {Integer} if greater than 1 the plural form otherwhise the singular form is returned.
 * @param varargs {Object} variable number of argumes applied to the format string
 * @return {qx.locale.LocalizedString)
 */
qx.Proto.trn = function(singularMessageId, pluralMessageId, count, varargs) {
  var nlsManager = qx.locale.Manager;
  return nlsManager.trn.apply(nlsManager, arguments);
};


/**
 * Mark the message for translation but return the original message.
 *
 * @param messageId {String} the message ID
 * @return {String} messageId
 */
qx.Proto.marktr = function(messageId) {
  var nlsManager = qx.locale.Manager;
  return nlsManager.marktr.apply(nlsManager, arguments);
};

/*
---------------------------------------------------------------------------
  LOGGING INTERFACE
---------------------------------------------------------------------------
*/

/**
 * Returns the logger of this class.
 *
 * @return {qx.log.Logger} the logger of this class.
 */
qx.Proto.getLogger = function() {
  return qx.log.Logger.getClassLogger(this.constructor);
}


/**
 * Logs a debug message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *        object dump will be logged.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.debug = function(msg, exc) {
  this.getLogger().debug(msg, this._hashCode, exc);
}


/**
 * Logs an info message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.info = function(msg, exc) {
  this.getLogger().info(msg, this._hashCode, exc);
}


/**
 * Logs a warning message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.warn = function(msg, exc) {
  this.getLogger().warn(msg, this._hashCode, exc);
}


/**
 * Logs an error message.
 *
 * @param msg {var} the message to log. If this is not a string, the
 *    object dump will be logged.
 * @param exc {var ? null} the exception to log.
 */
qx.Proto.error = function(msg, exc) {
  this.getLogger().error(msg, this._hashCode, exc);
}




/*
---------------------------------------------------------------------------
  COMMON SETTER/GETTER SUPPORT
---------------------------------------------------------------------------
*/

/**
 * Sets multiple properties at once by using a property list
 *
 * @param propertyValues {Object} A hash of key-value pairs.
 */
qx.Proto.set = function(propertyValues)
{
  if (typeof propertyValues !== "object") {
    throw new Error("Please use a valid hash of property key-values pairs.");
  }

  for (var prop in propertyValues)
  {
    try
    {
      this[qx.OO.setter[prop]](propertyValues[prop]);
    }
    catch(ex)
    {
      this.error("Setter of property '" + prop + "' returned with an error", ex);
    }
  }

  return this;
}

/**
 * Gets multiple properties at once by using a property list
 *
 * @param propertyNames {String | Array | Map} list of the properties to get
 * @param outputHint {String ? "array"} how should the values be returned. Possible values are "hash" and "array".
*/
qx.Proto.get = function(propertyNames, outputHint)
{
  switch(typeof propertyNames)
  {
    case "string":
      return this["get" + qx.lang.String.toFirstUp(propertyNames)]();

    case "object":
      if (typeof propertyNames.length === "number")
      {
        if (outputHint == "hash")
        {
          var h = {};

          propertyLength = propertyNames.length;
          for (var i=0; i<propertyLength; i++)
          {
            try{
              h[propertyNames[i]] = this["get" + qx.lang.String.toFirstUp(propertyNames[i])]();
            }
            catch(ex)
            {
              throw new Error("Could not get a valid value from property: " + propertyNames[i] + "! Is the property existing? (" + ex + ")");
            }
          }

          return h;
        }
        else
        {
          propertyLength = propertyNames.length;
          for (var i=0; i<propertyLength; i++)
          {
            try{
              propertyNames[i] = this["get" + qx.lang.String.toFirstUp(propertyNames[i])]();
            }
            catch(ex)
            {
              throw new Error("Could not get a valid value from property: " + propertyNames[i] + "! Is the property existing? (" + ex + ")");
            }
          }

          return propertyNames;
        }
      }
      else
      {
        for (var i in propertyNames) {
          propertyNames[i] = this["get" + qx.lang.String.toFirstUp(i)]();
        }

        return propertyNames;
      }

    default:
      throw new Error("Please use a valid array, hash or string as parameter!");
  }
}





/*
---------------------------------------------------------------------------
  USER DATA
---------------------------------------------------------------------------
*/

/**
 * Store user defined data inside the object.
 *
 * @param vKey {String} the key
 * @param vValue {Object} the value of the user data
 */
qx.Proto.setUserData = function(vKey, vValue)
{
  if (!this._userData) {
    this._userData = {};
  }

  this._userData[vKey] = vValue;
}


/**
 * Load user defined data from the object
 *
 * @param vKey {String} the key
 * @return {Object} the user data
 */
qx.Proto.getUserData = function(vKey)
{
  if (!this._userData) {
    return null;
  }

  return this._userData[vKey];
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto._disposed = false;

/**
 * Dispose this object
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  // Dispose user data
  if (this._userData)
  {
    for(var vKey in this._userData) {
      this._userData[vKey] = null;
    }

    this._userData = null;
  }

  // Finally cleanup properties
  if (this._objectproperties)
  {
    var a = this._objectproperties.split(",");
    var d = qx.OO.values;

    for (var i=0, l=a.length; i<l; i++) {
      this[d[a[i]]] = null;
    }

    this._objectproperties = null;
  }

  if (this.getSetting("enableDisposerDebug"))
  {
    for (var vKey in this)
    {
      if (this[vKey] !== null && typeof this[vKey] === "object")
      {
        this.debug("Missing class implementation to dispose: " + vKey);
        delete this[vKey];
      }
    }
  }

  /*
  if (typeof CollectGarbage === "function") {
    CollectGarbage();
  }
  */

  /*
  // see bug #258.
  if(this._dbKey != this._hashCode) {
    console.log("Disposing wrong entry: " + this._dbKey + " vs. " + this._hashCode);
  }
  */

  // Delete Entry from Object DB
  if (this._dbKey != null)
  {
    if (qx.core.Object._disposeAll)
    {
      qx.core.Object._db[this._dbKey] = null;
      this._hashCode = null;
      this._dbKey = null;
    }
    else
    {
      delete qx.core.Object._db[this._dbKey];
      delete this._hashCode;
      delete this._dbKey;
    }
  }

  // Mark as disposed
  this._disposed = true;
}
