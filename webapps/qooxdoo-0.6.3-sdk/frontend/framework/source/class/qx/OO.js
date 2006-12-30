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

#id(qx.OO)
#module(core)
#after(qx.Settings)
#load(qx.lang.Core)
#load(qx.util.Return)
#optional(qx.event.type.DataEvent)

************************************************************************ */

// Usage of this hacky construct to make qx.OO available inside the API viewer
qx.OO = {};
qx.OO.defineClass = function() {};
qx.Class = qx.OO;
qx.OO.defineClass("qx.OO");

qx.Class.classes = {};
qx.Class.setter = {};
qx.Class.getter = {};
qx.Class.resetter = {};
qx.Class.values = {};
qx.Class.propertyNumber = 0;




/*
---------------------------------------------------------------------------
  DEFINE CLASS IMPLEMENTATION
---------------------------------------------------------------------------
*/

/**
 * define a new qooxdoo class
 * All classes should be defined in this way.
 *
 * @param vClassName {string} fully qualified class name (e.g. "qx.ui.form.Button")
 * @param vSuper {Object} super class
 * @param vConstructor {Function} the constructor of the new class
 */
qx.Class.defineClass = function(vClassName, vSuper, vConstructor)
{
  var vSplitName = vClassName.split(".");
  var vNameLength = vSplitName.length-1;
  var vTempObject = window;

  // Setting up namespace
  for (var i=0; i<vNameLength; i++)
  {
    if (typeof vTempObject[vSplitName[i]] === "undefined") {
      vTempObject[vSplitName[i]] = {};
    }

    vTempObject = vTempObject[vSplitName[i]];
  }

  // Instantiate objects/inheritance
  if (typeof vSuper === "undefined")
  {
    if (typeof vConstructor !== "undefined") {
      throw new Error("SuperClass is undefined, but constructor was given for class: " + vClassName);
    }

    qx.Class = vTempObject[vSplitName[i]] = {};
    qx.Proto = null;
    qx.Super = null;
  }
  else if (typeof vConstructor === "undefined")
  {
    qx.Class = vTempObject[vSplitName[i]] = vSuper;
    qx.Proto = null;
    qx.Super = vSuper;
  }
  else
  {
    qx.Class = vTempObject[vSplitName[i]] = vConstructor;

    // build helper function
    // this omits the initial constructor call while inherit properties
    var vHelperConstructor = function() {};
    vHelperConstructor.prototype = vSuper.prototype;
    qx.Proto = vConstructor.prototype = new vHelperConstructor;

    qx.Super = vConstructor.superclass = vSuper;

    qx.Proto.classname = vConstructor.classname = vClassName;
    qx.Proto.constructor = vConstructor;
  }

  // Store reference to global classname registry
  qx.OO.classes[vClassName] = qx.Class;
}






/*
---------------------------------------------------------------------------
  OBJECT PROPERTY EXTENSION
---------------------------------------------------------------------------
*/

qx.Class.addFastProperty = function(vConfig)
{
  var vName = vConfig.name;
  var vUpName = qx.lang.String.toFirstUp(vName);

  var vStorageField = "_value" + vUpName;
  var vGetterName = "get" + vUpName;
  var vSetterName = "set" + vUpName;
  var vComputerName = "_compute" + vUpName;

  qx.Proto[vStorageField] = typeof vConfig.defaultValue !== "undefined" ? vConfig.defaultValue : null;

  if (vConfig.noCompute)
  {
    qx.Proto[vGetterName] = function() {
      return this[vStorageField];
    }
  }
  else
  {
    qx.Proto[vGetterName] = function() {
      return this[vStorageField] == null ? this[vStorageField] = this[vComputerName]() : this[vStorageField];
    }
  }

  if (vConfig.setOnlyOnce)
  {
    qx.Proto[vSetterName] = function(vValue)
    {
      this[vStorageField] = vValue;
      this[vSetterName] = null;

      return vValue;
    }
  }
  else
  {
    qx.Proto[vSetterName] = function(vValue) {
      return this[vStorageField] = vValue;
    }
  }

  if (!vConfig.noCompute)
  {
    qx.Proto[vComputerName] = function() {
      return null;
    }
  }
}

qx.OO.addCachedProperty = function(p)
{
  var vName = p.name;
  var vUpName = qx.lang.String.toFirstUp(vName);

  var vStorageField = "_cached" + vUpName;
  var vComputerName = "_compute" + vUpName;
  var vChangeName = "_change" + vUpName;

  if (typeof p.defaultValue !== "undefined") {
    qx.Proto[vStorageField] = p.defaultValue;
  }

  qx.Proto["get" + vUpName] = function()
  {
    if (this[vStorageField] == null) {
      this[vStorageField] = this[vComputerName]();
    }

    return this[vStorageField];
  }

  qx.Proto["_invalidate" + vUpName] = function()
  {
    if (this[vStorageField] != null)
    {
      this[vStorageField] = null;

      if (p.addToQueueRuntime) {
        this.addToQueueRuntime(p.name);
      }
    }
  }

  qx.Proto["_recompute" + vUpName] = function()
  {
    var vOld = this[vStorageField];
    var vNew = this[vComputerName]();

    if (vNew != vOld)
    {
      this[vStorageField] = vNew;
      this[vChangeName](vNew, vOld);

      return true;
    }

    return false;
  }

  qx.Proto[vChangeName] = function(vNew, vOld) {};
  qx.Proto[vComputerName] = function() { return null; };
}

qx.Class.addPropertyGroup = function(p)
{
  /* --------------------------------------------------------------------------------
      PRE-CHECKS
  -------------------------------------------------------------------------------- */
  if(typeof p !== "object") {
    throw new Error("Param should be an object!");
  }

  if (qx.util.Validation.isInvalid(p.name)) {
    throw new Error("Malformed input parameters: name needed!");
  }

  if (qx.util.Validation.isInvalid(p.members)) {
    throw new Error("Malformed input parameters: members needed!");
  }

  p.method = qx.lang.String.toFirstUp(p.name);


  /* --------------------------------------------------------------------------------
      CACHING
  -------------------------------------------------------------------------------- */
  p.getter = [];
  p.setter = [];

  for (var i=0, l=p.members.length; i<l; i++) {
    p.setter.push("set" + qx.lang.String.toFirstUp(p.members[i]));
  }

  for (var i=0, l=p.members.length; i<l; i++) {
    p.getter.push("get" + qx.lang.String.toFirstUp(p.members[i]));
  }


  /* --------------------------------------------------------------------------------
      GETTER
  -------------------------------------------------------------------------------- */
  qx.Proto["get" + p.method] = function()
  {
    var a = [];
    var g = p.getter;

    for (var i=0, l=g.length; i<l; i++) {
      a.push(this[g[i]]());
    }

    return a;
  };


  /* --------------------------------------------------------------------------------
      SETTER
  -------------------------------------------------------------------------------- */
  switch(p.mode)
  {
    case "shorthand":
      qx.Proto["set" + p.method] = function()
      {
        if (arguments.length > 4 || arguments.length == 0) {
          throw new Error("Invalid number of arguments for property " + p.name + ": " + arguments);
        }

        try
        {
          var ret = qx.lang.Array.fromShortHand(arguments);
        }
        catch(ex)
        {
          throw new Error("Invalid shorthand values for property " + p.name + ": " + arguments + ": " + ex);
        }

        var s = p.setter;
        var l = s.length;

        for (var i=0; i<l; i++) {
          this[s[i]](ret[i]);
        }
      };
      break;

    default:
      qx.Proto["set" + p.method] = function()
      {
        var s = p.setter;
        var l = s.length;

        if (arguments.length != l) {
          throw new Error("Invalid number of arguments (needs: " + l + ", is: " + arguments.length + ") for property " + p.name + ": " + qx.lang.Array.fromArguments(arguments).toString());
        }

        for (var i=0; i<l; i++) {
          this[s[i]](arguments[i]);
        }
      };
  }
}

qx.Class.removeProperty = function(p)
{
  if (typeof qx.Proto._properties !== "string") {
    throw new Error("Has no properties!");
  }

  if(typeof p !== "object") {
    throw new Error("Param should be an object!");
  }

  if (qx.util.Validation.isInvalid(p.name)) {
    throw new Error("Malformed input parameters: name needed!");
  }

  // building shorter prototype access
  var pp = qx.Proto;

  p.method = qx.lang.String.toFirstUp(p.name);
  p.implMethod = p.impl ? qx.lang.String.toFirstUp(p.impl) : p.method;

  var valueKey = "_value" + p.method;

  // Remove property from list
  pp._properties = qx.lang.String.remove(pp._properties, p.name);

  // Reset default value to null
  pp[valueKey] = null;

  // Reset methods
  pp["get" + p.method] = null;
  pp["set" + p.method] = null;
  pp["reset" + p.method] = null;
  pp["apply" + p.method] = null;
  pp["force" + p.method] = null;
  pp["getDefault" + p.method] = null;
  pp["setDefault" + p.method] = null;
}

qx.Class._createProperty = function(p)
{
  if(typeof p !== "object") {
    throw new Error("AddProperty: Param should be an object!");
  }

  if (qx.util.Validation.isInvalid(p.name)) {
    throw new Error("AddProperty: Malformed input parameters: name needed!");
  }

  // building shorter prototype access
  var pp = qx.Proto;

  p.method = qx.lang.String.toFirstUp(p.name);
  p.implMethod = p.impl ? qx.lang.String.toFirstUp(p.impl) : p.method;

  if (p.defaultValue == undefined) {
    p.defaultValue = null;
  }

  if (qx.util.Validation.isInvalidBoolean(p.allowNull)) {
    p.allowNull = true;
  }

  if (qx.util.Validation.isInvalidBoolean(p.allowMultipleArguments)) {
    p.allowMultipleArguments = false;
  }






  if (typeof p.type === "string") {
    p.hasType = true;
  }
  else if (typeof p.type !== "undefined") {
    throw new Error("AddProperty: Invalid type definition for property " + p.name + ": " + p.type);
  }
  else {
    p.hasType = false;
  }

  if (typeof p.instance === "string") {
    p.hasInstance = true;
  }
  else if (typeof p.instance !== "undefined") {
    throw new Error("AddProperty: Invalid instance definition for property " + p.name + ": " + p.instance);
  }
  else {
    p.hasInstance = false;
  }

  if (typeof p.classname === "string") {
    p.hasClassName = true;
  }
  else if (typeof p.classname !== "undefined") {
    throw new Error("AddProperty: Invalid classname definition for property " + p.name + ": " + p.classname);
  }
  else {
    p.hasClassName = false;
  }






  p.hasConvert = qx.util.Validation.isValidFunction(p.convert);
  p.hasPossibleValues = qx.util.Validation.isValidArray(p.possibleValues);
  p.hasUnitDetection = qx.util.Validation.isValidString(p.unitDetection);

  p.addToQueue = p.addToQueue || false;
  p.addToQueueRuntime = p.addToQueueRuntime || false;

  // upper-case name
  p.up = p.name.toUpperCase();

  // register global uppercase name
  qx.OO["PROPERTY_" + p.up] = p.name;

  var valueKey = "_value" + p.method;
  var evalKey = "_eval" + p.method;
  var changeKey = "change" + p.method;
  var modifyKey = "_modify" + p.implMethod;
  var checkKey = "_check" + p.implMethod;

  if (!qx.OO.setter[p.name])
  {
    qx.OO.setter[p.name] = "set" + p.method;
    qx.OO.getter[p.name] = "get" + p.method;
    qx.OO.resetter[p.name] = "reset" + p.method;
    qx.OO.values[p.name] = valueKey;
  }

  // unit detection support
  if (p.hasUnitDetection)
  {
    // computed unit
    var cu = "_computed" + p.method;
    pp[cu + "Value"] = null;
    pp[cu + "Parsed"] = null;
    pp[cu + "Type"] = null;
    pp[cu + "TypeNull"] = true;
    pp[cu + "TypePixel"] = false;
    pp[cu + "TypePercent"] = false;
    pp[cu + "TypeAuto"] = false;
    pp[cu + "TypeFlex"] = false;

    var unitDetectionKey = "_unitDetection" + qx.lang.String.toFirstUp(p.unitDetection);
  }

  // apply default value
  pp[valueKey] = p.defaultValue;

  // building getFoo(): Returns current stored value
  pp["get" + p.method] = function() {
    return this[valueKey];
  };

  // building forceFoo(): Set (override) without do anything else
  pp["force" + p.method] = function(newValue) {
    return this[valueKey] = newValue;
  };

  // building resetFoo(): Reset value to default value
  pp["reset" + p.method] = function() {
    return this["set" + p.method](p.defaultValue);
  };

  // building toggleFoo(): Switching between two boolean values
  if (p.type === "boolean")
  {
    pp["toggle" + p.method] = function(newValue) {
      return this["set" + p.method](!this[valueKey]);
    };
  }

  if (p.allowMultipleArguments || p.hasConvert || p.hasInstance || p.hasClassName || p.hasPossibleValues || p.hasUnitDetection || p.addToQueue || p.addToQueueRuntime || p.addToStateQueue)
  {
    // building setFoo(): Setup new value, do type and change detection, converting types, call unit detection, ...
    pp["set" + p.method] = function(newValue)
    {
      // convert multiple arguments to array
      if (p.allowMultipleArguments && arguments.length > 1) {
        newValue = qx.lang.Array.fromArguments(arguments);
      }

      // support converter methods
      if (p.hasConvert)
      {
        try
        {
          newValue = p.convert.call(this, newValue, p);
        }
        catch(ex)
        {
          throw new Error("Attention! Could not convert new value for " + p.name + ": " + newValue + ": " + ex);
        }
      }

      var oldValue = this[valueKey];

      if (newValue === oldValue) {
        return newValue;
      }

      if (!(p.allowNull && newValue == null))
      {
        if (p.hasType && typeof newValue !== p.type) {
          return this.error("Attention! The value \"" + newValue + "\" is an invalid value for the property \"" + p.name + "\" which must be typeof \"" + p.type + "\" but is typeof \"" + typeof newValue + "\"!", new Error());
        }

        if (p.hasInstance && !(newValue instanceof qx.OO.classes[p.instance])) {
          return this.error("Attention! The value \"" + newValue + "\" is an invalid value for the property \"" + p.name + "\" which must be an instance of \"" + p.instance + "\"!", new Error());
        }

        if (p.hasClassName && newValue.classname != p.classname) {
          return this.error("Attention! The value \"" + newValue + "\" is an invalid value for the property \"" + p.name + "\" which must be an object with the classname \"" + p.classname + "\"!", new Error());
        }

        if (p.hasPossibleValues && newValue != null && !qx.lang.Array.contains(p.possibleValues, newValue)) {
          return this.error("Failed to save value for " + p.name + ". '" + newValue + "' is not a possible value!", new Error());
        }
      }

      // Allow to check and transform the new value before storage
      if (this[checkKey])
      {
        try
        {
          newValue = this[checkKey](newValue, p);

          // Don't do anything if new value is indentical to old value
          if (newValue === oldValue) {
            return newValue;
          }
        }
        catch(ex)
        {
          return this.error("Failed to check property " + p.name, ex);
        }
      }

      // Store new value
      this[valueKey] = newValue;

      // Check if there is a modifier implementation
      if (this[modifyKey])
      {
        try
        {
          var r = this[modifyKey](newValue, oldValue, p);
          if (!r) {
            return this.error("Modification of property \"" + p.name + "\" failed without exception (" + r + ")", new Error());
          }
        }
        catch(ex)
        {
          return this.error("Modification of property \"" + p.name + "\" failed with exception", ex);
        }
      }

      // Unit detection support
      if (p.hasUnitDetection) {
        this[unitDetectionKey](p, newValue);
      }

      // Auto queue addition support
      if (p.addToQueue) {
        this.addToQueue(p.name);
      }
      else if (p.addToQueueRuntime) {
        this.addToQueueRuntime(p.name);
      }

      // Auto state queue addition support
      if (p.addToStateQueue) {
        this.addToStateQueue();
      }

      // Create Event
      if (this.hasEventListeners && this.hasEventListeners(changeKey))
      {
        try
        {
          this.createDispatchDataEvent(changeKey, newValue);
        }
        catch(ex)
        {
          throw new Error("Property " + p.name + " modified: Failed to dispatch change event: " + ex);
        }
      }

      return newValue;
    };
  }
  else
  {
    // building setFoo(): Setup new value, do type and change detection, converting types, call unit detection, ...
    pp["set" + p.method] = function(newValue)
    {
      // this.debug("Fast Setter: " + p.name);

      var oldValue = this[valueKey];

      if (newValue === oldValue) {
        return newValue;
      }

      if (!(p.allowNull && newValue == null))
      {
        if (p.hasType && typeof newValue !== p.type) {
          return this.error("Attention! The value \"" + newValue + "\" is an invalid value for the property \"" + p.name + "\" which must be typeof \"" + p.type + "\" but is typeof \"" + typeof newValue + "\"!", new Error());
        }
      }

      // Allow to check and transform the new value before storage
      if (this[checkKey])
      {
        try
        {
          newValue = this[checkKey](newValue, p);

          // Don't do anything if new value is indentical to old value
          if (newValue === oldValue) {
            return newValue;
          }
        }
        catch(ex)
        {
          return this.error("Failed to check property " + p.name, ex);
        }
      }

      // Store new value
      this[valueKey] = newValue;

      // Check if there is a modifier implementation
      if (this[modifyKey])
      {
        try
        {
          var r = this[modifyKey](newValue, oldValue, p);
          if (!r) {
            var valueStr = new String(newValue).substring(0, 50);
            return this.error("Setting property \"" + p.name + "\" to \"" + valueStr + "\" failed without exception (" + r + ")", new Error());
          }
        }
        catch(ex)
        {
          var valueStr = new String(newValue).substring(0, 50);
          return this.error("Setting property \"" + p.name + "\" to \"" + valueStr + "\" failed with exception", ex);
        }
      }

      // Create Event
      if (this.hasEventListeners && this.hasEventListeners(changeKey))
      {
        var vEvent = new qx.event.type.DataEvent(changeKey, newValue, oldValue, false);

        vEvent.setTarget(this);

        try
        {
          this.dispatchEvent(vEvent, true);
        }
        catch(ex)
        {
          throw new Error("Property " + p.name + " modified: Failed to dispatch change event: " + ex);
        }
      }

      return newValue;
    };
  }

  // building user configured get alias for property
  if (typeof p.getAlias === "string") {
    pp[p.getAlias] = pp["get" + p.method];
  }

  // building user configured set alias for property
  if (typeof p.setAlias === "string") {
    pp[p.setAlias] = pp["set" + p.method];
  }
}

qx.Class.changeProperty = qx.OO._createProperty;

qx.Class.addProperty = function(p)
{
  qx.OO.propertyNumber++;

  qx.OO._createProperty(p);

  // add property to (all) property list
  if (typeof qx.Proto._properties !== "string") {
    qx.Proto._properties = p.name;
  } else {
    qx.Proto._properties += "," + p.name;
  }

  // add property to object property list
  switch(p.type)
  {
    case undefined:
    case "object":
    case "function":
      if (typeof qx.Proto._objectproperties !== "string") {
        qx.Proto._objectproperties = p.name;
      } else {
        qx.Proto._objectproperties += "," + p.name;
      }
  }
}

qx.Class.inheritField = function(vField, vData)
{
  qx.lang.Object.carefullyMergeWith(vData, qx.Super.prototype[vField]);
  qx.Proto[vField] = vData;
}

qx.Class.isAvailable = function(vClassName) {
  return typeof qx.OO.classes[vClassName] !== "undefined";
}
