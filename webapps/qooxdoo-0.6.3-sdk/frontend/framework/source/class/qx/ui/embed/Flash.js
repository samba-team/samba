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


************************************************************************ */

/*!
  Original non qooxdoo Version by Geoff Stearns
    Flash detection and embed - http://blog.deconcept.com/flashobject/
    FlashObject is (c) 2005 Geoff Stearns and is released under the MIT License
    http://www.opensource.org/licenses/mit-license.php

  Modified for qooxdoo by Sebastian Werner
    Based on version 1.2.3
    Relicensed under LGPL in assent of Geoff Stearns
*/

qx.OO.defineClass("qx.ui.embed.Flash", qx.ui.basic.Terminator,
function(vSource, vVersion)
{
  qx.ui.basic.Terminator.call(this);

  // Use background handling of qx.ui.core.Widget instead
  this._params = {};
  this._variables = {};

  if(qx.util.Validation.isValidString(vSource)) {
    this.setSource(vSource);
  }

  this.setVersion(qx.util.Validation.isValidString(vVersion) ? vVersion : qx.ui.embed.Flash.MINREQUIRED);
});

qx.OO.addProperty({ name : "source", type : "string" });
qx.OO.addProperty({ name : "version" });

qx.OO.addProperty({ name : "enableExpressInstall", type : "boolean", defaultValue : false });
qx.OO.addProperty({ name : "enableDetection", type : "boolean", defaultValue : true });
qx.OO.addProperty({ name : "redirectUrl", type : "string" });

qx.OO.addProperty({ name : "quality", type : "string", impl : "param", defaultValue : "high", possibleValues : [ "low", "autolow", "autohigh", "medium", "high", "best" ] });
qx.OO.addProperty({ name : "scale", type : "string", impl : "param", defaultValue : "showall", possibleValues : [ "showall", "noborder", "excactfit", "noscale" ] });
qx.OO.addProperty({ name : "wmode", type : "string", impl : "param", defaultValue : "", possibleValues : [ "window", "opaque", "transparent" ] });
qx.OO.addProperty({ name : "play", type : "boolean", impl : "param", defaultValue : true });
qx.OO.addProperty({ name : "loop", type : "boolean", impl : "param", defaultValue : true });
qx.OO.addProperty({ name : "menu", type : "boolean", impl : "param", defaultValue : true });

qx.ui.embed.Flash.EXPRESSINSTALL = [6,0,65];
qx.ui.embed.Flash.MINREQUIRED = "1";
qx.ui.embed.Flash.PLAYERVERSION = null;
qx.ui.embed.Flash.PLUGINKEY = "Shockwave Flash";
qx.ui.embed.Flash.ACTIVEXKEY = "ShockwaveFlash.ShockwaveFlash";





/*
---------------------------------------------------------------------------
  PLAYER VERSION CACHE
---------------------------------------------------------------------------
*/

qx.ui.embed.Flash.getPlayerVersion = function()
{
  if (qx.ui.embed.Flash.PLAYERVERSION != null) {
    return qx.ui.embed.Flash.PLAYERVERSION;
  }

  var vPlayerVersion = new qx.type.Version(0,0,0);

  if(navigator.plugins && navigator.mimeTypes.length)
  {
    var x = navigator.plugins[qx.ui.embed.Flash.PLUGINKEY];

    if(x && x.description) {
      vPlayerVersion = new qx.type.Version(x.description.replace(/([a-z]|[A-Z]|\s)+/, '').replace(/(\s+r|\s+b[0-9]+)/, '.'));
    }
  }
  else if (window.ActiveXObject)
  {
    try {
      var axo = new ActiveXObject(qx.ui.embed.Flash.ACTIVEXKEY);
       vPlayerVersion = new qx.type.Version(axo.GetVariable("$version").split(" ")[1].split(","));
    }
    catch (e) {}
  }

  return qx.ui.embed.Flash.PLAYERVERSION = vPlayerVersion;
}






/*
---------------------------------------------------------------------------
  BASICS
---------------------------------------------------------------------------
*/

qx.Proto._version = null;
qx.Proto._source = "";

qx.Proto._applyElementData = function(el)
{
  qx.ui.basic.Terminator.prototype._applyElementData.call(this, el);

  // Check for ExpressInstall
  this._expressInstall = false;

  if (this.getEnableExpressInstall())
  {
    // check to see if we need to do an express install
    var expressInstallReqVer = new qx.type.Version(qx.ui.embed.Flash.EXPRESSINSTALL);
    var installedVer = qx.ui.embed.Flash.getPlayerVersion();

    if (installedVer.versionIsValid(expressInstallReqVer) && !installedVer.versionIsValid(this._version)) {
      this._expressInstall = true;
    }
  }

  // this.debug("ExpressInstall Enabled: " + this._expressInstall);

  // Apply HTML
  if(!this.getEnableDetection() || this._expressInstall || qx.ui.embed.Flash.getPlayerVersion().versionIsValid(this._version))
  {
    el.innerHTML = this.generateHTML();
  }
  else
  {
    var redir = this.getRedirectUrl();

    if(redir != "") {
      document.location.replace(redir);
    }
  }
}





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifySource = function(propValue, propOldValue, propName)
{
  this._source = qx.util.Validation.isValidString(propValue) ? qx.manager.object.AliasManager.getInstance().resolvePath(propValue) : "";
  return true;
}

qx.Proto._modifyVersion = function(propValue, propOldValue, propData)
{
  if (this._version)
  {
    this._version.dispose();
    this._version = null;
  }

  if (qx.util.Validation.isValidString(propValue)) {
    this._version = new qx.type.Version(propValue);
  }

  return true;
}

qx.Proto._modifyParam = function(propValue, propOldValue, propData)
{
  this.setParam(propData.name, propValue.toString());
  return true;
}





/*
---------------------------------------------------------------------------
  OVERWRITE BACKGROUND COLOR HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._modifyBackgroundColor = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue)
  {
    this._applyBackgroundColor(propValue.getHex());
    propValue.add(this);
  }
  else
  {
    this._resetBackgroundColor();
  }

  return true;
}

qx.Proto._applyBackgroundColor = function(vNewValue) {
  this.setParam("bgcolor", vNewValue);
}




/*
---------------------------------------------------------------------------
  PARAMS
---------------------------------------------------------------------------
*/

qx.Proto.setParam = function(name, value){
  this._params[name] = value;
}

qx.Proto.getParam = function(name){
  return this._params[name];
}

qx.Proto.getParams = function() {
  return this._params;
}





/*
---------------------------------------------------------------------------
  VARIABLES
---------------------------------------------------------------------------
*/

qx.Proto.setVariable = function(name, value){
  this._variables[name] = value;
}

qx.Proto.getVariable = function(name){
  return this._variables[name];
}

qx.Proto.getVariables = function(){
  return this._variables;
}





/*
---------------------------------------------------------------------------
  HTML UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.generateParamTags = function()
{
  var vParams = this.getParams();
  var vParamTags = [];

  for (var vKey in vParams)
  {
    vParamTags.push("<param name='");
    vParamTags.push(vKey);
    vParamTags.push("' value='");
    vParamTags.push(vParams[vKey]);
    vParamTags.push("'/>");
  }

  return vParamTags.join("");
}

qx.Proto.getVariablePairs = function()
{
  var variables = this.getVariables();
  var variablePairs = [];

  for (var key in variables) {
    variablePairs.push(key + "=" + variables[key]);
  }

  return variablePairs.join("&");
}






/*
---------------------------------------------------------------------------
  HTML GENERATOR
---------------------------------------------------------------------------
*/

// Netscape Plugin Architecture
if (navigator.plugins && navigator.mimeTypes && navigator.mimeTypes.length)
{
  qx.Proto.generateHTML = function()
  {
    var html = [];

    // Express Install Handling
    if (this._expressInstall)
    {
      document.title = document.title.slice(0, 47) + ' - Flash Player Installation';

      this.addVariable('MMredirectURL', escape(window.location));
      this.addVariable('MMdoctitle', document.title);
      this.addVariable('MMplayerType', 'PlugIn');
    }

    html.push("<embed type='application/x-shockwave-flash' width='100%' height='100%' src='");
    html.push(this._source);
    html.push("'");

    var params = this.getParams();

    for (var key in params)
    {
      html.push(" ");
      html.push(key);
      html.push("=");
      html.push("'");
      html.push(params[key]);
      html.push("'");
    }

    var pairs = this.getVariablePairs();

    if (pairs.length > 0)
    {
      html.push(" ");
      html.push("flashvars");
      html.push("=");
      html.push("'");
      html.push(pairs);
      html.push("'");
    }

    html.push("></embed>");

    return html.join("");
  }
}

// Internet Explorer ActiveX Architecture
else
{
  qx.Proto.generateHTML = function()
  {
    var html = [];

    // Express Install Handling
    if (this._expressInstall)
    {
      document.title = document.title.slice(0, 47) + ' - Flash Player Installation';

      this.addVariable("MMredirectURL", escape(window.location));
      this.addVariable("MMdoctitle", document.title);
      this.addVariable("MMplayerType", "ActiveX");
    }

    html.push("<object classid='clsid:D27CDB6E-AE6D-11cf-96B8-444553540000' width='100%' height='100%'>");
    html.push("<param name='movie' value='");
    html.push(this._source);
    html.push("'/>");

    var tags = this.generateParamTags();

    if(tags.length > 0) {
      html.push(tags);
    }

    var pairs = this.getVariablePairs();

    if(pairs.length > 0)
    {
      html.push("<param name='flashvars' value='");
      html.push(pairs);
      html.push("'/>");
    }

    html.push("</object>");

    return html.join("");
  }
}






/*
---------------------------------------------------------------------------
  METHODS TO GIVE THE LAYOUTERS INFORMATIONS
---------------------------------------------------------------------------
*/

qx.Proto._isWidthEssential = qx.util.Return.returnTrue;
qx.Proto._isHeightEssential = qx.util.Return.returnTrue;




/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto._computePreferredInnerWidth = qx.util.Return.returnZero;
qx.Proto._computePreferredInnerHeight = qx.util.Return.returnZero;





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

  delete this._source;
  delete this._params;
  delete this._variables;

  if (this._version)
  {
    this._version.dispose();
    this._version = null;
  }

  qx.ui.basic.Terminator.prototype.dispose.call(this);
}
