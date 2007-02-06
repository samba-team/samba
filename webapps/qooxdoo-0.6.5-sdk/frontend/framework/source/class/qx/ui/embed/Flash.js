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
   ________________________________________________________________________

   This class contains code based on the following work:

     SWFObject: Javascript Flash Player detection and embed script
     http://blog.deconcept.com/swfobject/
     Version: 1.4.4

     Copyright:
       2006 Geoff Stearns

     License:
       MIT: http://www.opensource.org/licenses/mit-license.php

       Permission is hereby granted, free of charge, to any person obtaining a
       copy of this software and associated documentation files (the "Software"),
       to deal in the Software without restriction, including without limitation
       the rights to use, copy, modify, merge, publish, distribute, sublicense,
       and/or sell copies of the Software, and to permit persons to whom the
       Software is furnished to do so, subject to the following conditions:

       The above copyright notice and this permission notice shall be included in
       all copies or substantial portions of the Software.

       THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
       IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
       FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
       AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
       LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
       FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
       DEALINGS IN THE SOFTWARE.

     Authors:
       * Geoff Stearns (geoff@deconcept.com)

************************************************************************ */

/* ************************************************************************


************************************************************************ */

/**
 * Flash Player detection and embed.
 *
 * This class contains code based on the following work:<br/>
 *   SWFObject: Javascript Flash Player detection and embed script<br/>
 *   http://blog.deconcept.com/swfobject/</br>
 *   Version: 1.4.4
 *
 * License:<br/>
 *   MIT: http://www.opensource.org/licenses/mit-license.php<br/>
 *   For more info, please see the corresponding source file.
 *
 * @param vSource {String} Url of the SWF file to embed
 * @param vVersion {String} Flash version of the SWF file
 */
qx.OO.defineClass("qx.ui.embed.Flash", qx.ui.basic.Terminator,
function(vSource, vVersion)
{
  qx.ui.basic.Terminator.call(this);

  // Use background handling of qx.ui.core.Widget instead
  this._params = {};
  this._variables = {};

  if(vSource != null) {
    this.setSource(vSource);
  }

  this.setVersion(vVersion != null ? vVersion : qx.ui.embed.Flash.MINREQUIRED);
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
      vPlayerVersion = new qx.type.Version(x.description.replace(/([a-zA-Z]|\s)+/, "").replace(/(\s+r|\s+b[0-9]+)/, ".").split("."));
    }
  }
  else if (window.ActiveXObject)
  {
    // do minor version lookup in IE, but avoid fp6 crashing issues
    // see http://blog.deconcept.com/2006/01/11/getvariable-setvariable-crash-internet-explorer-flash-6/
    try {
      var axo = new ActiveXObject(qx.ui.embed.Flash.ACTIVEXKEY + ".7");
    }
    catch(e)
    {
      try {
        var axo = new ActiveXObject(qx.ui.embed.Flash.ACTIVEXKEY + ".6");
        vPlayerVersion = new qx.type.Version([6,0,21]);
        axo.AllowScriptAccess = "always"; // throws if player version < 6.0.47 (thanks to Michael Williams @ Adobe for this code)
      }
      catch(e)
      {
        if (vPlayerVersion.major == 6) {
          return vPlayerVersion;
        }
      }

      try {
        axo = new ActiveXObject(qx.ui.embed.Flash.ACTIVEXKEY);
      } catch(e) {}
    }

    if (axo != null) {
      vPlayerVersion = new qx.type.Version(axo.GetVariable("$version").split(" ")[1].split(","));
    }
  }

  return qx.ui.embed.Flash.PLAYERVERSION = vPlayerVersion;
};






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
};





/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifySource = function(propValue, propOldValue, propName)
{
  this._source = qx.util.Validation.isValidString(propValue) ? qx.manager.object.AliasManager.getInstance().resolvePath(propValue) : "";
  return true;
};

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
};

qx.Proto._modifyParam = function(propValue, propOldValue, propData)
{
  this.setParam(propData.name, propValue.toString());
  return true;
};





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
};

qx.Proto._applyBackgroundColor = function(vNewValue) {
  this.setParam("bgcolor", vNewValue);
};




/*
---------------------------------------------------------------------------
  PARAMS
---------------------------------------------------------------------------
*/

qx.Proto.setParam = function(name, value){
  this._params[name] = value;
};

qx.Proto.getParam = function(name){
  return this._params[name];
};

qx.Proto.getParams = function() {
  return this._params;
};





/*
---------------------------------------------------------------------------
  VARIABLES
---------------------------------------------------------------------------
*/

qx.Proto.setVariable = function(name, value){
  this._variables[name] = value;
};

qx.Proto.getVariable = function(name){
  return this._variables[name];
};

qx.Proto.getVariables = function(){
  return this._variables;
};





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
};

qx.Proto.getVariablePairs = function()
{
  var variables = this.getVariables();
  var variablePairs = [];

  for (var key in variables) {
    variablePairs.push(key + "=" + variables[key]);
  }

  return variablePairs.join("&");
};






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
  };
}
else
{
  // Internet Explorer ActiveX Architecture
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
  };
}






/*
---------------------------------------------------------------------------
  METHODS TO GIVE THE LAYOUTERS INFORMATIONS
---------------------------------------------------------------------------
*/

qx.Proto._isWidthEssential = qx.lang.Function.returnTrue;
qx.Proto._isHeightEssential = qx.lang.Function.returnTrue;




/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto._computePreferredInnerWidth = qx.lang.Function.returnZero;
qx.Proto._computePreferredInnerHeight = qx.lang.Function.returnZero;





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
};
