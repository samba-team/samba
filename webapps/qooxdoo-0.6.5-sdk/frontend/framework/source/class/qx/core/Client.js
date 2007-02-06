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

************************************************************************ */

/*!
  Basic client detection implementation

  Version shemes following wikipedia: major.minor[.revision[.build]]
  http://en.wikipedia.org/wiki/Software_version
*/
qx.OO.defineClass("qx.core.Client", Object,
function()
{
  var vRunsLocally = window.location.protocol === "file:";

  var vBrowserUserAgent = navigator.userAgent;
  var vBrowserVendor = navigator.vendor;
  var vBrowserProduct = navigator.product;
  var vBrowserPlatform = navigator.platform;
  var vBrowserModeHta = false;
  var vBrowser;

  var vEngine = null;
  var vEngineVersion = null;
  var vEngineVersionMajor = 0;
  var vEngineVersionMinor = 0;
  var vEngineVersionRevision = 0;
  var vEngineVersionBuild = 0;

  var vEngineEmulation = null;
  var vVersionHelper;

  if (window.opera && /Opera[\s\/]([0-9\.]*)/.test(vBrowserUserAgent))
  {
    vEngine = "opera";
    vEngineVersion = RegExp.$1;

    // Fix Opera version to match wikipedia style
    vEngineVersion = vEngineVersion.substring(0, 3) + "." + vEngineVersion.substring(3);

    vEngineEmulation = vBrowserUserAgent.indexOf("MSIE") !== -1 ? "mshtml" : vBrowserUserAgent.indexOf("Mozilla") !== -1 ? "gecko" : null;
  }
  else if (typeof vBrowserVendor==="string" && vBrowserVendor==="KDE" && /KHTML\/([0-9-\.]*)/.test(vBrowserUserAgent))
  {
    vEngine = "khtml";
    vBrowser = "konqueror";
    vEngineVersion = RegExp.$1;
  }
  else if (vBrowserUserAgent.indexOf("AppleWebKit") != -1 && /AppleWebKit\/([0-9-\.]*)/.test(vBrowserUserAgent))
  {
    vEngine = "webkit";
    vEngineVersion = RegExp.$1;

    if(vBrowserUserAgent.indexOf("Safari") != -1) {
      vBrowser = "safari";
    } else if(vBrowserUserAgent.indexOf("Omni") != -1) {
      vBrowser = "omniweb";
    } else {
      vBrowser = "other webkit";
    }
  }
  else if (window.controllers && typeof vBrowserProduct==="string" && vBrowserProduct==="Gecko" && /rv\:([^\);]+)(\)|;)/.test(vBrowserUserAgent))
  {
    // http://www.mozilla.org/docs/dom/domref/dom_window_ref13.html
    vEngine = "gecko";
    vEngineVersion = RegExp.$1;

    if(vBrowserUserAgent.indexOf("Firefox") != -1) {
      vBrowser = "firefox";
    } else if(vBrowserUserAgent.indexOf("Camino") != -1) {
      vBrowser = "camino";
    } else if(vBrowserUserAgent.indexOf("Galeon") != -1) {
      vBrowser = "galeon";
    } else {
      vBrowser = "other gecko";
    }
  }
  else if (/MSIE\s+([^\);]+)(\)|;)/.test(vBrowserUserAgent))
  {
    vEngine = "mshtml";
    vEngineVersion = RegExp.$1;

    vBrowserModeHta = !window.external;
  }

  if (vEngineVersion)
  {
    vVersionHelper = vEngineVersion.split(".");

    vEngineVersionMajor = vVersionHelper[0] || 0;
    vEngineVersionMinor = vVersionHelper[1] || 0;
    vEngineVersionRevision = vVersionHelper[2] || 0;
    vEngineVersionBuild = vVersionHelper[3] || 0;
  }

  var vEngineBoxSizingAttr = vEngine == "gecko" ? "-moz-box-sizing" : vEngine == "mshtml" ? null : "box-sizing";
  var vEngineQuirksMode = document.compatMode !== "CSS1Compat";

  var vDefaultLocale = "en";
  var vBrowserLocale = (vEngine == "mshtml" ? navigator.userLanguage : navigator.language).toLowerCase();
  var vBrowserLocaleVariant = null;

  var vBrowserLocaleVariantIndex = vBrowserLocale.indexOf("-");
  if (vBrowserLocaleVariantIndex != -1)
  {
    vBrowserLocaleVariant = vBrowserLocale.substr(vBrowserLocaleVariantIndex+1);
    vBrowserLocale = vBrowserLocale.substr(0, vBrowserLocaleVariantIndex);
  }

  var vPlatform = "none";
  var vPlatformWindows = false;
  var vPlatformMacintosh = false;
  var vPlatformUnix = false;
  var vPlatformOther = false;

  if (vBrowserPlatform.indexOf("Windows") != -1 || vBrowserPlatform.indexOf("Win32") != -1 || vBrowserPlatform.indexOf("Win64") != -1)
  {
    vPlatformWindows = true;
    vPlatform = "win";
  }
  else if (vBrowserPlatform.indexOf("Macintosh") != -1 || vBrowserPlatform.indexOf("MacIntel") != -1)
  {
    vPlatformMacintosh = true;
    vPlatform = "mac";
  }
  else if (vBrowserPlatform.indexOf("X11") != -1 || vBrowserPlatform.indexOf("Linux") != -1 || vBrowserPlatform.indexOf("BSD") != -1)
  {
    vPlatformUnix = true;
    vPlatform = "unix";
  }
  else
  {
    vPlatformOther = true;
    vPlatform = "other";
  }

  var vGfxVml = false;
  var vGfxSvg = false;
  var vGfxSvgBuiltin = false;
  var vGfxSvgPlugin = false;

  if (vEngine == "mshtml")
  {
    vGfxVml = true;

    // TODO: Namespace for VML:
    // document.write('<style>v\:*{ behavior:url(#default#VML); }</style>');
    // document.write('<xml:namespace ns="urn:schemas-microsoft-com:vml" prefix="v"/>');
  }

  if (document.implementation && document.implementation.hasFeature)
  {
    if (document.implementation.hasFeature("org.w3c.dom.svg", "1.0"))
    {
      vGfxSvg = vGfxSvgBuiltin = true;
    }
  }

  this._runsLocally = vRunsLocally;

  this._engineName = vEngine;
  this._engineNameMshtml = vEngine === "mshtml";
  this._engineNameGecko = vEngine === "gecko";
  this._engineNameOpera = vEngine === "opera";
  this._engineNameKhtml = vEngine === "khtml";
  this._engineNameWebkit = vEngine === "webkit";

  this._engineVersion = parseFloat(vEngineVersion);
  this._engineVersionMajor = parseInt(vEngineVersionMajor);
  this._engineVersionMinor = parseInt(vEngineVersionMinor);
  this._engineVersionRevision = parseInt(vEngineVersionRevision);
  this._engineVersionBuild = parseInt(vEngineVersionBuild);

  this._engineQuirksMode = vEngineQuirksMode;
  this._engineBoxSizingAttribute = vEngineBoxSizingAttr;
  this._engineEmulation = vEngineEmulation;

  this._defaultLocale = vDefaultLocale;

  this._browserPlatform = vPlatform;
  this._browserPlatformWindows = vPlatformWindows;
  this._browserPlatformMacintosh = vPlatformMacintosh;
  this._browserPlatformUnix = vPlatformUnix;
  this._browserPlatformOther = vPlatformOther;
  this._browserModeHta = vBrowserModeHta;
  this._browserLocale = vBrowserLocale;
  this._browserLocaleVariant = vBrowserLocaleVariant;

  this._gfxVml = vGfxVml;
  this._gfxSvg = vGfxSvg;
  this._gfxSvgBuiltin = vGfxSvgBuiltin;
  this._gfxSvgPlugin = vGfxSvgPlugin;

  this._fireBugActive = (window.console && console.log && console.debug && console.assert);

  this._supportsTextContent = (document.documentElement.textContent !== undefined);
  this._supportsInnerText = (document.documentElement.innerText !== undefined);
});





/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.getRunsLocally = function() {
  return this._runsLocally;
}

qx.Proto.getEngine = function() {
  return this._engineName;
}

qx.Proto.getVersion = function() {
  return this._engineVersion;
}

qx.Proto.getMajor = function() {
  return this._engineVersionMajor;
}

qx.Proto.getMinor = function() {
  return this._engineVersionMinor;
}

qx.Proto.getRevision = function() {
  return this._engineVersionRevision;
}

qx.Proto.getBuild = function() {
  return this._engineVersionBuild;
}

qx.Proto.getEmulation = function() {
  return this._engineEmulation;
}

qx.Proto.isMshtml = function() {
  return this._engineNameMshtml;
}

qx.Proto.isGecko = function() {
  return this._engineNameGecko;
}

qx.Proto.isOpera = function() {
  return this._engineNameOpera;
}

qx.Proto.isKhtml = function() {
  return this._engineNameKhtml;
}

qx.Proto.isWebkit = function() {
  return this._engineNameWebkit;
}

qx.Proto.isSafari2 = function() {
  return this._engineNameWebkit && (this._engineVersion < 420);
}

qx.Proto.isInQuirksMode = function() {
  return this._engineQuirksMode;
}

qx.Proto.getLocale = function() {
  return this._browserLocale;
}

qx.Proto.getLocaleVariant = function() {
  return this._browserLocaleVariant;
}

qx.Proto.getDefaultLocale = function() {
  return this._defaultLocale;
}

qx.Proto.usesDefaultLocale = function() {
  return this._browserLocale === this._defaultLocale;
}



/**
 * Returns the CSS attribute name for box-sizing if supported.
 *
 * @return {String} the attribute name.
 */
qx.Proto.getEngineBoxSizingAttribute = function() {
  return this._engineBoxSizingAttribute;
}


qx.Proto.getPlatform = function() {
  return this._browserPlatform;
}

/**
 * Returns whether the client platform is a Windows machine.
 *
 * @return {Boolean} whether the client platform is a Windows.
 */
qx.Proto.runsOnWindows = function() {
  return this._browserPlatformWindows;
}

/**
 * Returns whether the client platform is a Macintosh machine.
 *
 * @return {Boolean} whether the client platform is a Macintosh.
 */
qx.Proto.runsOnMacintosh = function() {
  return this._browserPlatformMacintosh;
}

/**
 * Returns whether the client platform is a X11 powered machine.
 *
 * @return {Boolean} whether the client platform is a X11 powered machine.
 */
qx.Proto.runsOnUnix = function() {
  return this._browserPlatformUnix;
}

qx.Proto.supportsVml = function() {
  return this._gfxVml;
}

qx.Proto.supportsSvg = function() {
  return this._gfxSvg;
}

qx.Proto.usesSvgBuiltin = function() {
  return this._gfxSvgBuiltin;
}

qx.Proto.usesSvgPlugin = function() {
  return this._gfxSvgPlugin;
}

/**
 * Retuns whether the Mozilla FireBug extension is installed and active
 * http://www.getfirebug.com/
 *
 * @return {Boolean} whether FireBug is active
 */
 qx.Proto.isFireBugActive = function() {
   return this._fireBugActive;
 };

/**
 * Returns whether the client supports the W3C property textContent of DOM element nodes.
 *
 * @return {Boolean} whether the client supports textContent.
 */
qx.Proto.supportsTextContent = function() {
  return this._supportsTextContent;
}

/**
 * Returns whether the client supports the W3C property innerText of DOM element nodes.
 *
 * @return {Boolean} whether the client supports innerText.
 */
qx.Proto.supportsInnerText = function() {
  return this._supportsInnerText;
}



/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
