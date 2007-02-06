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

#module(io_remote)
#require(qx.core.Client)

************************************************************************ */

qx.OO.defineClass("qx.html.Iframe");

qx.html.Iframe.getWindow = function(vIframe) {};
qx.html.Iframe.getDocument = function(vIframe) {};

if (qx.core.Client.getInstance().isMshtml())
{
  qx.html.Iframe.getWindow = function(vIframe)
  {
    try
    {
      return vIframe.contentWindow;
    }
    catch(ex)
    {
      return null;
    }
  }

  qx.html.Iframe.getDocument = function(vIframe)
  {
    try
    {
      var vWin = qx.html.Iframe.getWindow(vIframe);
      return vWin ? vWin.document : null;
    }
    catch(ex)
    {
      return null;
    }
  }
}
else
{
  qx.html.Iframe.getWindow = function(vIframe)
  {
    try
    {
      var vDoc = qx.html.Iframe.getDocument(vIframe);
      return vDoc ? vDoc.defaultView : null;
    }
    catch(ex)
    {
      return null;
    }
  }

  qx.html.Iframe.getDocument = function(vIframe)
  {
    try
    {
      return vIframe.contentDocument;
    }
    catch(ex)
    {
      return null;
    }
  }
}

qx.html.Iframe.getBody = function(vIframe)
{
  var vDoc = qx.html.Iframe.getDocument(vIframe);
  return vDoc ? vDoc.getElementsByTagName("body")[0] : null;
}
