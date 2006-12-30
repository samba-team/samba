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
#require(qx.dom.Style)

************************************************************************ */

qx.OO.defineClass("qx.dom.ScrollIntoView");

// Internet Explorer has invented scrollIntoView, but does not behave the same like in Mozilla (which would be better)
// Mozilla has a native well working method scrollIntoView
// Safari does not support scrollIntoView (but it can be found in Webkit since May 2005)
// Opera does not support scrollIntoView

qx.dom.BODY_TAG_NAME = "body";

qx.dom.ScrollIntoView.scrollX = function(vElement, vAlignLeft)
{
  var vParentWidth, vParentScrollLeft, vWidth, vHasScroll;

  var vParent = vElement.parentNode;
  var vOffset = vElement.offsetLeft;
  var vWidth = vElement.offsetWidth;

  while(vParent)
  {
    switch(qx.dom.Style.getStyleProperty(vParent, "overflow"))
    {
      case "scroll":
      case "auto":
      case "-moz-scrollbars-horizontal":
        vHasScroll = true;
        break;

      default:
        switch(qx.dom.Style.getStyleProperty(vParent, "overflowX"))
        {
          case "scroll":
          case "auto":
            vHasScroll = true;
            break;

          default:
            vHasScroll = false;
        }
    }

    if (vHasScroll)
    {
      vParentWidth = vParent.clientWidth;
      vParentScrollLeft = vParent.scrollLeft;

      if (vAlignLeft)
      {
        vParent.scrollLeft = vOffset;
      }
      else if (vAlignLeft == false)
      {
        vParent.scrollLeft = vOffset + vWidth - vParentWidth;
      }
      else if (vWidth > vParentWidth || vOffset < vParentScrollLeft)
      {
        vParent.scrollLeft = vOffset;
      }
      else if ((vOffset + vWidth) > (vParentScrollLeft + vParentWidth))
      {
        vParent.scrollLeft = vOffset + vWidth - vParentWidth;
      }

      vOffset = vParent.offsetLeft;
      vWidth = vParent.offsetWidth;
    }
    else
    {
      vOffset += vParent.offsetLeft;
    }

    if (vParent.tagName.toLowerCase() == qx.dom.BODY_TAG_NAME) {
      break;
    }

    vParent = vParent.parentNode;
  }

  return true;
}

qx.dom.ScrollIntoView.scrollY = function(vElement, vAlignTop)
{
  var vParentHeight, vParentScrollTop, vHeight, vHasScroll;

  var vParent = vElement.parentNode;
  var vOffset = vElement.offsetTop;
  var vHeight = vElement.offsetHeight;

  while(vParent)
  {
    switch(qx.dom.Style.getStyleProperty(vParent, "overflow"))
    {
      case "scroll":
      case "auto":
      case "-moz-scrollbars-vertical":
        vHasScroll = true;
        break;

      default:
        switch(qx.dom.Style.getStyleProperty(vParent, "overflowY"))
        {
          case "scroll":
          case "auto":
            vHasScroll = true;
            break;

          default:
            vHasScroll = false;
        }
    }

    if (vHasScroll)
    {
      vParentHeight = vParent.clientHeight;
      vParentScrollTop = vParent.scrollTop;

      if (vAlignTop)
      {
        vParent.scrollTop = vOffset;
      }
      else if (vAlignTop == false)
      {
        vParent.scrollTop = vOffset + vHeight - vParentHeight;
      }
      else if (vHeight > vParentHeight || vOffset < vParentScrollTop)
      {
        vParent.scrollTop = vOffset;
      }
      else if ((vOffset + vHeight) > (vParentScrollTop + vParentHeight))
      {
        vParent.scrollTop = vOffset + vHeight - vParentHeight;
      }

      vOffset = vParent.offsetTop;
      vHeight = vParent.offsetHeight;
    }
    else
    {
      vOffset += vParent.offsetTop;
    }

    if (vParent.tagName.toLowerCase() == qx.dom.BODY_TAG_NAME) {
      break;
    }

    vParent = vParent.parentNode;
  }

  return true;
}
