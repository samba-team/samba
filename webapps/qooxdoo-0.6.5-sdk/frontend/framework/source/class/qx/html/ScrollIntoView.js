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

#module(ui_core)
#require(qx.html.Style)

************************************************************************ */

/**
 * Functions to scroll DOM elements into the visible area of the parent element
 */
qx.OO.defineClass("qx.html.ScrollIntoView");

// Internet Explorer has invented scrollIntoView, but does not behave the same like in Mozilla (which would be better)
// Mozilla has a native well working method scrollIntoView
// Safari does not support scrollIntoView (but it can be found in Webkit since May 2005)
// Opera does not support scrollIntoView

/** the documents body tag name */
qx.dom.BODY_TAG_NAME = "body";


/**
 * Scroll the parent DOM element so that the element's so that the x coordinate is inside
 * the visible area of the parent.
 *
 * @param vElement {Element} DOM node to be scrolled into view
 * @param vAlignLeft {Boolean} whether the element should be left aligned
 */
qx.html.ScrollIntoView.scrollX = function(vElement, vAlignLeft)
{
  var vParentWidth, vParentScrollLeft, vWidth, vHasScroll;

  var vParent = vElement.parentNode;
  var vOffset = vElement.offsetLeft;
  var vWidth = vElement.offsetWidth;

  while(vParent)
  {
    switch(qx.html.Style.getStyleProperty(vParent, "overflow"))
    {
      case "scroll":
      case "auto":
      case "-moz-scrollbars-horizontal":
        vHasScroll = true;
        break;

      default:
        switch(qx.html.Style.getStyleProperty(vParent, "overflowX"))
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


/**
 * Scroll the parent DOM element so that the element's so that the y coordinate is inside
 * the visible area of the parent.
 *
 * @param vElement {Element} DOM node to be scrolled into view
 * @param vAlignTop {Boolean} whether the element should be top aligned
 */
qx.html.ScrollIntoView.scrollY = function(vElement, vAlignTop)
{
  var vParentHeight, vParentScrollTop, vHeight, vHasScroll;

  var vParent = vElement.parentNode;
  var vOffset = vElement.offsetTop;
  var vHeight = vElement.offsetHeight;

  while(vParent)
  {
    switch(qx.html.Style.getStyleProperty(vParent, "overflow"))
    {
      case "scroll":
      case "auto":
      case "-moz-scrollbars-vertical":
        vHasScroll = true;
        break;

      default:
        switch(qx.html.Style.getStyleProperty(vParent, "overflowY"))
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
