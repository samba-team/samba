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

#module(ui_basic)
#require(qx.renderer.font.FontCache)
#after(qx.renderer.font.FontObject)

************************************************************************ */

qx.OO.defineClass("qx.ui.basic.Label", qx.ui.basic.Terminator,
function(vHtml, vMnemonic)
{
  qx.ui.basic.Terminator.call(this);

  // Apply constructor arguments
  if (qx.util.Validation.isValidString(vHtml)) {
    this.setHtml(vHtml);
  }

  if (qx.util.Validation.isValidString(vMnemonic)) {
    this.setMnemonic(vMnemonic);
  }

  // Prohibit stretching through layout handler
  this.setAllowStretchX(false);
  this.setAllowStretchY(false);

  // Auto Sized
  this.auto();
});

qx.Class._measureNodes = {};





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.changeProperty({ name : "appearance", type : "string", defaultValue : "label" });

/*!
  Any text string which can contain HTML, too
*/
qx.OO.addProperty({ name : "html", type : "string" });

/*!
  The alignment of the text.
*/
qx.OO.addProperty({ name : "textAlign", type : "string", defaultValue : "left", possibleValues : [ "left", "center", "right", "justify" ] });

/*!
  The styles which should be copied
*/
qx.OO.addProperty({ name : "fontPropertiesProfile", type : "string", defaultValue : "default", possibleValues : [ "none", "default", "extended", "multiline", "extendedmultiline", "all" ] });

/*!
  A single character which will be underlined inside the text.
*/
qx.OO.addProperty({ name : "mnemonic", type : "string" });

/*!
  The font property describes how to paint the font on the widget.
*/
qx.OO.addProperty({ name : "font", type : "object", instance : "qx.renderer.font.Font", convert : qx.renderer.font.FontCache, allowMultipleArguments : true });

/*!
  Wrap the text?
*/
qx.OO.addProperty({ name : "wrap", type : "boolean", defaultValue : true });









/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  DATA
---------------------------------------------------------------------------
*/

qx.ui.basic.Label.SYMBOL_ELLIPSIS = String.fromCharCode(8230);
qx.ui.basic.Label.SUPPORT_NATIVE_ELLIPSIS = qx.sys.Client.getInstance().isMshtml();

// these are the properties what will be copied to the measuring frame.
qx.ui.basic.Label._fontProperties =
{
  "none" : [],

  "default" : ["fontFamily", "fontSize", "fontStyle", "fontWeight", "textDecoration"],
  "extended" : ["fontFamily", "fontSize", "fontStyle", "fontWeight", "letterSpacing", "textDecoration", "textTransform", "whiteSpace", "wordSpacing"],

  "multiline" : ["fontFamily", "fontSize", "fontStyle", "fontWeight", "textDecoration", "lineHeight", "wordWrap"],
  "extendedmultiline" : ["fontFamily", "fontSize", "fontStyle", "fontWeight", "letterSpacing", "textDecoration", "textTransform", "whiteSpace", "wordSpacing", "lineHeight", "wordBreak", "wordWrap", "quotes"],

  "all" : ["fontFamily", "fontSize", "fontStyle", "fontVariant", "fontWeight", "letterSpacing", "lineBreak", "lineHeight", "quotes", "textDecoration", "textIndent", "textShadow", "textTransform", "textUnderlinePosition", "whiteSpace", "wordBreak", "wordSpacing", "wordWrap"]
}

qx.ui.basic.Label.htmlToText = function(s) {
  return String(s).replace(/\s+|<([^>])+>|&amp;|&lt;|&gt;|&quot;|&nbsp;|&#[0-9]+;|&#x[0-9a-fA-F];]/gi, qx.ui.basic.Label._htmlToText);
}

qx.ui.basic.Label._htmlToText = function(s)
{
  switch(s)
  {
    case "&amp;":
      return "&";

    case "&lt;":
      return "<";

    case "&gt;":
      return ">";

    case "&quot;":
      return '"';

    case "&nbsp;":
      return String.fromCharCode(160);

    default:
      if (s.substring(0, 3) == "&#x") {
        return String.fromCharCode(parseInt("0x" + s.substring(3, s.length - 1)));
      }
      else if (s.substring(0, 2) == "&#") {
        return String.fromCharCode(s.substring(2, s.length - 1));
      }
      else if (/\s+/.test(s)) {
        return " ";
      }
      else if (/^<BR/gi.test(s)) {
        return "\n";
      }

      return "";
  }
}

qx.ui.basic.Label.textToHtml = function(s) {
  return String(s).replace(/&|<|>|\n|\u00A0/g, qx.ui.basic.Label._textToHtml);
}

qx.ui.basic.Label._textToHtml = function(s)
{
  switch(s)
  {
    case "&":
      return "&amp;";

    case "<":
      return "&lt;";

    case ">":
      return "&gt;";

    case "\n":
      return "<br/>";

    default:
      return " ";
  }
}

qx.ui.basic.Label.createMeasureNode = function(vId)
{
  var vNode = qx.ui.basic.Label._measureNodes[vId];

  if (!vNode)
  {
    vNode = document.createElement("div");
    var vStyle = vNode.style;

    vStyle.width = vStyle.height = "auto";
    vStyle.visibility = "hidden";
    vStyle.position = "absolute";
    vStyle.zIndex = "-1";

    document.body.appendChild(vNode);

    qx.ui.basic.Label._measureNodes[vId] = vNode;
  }

  return vNode;
}








/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._htmlMode = false;
qx.Proto._hasMnemonic = false;
qx.Proto._mnemonicHtml = "";
qx.Proto._mnemonicTest = null;

qx.Proto._modifyHtml = function(propValue, propOldValue, propData)
{
  this._htmlMode = qx.util.Validation.isValidString(propValue) && propValue.match(/<.*>/) ? true : false;

  if (this._isCreated) {
    this._applyContent();
  }

  return true;
}

qx.Proto._modifyTextAlign = function(propValue, propOldValue, propData)
{
  this.setStyleProperty("textAlign", propValue);
  return true;
}

qx.Proto._modifyMnemonic = function(propValue, propOldValue, propData)
{
  this._hasMnemonic = qx.util.Validation.isValidString(propValue) && propValue.length == 1;

  this._mnemonicHtml = this._hasMnemonic ? "(<span style=\"text-decoration:underline\">" + propValue + "</span>)" : "";
  this._mnemonicTest = this._hasMnemonic ? new RegExp("^(((<([^>]|" + propValue + ")+>)|(&([^;]|" + propValue + ")+;)|[^&" + propValue + "])*)(" + propValue + ")", "i") : null;

  return true;
}

qx.Proto._modifyFont = function(propValue, propOldValue, propData)
{
  this._invalidatePreferredInnerDimensions();

  if (propValue) {
    propValue._applyWidget(this);
  } else if (propOldValue) {
    propOldValue._resetWidget(this);
  }

  return true;
}

qx.Proto._modifyWrap = function(propValue, propOldValue, propData)
{
  this.setStyleProperty("whiteSpace", propValue ? "normal" : "nowrap");
  return true;
}





/*
---------------------------------------------------------------------------
  HELPER FOR PREFERRED DIMENSION
---------------------------------------------------------------------------
*/

qx.Proto._computeObjectNeededDimensions = function()
{
  // copy styles
  var vNode = this._copyStyles();

  // prepare html
  var vHtml = this.getHtml();

  // test for mnemonic and fix content
  if (this._hasMnemonic && !this._mnemonicTest.test(vHtml)) {
    vHtml += this._mnemonicHtml;
  }

  // apply html
  vNode.innerHTML = vHtml;

  // store values
  this._cachedPreferredInnerWidth = vNode.scrollWidth;
  this._cachedPreferredInnerHeight = vNode.scrollHeight;
}

qx.Proto._copyStyles = function()
{
  var vProps = this.getFontPropertiesProfile();
  var vNode = qx.ui.basic.Label.createMeasureNode(vProps);
  var vUseProperties=qx.ui.basic.Label._fontProperties[vProps];
  var vUsePropertiesLength=vUseProperties.length-1;
  var vProperty=vUseProperties[vUsePropertiesLength--];

  var vStyle = vNode.style;
  var vTemp;

  if (!vProperty) {
    return vNode;
  }

  do {
    vStyle[vProperty] = qx.util.Validation.isValid(vTemp = this.getStyleProperty([vProperty])) ? vTemp : "";
  } while(vProperty=vUseProperties[vUsePropertiesLength--]);

  return vNode;
}






/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS
---------------------------------------------------------------------------
*/

qx.Proto._computePreferredInnerWidth = function()
{
  this._computeObjectNeededDimensions();
  return this._cachedPreferredInnerWidth;
}

qx.Proto._computePreferredInnerHeight = function()
{
  this._computeObjectNeededDimensions();
  return this._cachedPreferredInnerHeight;
}






/*
---------------------------------------------------------------------------
  LAYOUT APPLY
---------------------------------------------------------------------------
*/

qx.Proto._postApply = function()
{
  var vHtml = this.getHtml();
  var vElement = this._getTargetNode();
  var vMnemonicMode = 0;

  if (qx.util.Validation.isInvalidString(vHtml)) {
    vElement.innerHTML = "";
    return;
  }

  if (this._hasMnemonic) {
    vMnemonicMode = this._mnemonicTest.test(vHtml) ? 1 : 2;
  }

  // works only with text, don't use when wrap is enabled
  if (!this._htmlMode && !this.getWrap())
  {
    switch(this._computedWidthType)
    {
      case qx.ui.core.Widget.TYPE_PIXEL:
      case qx.ui.core.Widget.TYPE_PERCENT:

      //carstenl: enabled truncation code for flex sizing, too. Appears to work except for the
      //          truncation code (gecko version), which I have disabled (see below).
      case qx.ui.core.Widget.TYPE_FLEX:
        var vNeeded = this.getPreferredInnerWidth();
        var vInner = this.getInnerWidth();

        if (vInner < vNeeded)
        {
          vElement.style.overflow = "hidden";

          if (qx.ui.basic.Label.SUPPORT_NATIVE_ELLIPSIS)
          {
            vElement.style.textOverflow = "ellipsis";
            vHtml += this._mnemonicHtml;
          }
          else
          {
            var vMeasureNode = this._copyStyles();

            var vSplitString = vHtml.split(" ");
            var vSplitLength = vSplitString.length;

            var vWordIterator = 0;
            var vCharaterIterator = 0;

            var vPost = qx.ui.basic.Label.SYMBOL_ELLIPSIS;

            var vUseInnerText = true;
            if (vMnemonicMode == 2)
            {
              var vPost = this._mnemonicHtml + vPost;
              vUseInnerText = false;
            }

            // Measure Words (if more than one)
            if (vSplitLength > 1)
            {
              var vSplitTemp = [];

              for (vWordIterator=0; vWordIterator<vSplitLength; vWordIterator++)
              {
                vSplitTemp.push(vSplitString[vWordIterator]);

                var vLabelText = vSplitTemp.join(" ") + vPost;
                if (vUseInnerText) {
                  qx.dom.Element.setTextContent(vMeasureNode, vLabelText);
                } else {
                  vMeasureNode.innerHTML = vLabelText;
                }

                if ((vMeasureNode.scrollWidth > vInner)
                  /* carstenl: The following code (truncate the text to fit in the available
                   *           space, append ellipsis to indicate truncation) did not reliably
                   *           work in my tests. Problem was that sometimes the measurer returned
                   *           insanely high values for short texts, like "I..." requiring 738 px.
                   *
                   *           I don't have time to examine this code in detail. Since all of my
                   *           tests used flex width and the truncation code never was intended
                   *           for this, I am disabling truncation if flex is active.
                   */
                    && (this._computedWidthType != qx.ui.core.Widget.TYPE_FLEX)){
                  break;
                }
              }

              // Remove last word which does not fit
              vSplitTemp.pop();

              // Building new temportary array
              vSplitTemp = [ vSplitTemp.join(" ") ];

              // Extracting remaining string
              vCharaterString = vHtml.replace(vSplitTemp[0], "");
            }
            else
            {
              var vSplitTemp = [];
              vCharaterString = vHtml;
            }

            var vCharaterLength = vCharaterString.length;

            // Measure Chars
            for (var vCharaterIterator=0; vCharaterIterator<vCharaterLength; vCharaterIterator++)
            {
              vSplitTemp.push(vCharaterString.charAt(vCharaterIterator));

              var vLabelText = vSplitTemp.join("") + vPost;
              if (vUseInnerText) {
                qx.dom.Element.setTextContent(vMeasureNode, vLabelText);
              } else {
                vMeasureNode.innerHTML = vLabelText;
              }

              if (vMeasureNode.scrollWidth > vInner) {
                break;
              }
            }

            // Remove last char which does not fit
            vSplitTemp.pop();

            // Add mnemonic and ellipsis symbol
            vSplitTemp.push(vPost);

            // Building Final HTML String
            vHtml = vSplitTemp.join("");
          }

          break;
        }
        else
        {
          vHtml += this._mnemonicHtml;
        }

        // no break here

      default:
        vElement.style.overflow = "";

        if (qx.ui.basic.Label.SUPPORT_NATIVE_ELLIPSIS) {
          vElement.style.textOverflow = "";
        }
    }
  }

  if (vMnemonicMode == 1)
  {
    // re-test: needed to make ellipsis handling correct
    this._mnemonicTest.test(vHtml);
    vHtml = RegExp.$1 + "<span style=\"text-decoration:underline\">" + RegExp.$7 + "</span>" + RegExp.rightContext;
  }

  return this._postApplyHtml(vElement, vHtml, vMnemonicMode);
}


qx.Proto._postApplyHtml = function(vElement, vHtml, vMnemonicMode)
{
  if (this._htmlMode || vMnemonicMode > 0)
  {
    vElement.innerHTML = vHtml;
  }
  else
  {
    try {
      qx.dom.Element.setTextContent(vElement, vHtml);
    } catch(ex) {
      vElement.innerHTML = vHtml;
    }
  }
}