#!/usr/bin/env python

import tree, mapper

qooxdooStart = [
  # Properties
  "_modify", "_check", "_unitDetection",

  # Layout
  "_applyRuntime",

  # Cache Properties
  "_resetRuntime", "_compute", "_change", "_invalidate", "_recompute",

  # Property Methods
  "set", "get", "force", "reset"
]

qooxdooNames = [
  # Demos
  "ROOT_LOGGER", "removeAllAppenders", "addAppender", "DivAppender",

  # qx.ui.core.Widget.initApplyMethods
  "_style",
  "setStyleProperty", "removeStyleProperty",
  "constant", "Core",

  # Inheritance
  "qx", "Proto", "Class"
]

systemNames = [
  # Statement
  "break","catch","continue","do","for","in","finally","function","if","else","return","switch","case","default",
  "this","throw","try","var","while","with",

  # Operator
  "delete","false","instanceof","new","null","true","typeof","void",

  # Function
  "GetObject","ScriptEngine","ScriptEngineBuildVersion","ScriptEngineMajorVersion","ScriptEngineMinorVersion",

  # Objects
  "ActiveXObject","Arguments","Array","Boolean","Date","Dictionary","Enumerator","Error","FileSystemObject",
  "Function","Global","Image","Math","Number","Object","RegExp","String","VBArray",

  # Property
  "$1","$2","$3","$4","$5",
  "$6","$7","$8","$9","arguments","arity","callee","caller","constructor","description","E","global","ignoreCase",
  "index","Infinity","input","lastIndex","leftContext","length","LN2","LN10","LOG2E","LOG10E","MAX_VALUE",
  "MIN_VALUE","message","multiline","name","NaN","NEGATIVE_INFINITY","number","PI","POSITIVE_INFINITY",
  "prototype","rightContext","source","SQRT1_2","SQRT2","undefined",

  # Methods
  "abs","acos","anchor","apply","asin",
  "atan","atan2","atEnd","big","blink","bold","call","ceil","charAt","charCodeAt","compile","concat","cos",
  "decodeURI","decodeURIComponent","dimensions","encodeURI","encodeURIComponent","escape","eval","exec",
  "exp","fixed","floor","fontcolor","fontsize","fromCharCode","getDate","getDay","getFullYear","getHours",
  "getItem","getMilliseconds","getMinutes","getMonth","getSeconds","getTime","getTimezoneOffset","getUTCDate",
  "getUTCDay","getUTCFullYear","getUTCHours","getUTCMilliseconds","getUTCMinutes","getUTCMonth","getUTCSeconds",
  "getVarDate","getYear","hasOwnProperty","indexOf","isFinite","isNaN","isPrototypeOf","italics","item","join",
  "lastIndexOf","lastMatch","lastParen","lbound","link","localeCompare","log","match","max","min","moveFirst",
  "moveNext","parse","parseFloat","parseInt","pop","pow","propertyIsEnumerable","push","random","replace",
  "reverse","round","search","setDate","setFullYear","setHours","setMilliseconds","setMinutes","setMonth",
  "setSeconds","setTime","setUTCDate","setUTCFullYear","setUTCHours","setUTCMilliseconds","setUTCMinutes",
  "setUTCMonth","setUTCSeconds","setYear","shift","sin","slice","small","sort","splice","split","sqrt","strike",
  "sub","substr","substring","sup","tan","test","toArray","toDateString","toExponential","toFixed","toGMTString",
  "toLocaleDateString","toLocaleLowerCase","toLocaleString","toLocaleTimeString","toLocaleUpperCase","toLowerCase",
  "toPrecision","toString","toTimeString","toUpperCase","toUTCString","ubound","unescape","unshift","unwatch","UTC",
  "valueOf","watch",

  # HTML Entity
  "nbsp","lt","gt","amp","apos","quot","cent","pound","yen","sect","copy","reg","times","divide",

  # DHTML Constant
  "ATTRIBUTE_NODE","CDATA_SECTION_NODE","COMMENT_NODE","DOCUMENT_FRAGMENT_NODE","DOCUMENT_NODE","DOCUMENT_TYPE_NODE",
  "ELEMENT_NODE","ENTITY_NODE","ENTITY_REFERENCE_NODE","NOTATION_NODE","PROCESSING_INSTRUCTION_NODE","TEXT_NODE",
  "NOTATION_FRAGMENT_NODE","DOMSTRING_SIZE_ERR","HIERARCHY_REQUEST_ERR","INDEX_SIZE_ERR","INUSE_ATTRIBUTE_ERR",
  "INVALID_ACCESS_ERR","INVALID_CHARACTER_ERR","INVALID_MODIFICATION_ERR","INVALID_STATE_ERR","NAMESPACE_ERR",
  "NOT_FOUND_ERR","NOT_SUPPORTED_ERR","NO_DATA_ALLOWED_ERR","NO_MODIFICATION_ALLOWED_ERR","SYNTAX_ERR",
  "WRONG_DOCUMENT_ERR","ABORT","BLUR","CLICK","CHANGE","DBLCLICK","DRAGDROP","ERROR","FOCUS","KEYDOWN","KEYPRESS",
  "KEYUP","LOAD","MOUSEDOWN","MOUSEMOVE","MOUSEOUT","MOUSEOVER","MOUSEUP","MOVE","RESET","RESIZE","SELECT","SUBMIT",
  "UNLOAD","NODE_BEFORE","NODE_AFTER","NODE_BEFORE_AND_AFTER","NODE_INSIDE","START_TO_START","START_TO_END",
  "END_TO_END","END_TO_START","BAD_BOUNDARYPOINTS_ERR","INVALID_NODE_TYPE_ERR","UNKNOWN_RULE","STYLE_RULE",
  "CHARSET_RULE","IMPORT_RULE","MEDIA_RULE","FONT_FACE_RULE","PAGE_RULE","CSS_UNKNOWN","CSS_NUMBER","CSS_PERCENTAGE",
  "CSS_EMS","CSS_EXS","CSS_PX","CSS_CM","CSS_MM","CSS_IN","CSS_PT","CSS_PC","CSS_DEG","CSS_RAD","CSS_GRAD","CSS_MS",
  "CSS_S","CSS_HZ","CSS_KHZ","CSS_DIMENSION","CSS_STRING","CSS_URI","CSS_IDENT","CSS_ATTR","CSS_COUNTER","CSS_RECT",
  "CSS_RGBCOLOR","CSS_INHERIT","CSS_PRIMITIVE_VALUE","CSS_VALUE_LIST","CSS_CUSTOM","STATE_MAXIMIZED","STATE_MINIMIZED",
  "STATE_NORMAL","DOCUMENT_POSITION_DISCONNECTED","DOCUMENT_POSITION_PRECEDING","DOCUMENT_POSITION_FOLLOWING",
  "DOCUMENT_POSITION_CONTAINS","DOCUMENT_POSITION_CONTAINED_BY","DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC",
  "CAPTURING_PHASE","AT_TARGET","BUBBLING_PHASE","MOUSEDOWN","MOUSEUP","MOUSEOVER","MOUSEOUT","MOUSEMOVE",
  "MOUSEDRAG","CLICK","DBLCLICK","KEYDOWN","KEYUP","KEYPRESS","DRAGDROP","FOCUS","BLUR","SELECT","CHANGE",
  "RESET","SUBMIT","SCROLL","LOAD","UNLOAD","XFER_DONE","ABORT","ERROR","LOCATE","MOVE","RESIZE","FORWARD",
  "HELP","BACK","TEXT","ALT_MASK","CONTROL_MASK","SHIFT_MASK","META_MASK","SCROLL_PAGE_UP","SCROLL_PAGE_DOWN",
  "DOM_VK_CANCEL","DOM_VK_HELP","DOM_VK_BACK_SPACE","DOM_VK_TAB","DOM_VK_CLEAR","DOM_VK_RETURN","DOM_VK_ENTER",
  "DOM_VK_SHIFT","DOM_VK_CONTROL","DOM_VK_ALT","DOM_VK_PAUSE","DOM_VK_CAPS_LOCK","DOM_VK_ESCAPE","DOM_VK_SPACE",
  "DOM_VK_PAGE_UP","DOM_VK_PAGE_DOWN","DOM_VK_END","DOM_VK_HOME","DOM_VK_LEFT","DOM_VK_UP","DOM_VK_RIGHT","DOM_VK_DOWN",
  "DOM_VK_PRINTSCREEN","DOM_VK_INSERT","DOM_VK_DELETE","DOM_VK_0","DOM_VK_1","DOM_VK_2","DOM_VK_3","DOM_VK_4","DOM_VK_5",
  "DOM_VK_6","DOM_VK_7","DOM_VK_8","DOM_VK_9","DOM_VK_SEMICOLON","DOM_VK_EQUALS","DOM_VK_A","DOM_VK_B","DOM_VK_C",
  "DOM_VK_D","DOM_VK_E","DOM_VK_F","DOM_VK_G","DOM_VK_H","DOM_VK_I","DOM_VK_J","DOM_VK_K","DOM_VK_L","DOM_VK_M",
  "DOM_VK_N","DOM_VK_O","DOM_VK_P","DOM_VK_Q","DOM_VK_R","DOM_VK_S","DOM_VK_T","DOM_VK_U","DOM_VK_V","DOM_VK_W",
  "DOM_VK_X","DOM_VK_Y","DOM_VK_Z","DOM_VK_CONTEXT_MENU","DOM_VK_NUMPAD0","DOM_VK_NUMPAD1","DOM_VK_NUMPAD2",
  "DOM_VK_NUMPAD3","DOM_VK_NUMPAD4","DOM_VK_NUMPAD5","DOM_VK_NUMPAD6","DOM_VK_NUMPAD7","DOM_VK_NUMPAD8","DOM_VK_NUMPAD9",
  "DOM_VK_MULTIPLY","DOM_VK_ADD","DOM_VK_SEPARATOR","DOM_VK_SUBTRACT","DOM_VK_DECIMAL","DOM_VK_DIVIDE","DOM_VK_F1",
  "DOM_VK_F2","DOM_VK_F3","DOM_VK_F4","DOM_VK_F5","DOM_VK_F6","DOM_VK_F7","DOM_VK_F8","DOM_VK_F9","DOM_VK_F10",
  "DOM_VK_F11","DOM_VK_F12","DOM_VK_F13","DOM_VK_F14","DOM_VK_F15","DOM_VK_F16","DOM_VK_F17","DOM_VK_F18","DOM_VK_F19",
  "DOM_VK_F20","DOM_VK_F21","DOM_VK_F22","DOM_VK_F23","DOM_VK_F24","DOM_VK_NUM_LOCK","DOM_VK_SCROLL_LOCK","DOM_VK_COMMA",
  "DOM_VK_PERIOD","DOM_VK_SLASH","DOM_VK_BACK_QUOTE","DOM_VK_OPEN_BRACKET","DOM_VK_BACK_SLASH","DOM_VK_CLOSE_BRACKET",
  "DOM_VK_QUOTE","DOM_VK_META","MODIFICATION","ADDITION","REMOVAL","INVALID_EXPRESSION_ERR","TYPE_ERR","ANY_TYPE",
  "NUMBER_TYPE","STRING_TYPE","BOOLEAN_TYPE","UNORDERED_NODE_ITERATOR_TYPE","ORDERED_NODE_ITERATOR_TYPE",
  "UNORDERED_NODE_SNAPSHOT_TYPE","ORDERED_NODE_SNAPSHOT_TYPE","ANY_UNORDERED_NODE_TYPE","FIRST_ORDERED_NODE_TYPE",
  "UNSPECIFIED_EVENT_TYPE_ERR",

  # DHTML Object
  "a","AbstractView","acronym","address","applet","area","Attr","attribute","b",
  "BarProp","base","baseFont","bdo","BeforeUnloadEvent","bgSound","big","blockQuote","body","br","button",
  "CanvasGradient","CanvasPattern","CanvasRenderingContext2D","caption","CDATASection","center","CharacterData",
  "ChromeWindow","cite","clientInformation","clipboardData","code","col","colGroup","comment","Comment","Counter",
  "CSS2Properties","CSSCharsetRule","CSSFontFaceRule","CSSImportRule","CSSMediaRule","CSSPageRule","CSSPrimitiveValue",
  "CSSRGBColor","CSSRule","CSSRuleList","CSSStyleDeclaration","CSSStyleRule","CSSStyleSheet","CSSUnknownRule",
  "CSSValue","CSSValueList","currentStyle","custom","dataTransfer","dd","defaults","del","dfn","dir","div","dl",
  "document","Document","DocumentCSS","DocumentEvent","DocumentFragment","DocumentRange","DocumentStyle",
  "DocumentType","DocumentView","DOMException","DOMImplementation","DOMImplementationCSS","DOMParser",
  "DOMStringList","dt","Element","ElementCSSInlineStyle","em","embed","Entity","EntityReference","event",
  "Event","EventException","EventListener","EventTarget","external","fieldSet","font","form","frame","frameSet",
  "h","head","history","History","hr","html","HTMLAnchorElement","HTMLAppletElement","HTMLAreaElement",
  "HTMLBRElement","HTMLBaseElement","HTMLBaseFontElement","HTMLBodyElement","HTMLButtonElement","HTMLCanvasElement",
  "HTMLCollection","HTMLDListElement","HTMLDirectoryElement","HTMLDivElement","HTMLDocument","HTMLDOMImplementation",
  "HTMLElement","HTMLEmbedElement","HTMLFieldSetElement","HTMLFontElement","HTMLFormElement","HTMLFrameElement",
  "HTMLFrameSetElement","HTMLHRElement","HTMLHeadElement","HTMLHeadingElement","HTMLHtmlElement","HTMLIFrameElement",
  "HTMLImageElement","HTMLInputElement","HTMLIsIndexElement","HTMLLIElement","HTMLLabelElement","HTMLLegendElement",
  "HTMLLinkElement","HTMLMapElement","HTMLMenuElement","HTMLMetaElement","HTMLModElement","HTMLOListElement",
  "HTMLObjectElement","HTMLOptGroupElement","HTMLOptionElement","HTMLOptionsCollection","HTMLParagraphElement",
  "HTMLParamElement","HTMLPreElement","HTMLQuoteElement","HTMLScriptElement","HTMLSelectElement","HTMLStyleElement",
  "HTMLTableCaptionElement","HTMLTableCellElement","HTMLTableColElement","HTMLTableElement","HTMLTableRowElement",
  "HTMLTableSectionElement","HTMLTextAreaElement","HTMLTitleElement","HTMLUListElement","i","iframe","ImageDocument",
  "img","implementation","IMPORT","input","ins","isIndex","kbd","KeyboardEvent","KeyEvent","label","legend","li",
  "link","LinkStyle","listing","location","Location","map","marquee","MediaList","menu","meta","MimeType",
  "MimeTypeArray","MouseEvent","MutationEvent","NamedNodeMap","NameList","namespace","navigator","Navigator",
  "nextID","noBR","Node","NodeList","noFrames","noScript","Notation","NSDocument","NSEvent","NSHTMLAnchorElement",
  "NSHTMLAreaElement","NSHTMLButtonElement","NSHTMLDocument","NSHTMLElement","NSHTMLFormElement","NSHTMLFrameElement",
  "NSHTMLHRElement","NSHTMLImageElement","NSHTMLInputElement","NSHTMLOptionElement","NSHTMLSelectElement",
  "NSHTMLTextAreaElement","NSRange","NSUIEvent","object","ol","optGroup","option","p","page","PageTransitionEvent",
  "param","plainText","Plugin","PluginArray","popup","PopupBlockedEvent","pre","ProcessingInstruction","q","Range",
  "RangeException","Rect","RGBColor","rt","ruby","rule","runtimeStyle","s","samp","SchemaLoader","screen","Screen",
  "script","select","selection","Selection","small","SmartCardEvent","span","strike","strong","style","styleSheet",
  "StyleSheet","StyleSheetList","sub","sup","Supports","table","TableSectionElement","tBody","td","Text","textArea",
  "TextNode","TextRange","TextRectangle","tFoot","th","tHead","title","tr","TreeWalker","tt","u","UIEvent","ul",
  "userProfile","URI","var","ViewCSS","wbr","WebBrowser","WebNavigation","window","Window","Window2","WindowCollection",
  "WindowInternal","xml","XMLDocument","XMLHttpRequest","XMLSerializer","xmp","XPathEvaluator","XPathException",
  "XPathExpression","XPathNSResolver","XPathResult","XPointerResult","XSLTProcessor",

  # DHTML Property
  "_content","abbr","accelerator",
  "accept","acceptCharset","accessKey","action","activeElement","additive","align","aLink","alinkColor","allowTransparency",
  "alt","altHTML","altKey","altLeft","anchorNode","anchorOffset","appCodeName","APPLICATION","appMinorVersion","appName",
  "appVersion","archive","async","ATOMICSELECTION","attrChange","attrName","autocomplete","availHeight","availLeft",
  "availTop","availWidth","azimuth","axis","background","backgroundAttachment","backgroundColor","backgroundImage",
  "backgroundPosition","backgroundPositionX","backgroundPositionY","backgroundRepeat","balance","Banner",
  "BannerAbstract","BaseHref","baseURI","behavior","bgColor","BGCOLOR","bgProperties","blockDirection","blue",
  "booleanValue","border","borderBottom","borderBottomColor","borderBottomStyle","borderBottomWidth","borderCollapse",
  "borderColor","borderColorDark","borderColorLight","borderLeft","borderLeftColor","borderLeftStyle","borderLeftWidth",
  "borderRight","borderRightColor","borderRightStyle","borderRightWidth","borderSpacing","borderStyle","borderTop",
  "borderTopColor","borderTopStyle","borderTopWidth","borderWidth","borderWidths","bottom","bottomMargin","boundingHeight",
  "boundingLeft","boundingTop","boundingWidth","browserDOMWindow","browserLanguage","bubbles","bufferDepth","button",
  "cancelable","cancelBubble","canHaveChildren","canHaveHTML","canvas","caption","captionSide","cellIndex","cellPadding",
  "cellSpacing","ch","channel","charCode","charset","checked","characterSet","chOff","cite","classid","className",
  "clear","clientHeight","clientLeft","clientTop","clientWidth","clientX","clientY","clip","clipBottom","clipLeft",
  "clipRight","clipTop","cloneContents","closed","code","codeBase","codeType","collapsed","color","colorDepth","cols",
  "colSpan","columnNumber","commonAncestorContainer","compact","compatMode","complete","content","contentDocument",
  "contentEditable","contentOverflow","contentType","contentWindow","cookie","cookieEnabled","coords","Count",
  "counterIncrement","counterReset","cpuClass","crypto","cssFloat","cssRules","cssText","cssValueType","ctrlKey",
  "ctrlLeft","cue","cueAfter","cueBefore","current","currentNode","currentTarget","cursor","data","dataFld","DATAFLD",
  "dataFormatAs","DATAFORMATAS","dataPageSize","dataSrc","DATASRC","dateTime","declare","defaultCharset",
  "defaultChecked","defaultSelected","defaultStatus","defaultValue","defaultView","defer","description","designMode",
  "detail","deviceXDPI","deviceYDPI","dialogArguments","dialogHeight","dialogLeft","dialogTop","dialogWidth","dir",
  "direction","directories","disabled","display","displays","doctype","document","documentElement","documentURI",
  "domain","domConfig","dropEffect","dynsrc","effectAllowed","elevation","emptyCells","enabledPlugin","encoding",
  "enctype","endContainer","endOffset","entities","event","eventPhase","expandEntityReferences","expando",
  "explicitOriginalTarget","face","fgColor","FieldDelim","fileCreatedDate","fileModifiedDate","filename","fileSize",
  "fileUpdatedDate","fillStyle","filter","firstChild","focusNode","focusOffset","font","fontFamily","fontSize",
  "fontSizeAdjust","fontSmoothingEnabled","fontStretch","fontStyle","fontVariant","fontWeight","form","formName",
  "frame","frameBorder","frameElement","frameSpacing","fromElement","fullScreen","galleryImg","globalAlpha",
  "globalCompositeOperation","green","hash","hasLayout","headers","height","hidden","hideFocus","history","host",
  "hostname","href","hreflang","hspace","htmlFor","htmlText","httpEquiv","id","identifier","imageIsOverflowing",
  "imageIsResized","imageRequest","imageResizingEnabled","imeMode","implementation","indeterminate","index","inner",
  "innerHeight","innerHTML","innerText","innerWidth","inputEncoding","internalSubset","invalidIteratorState","isChar",
  "isCollapsed","isContentEditable","isDisabled","isMap","isMultiLine","isOpen","isTextEdit","isTrusted","keyCode",
  "label","lang","language","lastChild","lastModified","layerX","layerY","layoutFlow","layoutGrid","layoutGridChar",
  "layoutGridLine","layoutGridMode","layoutGridType","left","leftMargin","length","letterSpacing","lineBreak","lineCap",
  "lineHeight","lineJoin","lineNumber","lineWidth","link","linkColor","listStyle","listStyleImage","listStylePosition",
  "listStyleType","localName","location","locationbar","logicalXDPI","logicalYDPI","longDesc","loop","loop","lowsrc",
  "lowSrc","margin","marginBottom","marginHeight","marginLeft","marginRight","margins","marginTop","marginWidth",
  "markerOffset","marks","maxHeight","maxLength","maxWidth","media","mediaText","menuArguments","menubar","message",
  "metaKey","method","Methods","minHeight","minWidth","miterLimit","MozAppearance","MozBackgroundClip",
  "MozBackgroundInlinePolicy","MozBackgroundOrigin","MozBinding","MozBorderBottomColors","MozBorderLeftColors",
  "MozBorderRadius","MozBorderRadiusBottomleft","MozBorderRadiusBottomright","MozBorderRadiusTopleft",
  "MozBorderRadiusTopright","MozBorderRightColors","MozBorderTopColors","MozBoxAlign","MozBoxDirection","MozBoxFlex",
  "MozBoxOrdinalGroup","MozBoxOrient","MozBoxPack","MozBoxSizing","MozColumnCount","MozColumnGap","MozColumnWidth",
  "MozFloatEdge","MozForceBrokenImageIcon","MozImageRegion","MozMarginEnd","MozMarginStart","MozOpacity","MozOutline",
  "MozOutlineColor","MozOutlineOffset","MozOutlineRadius","MozOutlineRadiusBottomleft","MozOutlineRadiusBottomright",
  "MozOutlineRadiusTopleft","MozOutlineRadiusTopright","MozOutlineStyle","MozOutlineWidth","MozPaddingEnd",
  "MozPaddingStart","MozUserFocus","MozUserInput","MozUserModify","MozUserSelect","multipart","multiple","name",
  "nameProp","namespaceURI","naturalHeight","naturalWidth","navigator","newValue","next","nextPage","nextSibling",
  "nodeName","nodeType","nodeValue","noHref","noResize","noShade","notationName","notations","noWrap","numberValue",
  "object","offscreenBuffering","offsetHeight","offsetLeft","offsetParent","offsetTop","offsetWidth","offsetX",
  "offsetY","onBefore","onLine","opacity","opener","originalTarget","orphans","oscpu","outerHeight","outerHTML",
  "outerText","outerWidth","outline","outlineColor","outlineOffset","outlineStyle","outlineWidth","overflow","overflowX",
  "overflowY","ownerDocument","ownerElement","ownerNode","ownerRule","owningElement","padding","paddingBottom",
  "paddingLeft","paddingRight","paddings","paddingTop","page","pageBreakAfter","pageBreakBefore","pageBreakInside",
  "pageX","pageXOffset","pageY","pageYOffset","palette","parent","parentElement","parentNode","parentRule",
  "parentStyleSheet","parentTextEdit","parentWindow","pathname","pause","pauseAfter","pauseBefore","persisted",
  "personalbar","pitch","pitchRange","pixelBottom","pixelDepth","pixelHeight","pixelLeft","pixelRight","pixelTop",
  "pixelWidth","pkcs11","platform","playDuring","pluginspage","popupWindowFeatures","popupWindowURI","port","posBottom",
  "posHeight","position","posLeft","posRight","posTop","posWidth","preferredStylesheetSet","prefix","previous",
  "previousSibling","prevValue","primitiveType","product","productSub","profile","prompt","prompter","propertyName",
  "protocol","pseudoClass","publicId","qualifier","quotes","rangeCount","rangeOffset","rangeParent","readOnly",
  "readyState","reason","recordNumber","recordset","red","referrer","rel","relatedNode","relatedTarget","repeat",
  "requestingWindowURI","responseText","responseXML","result","resultType","returnValue","rev","richness","right",
  "rightMargin","root","rowIndex","rows","rowSpan","rubyAlign","rubyOverhang","rubyPosition","rules","saveType",
  "scheme","scope","scopeName","screen","screenLeft","screenTop","screenX","screenY","scroll","scrollAmount",
  "scrollbar3dLightColor","scrollbarArrowColor","scrollbarBaseColor","scrollbarDarkShadowColor","scrollbarFaceColor",
  "scrollbarHighlightColor","scrollbars","scrollbarShadowColor","scrollbarTrackColor","scrollDelay","scrollHeight",
  "scrolling","scrollLeft","scrollMaxX","scrollMaxY","scrollTop","scrollX","scrollY","scrollWidth","search",
  "sectionRowIndex","SECURITY","securityPolicy","selected","selectedIndex","selectionEnd","selectionStart","selector",
  "selectorText","self","separator","shape","sheet","shadowBlur","shadowColor","shadowOffsetX","shadowOffsetY",
  "shiftKey","shiftLeft","sidebar","singleNodeValue","size","snapshotLength","sourceIndex","span","speak","speakHeader",
  "speakNumeral","speakPunctuation","specified","speechRate","src","srcElement","srcFilter","srcUrn","standby","start",
  "startContainer","startOffset","status","statusbar","statusText","stress","strictErrorChecking","stringValue",
  "strokeStyle","style","STYLE","styleFloat","styleSheet","suffixes","summary","systemId","systemLanguage","tabIndex",
  "tableLayout","tabStop","tagName","tagUrn","target","text","textAlign","textAlignLast","textAutospace","textContent",
  "textDecoration","textDecorationBlink","textDecorationLineThrough","textDecorationNone","textDecorationOverline",
  "textDecorationUnderline","textIndent","textJustify","textKashidaSpace","textLength","textOverflow","textShadow",
  "textTransform","textUnderlinePosition","textZoom","tFoot","tHead","timeStamp","title","tmpRealOriginalTarget",
  "toElement","tokenName","toolbar","top","topMargin","trueSpeed","type","typeDetail","unicodeBidi","uniqueID","units",
  "unselectable","UNSELECTABLE","updateInterval","URL","URLUnencoded","urn","useMap","userAgent","userLanguage","vAlign",
  "value","valueType","vcard_name","vendor","vendorSub","version","verticalAlign","view","viewInheritStyle","viewLink",
  "viewMasterTab","visibility","visible","vLink","vlinkColor","voiceFamily","volume","vspace","whatToShow","wheelDelta",
  "which","whiteSpace","widows","width","window","windowRoot","windowState","wordBreak","wordSpacing","wordWrap","wrap",
  "writingMode","x","XMLDocument","xmlEncoding","XMLNS","xmlStandalone","xmlVersion","XSLDocument","y","zIndex","zoom",

  # DHTML Method
  "abort","add","addBehavior","addBinding","addColorStop","addEventListener","AddChannel","AddDesktopComponent",
  "addElement","AddFavorite","addImport","addPageRule","addRange","addReadRequest","addRule","adoptNode","alert",
  "appendChild","appendData","appendMedium","applyElement","arc","arcTo","assign","atob","attachEvent",
  "AutoCompleteSaveForm","AutoScan","back","beginPath","bezierCurveTo","blur","btoa","captureEvents","ChooseColorDlg",
  "clear","clearAttributes","clearData","clearInterval","clearParameters","clearRect","clearRequest","clearTimeout",
  "click","clip","cloneNode","cloneRange","close","closePath","collapse","collapseToEnd","collapseToStart",
  "compareBoundaryPoints","compareDocumentPosition","compareEndPoints","compareNode","comparePoint","componentFromPoint",
  "confirm","contains","containsNode","containsNS","createAttribute","createAttributeNS","createCaption",
  "createCDATASection","createComment","createContextualFragment","createControlRange","createCSSStyleSheet",
  "createDocument","createDocumentFragment","createDocumentType","createElement","createElementNS",
  "createEntityReference","createEvent","createEventObject","createExpression","createLinearGradient",
  "createHTMLDocument","createNodeIterator","createNSResolver","createPattern","createPopup",
  "createProcessingInstruction","createRadialGradient","createRange","createRangeCollection","createStyleSheet",
  "createTextNode","createTextRange","createTFoot","createTHead","createTreeWalker","deleteCaption","deleteCell",
  "deleteContents","deleteData","deleteFromDocument","deleteMedium","deleteRow","deleteRule","deleteTFoot",
  "deleteTHead","detach","detachEvent","disableExternalCapture","dispatchEvent","doImport","doReadRequest",
  "doScroll","dragDrop","drawImage","dump","duplicate","elementFromPoint","enableExternalCapture","empty",
  "escape","evaluate","evaluateFIXptr","evaluateWithContext","evaluateXPointer","execCommand","execCommandShowHelp",
  "execScript","expand","extend","extractContents","fill","fillRect","find","findText","fireEvent","firstPage",
  "focus","forward","getAdjacentText","getAllResponseHeaders","getAnonymousElementByAttribute","getAnonymousNodes",
  "getAttention","getAttentionWithCycleCount","getAttribute","getAttributeNode","getAttributeNodeNS","getAttributeNS",
  "getBindingParent","getBookmark","getBoundingClientRect","getBoxObjectFor","getCharset","getClientRects",
  "getComputedStyle","getContext","getCounterValue","getData","getElementById","getElementsByName","getElementsByTagName",
  "getElementsByTagNameNS","getExpression","getFeature","getFloatValue","getName","getNamedItem","getNamedItemNS",
  "getNamespaceURI","getOverrideStyle","getParameter","getPreventDefault","getPropertyCSSValue","getPropertyPriority",
  "getPropertyValue","getRangeAt","getRectValue","getResponseHeader","getRGBColorValue","getSelection","getStringValue",
  "getSVGDocument","getUserData","go","hasAttribute","hasAttributeNS","hasAttributes","hasChildNodes","hasFeature",
  "hasFocus","hide","home","ImportExportFavorites","importNode","importStylesheet","Init","initEvent","initKeyEvent",
  "initMouseEvent","initMutationEvent","initPageTransitionEvent","initPopupBlockedEvent","initUIEvent","inRange",
  "insertNode","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","insertBefore","insertCell","insertData",
  "insertRow","insertRule","intersectsNode","isDefaultNamespace","isEqual","isEqualNode","isPointInRange","isSameNode",
  "IsSubscribed","isSupported","item","Item","iterateNext","javaEnabled","lastPage","lineTo","load","loadAsync",
  "loadBindingDocument","loadOverlay","lookupNamespaceURI","lookupPrefix","maximize","mergeAttributes","minimize",
  "move","moveBy","moveEnd","moveRow","moveStart","moveTo","moveToBookmark","moveToElementText","moveToPoint",
  "namedItem","namedRecordset","navigate","NavigateAndFind","nextNode","nextPage","normalize","normalizeDocument",
  "nSDetach","open","openDialog","openRequest","overrideMimeType","parentElement","parseFromBuffer","parseFromStream",
  "parseFromString","pasteHTML","preference","preventBubble","preventCapture","preventDefault","previousNode",
  "previousPage","print","processSchemaElement","prompt","quadraticCurveTo","queryCommandEnabled","queryCommandIndeterm",
  "queryCommandState","queryCommandSupported","queryCommandText","queryCommandValue","recalc","rect","refresh",
  "releaseCapture","releaseEvents","reload","remove","removeAllRanges","removeAttribute","removeAttributeNode",
  "removeAttributeNS","removeBehavior","removeBinding","removeChild","removeEventListener","removeExpression",
  "removeNamedItem","removeNamedItemNS","removeNode","removeParameter","removeProperty","removeRange","removeRule",
  "renameNode","replace","replaceAdjacentText","replaceChild","replaceData","replaceNode","reset","resizeBy",
  "resizeTo","restore","restoreImage","restoreImageTo","rotate","routeEvent","save","scale","scroll","scrollBy",
  "scrollByLines","scrollByPages","scrollIntoView","scrollTo","select","selectAllChildren","selectionLanguageChange",
  "selectNode","selectNodeContents","send","serializeToStream","serializeToString","setActive","setAttribute",
  "setAttributeNode","setAttributeNodeNS","setAttributeNS","setBoxObjectFor","setCapture","setCursor","setData",
  "setEnd","setEndAfter","setEndBefore","setEndPoint","setExpression","setFloatValue","setInterval","setNamedItem",
  "setNamedItemNS","setParameter","setProperty","setPropertyPriority","setRequestHeader","setResizable",
  "setSelectionRange","setStart","setStartAfter","setStartBefore","setStringValue","setTimeout","setUserData",
  "show","ShowBrowserUI","showHelp","showModalDialog","showModelessDialog","shrinkToFit","sizeToContent",
  "snapshotItem","splitText","start","stop","stopPropagation","stroke","strokeRect","submit","substringData",
  "supports","surroundContents","swapNode","tags","taintEnabled","toggleImageSize","transformToDocument",
  "transformToFragment","translate","unescape","updateCommands","urns","write","writeln",

  # DHTML Event
  "onabort","onactivate",
  "onafterprint","onafterupdate","onbeforeactivate","onbeforecopy","onbeforecut","onbeforedeactivate","onbeforeeditfocus",
  "onbeforepaste","onbeforeprint","onbeforeunload","onbeforeupdate","onblur","onbounce","oncellchange","onchange",
  "onclick","onclose","oncontextmenu","oncontrolselect","oncopy","oncut","ondataavailable","ondatasetchanged",
  "ondatasetcomplete","ondblclick","ondeactivate","ondrag","ondragdrop","ondragend","ondragenter","ondragleave",
  "ondragover","ondragstart","ondrop","onerror","onerrorupdate","onfilterchange","onfinish","onfocus","onfocusin",
  "onfocusout","onhelp","onkeydown","onkeypress","onkeyup","onlayoutcomplete","onload","onlosecapture","onmousedown",
  "onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onmove","onmoveend",
  "onmovestart","onpaint","onpaste","onprogress","onpropertychange","onreadystatechange","onreset","onresize",
  "onresizeend","onresizestart","onrowenter","onrowexit","onrowsdelete","onrowsinserted","onscroll","onselect",
  "onselectionchange","onselectstart","onstart","onstop","onsubmit","onunload",

  # DHTML Collection
  "all","anchors","applets","areas",
  "attributes","behaviorUrns","blockFormats","bookmarks","boundElements","cells","childNodes","children","classes",
  "Components","controllers","controlRange","elements","embeds","filters","fonts","forms","frames","ids","images",
  "imports","interfaces","layers","links","mimeTypes","namespaces","options","pages","plugins","rows","rules","scripts",
  "styleSheets","tBodies","TextRange","TextRectangle",

  # IE Default Behavior
  "anchorClick","anim","clientCaps","download","homePage","httpFolder",
  "mediaBar","saveFavorite","saveHistory","saveSnapshot","userData",

  # IE Default Behavior Object
  "MediaItem","PlaylistInfo",

  # IE Default Behavior Property
  "attributeCount",
  "availHeight","availWidth","bufferDepth","colorDepth","connectionType","cookieEnabled","cpuClass","currentItem",
  "disabledUI","duration","enabled","expires","folder","hasNextItem","height","image","javaEnabled","name","nextItem",
  "openState","platform","playlistInfo","playState","sound","sourceURL","statics","systemLanguage","target",
  "userLanguage","width","XMLDocument",

  # IE Default Behavior Method
  "addComponentRequest","addDABehavior","clearComponentRequest","compareVersions",
  "doComponentRequest","getAttribute","getAttributeName","getComponentVersion","getItemInfo","isComponentInstalled",
  "isHomePage","load","navigate","navigateFrame","navigateHomePage","playNext","playURL","removeAttribute",
  "removeDABehavior","save","setAttribute","setHomePage","startDownload","stop",

  # IE Default Behavior Event
  "onhide","onload","onopenstatechange",
  "onplaystatechange","onsave","onshow",

  # XMLHTTP Object Property
  "onreadystatechange","readyState","responseBody","responseStream","responseText",
  "responseXML","status","statusText",

  # XMLHTTP Object Method
  "abort","getAllResponseHeaders","getResponseHeader","open","send",
  "setRequestHeader"
]


def search(node, names):

  if node.type == "assignment":
    left = node.getChild("left", False)

    if left:
      variable = left.getChild("variable", False)

      if variable:
        last = variable.getLastChild()
        first = variable.getFirstChild()

        if last == first:
          if last.type == "identifier":
            pass

        elif last.type == "identifier":
          name = last.get("name")

          ignore = False

          if name in systemNames or name in qooxdooNames:
            ignore = True

          if not ignore:
            for item in qooxdooStart:
              if name.startswith(item):
                ignore = True

          # only apply to names which starts with an underscore
          if not name.startswith("_"):
            ignore = True

          if not ignore:
            if not names.has_key(name):
              # print "Add %s" % name

              names[name] = 1
            else:
              names[name] += 1

  if node.hasChildren():
    for child in node.children:
      search(child, names)

  return names




def update(node, list, prefix):
  counter = 0

  if node.type == "identifier":
    idenName = node.get("name", False)

    if idenName != None and idenName in list:
      replName = "%s%s" % (prefix, mapper.convert(list.index(idenName)))
      node.set("name", replName)
      counter += 1

      # print "  - Replaced '%s' with '%s'" % (idenName, replName)

  if node.hasChildren():
    for child in node.children:
      counter += update(child, list, prefix)

  return counter



def sort(names):
  temp = []

  for name in names:
    temp.append({ "name" : name, "number" : names[name] })

  temp.sort(lambda x, y: y["number"]-x["number"])

  list = []

  for item in temp:
    list.append(item["name"])

  print "  * Found %s names" % len(list)

  return list
