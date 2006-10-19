(function()
{
  document.write('<div id="demoFoot">');
  document.write('</div>');

  document.write('<div id="demoDebug">');
  document.write('</div>');
  
  document.write('<div id="demoFrame">');
  document.write('&#160;');
  document.write('</div>');

  qx.dev.log.Logger.ROOT_LOGGER.removeAllAppenders();
  qx.dev.log.Logger.ROOT_LOGGER.addAppender(new qx.dev.log.DivAppender("demoDebug"));
})();
