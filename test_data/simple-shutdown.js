
var timeoutFired = false;

entd.onLoad = function() {
  // Start the callback server so we can be sure entd wouldn't stop on its
  // own.
  entd.callbackServer.start({});
  entd.setTimeout('timeoutFired = true', 250);
  entd.scheduleShutdown(0, 500);
}

entd.onUnload = function() {
  if (timeoutFired) {
    println("LOOKS OK");
  } else {
    println("timeout didn't fire before shutdown.");
  }
}
