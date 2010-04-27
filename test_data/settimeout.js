println("starting timeouts");

entd.setTimeout("println('string timeout')", 1000);

entd.setTimeout(function () { println('function timeout') }, 2000);
