function println(msg) {
  print(msg + '\n');
}

println("starting timeouts");

var h = entd.setTimeout("println('string timeout')", 1000);
println("h: " + h);

var h2 = entd.setTimeout(function () { println('function timeout') }, 2000);
println("h2: " + h2);

entd.clearTimeout(h);
