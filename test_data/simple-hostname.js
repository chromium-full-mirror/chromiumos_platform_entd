entd.onLoad = function () {
  println("Hostname: " + entd.hostname);

  // Should be able to make the current hostname more specific.
  entd.hostname = "corp." + entd.hostname;

  // Should be able to add a single character subdomain.
  entd.hostname = "a." + entd.hostname;

  // Current hostname, backwards.  Ensures that we're the same length but not
  // the same string (unless the hostname is something dumb like 'xxx' :).
  var tsoh = entd.hostname.split('').reverse().join('');

  // Should not be able to pick a different host of the same length.
  if (!test(tsoh))
    return;

  // Or a subdomain of a different host of the same length.
  if (!test("foo." + tsoh))
    return;

  // Should not be able to pick an entirely new hostname.
  if (!test("evil.com"))
    return;

  // Should not be able to alter the current hostname, only add subdomains.
  if (!test("xx" + entd.hostname))
    return;

  // This would be an invalid hostname, but we should catch it here anyway.
  if (!test("." + entd.hostname))
    return;

  // Should not be able to use any non-letter, number, [.-] characters.
  var ary = "`~!@#$%^&*()_+=\|/?>,<[]{}".split('');
  for (var i = 0; i < ary.length; ++i) {
    if (!test(ary[i] + "." + entd.hostname))
      return;
  }

  println("LOOKS OK");
}

function test(host) {
  try {
    entd.hostname = host;
  } catch (ex) {
    return (ex == "Invalid hostname");
  }

  return false;
}
