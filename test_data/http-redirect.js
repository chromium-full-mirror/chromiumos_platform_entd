var url = "www.google.com";
var params = new Array("name=me");
var headers = new Array("foo: bar");

var req = new entd.http.Request(url, params, headers);
function complete(response)
{
  println("HTTP COMPLETE. URL=" + response.url +
          ", CODE=" + response.code +
          ", CONTENT SIZE=" + response.content.length +
          ", HEADERS: " + response.headers.length);
//   println("CONTENT:");
//   println(response.content);
}
function timeout()
{
  println("HTTP TIMEOUT");
}
function error(errcode)
{
  println("HTTP ERROR: " + errcode);
}

req.onComplete = complete;
req.onTimeout = timeout;
req.onError = error;

entd.http.GET(req);
