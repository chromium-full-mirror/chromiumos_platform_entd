var url = "https://www.cia.gov";
var params = new Array("name=me");
var headers = new Array("foo: bar");

var req = new entd.http.Request(url, params, headers);
req.onComplete = function complete(response)
{
  println("HTTP COMPLETE. URL=" + response.url +
          ", CODE=" + response.code +
          ", CONTENT SIZE=" + response.content.length +
          ", HEADERS: " + response.headers.length);
//   print("CONTENT:");
//   print(response.content);
}
req.onTimeout = function timeout()
{
  println("HTTP TIMEOUT");
}
req.onError = function error(errcode)
{
  println("HTTP ERROR: " + errcode);
}

entd.http.GET(req);
entd.http.POST(req);
// println("REQ: " + JSON.stringify(req));
