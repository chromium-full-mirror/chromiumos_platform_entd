var req;
foo = entd.http.GET;
//foo(req);
//entd.http.GET();
entd.onLoad =
function onLoad(manifest)
{
  entd.http.GET(req);
}
