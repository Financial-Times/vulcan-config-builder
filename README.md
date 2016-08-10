# vulcan-config-builder

A simple application to interpret FT etcd service configuration and apply our routing policies to it, and setting the corresponding vulcand configuration in etcd.

Instead of configuring vulcand directly in etcd, this tool allows a more declarative approach, and keeps all of the policy logic about how to configure vulcand elsewhere (i.e., in this application)

Example
```
etcdctl set   /ft/services/service-a/healthcheck      true
etcdctl set   /ft/services/service-a/servers/1        "http://host:5678"
etcdctl set   /ft/services/service-a/path-regex/foo   /foo/.*
etcdctl set   /ft/services/service-a/path-regex/bar   /bar/.*
etcdctl set   /ft/services/service-a/path-host/bar  public-host
etcdctl set   /ft/services/service-a/failover         "(IsNetworkError() || ResponseCode() == 503 || ResponseCode() == 500) && Attempts() <= 1" //default failover value if /ft/services/service-a/failover key is missing is empty
```

will result in

```
# "main" backend & server(s)
/vulcand/backends/vcb-service-a-1/backend      {"Type": "http", "Settings": {"KeepAlive": {"MaxIdleConnsPerHost": 256, "Period": "35s"}}}
/vulcand/backends/vcb-service-a-1/servers/1    {"url":"http://host:5678"}

# instance backend & server(s)
/vulcand/backends/vcb-service-a/backend      {"Type":"http", "Settings": {"KeepAlive": {"MaxIdleConnsPerHost": 256, "Period": "35s"}}}
/vulcand/backends/vcb-service-a/servers/1    {"url":"http://host:5678"}

# internal routing frontend
/vulcand/frontends/vcb-internal-service-a/frontend            {"Type":"http", "BackendId":"vcb-service-a", "Route":"PathRegexp(`/__service-a/.*`)", "Settings": {"FailoverPredicate":"(IsNetworkError() || ResponseCode() == 503 || ResponseCode() == 500) && Attempts() <= 1"}}
/vulcand/frontends/vcb-internal-service-a/middlewares/rewrite {"Id":"rewrite", "Type":"rewrite", "Priority":1, "Middleware": {"Regexp":"/__service-a(/.*)", "Replacement":"$1"}}

# health check routing
/vulcand/frontends/vcb-health-service-a-1/frontend             {"Type":"http", "BackendId":"vcb-service-a-1", "Route":"Path(`/health/service-a-1/__health`)", "Settings": {"FailoverPredicate":""}}
/vulcand/frontends/vcb-health-service-a-1/middlewares/rewrite  {"Id":"rewrite", "Type":"rewrite", "Priority":1, "Middleware": {"Regexp":"/health/service-a-1(.*)", "Replacement":"$1"}}

# host header based routing
/vulcand/frontends/vcb-byhostheader-service-a/frontend         {"Type":"http", "BackendId":"vcb-service-a", "Route":"PathRegexp(`/.*`) && Host(`service-a`)", "Settings": {"FailoverPredicate":"(IsNetworkError() || ResponseCode() == 503 || ResponseCode() == 500) && Attempts() <= 1"}}

# etcdctl set   /ft/services/service-a/path-regex/foo   /foo/.*
# "public" routing
/vulcand/frontends/vcb-service-a-path-regex-foo/frontend  {"Type":"http", "BackendId":"vcb-service-a", "Route":"PathRegexp(`/foo/.*`)", "Settings": {"FailoverPredicate":"(IsNetworkError() || ResponseCode() == 503 || ResponseCode() == 500) && Attempts() <= 1"}}

# etcdctl set   /ft/services/service-a/path-regex/bar   /bar/.*
# etcdctl set   /ft/services/service-a/path-host/bar  public-host
# "public" routing with custom header
/vulcand/frontends/vcb-service-a-path-regex-bar/frontend  {"Type":"http", "BackendId":"vcb-service-a", "Route":"PathRegexp(`/bar/.*`) && Host(`public-host`)", "Settings": {"FailoverPredicate":"(IsNetworkError() || ResponseCode() == 503 || ResponseCode() == 500) && Attempts() <= 1"}}
```

These routing rules will change as we develop. The idea is they are in a single place in this application, not spread out across many unmaintainable sidekick services.

## Test the app locally

1. Install [__etcd__](https://github.com/coreos/etcd) and run.
2. `go get github.com/Financial-Times/vulcan-config-builder && cd $GOPATH/src/github.com/Financial-Times/vulcan-config-builder`
3. `go test`
