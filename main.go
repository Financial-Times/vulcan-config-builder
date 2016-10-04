package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/etcd/client"
	etcderr "github.com/coreos/etcd/error"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

var (
	socksProxy              = os.Getenv("VCB_SOCK_PROXY")
	etcdPeers               = os.Getenv("VCB_ETCD_PEERS")
	cooldownPeriod          = os.Getenv("VCB_COOLDOWN_PERIOD")
	notificationsBufferSize = os.Getenv("VCB_NOTIFICATIONS_BUFFER_SIZE")

	addressRegex = regexp.MustCompile(`^[.\-:/\w]*:[0-9]{2,5}$`)
)

func main() {
	if etcdPeers == "" {
		etcdPeers = "http://localhost:2379"
	}

	transport := client.DefaultTransport

	if socksProxy != "" {
		dialer, _ := proxy.SOCKS5("tcp", socksProxy, nil, proxy.Direct)
		transport = &http.Transport{Dial: dialer.Dial}
	}

	peers := strings.Split(etcdPeers, ",")
	log.Printf("etcd peers are %v\n", peers)

	cfg := client.Config{
		Endpoints:               peers,
		Transport:               transport,
		HeaderTimeoutPerRequest: 5 * time.Second,
	}

	etcd, err := client.New(cfg)
	if err != nil {
		log.Fatalf("failed to start etcd client: %v\n", err.Error())
	}

	cooldown := 30
	if cooldownPeriod != "" {
		cooldown, err = strconv.Atoi(cooldownPeriod)
		if err != nil {
			log.Printf("WARN - The provided cooldownPeriod=%s is invalid, using default value=%v", cooldownPeriod, cooldown)
		}
	}

	bufferSize := 128
	if notificationsBufferSize != "" {
		bufferSize, err = strconv.Atoi(notificationsBufferSize)
		if err != nil {
			log.Printf("WARN - The provided notificationsBufferSize=%s is invalid, using default value=%v", notificationsBufferSize, bufferSize)
		}
	}

	kapi := client.NewKeysAPI(etcd)
	notifier := newNotifier(kapi, "/ft/services/", bufferSize)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	for {
		reconfigStartTime := time.Now()
		log.Println("rebuilding configuration")
		// since vcb reads all the changes made in etcd, all notifications still in the channel can be ignored.
		drainChannel(notifier.notify())
		applyVulcanConf(kapi, buildVulcanConf(readServices(kapi)))
		log.Printf("completed reconfiguration. %v\n", time.Since(reconfigStartTime))

		// wait for a change
		select {
		case <-c:
			log.Println("exiting")
			return
		case <-notifier.notify():
		}

		log.Printf("change detected, waiting in cooldown period for %v", cooldown)
		<-time.After(time.Duration(cooldown) * time.Second)
	}

}

func drainChannel(notifications <-chan struct{}) {
	readNotifications := true
	log.Println("draining notifications channel")
	for readNotifications {
		select {
		case <-notifications:
		default:
			readNotifications = false
		}
	}
	log.Println("finished draining notifications channel")
}

type service struct {
	name              string
	hasHealthCheck    bool
	addresses         map[string]string
	pathPrefixes      map[string]string
	pathHosts         map[string]string
	failoverPredicate string
}

func readServices(kapi client.KeysAPI) []service {
	resp, err := kapi.Get(context.Background(), "/ft/services/", &client.GetOptions{Recursive: true})
	if err != nil {
		log.Println("error reading etcd keys.")
		if e, _ := err.(client.Error); e.Code == etcderr.EcodeKeyNotFound {
			log.Println("core key not found.")
			return []service{}
		}
		log.Panicf("failed to read from etcd: %v\n", err.Error())
	}
	if !resp.Node.Dir {
		log.Panicf("%v is not a directory", resp.Node.Key)
	}

	var services []service

	for _, node := range resp.Node.Nodes {
		if !node.Dir {
			log.Printf("skipping non-directory %v\n", node.Key)
			continue
		}
		s := service{
			name:         filepath.Base(node.Key),
			addresses:    make(map[string]string),
			pathPrefixes: make(map[string]string),
			pathHosts:    make(map[string]string),
		}
		for _, child := range node.Nodes {
			switch filepath.Base(child.Key) {
			case "healthcheck":
				s.hasHealthCheck = child.Value == "true"
			case "servers":
				for _, server := range child.Nodes {
					s.addresses[filepath.Base(server.Key)] = server.Value
				}
			case "path-regex":
				for _, path := range child.Nodes {
					s.pathPrefixes[filepath.Base(path.Key)] = path.Value
				}
			case "path-host":
				for _, path := range child.Nodes {
					s.pathHosts[filepath.Base(path.Key)] = path.Value
				}
			case "failover-predicate":
				s.failoverPredicate = child.Value
			default:
				fmt.Printf("skipped key %v for node %v\n", child.Key, child)
			}
		}
		services = append(services, s)
	}
	return services
}

type vulcanConf struct {
	FrontEnds map[string]vulcanFrontend
	Backends  map[string]vulcanBackend
}

type vulcanFrontend struct {
	BackendID         string
	Route             string
	Type              string
	rewrite           vulcanRewrite
	FailoverPredicate string
}

type vulcanRewrite struct {
	ID         string
	Type       string
	Priority   int
	Middleware vulcanRewriteMw
}

type vulcanRewriteMw struct {
	Regexp      string
	Replacement string
}

type vulcanBackend struct {
	Servers map[string]vulcanServer
}

type vulcanServer struct {
	URL string
}

func buildVulcanConf(services []service) vulcanConf {
	vc := vulcanConf{
		Backends:  make(map[string]vulcanBackend),
		FrontEnds: make(map[string]vulcanFrontend),
	}

	for _, service := range services {

		// "main" backend
		mainBackend := vulcanBackend{Servers: make(map[string]vulcanServer)}
		backendName := fmt.Sprintf("vcb-%s", service.name)
		for svrID, sa := range service.addresses {
			if addressRegex.MatchString(sa) {
				mainBackend.Servers[svrID] = vulcanServer{sa}
			} else {
				log.Printf("Skipping invalid backend address: %v for service %s\n", sa, service.name)
			}

		}
		vc.Backends[backendName] = mainBackend

		// Host header front end
		frontEndName := fmt.Sprintf("vcb-byhostheader-%s", service.name)
		vc.FrontEnds[frontEndName] = vulcanFrontend{
			Type:              "http",
			BackendID:         backendName,
			Route:             fmt.Sprintf("PathRegexp(`/.*`) && Host(`%s`)", service.name),
			FailoverPredicate: service.failoverPredicate,
		}

		// instance backends
		for svrID, sa := range service.addresses {
			instanceBackend := vulcanBackend{Servers: make(map[string]vulcanServer)}
			if addressRegex.MatchString(sa) {
				instanceBackend.Servers[svrID] = vulcanServer{sa}
			} else {
				log.Printf("Skipping invalid backend address: %v for service %s\n", sa, service.name)
			}
			backendName = fmt.Sprintf("vcb-%s-%s", service.name, svrID)
			vc.Backends[backendName] = instanceBackend
		}

		// health check front ends
		if service.hasHealthCheck {
			for svrID := range service.addresses {
				frontEndName := fmt.Sprintf("vcb-health-%s-%s", service.name, svrID)
				backendName = fmt.Sprintf("vcb-%s-%s", service.name, svrID)

				vc.FrontEnds[frontEndName] = vulcanFrontend{
					Type:      "http",
					BackendID: backendName,
					Route:     fmt.Sprintf("Path(`/health/%s-%s/__health`)", service.name, svrID),
					rewrite: vulcanRewrite{
						ID:       "rewrite",
						Type:     "rewrite",
						Priority: 1,
						Middleware: vulcanRewriteMw{
							Regexp:      fmt.Sprintf("/health/%s-%s(.*)", service.name, svrID),
							Replacement: "$1",
						},
					},
				}

			}
		}

		// internal frontend
		internalFrontEndName := fmt.Sprintf("vcb-internal-%s", service.name)
		vc.FrontEnds[internalFrontEndName] = vulcanFrontend{
			Type:      "http",
			BackendID: backendName,
			Route:     fmt.Sprintf("PathRegexp(`/__%s/.*`)", service.name),
			rewrite: vulcanRewrite{
				ID:       "rewrite",
				Type:     "rewrite",
				Priority: 1,
				Middleware: vulcanRewriteMw{
					Regexp:      fmt.Sprintf("/__%s(/.*)", service.name),
					Replacement: "$1",
				},
			},
			FailoverPredicate: service.failoverPredicate,
		}

		// public path front ends
		for pathName, pathRegex := range service.pathPrefixes {
			customHost, customHostExists := service.pathHosts[pathName]
			var route string
			if customHostExists {
				route = fmt.Sprintf("PathRegexp(`%s`) && Host(`%s`)", pathRegex, customHost)
			} else {
				route = fmt.Sprintf("PathRegexp(`%s`)", pathRegex)
			}
			vc.FrontEnds[fmt.Sprintf("vcb-%s-path-regex-%s", service.name, pathName)] = vulcanFrontend{
				Type:              "http",
				BackendID:         backendName,
				Route:             route,
				FailoverPredicate: service.failoverPredicate,
			}
		}
	}

	return vc
}

func applyVulcanConf(kapi client.KeysAPI, vc vulcanConf) {

	newConf := vulcanConfToEtcdKeys(vc)

	existing, err := readAllKeysFromEtcd(kapi, "/vulcand/")
	if err != nil {
		panic(err)
	}

	for k, v := range existing {
		// keep the keys not created by us
		if !strings.HasPrefix(k, "/vulcand/backends/vcb-") && !strings.HasPrefix(k, "/vulcand/frontends/vcb-") {
			newConf[k] = v
		}
	}

	changed := false
	// remove unwanted frontends
	for k := range existing {
		if strings.HasPrefix(k, "/vulcand/frontends/vcb-") {
			_, found := newConf[k]
			if !found {
				changed = true
				log.Printf("deleting frontend %s\n", k)
				_, err := kapi.Delete(context.Background(), k, &client.DeleteOptions{Recursive: false})
				if err != nil {
					log.Printf("error deleting frontend %v\n", k)
				}
			}
		}
	}

	// remove unwanted backends
	for k := range existing {
		if strings.HasPrefix(k, "/vulcand/backends/vcb-") {
			_, found := newConf[k]
			if !found {
				changed = true
				log.Printf("deleting backend%s\n", k)
				_, err := kapi.Delete(context.Background(), k, &client.DeleteOptions{Recursive: false})
				if err != nil {
					log.Printf("error deleting backend %v\n", k)
				}
			}
		}
	}

	// add or modify backends
	for k, v := range newConf {
		if strings.HasPrefix(k, "/vulcand/backends") {
			oldVal := existing[k]
			if v != oldVal {
				changed = true
				log.Printf("setting backend %s to %s\n", k, v)
				if _, err := kapi.Set(context.Background(), k, v, nil); err != nil {
					log.Printf("error setting %s to %s\n", k, v)
				}
			}
		}
	}

	// add or modify frontends
	for k, v := range newConf {
		if strings.HasPrefix(k, "/vulcand/frontends") && !strings.HasSuffix(k, "/middlewares/rewrite") {
			oldVal := existing[k]
			if v != oldVal {
				changed = true
				log.Printf("setting frontend %s to %s\n", k, v)
				if _, err := kapi.Set(context.Background(), k, v, nil); err != nil {
					log.Printf("error setting %s to %s\n", k, v)
				}
			}
		}
	}

	// add or modify everything else
	for k, v := range newConf {
		oldVal := existing[k]
		if v != oldVal {
			changed = true
			log.Printf("setting %s to %s\n", k, v)
			if _, err := kapi.Set(context.Background(), k, v, nil); err != nil {
				log.Printf("error setting %s to %s\n", k, v)
			}
		}
	}

	log.Printf("changes occured: %t ", changed)
	// some cleanup of known possible empty directories
	cleanFrontends(kapi)
	cleanBackends(kapi)
}

func cleanFrontends(kapi client.KeysAPI) {

	resp, err := kapi.Get(context.Background(), "/vulcand/frontends/", &client.GetOptions{Recursive: true})
	if err != nil {
		if e, _ := err.(client.Error); e.Code == etcderr.EcodeKeyNotFound {
			return
		}
		panic(err)
	}
	if !resp.Node.Dir {
		log.Println("/vulcand/frontends is not a directory.")
		return
	}
	for _, fe := range resp.Node.Nodes {
		feHasContent := false
		if fe.Dir {
			for _, child := range fe.Nodes {
				// anything apart from an empty "middlewares" dir means this is needed.
				if filepath.Base(child.Key) != "middlewares" || len(child.Nodes) > 0 {
					feHasContent = true
					break
				}
			}
		}
		if !feHasContent {
			_, err := kapi.Delete(context.Background(), fe.Key, &client.DeleteOptions{Recursive: true})
			if err != nil {
				log.Printf("failed to remove unwanted frontend %v\n", fe.Key)
			}
		}
	}

}

func cleanBackends(kapi client.KeysAPI) {

	resp, err := kapi.Get(context.Background(), "/vulcand/backends/", &client.GetOptions{Recursive: true})
	if err != nil {
		if e, _ := err.(client.Error); e.Code == etcderr.EcodeKeyNotFound {
			return
		}
		panic(err)
	}
	if !resp.Node.Dir {
		log.Println("/vulcand/backends is not a directory.")
		return
	}
	for _, be := range resp.Node.Nodes {
		beHasContent := false
		if be.Dir {
			for _, child := range be.Nodes {
				// anything apart from an empty "servers" dir means this is needed.
				if filepath.Base(child.Key) != "servers" || len(child.Nodes) > 0 {
					beHasContent = true
					break
				}
			}
		}
		if !beHasContent {
			_, err := kapi.Delete(context.Background(), be.Key, &client.DeleteOptions{Recursive: true})
			if err != nil {
				log.Printf("failed to remove unwanted backend %v\n", be.Key)
			}
		}
	}

}

func vulcanConfToEtcdKeys(vc vulcanConf) map[string]string {
	m := make(map[string]string)

	// create backends
	for beName, be := range vc.Backends {
		k := fmt.Sprintf("/vulcand/backends/%s/backend", beName)
		v := `{"Type": "http", "Settings": {"KeepAlive": {"MaxIdleConnsPerHost": 256, "Period": "35s"}}}`
		m[k] = v

		for sName, s := range be.Servers {
			k := fmt.Sprintf("/vulcand/backends/%s/servers/%s", beName, sName)
			v := fmt.Sprintf(`{"url":"%s"}`, s.URL)
			m[k] = v
		}

	}

	// create frontends
	for feName, be := range vc.FrontEnds {
		k := fmt.Sprintf("/vulcand/frontends/%s/frontend", feName)
		v := fmt.Sprintf(`{"Type":"%s", "BackendId":"%s", "Route":"%s", "Settings": {"FailoverPredicate":"%s"}}`, be.Type, be.BackendID, be.Route, be.FailoverPredicate)
		m[k] = v
		if be.rewrite.ID != "" {
			k := fmt.Sprintf("/vulcand/frontends/%s/middlewares/rewrite", feName)
			v := fmt.Sprintf(

				`{"Id":"%s", "Type":"%s", "Priority":%d, "Middleware": {"Regexp":"%s", "Replacement":"%s"}}`,
				be.rewrite.ID,
				be.rewrite.Type,
				be.rewrite.Priority,
				be.rewrite.Middleware.Regexp,
				be.rewrite.Middleware.Replacement,
			)
			m[k] = v
		}
	}

	return m
}

func newNotifier(kapi client.KeysAPI, path string, bufferSize int) notifier {
	w := notifier{make(chan struct{}, bufferSize)}

	go func() {
		for {
			watcher := kapi.Watcher(path, &client.WatcherOptions{Recursive: true})

			var err error
			for err == nil {
				_, err = watcher.Next(context.Background())
				w.ch <- struct{}{}
				log.Println("sent message on notifier channel.")
			}

			if err == context.Canceled {
				log.Println("context cancelled error")
			} else if err == context.DeadlineExceeded {
				log.Println("deadline exceeded error")
			} else if cerr, ok := err.(*client.ClusterError); ok {
				log.Printf("cluster error. Details: %v\n", cerr.Detail())
			} else {
				// bad cluster endpoints, which are not etcd servers
				log.Println(err.Error())
			}

			log.Println("sleeping for 15s before rebuilding config due to error")
			time.Sleep(15 * time.Second)
		}
	}()

	return w
}

type notifier struct {
	ch chan struct{}
}

func (w *notifier) notify() <-chan struct{} {
	return w.ch
}

func readAllKeysFromEtcd(kapi client.KeysAPI, root string) (map[string]string, error) {
	m := make(map[string]string)

	resp, err := kapi.Get(context.Background(), root, &client.GetOptions{Recursive: true})
	if err != nil {
		if e, _ := err.(client.Error); e.Code == etcderr.EcodeKeyNotFound {
			return m, nil
		}
		panic(err)
	}
	addAllValuesToMap(m, resp.Node)
	return m, nil
}

func addAllValuesToMap(m map[string]string, node *client.Node) {
	if node.Dir {
		for _, child := range node.Nodes {
			addAllValuesToMap(m, child)
		}
	} else {
		m[node.Key] = node.Value
	}
}
