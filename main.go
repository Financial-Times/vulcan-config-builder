package main

import (
	"flag"
	"fmt"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	var (
		socksProxy = flag.String("socks-proxy", "", "Use specified SOCKS proxy (e.g. localhost:2323)")
		etcdPeers  = flag.String("etcd-peers", "http://localhost:2379", "Comma-separated list of addresses of etcd endpoints to connect to")
	)

	flag.Parse()

	transport := client.DefaultTransport

	if *socksProxy != "" {
		dialer, _ := proxy.SOCKS5("tcp", *socksProxy, nil, proxy.Direct)
		transport = &http.Transport{Dial: dialer.Dial}
	}

	peers := strings.Split(*etcdPeers, ",")

	cfg := client.Config{
		Endpoints:               peers,
		Transport:               transport,
		HeaderTimeoutPerRequest: time.Second,
	}

	etcd, err := client.New(cfg)
	if err != nil {
		log.Fatal("failed to start etcd client: %v\n", err.Error())
	}

	watcher := newWatcher(etcd, "/ft/services/", *socksProxy, peers)

	tick := time.NewTicker(2 * time.Second)

	for {
		<-watcher.wait()
		fmt.Println("something changed")

		<-tick.C

		newConf := buildVulcanConf()
		if newConf != currentVulcanConf() {
			setVulcanConf(newConf)
		}
	}

}

type vulcanConf struct {
	// TODO
}

func buildVulcanConf() vulcanConf {
	panic("implement me")
}

func currentVulcanConf() vulcanConf {
	panic("implement me")
}

func setVulcanConf(vc vulcanConf) {
	panic("implement me")
}

func newWatcher(etcd client.Client, path string, socksProxy string, etcdPeers []string) watcher {
	w := watcher{make(chan struct{}, 1)}

	go func() {

		kapi := client.NewKeysAPI(etcd)
		watcher := kapi.Watcher(path, &client.WatcherOptions{Recursive: true})

		for {
			_, err := watcher.Next(context.Background())
			if err != nil {
				log.Printf("watch failed %v, sleeping for 1s\n", err.Error())
				time.Sleep(1 * time.Second)
			} else {
				select {
				case w.ch <- struct{}{}:
				default:
				}
			}
		}
	}()

	return w
}

type watcher struct {
	ch chan struct{}
}

func (w *watcher) wait() <-chan struct{} {
	return w.ch
}
