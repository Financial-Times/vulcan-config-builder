package main

import (
	"flag"
	"fmt"
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
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

		newConf := buildVulcanConf(readServices(etcd))
		if newConf != currentVulcanConf(etcd) {
			setVulcanConf(newConf)
		}
	}

}

type ServiceAddress struct {
	Host string
	Port int
}

type Service struct {
	Name           string
	HasHealthCheck bool
	Addresses      []ServiceAddress
	//TODO: prefixes
}

func readServices(etcd client.Client) []Service {
	kapi := client.NewKeysAPI(etcd)
	resp, err := kapi.Get(context.Background(), "/ft/services/", &client.GetOptions{Recursive: true})
	if err != nil {
		panic("failed to read from etcd")
	}
	if !resp.Node.Dir {
		panic(fmt.Sprintf("%v is not a directory", resp.Node.Key))
	}

	var services []Service

	for _, node := range resp.Node.Nodes {
		if !node.Dir {
			log.Printf("skipping non-directory %v\n", node.Key)
			continue
		}
		service := Service{Name: filepath.Base(node.Key)}
		for _, child := range node.Nodes {
			switch filepath.Base(child.Key) {
			case "healthcheck":
				service.HasHealthCheck = child.Value == "true"
			case "servers":
				for _, server := range child.Nodes {
					hostPort := strings.Split(server.Value, ":")
					if len(hostPort) != 2 {
						log.Printf("can't parse host and port from %v, skipping\n", server.Value)
						continue
					}
					port, err := strconv.Atoi(hostPort[1])
					if err != nil {
						log.Printf("can't parse port from %v, skipping\n", hostPort[1])
						continue
					}
					sa := ServiceAddress{Host: hostPort[0], Port: port}
					service.Addresses = append(service.Addresses, sa)
				}
			default:
				fmt.Printf("skipped key %v for node %v\n", child.Key, child)
			}
		}
		services = append(services, service)
	}
	return services
}

type vulcanConf struct {
	// TODO
}

func buildVulcanConf(services []Service) vulcanConf {
	panic("implement me")
}

func currentVulcanConf(etcd client.Client) vulcanConf {
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
