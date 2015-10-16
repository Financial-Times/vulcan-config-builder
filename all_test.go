package main

import (
	"github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"testing"
)

func TestReadServices(t *testing.T) {
	etcd, err := client.New(client.Config{Endpoints: []string{"http://localhost:2379"}})
	if err != nil {
		t.Fatal(err)
	}
	kapi := client.NewKeysAPI(etcd)

	if _, err := kapi.Delete(context.Background(), "/ft/services/", &client.DeleteOptions{Recursive: true}); err != nil {
		//	t.Error(err)
	}

	kvs := [][]string{
		[]string{"/ft/services/service-a/healthcheck", "true"},
		[]string{"/ft/services/service-a/servers/srv1", "host1:1"},
		[]string{"/ft/services/service-a/path-prefixes", "/bananas/"},
		[]string{"/ft/services/service-b/healthcheck", "false"},
		[]string{"/ft/services/service-b/servers/srv1", "host1:1"},
		[]string{"/ft/services/service-b/servers/srv2", "host2:2"},
		[]string{"/ft/services/service-b/path-prefixes", "/content/,/bananas/"},
	}
	if err := setValues(kvs, kapi); err != nil {
		t.Error(err)
	}

	smap := make(map[string]Service)
	for _, s := range readServices(kapi) {
		smap[s.Name] = s
	}
	if len(smap) != 2 {
		t.Fatal("unexpected length")
	}

	a := Service{
		Name:           "service-a",
		HasHealthCheck: true,
		Addresses: []ServiceAddress{
			ServiceAddress{Host: "host1", Port: 1},
		},
		PathPrefixes: []string{"/bananas/"},
	}
	if !equalServices(a, smap["service-a"]) {
		t.Errorf("service does not match:\n%v\n%v\n", a, smap["service-a"])
	}

	b := Service{
		Name:           "service-b",
		HasHealthCheck: false,
		Addresses: []ServiceAddress{
			ServiceAddress{Host: "host1", Port: 1},
			ServiceAddress{Host: "host2", Port: 2},
		},
		PathPrefixes: []string{"/content/", "/bananas/"},
	}
	if !equalServices(b, smap["service-b"]) {
		t.Errorf("service does not match:\n%v\n%v\n", b, smap["service-b"])
	}
}

func equalServices(a, b Service) bool {
	if a.HasHealthCheck != b.HasHealthCheck {
		return false
	}
	if a.Name != b.Name {
		return false
	}
	if len(a.Addresses) != len(b.Addresses) {
		return false
	}
	for i, addr := range a.Addresses {
		if addr != b.Addresses[i] {
			return false
		}
	}
	if len(a.PathPrefixes) != len(b.PathPrefixes) {
		return false
	}
	for i, prefix := range a.PathPrefixes {
		if prefix != b.PathPrefixes[i] {
			return false
		}
	}
	return true
}

func setValues(kvs [][]string, kapi client.KeysAPI) error {
	for _, kv := range kvs {
		if _, err := kapi.Set(context.Background(), kv[0], kv[1], &client.SetOptions{}); err != nil {
			return err
		}
	}
	return nil
}
