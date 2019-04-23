package firewall

import (
	"log"
	"net/http"
)

type Firewall struct {
	Map    Map
	Events Dispatcher
}

func (fw *Firewall) Handle(w http.ResponseWriter, r *http.Request) {
	listeners := fw.Map.Listeners(r)

	for _, l := range listeners {
		log.Printf("%#v\n", l)
	}
}
