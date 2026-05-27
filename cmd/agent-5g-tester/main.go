package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/ellanetworks/3gpp-server/internal/api"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	flag.Parse()

	s := store.New()
	h := api.NewHandler(s)
	mux := api.NewRouter(h)

	fmt.Printf("3gpp-server-tester listening on %s\n", *listen)

	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
