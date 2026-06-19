// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ellanetworks/3gpp-server/internal/api"
	"github.com/ellanetworks/3gpp-server/internal/store"
)

func main() {
	signal.Ignore(syscall.SIGPIPE)

	listen := flag.String("listen", ":8080", "HTTP listen address")
	flag.Parse()

	log.SetOutput(os.Stderr)

	s := store.New()
	h := api.NewHandler(s)
	mux := api.NewRouter(h)

	fmt.Printf("3gpp-server-tester listening on %s\n", *listen)

	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
