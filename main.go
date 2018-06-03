package main

//go:generate $GOPATH/bin/ego templates templates/partitial

import (
	"log"
	"net/http"
	"os"
)

func main() {
	handler, err := OpenHandlerFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", handler.Handler)

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	http.ListenAndServe(listen, nil)
}
