package main

//go:generate $GOPATH/bin/ego -o templates/ego.go -package=template templates

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

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.ListenAndServe(":"+port, nil)
}
