package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	handler, err := OpenHandlerFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
