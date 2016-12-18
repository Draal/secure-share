package main

//go:generate $GOPATH/bin/ego -o templates/ego.go -package=template templates

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Draal/secure-share/config"
)

func main() {
	handler, err := OpenHandlerFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/", handler.Handler)
	for _, l := range handler.config.Languages {
		if l.Code != config.LangEnglish {
			http.HandleFunc(fmt.Sprintf("/%s/", l.Iso), handler.Handler)
		}
	}

	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	http.ListenAndServe(listen, nil)
}
