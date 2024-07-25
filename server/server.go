package server

import (
	"log"
	"net/http"

	"github.com/alphadev97.com/go-csrf/server/middleware"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port

	log.Printf("listening on: %s", host)

	handler := middleware.NewHandler()

	http.Handle("/", handler)

	return http.ListenAndServe(host, nil)
}
