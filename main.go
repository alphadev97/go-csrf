package main

import (
	"log"

	"github.com/alphadev97.com/go-csrf/db"
	"github.com/alphadev97.com/go-csrf/server"
	"github.com/alphadev97.com/go-csrf/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}
}
