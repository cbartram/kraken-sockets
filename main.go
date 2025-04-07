package main

import (
	"flag"
	"github.com/cbartram/kraken-sockets/manifests/server"
)

func main() {
	var host, port string
	flag.StringVar(&port, "port", "26388", "port to listen on")
	flag.StringVar(&host, "host", "localhost", "host to listen on")
	flag.Parse()

	server.RegisterNewSocketServer(host, port)
}
