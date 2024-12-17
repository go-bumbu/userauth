package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	srv := NewServer()
	go srv.Start()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan
	fmt.Println("Signal received, shutting down...")
	srv.Stop()
}

type Server struct {
	server *http.Server
	router http.Handler
}

func NewServer() *Server {
	handler := demoHandler()
	s := &Server{
		router: handler,
	}
	return s
}

func (s *Server) Start() {
	fmt.Println("Server is running on port http://localhost:8085")
	_ = http.ListenAndServe(":8085", s.router)
}

func (s *Server) Stop() {
	if s.server != nil {
		fmt.Println("Stopping server")
		s.server.Close()
	}
}
