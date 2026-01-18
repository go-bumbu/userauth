package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	initLogger()
	srv := NewServer()
	go srv.Start()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	<-signalChan
	logger.Info("Signal received, shutting down...")
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
	logger.Info("Server is running on port http://localhost:8085")
	_ = http.ListenAndServe(":8085", s.router)
}

func (s *Server) Stop() {
	if s.server != nil {
		fmt.Println("Stopping server")
		s.server.Close()
	}
}

var logger *slog.Logger

func initLogger() {
	// TODO add a nice human logger

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug, // show all messages including debug
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Format time nicely
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05"))
			}
			return a
		},
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger = slog.New(handler)
}
