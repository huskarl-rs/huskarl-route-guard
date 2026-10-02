package main

import (
	"io"
	"log"
	"net/http"
	"runtime"
	"time"
)

func marker(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Route-ID", id)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, id)
	}
}

func main() {
	// Native ServeMux routing only; policies live in the independent Rust harness.
	mux := http.NewServeMux()
	for _, route := range []struct{ path, id string }{
		{"/admin", "admin"},
		{"/files", "files"},
		{"/files/private", "private"},
	} {
		mux.HandleFunc("GET "+route.path, marker(route.id))
		mux.HandleFunc("GET "+route.path+"/", marker(route.id))
	}
	// ServeMux selects this parent POST handler even under the GET-only child.
	mux.HandleFunc("POST /files", marker("files"))
	mux.HandleFunc("POST /files/", marker("files"))
	for _, route := range []struct{ path, id string }{
		{"/exact.txt", "exact"},
		{"/foo/{segment}/bar", "parameterized"},
	} {
		mux.HandleFunc("GET "+route.path, marker(route.id))
		mux.HandleFunc("GET "+route.path+"/{$}", marker(route.id))
	}
	mux.HandleFunc("/", marker("public"))
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("%s; net/http.ServeMux; modern routing; no rewriting middleware", runtime.Version())
	log.Fatal(server.ListenAndServe())
}
