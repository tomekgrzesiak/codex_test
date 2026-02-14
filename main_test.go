package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("mock server received request:")
		for k, v := range r.Header {
			fmt.Printf("%s: %v\n", k, v)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	fmt.Println("boot mock server at", srv.URL)

	client := srv.Client()

	url := flag.String("url", srv.URL, "POST URL")
	token := flag.String("token", "", "Bearer token")
	filePath := flag.String("file", "/usr/bin/curl", "File to upload")
	filename := flag.String("filename", "cu", "Filename to send in Content-Disposition header")

	flag.Parse()

	f, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("opening file %s: %v", *filePath, err)
	}
	defer f.Close()

	//fs, err := f.Stat()
	if err != nil {
		log.Fatalf("stat file %s: %v", *filePath, err)
	}

	req, err := http.NewRequest("POST", *url, f)
	if err != nil {
		log.Fatalf("creating request: %v", err)
	}

	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", *filename))
	//	req.ContentLength = fs.Size()

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	fmt.Println("response status:", resp.Status)
}
