package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func GoVisit(r *http.Request) {
	query := r.URL.Query()
	src := query.Get("src")
	
	if src == "" {
		return
	}

	// Check if has vistor counter endpoint
	VISITOR_ENDPOINT := os.Getenv("VISITOR_ENDPOINT")
	if VISITOR_ENDPOINT == "" {
		return
	}


	// Create a new HTTP request
	url := fmt.Sprintf("%s/%s",VISITOR_ENDPOINT , src)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return // silently fail like the JS version
	}

	// Set the custom header
	req.Header.Set("x-citycam-action", "visitor")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return // silently fail
	}
	defer resp.Body.Close()

	// (Optional) Read response if needed
	_, _ = io.ReadAll(resp.Body)
}