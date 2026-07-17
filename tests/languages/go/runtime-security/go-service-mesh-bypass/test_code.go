package main

import (
	"net/http"
)

func main() {
	// Direct HTTP bypass of service mesh - line 12
	serviceIP := "10.0.0.1"
	port := "8080"
	url := "http://" + serviceIP + ":" + port
	http.Get(url)

	// Direct HTTP HEAD bypass - line 16
	headURL := "http://" + serviceIP
	http.Head(headURL)

	// Service discovery bypass loop - line 20
	endpoints := getServiceEndpoints("user-service")
	for _, endpoint := range endpoints {
		url := "http://" + endpoint
		http.Post(url, "application/json", nil)
	}

}

// Helper functions
func getServiceEndpoints(serviceName string) []string {
	return []string{"10.0.0.1:8080", "10.0.0.2:8080"}
}
