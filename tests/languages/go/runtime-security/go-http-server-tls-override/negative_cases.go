package gohttpservertlsoverride

import (
	"net/http"
)

func serverWithoutTLSConfig() {
	server := &http.Server{
		Addr: ":8080",
	}
	_ = server
}
