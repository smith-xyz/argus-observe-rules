package main

import (
	"fmt"
)

// Negative cases - should NOT trigger go-pqc-grpc-tls

func logGRPCStatus(status string) {
	fmt.Printf("status: %s\n", status)
}

func serviceName() string {
	return "example.Service"
}

func endpoint() string {
	return "localhost:50051"
}
