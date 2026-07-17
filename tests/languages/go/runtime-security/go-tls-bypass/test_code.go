package main

import (
	"crypto/tls"
	"database/sql"
	"os"
	"reflect"
)

func main() {
	// Direct TLS validation bypass - line 12
	config := &tls.Config{InsecureSkipVerify: true}

	// Variable assignment - line 15
	insecureVar := true
	config.InsecureSkipVerify = insecureVar

	// Function assignment - line 19
	config.InsecureSkipVerify = getInsecureFlag()

	// TLS Config struct initialization - line 22
	tlsConfig := tls.Config{InsecureSkipVerify: true}

	// TLS Config pointer initialization - line 25
	tlsConfigPtr := &tls.Config{InsecureSkipVerify: true}

	// Conditional bypass - line 28
	if isDevelopment() {
		config.InsecureSkipVerify = true
	}

	// Environment variable bypass - line 33
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		config.InsecureSkipVerify = true
	}

	// Reflection-based bypass - line 38
	field := reflect.ValueOf(config).Elem().FieldByName("InsecureSkipVerify")
	field.SetBool(true)

	// Empty ServerName bypass - line 42
	config.ServerName = ""

	// DSN connection string bypasses - line 45
	connectionString := "host=localhost"
	sql.Open("postgres", connectionString+"?sslmode=disable")

	// DSN with tls=false - line 49
	dsn := "user:pass@tcp(localhost:3306)/db"
	sql.Open("mysql", dsn+"&tls=false")

	// DSN with ssl=false - line 53
	connStr := "server=localhost"
	sql.Open("driver", connStr+"?ssl=false")
}

func getInsecureFlag() bool {
	return true
}

func isDevelopment() bool {
	return true
}
