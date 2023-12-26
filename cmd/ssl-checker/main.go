package main

import (
	"flag"
	"fmt"
	"your-project/sslchecker"
)

const banner = `
======================================================
    SSL Certificate Checker - by CYBER30
======================================================
`

func main() {
	fmt.Print(banner)

	// Parse command-line arguments for domain and port
	var domain, port string
	flag.StringVar(&domain, "u", "luckyngabu.com", "Domain to check for SSL certificate")
	flag.StringVar(&port, "p", "443", "Port to check for SSL certificate")
	flag.Parse()

	// Call the SSL certificate checking function from sslchecker package
	sslchecker.CheckCertificate(domain, port)
}
