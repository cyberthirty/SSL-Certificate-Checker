package sslchecker

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

// CheckCertificate checks the SSL certificate for the specified domain and port
func CheckCertificate(domain, port string) {
	// Set a timeout for the connection
	timeout := 5 * time.Second

	// Dial the server with SNI (Server Name Indication) extension
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", domain+":"+port, &tls.Config{ServerName: domain})
	if err != nil {
		fmt.Printf("Error connecting to %s:%s - %v\n", domain, port, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Handshake with the server
	err = conn.Handshake()
	if err != nil {
		fmt.Printf("TLS Handshake error: %v\n", err)
		os.Exit(1)
	}

	// Get the peer certificate
	cert := conn.ConnectionState().PeerCertificates[0]

	// Print information about the certificate
	fmt.Printf("Certificate Information for %s:\n", domain)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Valid From: %s\n", cert.NotBefore.Format("2006-01-02"))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02"))

	// Check if the certificate is self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		fmt.Println("\nCertificate is self-signed.")
	}

	// Check if the certificate is expired
	if time.Now().After(cert.NotAfter) {
		fmt.Println("Certificate has already expired.")
	} else {
		// Check the certificate expiration date
		daysUntilExpiration := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		fmt.Printf("Certificate for %s expires in %d days on %s\n", domain, daysUntilExpiration, cert.NotAfter.Format("2006-01-02"))

		// Print a warning if the certificate is expiring within 30 days
		const warningDays = 30
		if daysUntilExpiration <= warningDays {
			fmt.Printf("Warning: Certificate will expire in the next %d days!\n", warningDays)
		}
	}
}
