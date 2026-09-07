// Copyright (c) 2026 Damien Daly. All rights reserved.

// Command gencerts writes a throwaway CA and server certificate for the local
// docker-compose stack, so that trying the relay locally needs neither openssl
// nor cert-manager.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/maitredede/mailout-operator/internal/pki"
)

func main() {
	dir := flag.String("dir", "deploy/compose/certs", "output directory")
	names := flag.String("names", "mailout.test,alt.mailout.test,localhost,127.0.0.1",
		"comma-separated names for the primary certificate")
	altNames := flag.String("alt-names", "",
		"comma-separated names for a second certificate, to exercise SNI")
	// The compose stack runs the gateway as uid 65532, which cannot read a
	// 0600 file owned by the developer. These keys are throwaway.
	keyMode := flag.Uint("key-mode", 0o644, "permissions of the generated private keys")
	flag.Parse()

	if err := run(*dir, *names, *altNames, os.FileMode(*keyMode)); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir, names, altNames string, keyMode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ca, err := pki.NewCA("mailout local dev")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/ca.crt", ca.CertPEM, 0o644); err != nil {
		return err
	}
	primary, err := ca.Issue(strings.Split(names, ",")...)
	if err != nil {
		return err
	}
	if _, keyFile, err := primary.WriteFiles(dir, "gateway"); err != nil {
		return err
	} else if err := os.Chmod(keyFile, keyMode); err != nil {
		return err
	}
	fmt.Printf("wrote %s/ca.crt, %s/gateway.crt, %s/gateway.key (%s)\n", dir, dir, dir, names)

	if altNames != "" {
		alt, err := ca.Issue(strings.Split(altNames, ",")...)
		if err != nil {
			return err
		}
		if _, keyFile, err := alt.WriteFiles(dir, "gateway-alt"); err != nil {
			return err
		} else if err := os.Chmod(keyFile, keyMode); err != nil {
			return err
		}
		fmt.Printf("wrote %s/gateway-alt.crt, %s/gateway-alt.key (%s)\n", dir, dir, altNames)
	}
	return nil
}
