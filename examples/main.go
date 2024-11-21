package main

import (
	"fmt"
	"github.com/google/uuid"
	"net"
	"smtp"
)

// DatabaseBackend is a smtp.DatabaseBackend implementation that always returns true for CheckUser and prints the mail data to stdout.
var DatabaseBackend = smtp.DatabaseBackend{
	CheckUser: func(address *smtp.Address) (bool, error) {
		return true, nil
	},
	WriteMail: func(mail *smtp.Mail) (uuid.UUID, error) {
		fmt.Println(string(mail.Data))
		return uuid.New(), nil
	},
}

// AuthenticationBackend is a smtp.AuthenticationBackend implementation that always returns a fixed address for Authenticate.
var AuthenticationBackend = smtp.AuthenticationBackend{
	Authenticate: func(authCommand string) (*smtp.Address, error) {
		return &smtp.Address{
			Name:    "test",
			Address: "example.org",
		}, nil
	},
}

func main() {
	go func() {
		// Serve on the server-to-server port
		listener, err := net.Listen("tcp", ":25")
		if err != nil {
			panic(err)
		}
		receiver := smtp.NewReceiver(listener, "localhost", []string{"localhost", "127.0.0.1", "0.0.0.0", "example.org", "192.168.1.253"}, false, DatabaseBackend, AuthenticationBackend, nil)
		err = receiver.Serve()
		panic(err)
	}()
	go func() {
		// Serve on the submission port
		listener, err := net.Listen("tcp", ":587")
		if err != nil {
			panic(err)
		}
		receiver := smtp.NewReceiver(listener, "localhost", []string{"localhost", "127.0.0.1", "0.0.0.0", "cta.social"}, false, DatabaseBackend, AuthenticationBackend, nil)
		err = receiver.Serve()
		panic(err)
	}()

	// Block forever
	select {}
}
