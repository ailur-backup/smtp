package smtp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/tls"
	"net/textproto"

	"git.ailur.dev/ailur/spf"
)

var (
	defaultCapabilities = []string{
		"250-8BITMIME",
		"250-ENHANCEDSTATUSCODES",
		"250-SMTPUTF8",
		"250 BINARYMIME",
	}
	queue = make(map[time.Time]*MailQueueItem)
)

// MailQueueItem is a struct that represents an item in the mail queue
type MailQueueItem struct {
	From *Address
	To   []*Address
	Host string
}

// ViewMailQueue returns the current mail queue
func ViewMailQueue() map[time.Time]*MailQueueItem {
	return queue
}

// Address is a struct that represents an email address
type Address struct {
	Name    string
	Address string
}

// Mail is a struct that represents an email
type Mail struct {
	From *Address
	To   []*Address
	Data []byte
}

// DatabaseBackend is a struct that represents a database backend
type DatabaseBackend struct {
	CheckUser func(*Address) (bool, error)
	WriteMail func(*Mail) error
}

// AuthenticationBackend is a struct that represents an authentication backend
type AuthenticationBackend struct {
	Authenticate        func(initial string, conn *textproto.Conn) (CheckAddress, error)
	SupportedMechanisms []string
}

type CheckAddress func(*Address) (bool, error)

func readMultilineCodeResponse(conn *textproto.Conn) (int, string, error) {
	var lines strings.Builder
	for {
		line, err := conn.ReadLine()
		if err != nil {
			return 0, "", err
		}

		lines.WriteString(line)

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", err
		}

		if line[3] != '-' {
			return code, lines.String(), nil
		}
	}
}

func systemError(err error, receiver *Address, database DatabaseBackend) {
	_ = database.WriteMail(&Mail{
		From: &Address{
			Name:    "EMail System",
			Address: "system",
		},
		To:   []*Address{receiver},
		Data: []byte(fmt.Sprintf("Hello there. This is the EMail system.\n We're sorry, but an error occurred while trying to send your email. The error was: %s. The email has not been sent.", err.Error())),
	})
}

func sendEmail(args SenderArgs, mail *Mail, database DatabaseBackend, queueID time.Time) {
	mxs, err := net.LookupMX(mail.To[0].Address)
	if err != nil {
		systemError(err, queue[queueID].From, database)
		delete(queue, queueID)
		return
	}

	ips, err := net.LookupIP(mxs[0].Host)
	if err != nil {
		systemError(err, queue[queueID].From, database)
		delete(queue, queueID)
		return
	}

	conn, err := net.Dial("tcp", ips[0].String()+":25")
	if err != nil {
		systemError(err, queue[queueID].From, database)
		delete(queue, queueID)
		return
	}

	err = Send(args, mail, conn, mxs[0].Host)
	if err != nil {
		systemError(err, queue[queueID].From, database)
		delete(queue, queueID)
		return
	}

	err = conn.Close()
	if err != nil {
		systemError(err, queue[queueID].From, database)
		delete(queue, queueID)
		return
	}

	delete(queue, queueID)
}

func speakMultiLine(conn *textproto.Conn, lines []string) error {
	for _, line := range lines {
		err := conn.PrintfLine(line)
		if err != nil {
			return err
		}
	}

	return nil
}

// Receiver is a struct that represents an SMTP receiver
type Receiver struct {
	underlyingListener net.Listener
	hostname           string
	ownedDomains       map[string]struct{}
	enforceTLS         bool
	tlsConfig          *tls.Config
	database           DatabaseBackend
	auth               AuthenticationBackend
}

// NewReceiver creates a new Receiver
func NewReceiver(conn net.Listener, hostname string, ownedDomains []string, enforceTLS bool, database DatabaseBackend, authentication AuthenticationBackend, tlsConfig *tls.Config) *Receiver {
	var ownedDomainsMap = make(map[string]struct{})
	for _, domain := range ownedDomains {
		ownedDomainsMap[domain] = struct{}{}
	}
	return &Receiver{
		underlyingListener: conn,
		hostname:           hostname,
		ownedDomains:       ownedDomainsMap,
		enforceTLS:         enforceTLS,
		tlsConfig:          tlsConfig,
		database:           database,
		auth:               authentication,
	}
}

// Close closes the connection to the Receiver
func (fr *Receiver) Close() error {
	return fr.underlyingListener.Close()
}

// Serve serves the Receiver. It will always return a non-nil error
func (fr *Receiver) Serve() error {
	for {
		conn, err := fr.underlyingListener.Accept()
		if err != nil {
			return err
		}

		go fr.handleConnection(conn)
	}
}

func (fr *Receiver) handleConnection(conn net.Conn) {
	var state struct {
		HELO bool
		AUTH CheckAddress
		TLS  bool
		FROM *Address
		RCPT []*Address
		DATA []byte
	}

	submissionSlice := strings.Split(conn.LocalAddr().String(), ":")
	isSubmission := submissionSlice[len(submissionSlice)-1] != "25"
	textProto := textproto.NewConn(conn)

	err := textProto.PrintfLine("220 %s ESMTP At your service", fr.hostname)
	if err != nil {
		_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
		_ = conn.Close()
		return
	}

	for {
		line, err := textProto.ReadLine()
		if err != nil {
			_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
			_ = conn.Close()
			return
		}

		switch {
		case strings.HasPrefix(line, "QUIT"):
			err = textProto.PrintfLine("221 2.0.0 See you soon")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
			}
			_ = conn.Close()
			return
		case strings.HasPrefix(line, "RSET"):
			state.HELO = false
			state.AUTH = nil
			state.FROM = nil
			state.RCPT = nil
			state.DATA = nil
			err = textProto.PrintfLine("250 2.0.0 Connection reset")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}
		case strings.HasPrefix(line, "NOOP"):
			err = textProto.PrintfLine("250 2.0.0 Take your time")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}
		case strings.HasPrefix(line, "HELO"):
			if state.HELO {
				err = textProto.PrintfLine("503 5.5.1 HELO already called")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			} else {
				state.HELO = true
				err = textProto.PrintfLine("250 %s, ready to receive mail", fr.hostname)
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
			}
		case strings.HasPrefix(line, "EHLO"):
			if state.HELO {
				err = textProto.PrintfLine("503 5.5.1 EHLO already called")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			} else {
				var capabilities []string
				if fr.tlsConfig != nil {
					capabilities = append(capabilities, "250-STARTTLS")
				}
				if fr.enforceTLS {
					capabilities = append(capabilities, "250-REQUIRETLS")
				}
				if fr.auth.SupportedMechanisms != nil {
					capabilities = append(capabilities, "250-AUTH "+strings.Join(fr.auth.SupportedMechanisms, " "))
				}
				capabilities = append(capabilities, defaultCapabilities...)
				state.HELO = true
				err = speakMultiLine(textProto, capabilities)
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
			}
		case strings.HasPrefix(line, "AUTH"):
			if !isSubmission {
				err = textProto.PrintfLine("503 5.5.1 AUTH only allowed on submission port")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			if !state.TLS && fr.enforceTLS {
				err = textProto.PrintfLine("530 5.7.0 Must issue a STARTTLS command first")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			if state.AUTH != nil {
				err = textProto.PrintfLine("503 5.5.1 AUTH already called")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			} else {
				checkAddress, err := fr.auth.Authenticate(strings.TrimPrefix(line, "AUTH "), textProto)
				if err != nil {
					_ = textProto.PrintfLine(err.Error())
					_ = conn.Close()
					return
				}

				if checkAddress == nil {
					err = textProto.PrintfLine("535 5.7.8 Authentication failed")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
				} else {
					state.AUTH = checkAddress
					err = textProto.PrintfLine("235 2.7.0 Authentication successful")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
				}
			}
		case strings.HasPrefix(line, "STARTTLS"):
			if state.TLS {
				err = textProto.PrintfLine("503 5.5.1 STARTTLS already called")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			} else {
				err = textProto.PrintfLine("220 2.0.0 Ready to start TLS")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}

				tlsConn := tls.Server(conn, fr.tlsConfig)
				textProto = textproto.NewConn(tlsConn)

				state.HELO = false
				state.AUTH = nil
				state.FROM = nil
				state.RCPT = nil
				state.DATA = nil
				state.TLS = true
			}
		case strings.HasPrefix(line, "MAIL FROM"):
			if !state.HELO {
				err = textProto.PrintfLine("503 5.5.1 HELO required")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			if !state.TLS && fr.enforceTLS {
				err = textProto.PrintfLine("530 5.7.0 Must issue a STARTTLS command first")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			addressSlice := strings.Split(strings.TrimPrefix(strings.TrimSuffix(line, ">"), "MAIL FROM:<"), "@")

			address := &Address{
				Name:    addressSlice[0],
				Address: addressSlice[1],
			}

			if isSubmission {
				if state.AUTH == nil {
					err = textProto.PrintfLine("503 5.5.1 AUTH required")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
					continue
				}

				ok, err := state.AUTH(address)
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}

				if !ok {
					err = textProto.PrintfLine("535 5.7.8 Authenticated wrong user")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
					continue
				}
			} else {
				err := spf.CheckIP(strings.Split(conn.RemoteAddr().String(), ":")[0], address.Address)
				if err != nil {
					if err.Type() == spf.ErrTypeInternal {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					} else {
						err := textProto.PrintfLine("550 5.7.1 SPF check failed")
						if err != nil {
							_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
							_ = conn.Close()
							return
						}
						continue
					}
				}
			}

			state.FROM = address
			err = textProto.PrintfLine("250 2.1.0 Sender OK")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}
		case strings.HasPrefix(line, "RCPT TO"):
			if !state.TLS && fr.enforceTLS {
				err = textProto.PrintfLine("530 5.7.0 Must issue a STARTTLS command first")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			addressSlice := strings.Split(strings.TrimPrefix(strings.TrimSuffix(line, ">"), "RCPT TO:<"), "@")
			address := &Address{
				Name:    addressSlice[0],
				Address: addressSlice[1],
			}

			if isSubmission {
				if state.AUTH == nil {
					err = textProto.PrintfLine("503 5.5.1 AUTH required")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
					continue
				}
			} else {
				_, ok := fr.ownedDomains[address.Address]
				if !ok {
					err = textProto.PrintfLine("503 5.5.1 Relaying not allowed")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
					continue
				}

				ok, err := fr.database.CheckUser(address)
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}

				if !ok {
					err = textProto.PrintfLine("550 5.1.1 User not found")
					if err != nil {
						_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
						_ = conn.Close()
						return
					}
					continue

				}
			}

			state.RCPT = append(state.RCPT, address)
			err = textProto.PrintfLine("250 2.1.5 Recipient OK")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}
		case strings.HasPrefix(line, "DATA"):
			if !state.TLS && fr.enforceTLS {
				err = textProto.PrintfLine("530 5.7.0 Must issue a STARTTLS command first")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			if state.FROM == nil {
				err = textProto.PrintfLine("503 5.5.1 MAIL FROM required")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			if len(state.RCPT) == 0 {
				err = textProto.PrintfLine("503 5.5.1 RCPT TO required")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
				continue
			}

			err = textProto.PrintfLine("354 2.0.0 Start mail input; end with <CRLF>.<CRLF>")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}

			state.DATA, err = io.ReadAll(textProto.DotReader())

			mail := &Mail{
				From: state.FROM,
				To:   state.RCPT,
				Data: state.DATA,
			}

			if !isSubmission {
				err := fr.database.WriteMail(mail)
				if err != nil {
					_ = textProto.PrintfLine(err.Error())
					_ = conn.Close()
					return
				}

				err = textProto.PrintfLine("250 2.0.0 Message accepted for delivery")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}
			} else {
				queueID := time.Now()

				queue[queueID] = &MailQueueItem{
					From: state.FROM,
					To:   state.RCPT,
					Host: strings.Split(conn.RemoteAddr().String(), ":")[0],
				}
				go sendEmail(SenderArgs{
					EnforceTLS: fr.enforceTLS,
				}, mail, fr.database, queueID)

				err = textProto.PrintfLine("250 2.0.0 Message queued for delivery")
				if err != nil {
					_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
					_ = conn.Close()
					return
				}

				state.DATA = nil
				state.FROM = nil
				state.RCPT = nil
			}
		default:
			err = textProto.PrintfLine("500 5.5.2 Command not recognized")
			if err != nil {
				_ = textProto.PrintfLine("421 4.7.0 Temporary server error")
				_ = conn.Close()
				return
			}
		}
	}

}

// SenderArgs is a struct that represents the arguments for the Sender
type SenderArgs struct {
	EnforceTLS bool
}

type DebugRWC struct {
	net.Conn
}

func (d DebugRWC) Write(p []byte) (n int, err error) {
	fmt.Println("Write: ", string(p))
	return d.Conn.Write(p)
}

func (d DebugRWC) Read(p []byte) (n int, err error) {
	n, err = d.Conn.Read(p)
	fmt.Println("Read: ", string(p))
	return
}

func (d DebugRWC) Close() error {
	fmt.Println("Close")
	return d.Conn.Close()
}

// Send sends an email to another server
func Send(args SenderArgs, mail *Mail, conn net.Conn, mxHost string) (err error) {
	textConn := textproto.NewConn(DebugRWC{conn})

	err = textConn.PrintfLine("RSET")
	if err != nil {
		return err
	}

	code, line, err := textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 220 {
		return errors.New("unexpected RSET response - " + line)
	}

	code, line, err = textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 250 {
		return errors.New("unexpected greeting - " + line)
	}

	err = textConn.PrintfLine("EHLO %s", mxHost)
	if err != nil {
		return err
	}

	code, lines, err := readMultilineCodeResponse(textConn)
	if err != nil {
		return err
	}

	if code != 250 {
		return errors.New("unexpected EHLO response - " + lines)
	}

	if strings.Contains(lines, "STARTTLS") {
		err = textConn.PrintfLine("STARTTLS")
		if err != nil {
			return err
		}

		code, line, err := textConn.ReadCodeLine(0)
		if err != nil {
			return err
		}

		if code != 220 {
			return errors.New("unexpected STARTTLS response - " + line)
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         mxHost,
			InsecureSkipVerify: false,
		})

		err = tlsConn.Handshake()
		if err != nil {
			return err
		}

		textConn = textproto.NewConn(tlsConn)

		// Just use HELO, no point using EHLO when we already have all the capabilities
		// This also gets us out of using readMultilineCodeResponse
		err = textConn.PrintfLine("HELO %s", mxHost)
		if err != nil {
			return err
		}

		code, line, err = textConn.ReadCodeLine(0)
		if err != nil {
			return err
		}

		if code != 250 {
			return errors.New("unexpected STARTTLS HELO response - " + line)
		}
	} else if args.EnforceTLS {
		return errors.New("STARTTLS not supported")
	}

	err = textConn.PrintfLine("MAIL FROM:<%s@%s>", mail.From.Name, mail.From.Address)
	if err != nil {
		return err
	}

	code, line, err = textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 250 {
		return errors.New("unexpected MAIL FROM response - " + line)
	}

	for _, recipient := range mail.To {
		err = textConn.PrintfLine("RCPT TO:<%s@%s>", recipient.Name, recipient.Address)
		if err != nil {
			return err
		}

		code, line, err = textConn.ReadCodeLine(0)
		if err != nil {
			return err
		}

		if code != 250 {
			return errors.New("unexpected RCPT TO response - " + line)
		}
	}

	err = textConn.PrintfLine("DATA")
	if err != nil {
		return err
	}

	code, line, err = textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 354 {
		return errors.New("unexpected DATA response - " + line)
	}

	writer := textConn.DotWriter()
	_, err = writer.Write(mail.Data)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return errors.New("failed to close data writer - " + err.Error())
	}

	code, line, err = textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 250 {
		return errors.New("unexpected DATA finish response - " + line + ", your message may have been sent, but it is not guaranteed")
	}

	err = textConn.PrintfLine("QUIT")
	if err != nil {
		return err
	}

	code, line, err = textConn.ReadCodeLine(0)
	if err != nil {
		return err
	}

	if code != 221 {
		return errors.New("unexpected QUIT response - " + line + ", your message may have been sent, but it is not guaranteed")
	}

	return
}
