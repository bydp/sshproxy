package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	// "time"
)

func remoteServer(login string) string {
	var remote string
	//	remote := ""

	content, err := ioutil.ReadFile("/home/system/sftp.login")
	if err != nil {
		log.Println("SFTP login db load failed!")
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(strings.TrimSpace(line), " ")
		username := strings.TrimSpace(parts[0])
		remote = strings.TrimSpace(parts[1])
		if username == login {
			log.Printf("Found login %s - %s", username, remote)
			return remote
		}

	}

	return ""
}

func main() {
	var private ssh.Signer

	f, err := os.OpenFile("/var/log/sshproxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	log.Printf("SSHProxy v0.17")

	privateBytes, err := ioutil.ReadFile("/home/system/id_rsa")
	if err != nil {
		log.Println("Failed to load private key")
		return
	}

	private, err = ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Println("Failed to parse private key")
		return
	}

	listener, err := net.Listen("tcp", ":22")
	if err != nil {
		log.Printf("net.Listen failed: %v", err)
		panic("chyba")
	}
	defer func() {
		listener.Close()
		log.Printf("SSHProxy server closed")
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("%s listen.Accept failed: %v", err)

		}
		go serveConnection(conn, private)
	}
}

func serveConnection(conn net.Conn, private ssh.Signer) {
	var login string
	var password []byte
	var remote string
	var ip string

	ip = fmt.Sprintf("%s", conn.RemoteAddr())

	log.Printf("%s new connection", ip)

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("%s Login attempt: user %s password: %s\n", c.RemoteAddr(), c.User(), string(pass))
			login = c.User()
			password = pass
			return nil, nil
		},
	}
	config.AddHostKey(private)

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("%s failed to handshake: %s", ip, err)
		return
	}
	log.Printf("%s new SSH connection from (%s)", ip, serverConn.ClientVersion())

	defer func() {
		serverConn.Close()
		log.Printf("%s Closed connection", serverConn.RemoteAddr())
		return
	}()

	clientConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.Password(string(password))},
	}

	remote = remoteServer(login)
	if remote == "" {
		log.Printf("%s nelze najit login %s", ip, login)
		serverConn.Close()
		return
	}

	log.Printf("%s Dial %s: %s %s", ip, remote, login, string(password))

	clientConn, err := ssh.Dial("tcp", remote, clientConfig)
	defer func() {
		log.Printf("%s dial end", ip)
		return
	}()
	if err != nil {
		log.Printf("%s nelze pripojit na upstream %s", ip, remote)
		return
	}

	go func() { err := serverConn.Wait(); log.Printf("%s Wait: %v", ip, err); serverConn.Close() }()
	go func() { err := clientConn.Wait(); log.Printf("%s Wait2: %v", ip, err); clientConn.Close() }()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		log.Printf("%s New SSH channel %s", ip, newChannel.ChannelType())

		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("%s unknown channel type: %s", ip, t))
			return
		}

		channel2, requests2, err2 := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err2 != nil {
			log.Printf("%s could not accept client channel: %s", ip, err2.Error())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("%s could not accept server channel: %s", ip, err.Error())
			continue
		}
	r:
		for {
			// log.Printf("...")
			var req *ssh.Request
			var dst ssh.Channel
			select {
			case req = <-requests:
				dst = channel2
			case req = <-requests2:
				dst = channel
			}

			log.Printf("%s Request: %s %s %s\n", ip, req.Type, req.Payload, req.WantReply)

			b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Printf("%s Err: %s", ip, err)
			}
			if req.WantReply {
				req.Reply(b, nil)
			}

			log.Printf("%s req type: %s", ip, req.Type)
			switch req.Type {
			case "exec":
				log.Printf("%s req exec - force close!", ip)
				channel.Close()
				channel2.Close()
				break r
			case "subsystem":
				done := make(chan bool)
				go func() {
					io.Copy(channel, channel2)
					done <- true
				}()
				go func() {
					io.Copy(channel2, channel)
					done <- true
				}()
				<-done
				channel.Close()
				channel2.Close()
				<-done
				break r
			}
		}
	}
}
