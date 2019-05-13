package main

import (
	"bufio"
	"flag"
	"fmt"
	"ghidorah/ssh"
	"ghidorah/structs"
	"os"
	"strings"
)

func main() {
	hostArgPtr := flag.String("host", "", "Host to bruteforce against.")
	portArgPtr := flag.Int("port", 0, "Port the service is running on.")
	hostListPtr := flag.String("host-list", "", "List of hosts to attempt brute force against (one per line)")
	userNamePtr := flag.String("username", "", "Username to attempt login as.")
	passwordPtr := flag.String("password", "", "Password to login as.")
	sshPrivateKey := flag.String("private-key", "", "SSH Certificate file/Private key to use for authentication.")
	userListPtr := flag.String("user-list", "", "Text file of usernames to try (one per line).")
	passwordListPtr := flag.String("password-list", "", "Text file of passwords to try (one per line).")
	credentialFilePtr := flag.String("credential-file", "", "Colon separated list of credentials to try, one per line. (i.e. root:root)")
	debugPtr := flag.Bool("debug", false, "Turn on debug output.")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("[-] Error: No service specified. Must be one of ftp or ssh.")
		fmt.Println("[-] Example: ghidorah --username admin --password admin --host 127.0.0.1 ssh")
		return
	}

	// Parse arguments here
	if *hostArgPtr == "" && *hostListPtr == "" {
		fmt.Println("[-] Error: No hosts given. Pass --host or --host-list.")
		return
	}

	if *portArgPtr < 0 || *portArgPtr > 65535 {
		fmt.Println("[-] Error: Invalid port passed.")
		return
	}

	if *userNamePtr == "" && *userListPtr == "" && *credentialFilePtr == "" {
		fmt.Println("[-] Error: No username provided. Pass --username or --user-list.")
		return
	}

	if *passwordPtr == "" && *passwordListPtr == "" && *credentialFilePtr == "" && *sshPrivateKey == "" {
		fmt.Println("[-] Error: No password provided. Pass --password or --password-list.")
		return
	}

	// variable declarations
	var hosts []string
	var usernames []string
	var passwords []string
	var credentials []structs.Credential
	var service string
	var port int

	// parse the hosts into the hosts array
	if *hostArgPtr != "" {
		hosts = append(hosts, *hostArgPtr)
	} else {
		file, err := os.Open(*hostListPtr)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			host := scanner.Text()
			hosts = append(hosts, host)
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}

	// Parse credential file, if it exists
	if *credentialFilePtr != "" {
		file, err := os.Open(*credentialFilePtr)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			credentialStr := scanner.Text()
			credentialParts := strings.SplitN(credentialStr, ":", 2)
			var cred structs.Credential
			cred.Username = credentialParts[0]
			if _, err := os.Stat(credentialParts[1]); os.IsNotExist(err) {
				// path/to/whatever does not exist
				cred.Password = credentialParts[1]
			} else {
				cred.PrivateKey = credentialParts[1]
			}
			credentials = append(credentials, cred)
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	} else {
		// Parse all usernames
		if *userNamePtr != "" {
			usernames = append(usernames, *userNamePtr)
		} else {
			file, err := os.Open(*userListPtr)
			if err != nil {
				panic(err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				username := scanner.Text()
				if username != "" {
					usernames = append(usernames, username)
				}
			}
			if err := scanner.Err(); err != nil {
				panic(err)
			}
		}
		// Parse passwords
		if *passwordPtr != "" && *passwordPtr != "null" {
			passwords = append(passwords, *passwordPtr)
		} else if *passwordListPtr != "" {
			file, err := os.Open(*passwordListPtr)
			if err != nil {
				panic(err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				password := scanner.Text()
				if password != "" {
					passwords = append(passwords, password)
				}
			}
			if err := scanner.Err(); err != nil {
				panic(err)
			}
		} else if *passwordPtr == "null" {
			passwords = append(passwords, "")
		}

		// Now populate the credentials
		if len(passwords) > 0 {
			for i := 0; i < len(usernames); i++ {
				for j := 0; j < len(passwords); j++ {
					var cred structs.Credential
					cred.Username = usernames[i]
					cred.Password = passwords[j]
					credentials = append(credentials, cred)
				}
			}
		} else {
			for i := 0; i < len(usernames); i++ {
				var cred structs.Credential
				cred.Username = usernames[i]
				cred.PrivateKey = *sshPrivateKey
				credentials = append(credentials, cred)
			}
		}
	}

	if len(credentials) == 0 {
		// Something horrible happened.
		fmt.Println("[-] Could not parse any credentials from the files passed.")
		return
	}
	if len(hosts) == 0 {
		fmt.Println("[-] Could not parse any hosts to target.")
		return
	}

	if *debugPtr {
		hostDebugStr := fmt.Sprintf("[DEBUG] Parsed %d host(s):", len(hosts))
		fmt.Println(hostDebugStr)
		credDebugStr := fmt.Sprintf("[DEBUG] Created %d credential pair(s):", len(credentials))
		fmt.Println(credDebugStr)
	}

	switch service = flag.Args()[0]; service {
	case "ssh":
		if *portArgPtr == 0 {
			port = 22
		} else {
			port = *portArgPtr
		}
		ssh.SSHBruteForce(hosts, port, credentials, *debugPtr)
	// case "ftp":
	// 	if *portArgPtr == 0 {
	// 		port = 21
	// 	} else {
	// 		port = *portArgPtr
	// 	}
	// 	FTPBruteForce(hosts, port, credentials, *debugPtr)
	default:
		fmt.Println("[-] Error: Invalid service provided. Please pass one of 'ssh' or 'ftp'. Got:", service)
	}
	fmt.Println("[*] All done!")
	return
}
