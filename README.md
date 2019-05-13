# Ghidorah

Ghidorah is an incomplete Golang port of the tool `hydra`. 

## Supported Authentication Methods

1. SSH

## Usage

```
Usage of ghidorah:
  -credential-file string
        Colon separated list of credentials to try, one per line. (i.e. root:root)
  -debug
        Turn on debug output.
  -host string
        Host to bruteforce against.
  -host-list string
        List of hosts to attempt brute force against (one per line)
  -password string
        Password to login as.
  -password-list string
        Text file of passwords to try (one per line).
  -port int
        Port the service is running on.
  -private-key string
        SSH Certificate file/Private key to use for authentication.
  -user-list string
        Text file of usernames to try (one per line).
  -username string
        Username to attempt login as.
```

## Example

`ghidorah -host 127.0.0.1 -username root -password root ssh`

## Issues?

This project is not under active development and as such will not be supported like it is. All issues will be closed.