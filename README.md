# PAM TOTP Authentication Module
A lightweight C-based Pluggable Authentication Module (PAM) for **Two-Factor Authentication** using RFC 6238 TOTP tokens.

This module provides an additional layer of security by requiring a TOTP (Time-based One-Time Password) during the authentication stack.

## Compilation
To compile the source code into a shared object (`.so`) file that PAM can load:

```bash
gcc -fPIC -shared -o pam_totp.so totp.c -lpam -loath
```

## Secret storage

Create the following directory to store the secrets for each user:

```bash
sudo mkdir -p /etc/totp_secrets/
sudo chmod 700 /etc/totp_secrets/
```

To store the secret, write a base32 encoded string of the secret, into a file with the relevant username, to that directory:

e.g.
```bash
 echo "GEZDGNBVGY3TQOI=" | sudo tee /etc/totp_secrets/root > /dev/null
```