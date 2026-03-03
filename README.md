# nailed

Use Secure Enclave on M* Macs as a generic PKCS#11 secure token.

<img width="2358" height="696" alt="connection" src="https://github.com/user-attachments/assets/f80e0455-c228-4596-9d49-86f4ba3340b4" />


## Motivation

TL;DR: The main goal of this project is to make it possible to run OpenVPN with keys stored inside Secure Enclave. But it works as a generic PKCS#11 interface.

You can run OpenVPN on Linux with unextractable key material on TPM using [tpm-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) or [tpm2-openssl provider](https://github.com/tpm2-software/tpm2-openssl). You can run OpenVPN on Windows with key material on TPM by just using appropriate [Crypto Provider](https://en.wikipedia.org/wiki/Cryptographic_Service_Provider). What about modern Macs, those with Secure Enclave chips? Secure Enclave does not have standard interfaces (well, it [does](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf), but it does not solve my problem). You cannot run OpenVPN with keys inside Secure Enclave. 

## How to use

You can find built, signed and notarized binaries in `Releases` of this repo (or you can build everything yourself).

GUI was removed in 1.3.0. You get a menu bar item with basic info and a CLI:

```
nailed --help
nailed v1.3.0 — Secure Enclave identity manager

Usage: nailed <command> [options]

Commands:
  status                          Show identity and certificate status
  generate-identity               Generate a new Secure Enclave key pair
  generate-csr <CN> [-o FILE]     Generate a Certificate Signing Request
  import-certificate <FILE>       Import a signed certificate (PEM or DER)
  export-certificate [-o FILE]    Export the certificate in PEM format
  delete-identity [--force]       Delete the identity (irreversible)
  enable-login-item               Register nailed to launch at login
  disable-login-item              Remove nailed from login items

Run 'nailed <command> --help' for details on a specific command.

When invoked without a command, the menu bar service starts (signing server + status icon).
```

You can generate a key and a CSR via CLI, sign the CSR with your CA, import the certificate back. `nailed enable-login-item` makes the service auto-start on boot.

The PKCS#11 module is installed in `~/.pkcs11_modules` - you can use it with `OpenVPN Connect` right away.

To run `openvpn` from the terminal/Tunnelblick, find the PKCS#11 ID with `openvpn --show-pkcs11-ids ~/.pkcs11_modules/libnailed_pkcs11.dylib` and use the following snippet in your config:

```
pkcs11-id <serialized id>
pkcs11-providers ~/.pkcs11_modules/libnailed_pkcs11.dylib
```

Currently the default Tunnelblick openvpn binary does not support PKCS#11; see below.


## Current OpenVPN client situation

OpenVPN Connect has PKCS#11 support out of the box, but has a bug where it asks for PKCS#11 PIN even when the module does not require a PIN (`CKF_PROTECTED_AUTHENTICATION_PATH` in case of nailed). That's quite a letdown on the UX side.  
Tunnelblick ships openvpn binaries without PKCS#11 support for some reason.  
So, now openvpn binaries with PKCS#11 support are built and released together with nailed to simplify nailed+Tunnelblick deployments. The binary is put in the directory where Tunnelblick expects it by the package. Homebrew-provided binary works just as well though - you don't need this specially-crafted one. 

## How it works

This solution started as an OpenVPN management server, but evolved into a PKCS#11 module (that OpenVPN can use). Currently, the PKCS#11 shared library communicates with a signing server over a Unix socket using the OpenVPN management protocol. 

## Roadmap

1) ~~Switch from "OpenVPN Management Protocol over Unix Socket" to "Background Service available over XPC"~~ - does not work for nailed.
2) ~~Introduce App Attestation with configurable backend. My hypothesis is that app attestation can work as a surrogate [key attestation](https://www.security-embedded.com/blog/2021/5/2/under-the-hood-webauthn-in-safari); I may be wrong. We'll see.~~ - I was wrong, app attestation keys cannot be used as generic SE-backed keys, they cannot sign arbitrary data (obvious in hindsight). The only way seems to be "attest the app; then believe attested app that the key it generated is really SE-backed". But the trust shift is too radical and is not worth it in my book.

The project is feature-complete for my use cases. No major features are planned.