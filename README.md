# nailed

Use Secure Enclave on M* Macs as a generic PKCS11 secure token.

<img width="1820" height="918" alt="interface" src="https://github.com/user-attachments/assets/3f7c33d0-f154-44b2-a979-a6a63c5ee283" />

<img width="2358" height="696" alt="connection" src="https://github.com/user-attachments/assets/f80e0455-c228-4596-9d49-86f4ba3340b4" />


## Motivation

TL;DR: Main goal of this project is to make it possible to run OpenVPN with keys stored inside Secure Enclave. But it does work as a generic PKCS11 interface.

You can run OpenVPN on Linux with key material unextractable on TPM using [tpm-pkcs11](https://github.com/tpm2-software/tpm2-pkcs11) or [tpm2-openssl provider](https://github.com/tpm2-software/tpm2-openssl). You can run OpenVPN on Windows with key material on TPM by just using appropriate [Crypto Provider](https://en.wikipedia.org/wiki/Cryptographic_Service_Provider). Modern Macs? Secure Enclave does not have standard interfaces (well, it [does](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf), but it does not solve my problem), you cannot run OpenVPN with keys inside Secure Enclave. 

## How to use

You can find built, signed and notarized binaries in `Releases` of this repo (or you can build everything yourself). After that, in the GUI you can generate a key, generate a CSR. Sign the CSR with your CA, then import the certificate.

PKCS11 module is installed into `~/.pkcs11_modules` - you can use it with `OpenVPN Connect` right away.
To run `openvpn` from the terminal:
1) Find the pkcs11 id with `openvpn --show-pkcs11-ids ~/.pkcs11_modules/libnailed_pkcs11.dylib` and use

```
pkcs11-id <serialized id>
pkcs11-providers ~/.pkcs11_modules/libnailed_pkcs11.dylib
```

## How it works

This solution started as an OpenVPN management server, but evolved into a PKCS11 module (that OpenVPN can use). Currently the pkcs11 shared library communicates with a signing server over a unix socket using the openvpn management protocol. 

## Roadmap

Currently, I have two changes planned:
1) Switch from "OpenVPN Management Protocol over Unix Socket" to "Background Service available over XPC"
2) Introduce App Attestation with configurable backend. My hypothesis is that app attestation can work as a surrogate [key attestation](https://www.security-embedded.com/blog/2021/5/2/under-the-hood-webauthn-in-safari); I may be wrong. We'll see. 
