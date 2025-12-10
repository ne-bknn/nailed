# nailed

Launch OpenVPN on Apple Silicone Macs with private keys stored on Secure Enclave chip.

<img width="1820" height="918" alt="interface" src="https://github.com/user-attachments/assets/3f7c33d0-f154-44b2-a979-a6a63c5ee283" />

<img width="2358" height="696" alt="connection" src="https://github.com/user-attachments/assets/f80e0455-c228-4596-9d49-86f4ba3340b4" />


## Motivation

On Linux you can use generic TPMs to store OpenVPN key material. Windows? Just use appropriate crypto provider and your VPN keys are unextractible, too. Apple's Secure Enclave? No go-to method exists.

## How to use

You can find built, signed and notorized binaries in `Releases` of this repo (or you can build everything yourself). After that in GUI you can generate key, generate CSR. Sign the CSR with your CA, import the certificate.

Update you openvpn config to include the following directives:
```
management /tmp/nailed_signing.sock unix
management-client
management-external-key
management-external-cert enclaved
```

...that's all.

## How it works
You can deduce by config changes that this solution uses OpenVPN's `management` interface to delegate handshake signing to `nailed`. You can learn more in openvpn's manpages.

## OpenVPN frontends' integration

Unfortunately, all of the frontends for OpenVPN use management interface to control openvpn process. And there can be only one - no sharing. Thus, configuration files with `management` directives are not supported by OpenVPN Connect, Viscosity, Tunnelblick. I've [patched Tunnelblick](https://github.com/ne-bknn/Tunnelblick/) to support the integration, but:
1) I am [not sure](https://github.com/Tunnelblick/Tunnelblick/pull/871) whether it will land in upstream Tunnelblick
2) Tunnelblick's build infra is pretty complex and I am failing to re-sign my fork properly with my own keys. Maybe later.
