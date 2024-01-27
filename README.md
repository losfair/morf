# MoRF

MoRF is a mutually-authenticated, encrypted communication protocol over lossy
packet links with small MTUs, e.g. LoRa. Inspired by
[Noise](http://www.noiseprotocol.org/).

- `no_std` compatible, no dynamic memory allocation
- Minimum supported MTU: 49 bytes, overhead per data packet: 19 bytes
- Primitives: X25519 + HMAC-SHA256 + ChaCha20-Poly1305
- Identity hiding, forward secrecy, replay protection

## Handshake

To establish an encrypted session, a _client_ initiates a handshake to a
_server_ to exchange keys. Both peers are required to have ahead-of-time
knowledge of each other's public key.

### Notations

- $CE_{pub}$, $CE_{sec}$: Client ephemeral X25519 public/secret key
- $SE_{pub}$, $SE_{sec}$: Server ephemeral X25519 public/secret key
- $CS_{pub}$, $CS_{sec}$: Client static X25519 public/secret key
- $SS_{pub}$, $SS_{sec}$: Server static X25519 public/secret key
- $X25519(secret, public)$: X25519 Diffie-Hellman key agreement
- $ChaCha20(key, payload)$: Apply (unauthenticated) ChaCha20 keystream derived
  from $key$ to $payload$
- $Mac(key, payload)$: Apply HMAC-SHA256 with $key$ to $payload$, and truncate
  the output to the first 16 bytes.
- $DeriveKey(key, info)$: Derive a 32-byte subkey from $key$ using HKDF-SHA256
  with $info$ as the info string
- $Hash(payload)$: Calculate the SHA256 hash of $payload$ and truncate the
  output to the first 16 bytes.
- $InitialEncryptionKeyInfo$: The string `initial_encryption_key`
- $ServerEphemeralPublicKeyMacKeyInfo$: The string
  `server_ephemeral_public_key_mac_key`

### Packet 1: client to server (49 bytes)

Let $InitialKey = DeriveKey(X25519(CE_{sec}, SS_{pub}),
InitialEncryptionKeyInfo)$.

| Field                                  | Length |
| -------------------------------------- | ------ |
| $Const(3)$                             | 1      |
| $CE_{pub}$                             | 32     |
| $ChaCha20(InitialKey, Hash(CS_{pub}))$ | 16     |

### Packet 2: server to client (49 bytes)

Lookup client static public key $CS_{pub}$ from the provided hash.

Let $ServerSepkMacKey = DeriveKey(X25519(SS_{sec}, CE_{pub}),
ServerEphemeralPublicKeyMacKeyInfo)$.

Let $ServerSessionKey = Concat(X25519(SE_{sec}, CS_{pub}), X25519(SE_{sec},
CE_{pub}))$.

| Field                             | Length |
| --------------------------------- | ------ |
| $Const(1)$                        | 1      |
| $SE_{pub}$                        | 32     |
| $Mac(ServerSepkMacKey, SE_{pub})$ | 16     |

### Finalize (client)

Let $ClientSepkMacKey = DeriveKey(X25519(CE_{sec}, SS_{pub}),
ServerEphemeralPublicKeyMacKeyInfo)$.

Check that:

$Mac(ClientSepkMacKey, Packet2[1:33]) == Packet2[33:49]$

Let $ClientSessionKey = Concat(X25519(CS_{sec}, SE_{pub}), X25519(CE_{sec},
SE_{pub}))$.
