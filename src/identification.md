# Identification exchange

SSH starts with one line of text in each direction. The exchange answers a
narrow question: can the endpoints continue with SSH version 2? It also
records implementation identifiers that later become part of the
authenticated key-exchange transcript.

## The identification line

The line has this form:

```text
SSH-protoversion-softwareversion [SP comments] CR LF
```

Square brackets mark an optional part: the comment and its preceding space
may be omitted. `SP` denotes a space, and `CR LF` denotes the line ending.

For example, an OpenSSH 9.6 client might send:

```text
SSH-2.0-OpenSSH_9.6<CR><LF>
```

An Ubuntu-packaged OpenSSH server might send:

```text
SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13<CR><LF>
```

In the server example, `OpenSSH_9.6p1` is the software version and
`Ubuntu-3ubuntu13` is the optional comment.

The complete line is at most 255 characters including CRLF and must not
contain NUL. Version `2.0`
selects the protocol described by the SSH version 2 RFCs. The historical
value `1.99` also advertises version 2 compatibility; it is not a separate
protocol version.

The peers may send their lines without waiting for each other. The exchange
has no request-response order.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: Open byte stream
    par Client direction
        C->>S: Client identification line
        C->>S: First client binary packet
    and Server direction
        S->>C: Server identification line
        S->>C: First server binary packet
    end
```

This guide uses two related terms:

- **identification line**: the transmitted bytes, including the line ending;
- **identification string**: the value placed in the exchange hash, without
  the line ending.

Keeping the distinction avoids hashing a reconstructed or normalized value.

## Server lines before identification

A server may send other lines before its SSH identification line. This was
designed for notices from wrappers and gateways. A conforming client accepts
these lines until it finds a line beginning with `SSH-`.

```text
This system is restricted to authorized users.<CR><LF>
Maintenance window: Sunday 02:00 UTC.<CR><LF>
SSH-2.0-ExampleServer_4.2<CR><LF>
```

Pre-identification lines must not begin with `SSH-`. They are not included in
the exchange hash. If a client displays them, it should filter terminal
control characters. They are peer-controlled text.

The OpenSSH client does not display these lines by default; with verbose
mode (`-v`), it displays them as debug messages.

This allowance is asymmetric. The client's identification line is its first
line on the connection.

## The boundary to binary packets

There is no content-type marker between the line exchange and binary SSH.
After the LF that terminates an endpoint's identification line, that endpoint's
next byte starts its first binary packet.

```text
... ExampleServer_4.2 CR LF | 00 00 04 ec ...
                             ^ first binary-packet byte
```

The first packet is normally `SSH_MSG_KEXINIT`. TCP may deliver the line and
part of this packet in one read. Read boundaries do not change the protocol
boundary.

## Cleartext authenticated later

Identification lines are cleartext. A network observer can read them, and an
active attacker can change bytes before key exchange has authenticated the
connection.

Key exchange later hashes the exact client and server identification strings
into the
[exchange hash](./key-exchange.md#the-exchange-hash-authenticate-the-whole-decision).
The server signs that hash. A simple in-transit change
makes the client and server compute different hashes, so signature verification
fails. A full machine-in-the-middle can instead conduct two self-consistent
exchanges and sign one with a substituted host key; the client's host-key trust
check rejects that case.

This is retrospective authentication, not confidentiality. A successful
handshake detects modification of the identification strings but never hides
them.

## Check the boundary

1. Can the server send a notice before its identification line? Can the
   client?
2. Does CRLF enter the exchange hash?
3. If one TCP read contains the server line and 20 more bytes, what are those
   20 bytes?
4. Why can a passive observer read an identification string even though the
   string is authenticated later?

<details>
<summary>Answers</summary>

1. The server can send other lines first, as long as none begins with `SSH-`.
   The client cannot: its identification line is its first line.
2. No. The exchange hash uses the identification string, which excludes the
   CR and LF.
3. The first 20 bytes of the server's first binary packet, normally the start
   of its `SSH_MSG_KEXINIT` packet.
4. Authentication detects modification after the fact; it does not encrypt.
   The lines are sent before any keys exist and are never encrypted.

</details>

## References

- [RFC 4253, Section 4 — Connection Setup](https://www.rfc-editor.org/rfc/rfc4253.html#section-4)
- [RFC 4253, Section 8 — Diffie-Hellman Key Exchange](https://www.rfc-editor.org/rfc/rfc4253.html#section-8)
