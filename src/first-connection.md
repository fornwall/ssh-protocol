# Observe a connection

Before studying the packet format, watch a mature client perform the protocol. OpenSSH's
debug log uses implementation terminology, but its order closely follows the
wire exchange.

## A safe observation lab

Use a test server whose host-key fingerprint you can verify independently. The
commands below do not weaken host verification and do not put a password on the
command line.

First inspect the effective configuration without connecting:

```console
ssh -G example.test | less
```

Then connect with verbose logging and run a harmless command:

```console
ssh -vvv -S none user@example.test 'printf "hello from the server\n"'
```

`-S none` disables OpenSSH connection sharing for this invocation. Otherwise,
an existing `ControlMaster` connection could carry the command without a new
identification exchange, key exchange, or user authentication. That would hide
the very phases this lab is meant to observe. If the effective configuration
uses a jump host, distinguish its connection from the final server's; see
[SSH through a jump host](./forwarding.md#ssh-through-a-jump-host).

The options are documented by the
[OpenBSD `ssh(1)` manual](https://man.openbsd.org/ssh.1). Debug output can
contain hostnames, usernames, paths, key fingerprints, and command text. Review
it before sharing it.

> If the client asks whether to trust a new host key, pause. Compare the shown
> fingerprint with a value obtained through a separate trusted channel. The
> prompt is a security decision, not connection boilerplate.

## Turn the log into phases

Exact messages vary by client version and server configuration. Instead of
matching every log line, classify the evidence.

```mermaid
flowchart TD
    A["TCP connected"] --> B["Local and remote<br/>identification strings"]
    B --> C["Algorithm proposals"]
    C --> D["Chosen KEX, host key,<br/>cipher and integrity"]
    D --> E["Server host-key fingerprint"]
    E --> F{"Host trusted?"}
    F -- no --> X["Stop"]
    F -- yes --> G["New traffic keys active"]
    G --> H["Authentication methods"]
    H --> I["Authentication succeeded"]
    I --> J["Session channel opened"]
    J --> K["Command and exit status"]
```

Build a small table from your own log:

| Question | Evidence to find |
| --- | --- |
| Which protocol/software versions met? | local and remote version strings |
| Which key exchange was selected? | negotiated KEX name |
| Which long-term server key signed it? | host-key algorithm and fingerprint |
| How are packets protected each way? | cipher and MAC, or an AEAD cipher |
| How was the user authenticated? | offered and accepted method |
| What application stream was opened? | session channel and `exec` request |
| How did the result finish? | EOF, exit status, and channel close |

Do not expect debug lines to be protocol packets one-for-one. A client may log
one decision after processing several packets, and one SSH packet may trigger
several log entries.

### A compact annotated trace

The following synthetic excerpt uses OpenSSH-like wording. It is not a literal
wire dump, and real versions include more detail.

```text
Connection established.
Local version string SSH-2.0-OpenSSH_X
Remote protocol version 2.0, remote software version OpenSSH_Y
kex: algorithm: curve25519-sha256
kex: host key algorithm: ssh-ed25519
Server host key: ssh-ed25519 SHA256:example
Host 'example.test' is known and matches the ED25519 host key.
kex: server->client cipher: ...
kex: client->server cipher: ...
Authentications that can continue: publickey,password
Offering public key: ...
Authenticated to example.test using "publickey".
Entering interactive session.
Sending command: printf "hello from the server\n"
Exit status 0
```

Read it as evidence, not as a packet list:

| Log evidence | Protocol conclusion |
| --- | --- |
| Both version strings | Identification exchange completed. |
| KEX and host-key names | Both `KEXINIT` proposals had a usable match. |
| Host key matches | The presented key matched a local trust entry; this line alone does not prove the exchange signature was verified. |
| Directional cipher lines | New packet-protection algorithms were selected. |
| Methods can continue | The server rejected or answered an authentication request and supplied current policy choices. |
| Authenticated | The client received `SSH_MSG_USERAUTH_SUCCESS`. |
| Sending command | The client attempted an `exec` request; look for its success reply to confirm acceptance. |
| Exit status 0 | The client reports that the server supplied status 0 for the command. |

The log does not show every `NEWKEYS`, channel-window update, EOF, or CLOSE.
Absence from the log is not absence from the protocol.

## Inspect supported algorithms

OpenSSH can list locally supported algorithm names without connecting:

```console
ssh -Q kex
ssh -Q key
ssh -Q cipher
ssh -Q mac
```

“Supported” is not the same as “enabled by default,” “negotiated,” or “safe for
new deployments.” This distinction becomes central during KEXINIT negotiation.

Keep four sets distinct: supported, enabled by policy, offered to the peer,
and selected for this connection.

## What a packet capture can show

A capture can show the TCP connection, both textual identification lines, the
initial unencrypted SSH packets, traffic sizes, timings, and connection closure.
After `SSH_MSG_NEWKEYS`, it cannot reveal protected message contents without
the traffic keys.

Exact SSH packet boundaries may also be hidden when the negotiated cipher
encrypts packet lengths. TCP segment sizes remain visible, but they are not
SSH message sizes. Possession of the server's long-term host private key is
insufficient to decrypt a recording of an ephemeral key exchange; that is the
point of [forward secrecy](./key-exchange.md#the-basic-signed-key-exchange-flow).

```mermaid
timeline
    title Visibility to a passive packet capture
    TCP setup : addresses and ports
    Identification : readable protocol lines
    Initial key exchange : framing and public handshake data
    NEWKEYS : protection changes direction by direction
    Protected session : sizes and timing, not plaintext contents
```

The remaining metadata is still sensitive. Packet lengths and timing can leak
behavioral clues, which is one reason the transport includes random padding.
Padding reduces some obvious structure; it does not make all traffic patterns
invisible. See the traffic-analysis discussion in
[RFC 4251 section 9.3.9](https://www.rfc-editor.org/rfc/rfc4251#section-9.3.9).

## Checkpoint

Given an `ssh -vvv` log, you should now be able to mark these boundaries:

1. the reliable stream exists;
2. algorithm negotiation begins;
3. the server's identity is accepted;
4. packet protection becomes active;
5. the user is authenticated; and
6. a connection-protocol channel carries the command.

If a connection fails, name the last boundary crossed. That single habit turns
“SSH is broken” into a much smaller investigation.
