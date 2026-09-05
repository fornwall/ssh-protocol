# Security properties and boundaries

SSH is often summarized as “an encrypted connection,” but that description is
too weak. Its security comes from a chain of distinct claims, and each claim
has a boundary.

## The chain of claims

```mermaid
flowchart LR
    Stream["Reliable byte stream"] --> KEX["Authenticated key exchange"]
    KEX --> Host["Trusted server identity"]
    Host --> Protected["Confidential and<br/>integrity-protected packets"]
    Protected --> User["Authenticated user"]
    User --> Policy["Authorized channels<br/>and forwarding"]
```

Breaking any link changes what later success means. A password sent through an
encrypted tunnel is not safe if the tunnel terminates at an attacker. A valid
user signature does not authorize a port forward unless server policy allows
it. A trusted server may still run a compromised operating system.

The full security discussion spans
[RFC 4251 section 9](https://www.rfc-editor.org/rfc/rfc4251#section-9) and the
security considerations of every algorithm-specific RFC.

## What the network attacker can do

Before host authentication completes, assume an active network attacker can
read, change, delete, delay, or replace the traffic. SSH detects modification
by binding the version strings, algorithm proposals, key-exchange values, and
host key into the signed exchange hash.

```mermaid
flowchart TD
    A["Attacker alters a covered handshake value"] --> C["Client and server form different exchange hashes"]
    C --> V["Host-key signature verification fails"]
    V --> X["Connection must not continue"]
```

This prevents an invisible downgrade of the signed algorithm proposals. It
does not prevent denial of service: an attacker can always drop the TCP
connection or corrupt a packet and make SSH stop.

After keys are active, confidentiality hides packet contents and integrity
protection detects changes. Packet authentication does not guarantee delivery;
the peer or network can still stop sending.

## Server proof and server trust

The key-exchange signature proves control of the private key corresponding to
the presented host key. A separate trust rule binds that key to the destination
the user intended.

```mermaid
flowchart LR
    Sig["Valid signature under<br/>presented host key"] --> Both{"Both true?"}
    Trust["Host key trusted for<br/>requested destination"] --> Both
    Both -- yes --> Accept["Server authenticated"]
    Both -- no --> Reject["Reject before credentials"]
```

Trust on first use can detect a later key change, but it cannot identify an
attacker present on the first connection. A changed key can be a legitimate
rotation or an attack; the protocol cannot decide which. That decision needs
information from outside the connection.

## Algorithm negotiation and downgrade resistance

KEXINIT chooses the first client-preferred algorithm also offered by the
server. The signed exchange hash covers both complete KEXINIT payloads, so a
network attacker cannot delete strong choices and still produce a valid host
signature.

The authenticated negotiation can still select a weak algorithm if both peers
offer it and client policy prefers or permits it. Transcript integrity cannot
repair unsafe policy.

```mermaid
flowchart TD
    Implemented["Algorithm name understood"] --> Allowed["Allowed by local policy"]
    Allowed --> Offered["Offered on this connection"]
    Offered --> Mutual["Also offered by peer"]
    Mutual --> Selected["Selected by client preference"]
```

Registration is not endorsement. The
[IANA SSH registries](https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml)
record interoperable names, while documents such as
[RFC 9142](https://www.rfc-editor.org/rfc/rfc9142) give updated security and
implementation recommendations.

## Forward secrecy and rekeying

Ephemeral key agreement means later theft of the server's long-term host key
should not reveal old recorded session keys. This is forward secrecy. It
depends on fresh ephemeral secrets being generated and discarded.

Rekeying creates new traffic keys for a live connection. It limits the amount
of data protected under one key set and respects algorithm-specific usage
limits. It does not undo exposure that has already occurred and does not change
the original session identifier.

```mermaid
timeline
    title Key lifetimes in one SSH connection
    Initial KEX : ephemeral values produce traffic keys 1
                : first exchange hash becomes session identifier
    Protected traffic : traffic keys 1 active
    Rekey : new ephemeral values produce traffic keys 2
          : session identifier remains unchanged
    More traffic : traffic keys 2 active
```

Hybrid post-quantum key exchange addresses a different future threat: an
adversary recording traffic now and later gaining a cryptographically relevant
quantum computer. It strengthens secret establishment. A traditional host
signature remains traditional server authentication, even when the KEX itself
is hybrid.

## What remains visible

SSH does not hide the network endpoints, connection duration, or all traffic
patterns. The identification strings and initial key-exchange packets are
visible before `NEWKEYS`. Later encryption hides message contents, but an
observer can still see packet timing and some representation of packet sizes.

Random padding obscures exact content lengths to a degree; it does not make SSH
a traffic-flow confidentiality system. See
[RFC 4251 section 9.3.9](https://www.rfc-editor.org/rfc/rfc4251#section-9.3.9).

## Authentication is only as strong as allowed policy

A server can require one method or a sequence of factors. If it accepts either
a strong public-key proof or a weak password, an attacker may target the weaker
route. If it requires both, `partial success` carries the conversation from the
first accepted method to the next.

Passwords and keyboard-interactive responses are protected on the network, but
the authenticated server receives them. Public-key authentication instead
proves possession by signing connection-bound data; the private key need not
leave the client or signing agent.

## Channels cross new trust boundaries

Connection-layer encryption ends at the SSH endpoints.

```mermaid
flowchart LR
    App["Local application"] --> C["SSH client"]
    C == "SSH-protected channel" ==> S["SSH server"]
    S --> T["Forwarding target"]
```

For a `direct-tcpip` channel, traffic from the server to the target is not
protected by SSH unless that application protocol supplies its own protection.
A remote forward may expose a client-side service to machines which can reach
the server's listener. Agent forwarding delegates access to a signing service
through the remote host. Each feature creates a capability which server and
client policy must deliberately authorize.

## Endpoint security is assumed

SSH cannot protect plaintext from a compromised client or server. A malicious
server can capture commands, terminal input, forwarded data, passwords, and
interactive responses which legitimately reach it. A compromised client can
steal credentials before the protocol protects them.

Host authentication answers “which SSH host key participated?” It is valuable,
but it is not an attestation that the remote operating system, account, command,
or forwarded destination is trustworthy.

## Security review

For any point in a connection, ask:

1. Which identity has been authenticated so far?
2. Which bytes are confidential, integrity-protected, or still observable?
3. Which exact transcript or sequence state is authenticated?
4. Which decision comes from protocol proof, and which comes from local policy?
5. Where does the SSH protection end for this channel's data?

These questions give a more accurate security description than the single word
“encrypted.”
