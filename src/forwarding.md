# TCP forwarding

TCP forwarding uses SSH channels as byte relays. It lets one endpoint request
a connection from the other endpoint's network position. Channel identifiers,
windows, and close behavior follow
[Channels and flow control](./channels.md).

The familiar labels *local*, *dynamic*, and *remote* forwarding describe local
client behavior. On the SSH wire, the core mechanisms are `direct-tcpip`
channels and a combination of `tcpip-forward` requests with
`forwarded-tcpip` channels.

| User-facing mode | Listener | SSH action for each connection | Peer that connects to target |
| --- | --- | --- | --- |
| Local forwarding | Client | Client opens `direct-tcpip` | Server |
| Dynamic forwarding | Client | Client translates SOCKS, then opens `direct-tcpip` | Server |
| Remote forwarding | Server | Server opens `forwarded-tcpip` | Client |

## Direct TCP channels

A `direct-tcpip` open asks the SSH peer to make an outbound TCP connection:

```text
string    "direct-tcpip"
uint32    sender channel
uint32    initial window size
uint32    maximum packet size
string    host to connect
uint32    port to connect
string    originator IP address
uint32    originator port
```

The client normally sends this open to the server. RFC 4254 recommends that
clients reject server-initiated `direct-tcpip` opens.

For a conceptual local forward
`-L 127.0.0.1:8080:db.internal:5432`, the client listens locally. Each accepted
connection creates a new channel:

```mermaid
sequenceDiagram
    participant A as Local application
    participant C as SSH client
    participant S as SSH server
    participant T as db.internal:5432
    A->>C: Connect to 127.0.0.1:8080
    C->>S: OPEN direct-tcpip<br/>target db.internal:5432
    S->>T: TCP connect
    alt Target connected
        T-->>S: Connected
        S-->>C: OPEN_CONFIRMATION
        A<<->>T: Bytes in channel data
    else Connect failed or policy denied
        S-->>C: OPEN_FAILURE
    end
```

The server resolves the target name and makes the connection. The target may
be visible from the server's network but not from the client. The originator
address is peer-supplied context; it is not an authenticated user identity.

Dynamic forwarding differs before the channel opens. The SSH client accepts a
SOCKS request, extracts its destination, and opens a `direct-tcpip` channel for
that destination. SOCKS messages do not cross the SSH connection.

## Requesting a remote listener

Remote forwarding has two levels of state:

1. A `tcpip-forward` global request creates a server-side listener.
2. Each accepted TCP connection creates a `forwarded-tcpip` channel.

```mermaid
sequenceDiagram
    participant C as SSH client
    participant S as SSH server
    participant R as Remote application
    participant T as Client-side target
    C->>S: GLOBAL_REQUEST tcpip-forward<br/>bind address and port, reply=true
    S-->>C: REQUEST_SUCCESS
    R->>S: Connect to server listener
    S->>C: OPEN forwarded-tcpip<br/>connected address and originator
    C->>T: TCP connect
    alt Target connected
        T-->>C: Connected
        C-->>S: OPEN_CONFIRMATION
        R<<->>T: Bytes in channel data
    else Target failed or open was not authorized
        C-->>S: OPEN_FAILURE
    end
```

The forwarded-channel fields contain the server address that received the
connection and the reported originator. They do not contain the client-side
target. The client remembers that target as part of the forwarding request's
local state.

If the requested port is zero, the server allocates a port. A successful reply
then carries the allocated port as a `uint32`. The client needs that value
before it can report where the listener exists.

## Cancellation and races

The client cancels a listener with `cancel-tcpip-forward`, using the same bind
address and actual listener port. If the request used port zero, this means the
allocated port returned in `REQUEST_SUCCESS`, not zero. The client should wait
for a reply when it needs a clear end boundary.

A forwarded connection can race with cancellation. A channel open that was
already in flight may arrive before the cancellation result. The client must
match each `forwarded-tcpip` open to forwarding state that was authorized when
the server accepted the connection; it must reject unsolicited opens.

Closing a shell channel does not cancel a listener or close existing forwarded
channels. They are independent connection-protocol objects. Ending the SSH
transport ends all of them.

## Where protection ends

SSH protects channel data only between the SSH client and SSH server.

For local or dynamic forwarding, the server-to-target connection needs its own
application security if the target network is untrusted. SSH does not verify
the target's identity.

For remote forwarding, listener scope controls exposure. A loopback bind
normally limits who can connect on the server. A wildcard bind can expose the
client-side target to other hosts that can reach the server.

Forwarding also changes reachability. A direct channel may reach an internal
server-side service. A remote listener may expose a private client-side
service. Server and client policy can restrict bind addresses, ports, and
targets before granting these capabilities.

## Related channels are separate protocols

X11 forwarding, agent forwarding, and Unix-domain-socket forwarding use
additional channel types or requests. They are not alternative spellings of
TCP forwarding.

Agent forwarding has a particularly sharp boundary: the remote host receives
access to a signing service, not the private-key bytes. A compromised remote
host may still ask that service to sign while the forwarding channel is open.
Key constraints and host-bound authentication can narrow this delegated
capability, but ordinary SSH transport protection does not remove it.

## Check the viewpoint

1. Who resolves a `direct-tcpip` target name?
2. Where is SOCKS interpreted during dynamic forwarding?
3. What persistent state links a `forwarded-tcpip` open to its client-side
   target?
4. Does closing a session channel cancel a remote-forwarding listener?
5. Which links in a local forward are protected by SSH?

## References

- [RFC 4254, Section 4 — Global Requests](https://www.rfc-editor.org/rfc/rfc4254.html#section-4)
- [RFC 4254, Section 7 — TCP/IP Port Forwarding](https://www.rfc-editor.org/rfc/rfc4254.html#section-7)
- [OpenSSH protocol extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
