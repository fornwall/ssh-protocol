# Sessions: commands, terminals, and subsystems

A `session` channel carries one remote program. The program can be a shell, a
command, or a named subsystem. Opening the channel does not start the program;
the client starts it with a channel request.

Several session channels can share one SSH connection. Each has independent
data, flow control, exit information, and close state. This chapter applies
the mechanics from [Channels and flow control](./channels.md).

## Open, prepare, start

A client first opens a channel of type `session`. The open message contains no
command or terminal settings. RFC 4254 recommends that clients reject
server-initiated `session` opens; the normal direction is client to server.

After confirmation, the client may send setup requests such as `env` and
`pty-req`. To start a program, it chooses one of these requests:

| Request | Request-specific data | Meaning |
| --- | --- | --- |
| `shell` | none | Start the account's default shell. |
| `exec` | command string | Ask the server to execute a command. |
| `subsystem` | subsystem name | Start a configured service such as `sftp`. |

Only one of these requests can succeed on a session channel.
If a start request fails, the client may try another request on that channel
or close it. Once a program has started, running another program requires a
new session channel.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: CHANNEL_OPEN("session", client ID, window, max packet)
    S-->>C: OPEN_CONFIRMATION(client ID, server ID, window, max packet)
    opt Setup
        C->>S: CHANNEL_REQUEST("env" or "pty-req", reply=true)
        S-->>C: CHANNEL_SUCCESS or CHANNEL_FAILURE
    end
    C->>S: CHANNEL_REQUEST("exec", command, reply=true)
    S-->>C: CHANNEL_SUCCESS
    C<<->>S: CHANNEL_DATA
    S-->>C: exit-status, EOF, CLOSE
    C->>S: CLOSE
```

The request's `want reply` flag matters. A client should request a reply when
later behavior depends on success. Otherwise a refused `exec` request can look
like a command that produced no output and closed immediately.

## `exec` carries a string, not an argument vector

The `exec` request contains one SSH string. RFC 4254 does not define an array
of arguments, quoting rules, a shell language, or a character encoding for it.
The server decides how to interpret the string.

```text
string "exec"
boolean want_reply
string command
```

A client therefore cannot infer a portable `argv` boundary from the wire.
Quoting rules used by a command-line SSH program belong to that program and
the remote execution environment, not to the SSH connection protocol.

For example, OpenSSH's server normally passes the string to the account's
shell with `-c`. A string such as `printf '%s\n' "$HOME"` therefore asks the
remote shell to expand its own `HOME`. Local shell quoting determines which
bytes reach the SSH client in the first place. These are two distinct rounds
of interpretation; SSH does not provide escaping between them. See the
[OpenBSD `sshd(8)` execution description](https://man.openbsd.org/sshd#LOGIN_PROCESS).

## A PTY changes the byte-stream environment

`pty-req` asks the server to attach the remote program to a pseudo-terminal.
It supplies a terminal type, character and pixel dimensions, and encoded
terminal modes. The request is separate from `shell` or `exec`.

```text
string "pty-req"
boolean want_reply
string terminal type
uint32 columns
uint32 rows
uint32 pixel width
uint32 pixel height
string encoded terminal modes
```

Without a PTY, a session behaves more like ordinary input, output, and error
streams. With a PTY, terminal line discipline can echo input, translate bytes,
interpret control characters, and combine output streams. A binary protocol
or machine-readable command normally should not request a PTY.

After a terminal size changes, the client can send `window-change`. This is a
channel request with the new dimensions. The client should set its `want reply`
flag to false. It is unrelated to `SSH_MSG_CHANNEL_WINDOW_ADJUST`: terminal
dimensions describe a display, while a channel window controls data credit.

The terminal-mode string is its own compact protocol: opcode/value pairs end
with `TTY_OP_END`. It is not a native `termios` structure and should not be
copied as one.

## Environment requests are policy requests

An `env` request carries a name and value. The server may reject it, and many
servers accept only configured names. The request does not modify the SSH
transport or the server process that handles the connection; it asks the
server to construct part of the new program's environment.

Environment values cross a privilege boundary. A server needs policy for
variables that affect library loading, command lookup, localization, or
application configuration.

## Data and extended data

The client usually sends program input with `SSH_MSG_CHANNEL_DATA`. The server
uses the same message for normal output. It may use
`SSH_MSG_CHANNEL_EXTENDED_DATA` with type `SSH_EXTENDED_DATA_STDERR` for the
error stream.

Both message types consume the same receive window. Their SSH message
boundaries do not become record boundaries in the program's byte stream.

When a PTY is present, the remote terminal normally presents one combined
output stream. A client must not assume that extended data will preserve a
separate standard-error stream in that case.

## Signals and process completion

The client can request `signal` on a session channel. SSH uses signal names
such as `TERM`, without the `SIG` prefix. Whether the server can deliver a
signal, and what the remote program does with it, is outside the protocol.

The server reports completion with channel requests sent in the other
direction:

- `exit-status` carries a `uint32` process status;
- `exit-signal` reports signal termination and may include error text.

These reports do not close the channel. A client can receive final data, an
exit report, EOF, and CLOSE as separate events. TCP EOF is not a substitute
for an SSH exit status: it ends the entire transport and may leave the command
result unknown.

Both exit reports use `want_reply = false`. RFC 4254 recommends returning a
status but does not require it, so even a complete channel CLOSE handshake can
leave the process result unknown. `CHANNEL_SUCCESS` for `exec` means that the
start request was accepted, not that the command eventually exited with zero.
See [RFC 4254 section 6.10](https://www.rfc-editor.org/rfc/rfc4254#section-6.10).

If the transport disappears after an `exec` request, the client may not know
whether the command started, finished, or changed remote state. Even losing
the connection before its success reply arrives does not prove that the
request was never accepted. Reconnecting starts a new SSH connection; the core
protocol has no operation to recover the old channel or its missing result.
For example, retrying a command that appends a line to a file can append it
twice. Such uncertainty needs an application-level way to check the result
before retrying.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: DATA(input)
    C->>S: EOF
    Note over C,S: Only client-to-server data ended
    S-->>C: DATA(final output)
    S-->>C: CHANNEL_REQUEST("exit-status", 0, reply=false)
    S-->>C: EOF
    S-->>C: CLOSE
    C->>S: CLOSE
```

## Worked exchange: send input and collect a result

Consider an authenticated connection that starts `cat` without a PTY. The
client calls the channel `7`; the server calls it `42`. Both advertise a
receive window of 16 bytes and a maximum data size of 8 bytes per message.
These tiny limits make the accounting visible; they are not suggested settings.

| Direction | Message or event | What changes |
| --- | --- | --- |
| C → S | `CHANNEL_OPEN("session", sender=7, window=16, max=8)` | Client offers 16 bytes of receive credit. |
| S → C | `OPEN_CONFIRMATION(recipient=7, sender=42, window=16, max=8)` | Client learns the server ID and its receive credit. |
| C → S | `CHANNEL_REQUEST(recipient=42, "exec", reply=true, "cat")` | Client asks to start the command. |
| S → C | `CHANNEL_SUCCESS(recipient=7)` | Start request accepted; no process result yet. |
| C → S | `CHANNEL_DATA(recipient=42, "hello\n")` | Six data bytes reduce server-granted credit from 16 to 10. |
| C → S | `CHANNEL_EOF(recipient=42)` | No more input; output remains open. |
| S → C | `CHANNEL_DATA(recipient=7, "hello\n")` | Six output bytes reduce client-granted credit from 16 to 10. |
| S → C | `CHANNEL_EOF(recipient=7)` | No more output; channel requests can still arrive. |
| S → C | `CHANNEL_REQUEST(recipient=7, "exit-status", reply=false, 0)` | Server reports successful process completion. |
| S → C | `CHANNEL_CLOSE(recipient=7)` | Server starts the channel close handshake. |
| C → S | `CHANNEL_CLOSE(recipient=42)` | Close completes; each peer may reuse its ID. |

Here `\n` denotes one LF byte. Control messages consume no channel credit,
and the six bytes fit both advertised limits, so no `WINDOW_ADJUST` is needed.
This is one valid ordering: `cat` may echo input before the client sends EOF,
and the exit report may arrive before the server's EOF. The events remain
distinct in either ordering.

## Subsystems

A subsystem is a named protocol service carried inside the session channel.
After a successful `subsystem` request, channel data belongs to that subsystem
protocol. SSH still supplies transport protection, multiplexing, flow control,
and channel closure, but it does not interpret the subsystem messages.

SFTP is the common example. “SFTP over SSH” means that SFTP packets are the
application byte stream of a session channel; SFTP is not an SSH channel type
and is not the same protocol as SCP.

## Trace a command correctly

For one command channel, record these events separately:

1. channel open confirmation;
2. optional setup-request results;
3. start-request result;
4. input EOF, if sent;
5. normal and extended output;
6. exit status or exit signal, if sent; and
7. any EOF events, then CLOSE sent and received.

This prevents three common mistakes: treating channel open as command start,
treating EOF as full close, and treating transport loss as a zero exit status.

## References

- [RFC 4254, Section 5 — Channels](https://www.rfc-editor.org/rfc/rfc4254.html#section-5)
- [RFC 4254, Section 6 — Interactive Sessions](https://www.rfc-editor.org/rfc/rfc4254.html#section-6)
