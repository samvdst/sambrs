# SMB Resource Management

This context describes connecting to SMB resources and inspecting shares hosted by SMB servers.

## Language

**SMB target**:
A reusable description of a remote SMB resource, its credentials, and its desired local redirection. It exists independently of whether a connection is active.
_Avoid_: SMB share, connection

**Connection**:
An active, owned local-device redirection to an SMB target. Its lifetime determines when that redirection is disconnected.
_Avoid_: SMB target, share

**Server share info**:
A snapshot describing an SMB share hosted by a server, including its type and available administrative details.
_Avoid_: SMB target, connection
