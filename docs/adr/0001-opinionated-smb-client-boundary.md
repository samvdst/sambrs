# Keep sambrs an opinionated SMB client boundary

sambrs exists to keep unsafe Windows FFI, UTF-16 conversion, buffer and handle ownership, validation, cleanup, and WNet quirks out of its consuming application. It is a Windows-only client for connecting to and inspecting existing disk shares, not a complete or unopinionated wrapper over the Windows networking APIs.

## Consequences

The public API uses SMB concepts rather than raw WNet flags and metadata. It supports deviceless, explicit-drive, and auto-assigned connections; temporary and remembered mappings; default, paired, and partial credentials; signing and encryption requirements; forced disconnect and forgetting mappings; guarded temporary mappings; and focused query and enumeration operations.

Server administration, share creation, printers, arbitrary local devices, custom network providers, raw enumeration, interactive authentication, write-through connections, and file-transfer logic are out of scope. Tracing and password zeroization are unconditional: traces may include UNC paths, drive letters, and usernames, but never passwords.

Invalid combinations are rejected before Windows is called: persistence requires a drive mapping, guarded connections cannot persist, and forgetting requires a drive mapping. Deviceless connections are kept out of Windows' recent-connections list.
