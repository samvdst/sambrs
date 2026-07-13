# Existing SMB Resource Access

This context describes client-side access to existing SMB shares: authenticating, mapping drives, remembering mappings, and inspecting available or active resources.

## Language

**SMB target**:
A reusable description of an existing remote SMB resource, its credentials, and an optional desired drive letter. It exists independently of whether access is active.
_Avoid_: New share, connection

**Deviceless connection**:
Active authenticated access to an SMB target through its UNC path, without assigning a local drive letter.
_Avoid_: Drive mapping

**Drive mapping**:
An active association between a Windows drive letter and an SMB target. It may be temporary or remembered.
_Avoid_: Share, deviceless connection

**Remembered mapping**:
A drive mapping recorded in the Windows user profile so Windows can restore it at logon.
_Avoid_: Active connection, recent connection

**Connection**:
An owned temporary drive mapping whose lifetime controls when the mapping is disconnected.
_Avoid_: SMB target, remembered mapping

**Server share**:
An existing disk resource exposed by an SMB server for clients to inspect or access.
_Avoid_: Local directory, newly created share
