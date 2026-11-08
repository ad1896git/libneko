# Desktop log files

`SetupLog` uses the safe file path on macOS, Linux and Windows for the
`RunMode_NekoRay_Core` and `RunMode_NekoBox_Core` modes. Other modes retain their
existing behavior.

If opening or preparing the file fails, `SetupLog` returns a diagnostic beginning
with `file logging disabled` and installs a stdout-only `LogWriter`. Callers should
report the error and continue running. Standard logging and the core's writer
remain usable. No alternate log path is selected automatically.

- Unix creates logs with mode `0600`. Existing files must be owned by the effective
  user, have no group/other permission bits and have exactly one hard link.
  Ancestors are traversed using directory FDs with `O_NOFOLLOW`; they must belong
  to root or the effective user and disallow group/other writes. Root-owned sticky
  ancestors such as `/tmp` are allowed; the immediate parent must be owned by the
  effective user and disallow group/other writes. Symlinks in any path component
  are refused, including aliases such as macOS `/var` (use `/private/var`).
- macOS extended ACL grants are refused on ancestor directories; ordinary
  deny-only directory ACLs are accepted. Files with ACL entries are refused,
  because mode `0600` alone does not restrict Darwin ACL grants. Filesystems that
  cannot provide the required ACL metadata fail closed to console logging.
- Windows accepts local drive paths and rejects alternate data streams and device
  or network namespaces. Each ancestor is opened with reparse-point semantics,
  checked for directory type and trusted ownership (current user, SYSTEM,
  Administrators or TrustedInstaller), and held without write/delete sharing until the log is open.
  The file must be a non-reparse disk file with one link, owned by the current user,
  with a protected DACL containing only that user's full-control ACE. A new file
  receives that ACL at creation. Existing broader ACLs are refused, never changed.
  Sharing conflicts also fall back to console logging.
- Startup truncation keeps the last `maxSize` bytes on the same validated handle.
  A zero limit empties the file; a negative limit is refused. Disabling
  `TruncateOnStart` preserves the contents. Writes, explicit truncation and close
  are serialized for the desktop file writer; Unix also uses `flock` to coordinate
  cooperating processes. Windows allows only one writer handle. Setup and global
  logging settings remain startup-only operations.

Existing unsafe log files are not migrated, removed or chmodded. Their handling
is an owner decision. Updating callers' log directory selection or pre-opening
behavior is a separate integration task; the library cannot undo earlier opens
performed by a caller.

The Windows and Linux unit tests are supplied and cross-compiled. They have not
been run on those platforms in this change.
