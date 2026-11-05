# IR evidence import storage and recovery

The offline IR importer stores evidence objects by SHA-256 digest beside its
SQLite database. It writes each new object to a reserved temporary file, links
the completed file into its digest name without replacing an existing object,
then commits the evidence rows. Both the object directory and database must be
on a filesystem that supports hard links. If the filesystem cannot publish an
object safely, the import fails closed.

After an ordinary process interruption, the next import can remove a
single-link temporary left before publication or the extra link left directly
after publication. If recovery reports `unsafe interrupted object temporary`,
the store contains a state the importer cannot identify safely. Stop all
writers and preserve a backup before investigating. Compare the temporary and
digest object with `lstat` (file type, owner, mode, device, inode and link
count). A temporary with one link and no published digest object is an
unpublished temporary; a temporary and digest object with the same device and
inode and exactly two links represent a redundant temporary name. Other states
must be preserved for investigation. Do not remove or replace the digest
object or force an import past this error.

If a database commit reports an error after it may have completed, an
unreferenced digest object can remain. This is safer than deleting an object
that a committed row may reference. The importer reuses a matching object on a
later import; this tool does not automatically garbage-collect objects.

The importer requests file and directory `fsync` before committing database
references. This ordering is covered by unit tests; it is not a hardware
power-loss certification. Actual storage durability depends on the filesystem,
operating system, device and SQLite configuration.
