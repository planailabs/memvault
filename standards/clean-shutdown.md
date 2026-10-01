# clean shutdown (close the store before exiting)

**A process that opened the store closes it (`MemvaultStore::close`) before it
exits, and stops on SIGTERM as well as Ctrl-C.**

redb marks its file clean only when the `Database` is dropped. Anything that
keeps the store alive past shutdown (a static client, a leaked `Arc`, a task
that's never joined) leaves the file marked "recovery required", and the next
open repairs it by reading all of it: about a minute per 12 GB, every start.

## Why this exists

The daemon's web UI keeps its client in a static, so the store was never
dropped: every restart of a 12 GB vault spent ~60 s in repair, then failed the
researcher's 60 s startup wait. Its supervisor also stopped it with SIGKILL.

## The rule

- After the main loop returns, call `close()` on the store. Later calls fail
  with "the store is closed" rather than touching a dropped database.
- Handle SIGTERM (`memvault_swarm`'s loop does): supervisors and service
  managers stop daemons with it.
- Embedders stop the daemon with SIGTERM and give it time before killing it.
- A repair is logged with its progress (`repairing the store`), so a slow
  start explains itself.
