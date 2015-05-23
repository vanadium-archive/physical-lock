# Physical lock

This is an example application built on the Vanadium stack.

<!-- TODO(ataly): Write a detailed design doc. -->

# Development

Features to add to the Lock server:

1) Auditing: This is one of the strong features of our model, so I'd imagine that we'd want a:
AuditLog(startTime, endTime time.Time) []AuditLog | error
type AuditLog struct {
  Blessing string
  Action LockStatus
  Timestamp time.Time
}
We'd also have to work out how to control access to this AuditLog. One option is to use caveats - so when "making" a new key one can choose to insert the "noadmin" caveat?

Features to add to the Lock client:

1) "makekey"

> makekey <lockname> <for>
makekey creates a key for the specified lock and principal.
<lockname> is the name of the lock object for which 'key' should be created,
and <for> is the public key of the principal to which the minted key must
be bound to.

2) "sendkey" <lockname> <email>
sendkey sends a key for the specified lock and any principal with the specified
<email> who is current running "recvkey".

# Deployment
