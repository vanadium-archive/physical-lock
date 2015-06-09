# Physical lock

This is an example application built on the Vanadium stack.

<!-- TODO(ataly): Write a detailed design doc. -->

# Development

Conventions

* The name used to claim a lock cannot contain slashes. It is also the blessing name
  that the lock subsequently authenticates with.
* A key to a claimed lock is a blessing with a name matching the pattern "<lock name>/key"

Features to add to the Lock server:

1) Auditing: This is one of the strong features of our model, so I'd imagine that we'd want a:
```
AuditLog(startTime, endTime time.Time) []AuditLog | error
type AuditLog struct {
  Blessing string
  Action LockStatus
  Timestamp time.Time
}
```
We'd also have to work out how to control access to this AuditLog. One option
is to use caveats - so when "making" a new key one can choose to insert the
"noadmin" caveat?

Features to add to the Lock client:

1) Support more caveats in `sendkey`
* TimeRange Caveat
* AskForPermission Caveat

# Circuitry with the RaspberryPi

### Equipment
- 10KΩ resistor
- 1KΩ resistor
- Magnetic switch (normally open circuit - closed when the sensor moves away)
  (e.g. [P/N 8601 Magnetic Switch](http://www.amazon.com/gp/product/B0009SUF08/ref=oh_aui_detailpage_o03_s00?ie=UTF8&psc=1))
- For now, an active buzzer to simulate a relay.
  Will fill in the relay details here once we have that setup.
- Breadboard, jumper cables, ribbon cable - or whatever is needed to connect to the RPi's GPIO pins

### Circuitry

Apologies for this unconventional, possibly unreadable circuit representation. Putting it down
so that the author can remember! TODO(ashankar): Clean it up!

The pin number assignments here work both for RaspberryPi Model B/B+ and RaspberryPi2-ModelB.

```
---(Pin 1)-------/\/\(10KΩ)/\/\---------(COM port of magnetic switch)
                                  \
                                   \----/\/\(1KΩ)/\/\---------(Pin 15 = GPIO22)
                                                          \
                                                           \----(LED)-----|
                                                                          |
                                                                          |
                                          (N.O. port of magnetic switch)--|
                                                                          |
                                                                          |
                                         (-ve terminal of active buzzer)--|
                                                                          |
                                                                          |
                                                                          |
                                                           (Pin 6 = GND)--|

---(Pin 11 = GPIO17)-----------(+ terminal of active buzzer)
```

# Deployment

To build for the RaspberryPi setup with the circuitry mentioned above:
```
v23 go get -u github.com/davecheney/gpio
V23_PROFILE=arm v23 go install v.io/x/lock/lockd
scp $V23_ROOT/release/projects/physical-lock/go/bin/lockd <rpi_scp_location>
```

If building without the `arm` profile, there are no physical switches/relays
and instead a simulated hardware is used that uses the interrupt signal
(SIGINT) to simulate locking/unlocking externally.
