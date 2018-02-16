DNSBotnet
=========
Controller for a DNS TXT record-based botnet.

Work in progress, though works pretty well as-is.



More documentation (and ease-of-use) will be implemented in the future.

For legal use only.

Building / Installation
-----------------------
The botnet Controller (in the same directory as this file) can be built and
installed with the customary
```bash
go get github.com/magisterquis/dnsbotnet
```
or
```bash
git clone github.com/magisterquis/dnsbotnet
cd dnsbotnet
go build
```

Aside from the binary, an NS record for the domain to be used for beacons must
be set up such that the Controller will receive DNS requests from recursive
resolvers.  This usually means setting a glue (A) records or two and an NS
record with the registrar to point to the IP address of the Controller.

A file containing the SSH public keys should be made to authenticate C2 clients
(i.e. botnet Controller users).  This file is in the same format as OpenSSH's
`authorized_keys`. and is named `authorized_keys.dnsbotnet` by default.

Implants / Protocol
-------------------
Each individual implant has a README with more information.

There are two DNS request formats that the Controller understands: beacons
and output.  In general, clients should beacon periodically to check for
tasking, and if tasking is received, execute it and return any output with
a further series of DNS requests.

The timing of DNS requests is left up to the implant.  They should be fast
enough to allow for usage (interactive, if desired), but slow enough not to get
caught.

### Beacons
Beacon requests should have exactly one name in the following format:
```
ignored.counter.t.implantid.domain
```
The response will either contain a single text record with the task to execute
or no responses at all.  How the tasking is executed is up to the implant.  The
implants contained within this repository run the tasking as a shell command
and return its stdout and stderr.  The meaning of each part of the name will be
explained below.

### Output
Output requests should have exactly one name in the following format:
```
outhex.counter.o.implantid.domain
```
The response will always have 0 records.  The output is printed to any C2
Clients which request it, explained below.  The meaning of each part of the
name will be explained below.  The output should be carefully chunked to

### Names
Request and response names have the following parts
|Label|Meaning|Example|
|-----|-------|-------|
|ignored   | Ignored, for symmetry with beacons.                                                                                   | 0           |
|outhex    | Tasking output, hex-encoded.  The maximum length is 31 bytes (62 hex digits).                                         | 4920616d20313333370a |
|counter   | A unique number per request to prevent caching (i.e. cachebusting).                                                   | 37          |
|t         | A literal t, to signify a beacon (request for tasking).                                                               | t           |
|o         | A literal o, to signify an output request.                                                                            | o           |
|implantid | An ID chosen by the implant to uniquely identify itself.  IP addresses with dots replaced by dashes are good choices. | 192-168-2-3 |
|domain    | The malicious domain.                                                                                                 | example.com |

A beacon name might look like
```
0.3580645942777501247.t.192-168-2-3.example.com
```
An output name might look like
```
202020202020202020202020203634353220436f6e736f6c65202020202020.1150749505258401772.o.192-168-2-3.example.com
```

C2 Clients
----------
All acutal tasking of bots is done by first SSHing to the Controller, then
issuing commands via SSH.  A complete list of commands is available with the
`help` command.

The C2 client session can either be used to display tasking output or beacons
(which may be filtered to only show certain beacons of interest).

TODO: Example here

Unless a particular implant is specified with the `id` command, only beacons
will be printed.  To interact with a particular implant, use the `id` command
to specify the implant by ID  and then the `t` command to give it tasking.
Output from tasking will be printed to the terminal.  The `last` commands work
whether an implant is selected or not.  The `idr` command and the `id` command
without an implant ID can be used to return to printing beacons.

In practical usage, it's helpful to have one C2 connection showing beacons as
they come in and one or more to interact with implants.

Logging
-------
A log file is generated with all tasking and output.  It can be used as a
history of commands run as well as to recover output lost when tasking finished
after `id` was used to view another implant's output.
