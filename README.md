# WWCP Node

[![CI](https://github.com/OpenChargingCloud/WWCP_Node/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenChargingCloud/WWCP_Node/actions/workflows/ci.yml)
[![Nightly](https://github.com/OpenChargingCloud/WWCP_Node/actions/workflows/nightly.yml/badge.svg)](https://github.com/OpenChargingCloud/WWCP_Node/actions/workflows/nightly.yml)

What every one of these programs is before it is anything in particular: a
log, a configuration file, name resolution and the time, a certificate store,
accounts, and an HTTP server with a web interface behind it.

A simulated electric vehicle, a charging station and an energy meter differ
in what they do and agree on everything around it - where they read the time
from, who may sign in, what a day's log file is called. Each of them used to
grow that for itself, and the vehicle's version is the one that ended up here.
`WWCPNode` is that part, on its own; a kind of node is a class built on it
that adds its own sections to the same configuration file, its own routes to
the JSON API every node has below `/api`, and its own bundle to serve. [EV](https://github.com/OpenChargingCloud/EV)
is the first of them: one `WWCPNode` with a battery.
[ChargingStation](https://github.com/OpenChargingCloud/ChargingStation) is the
second: one with EVSEs, a display on a port of its own, and the roles of the
people who run it.
[LocalController](https://github.com/OpenChargingCloud/LocalController) is the
third: one between a CSMS above it and the charging stations below, which have
a port of their own to connect to.


## What is in it

| | |
|---|---|
| `WWCPNode.cs` | the node: its log, its clients, its store, its accounts and its web server, made in that order |
| `WWCPNode.Clock.cs` | what time it thinks it is, and what that is worth |
| `WWCPNode.Diagnostics.cs` | asking a name server or a time server something, step by step, for a page to show |
| `WWCPNode.TimeServerCertificates.cs` | which certificates of its time servers it believes: the machine's roots, its own, and the fingerprints a server is held to |
| `NodeKind.cs` | the five names a kind of node goes by |
| `BuiltFrom.cs` | what the node was built from: every assembly of ours it runs, and the commit each was built from - for the banner, the Configuration page and a bug report |
| `CommandLine/` | `NodeCLI`, the command line every kind of node has: its commands, `syncNTS` among them, and the console from the first prompt until 'quit', Ctrl+C, SIGTERM or the end of a task it is given, after which the log has the screen to itself again. And what a kind's program does before it: the switches every node has, the certificate store's among them, with the rest left for the kind (`NodeArguments`), what -h says of them (`NodeUsage`), why a node could not be set up or could not start and what the command line puts into the store (`NodeProgram`), and the banner, the kind's lines in their places (`NodeBanner`) |
| `WWCPNode.SSH.cs`, `SecureShell/` | the command line over SSH: the server, its host key, who may sign in with which key (`NodeSSHAuthenticator`, asking the keys kept with the account; `AuthorizedKeysStore`, reading what is handed over), and what the program says about it (`SSHSettings`) - see "The command line over SSH" below |
| `PortUnavailableException.cs` | a port the node has to have, and cannot get - which one, and what it was for, said in a sentence rather than in a stack trace |
| `Certificates/` | the store: what a certificate is for, what may go in, and what survives a restart |
| `Configuration/` | the file, and one record per section of it that every node has: `dns`, `nts`, `certificates`, `roles`, `ssh` |
| `Logging/` | one log for everything: in memory, on the console, in a file, what the libraries below say through it - and, signed, what bears on the time and the trust |
| `WWCPNode.Certificates.cs` | what the node says about its store, and what a kind of node adds to it or needs a certificate for |
| `Web/` | who may do what: the resources of a node, the three operations on them, and the roles that carry them - and `NodeHTTPAPI`, the JSON API every node has |
| `Frontend/` | what every kind of node's web interface shares: TypeScript and SCSS that each kind bundles into its own, imported as `@node/...` - see "The web interface" below |
| `WWCP_Node_TestKit/` | what every kind of node's test suite shares: `NodeConformanceTests`, the tests every node has to pass against its own JSON API, and the helpers they are written with - see "Testing a kind of node" below |
| `WWCP_Node_Tests/` | six hundred and twenty-seven tests, none of which constructs a vehicle, a station or a controller: the node's own code - its log, its clock, its file, its start - which the suites of the kinds each used to carry a copy of, the conformance suite asked of a node of no particular kind, and five over a real key exchange with a time server of Norn's own |


## A kind of node

`WWCPNode` is a class, not an abstract one. Constructed with nothing it is a
node of no particular kind - listening on port 2593, called "WWCP node" in
its own log, with no web interface - and that is what the tests construct.
A kind of node derives from it and says what it is:

```csharp
public class EV : WWCPNode
{
    public static new readonly IPPort DefaultHTTPPort = IPPort.Parse(2347);

    public EV(IPPort? HTTPPort = null, WWCPConfigFile? ConfigFile = null, ...)

        : base(Kind:      new NodeKind(Name:           "electric vehicle",
                                       Tag:            "vehicle",
                                       Product:        "EV",
                                       Organization:   "Vehicle",
                                       LogFilePrefix:  "ev"),
               Version:   typeof(EV).Assembly.GetName().Version?.ToString(3),
               HTTPPort:  HTTPPort ?? DefaultHTTPPort,
               Frontend:  new EmbeddedContentSource("cloud.charging.open.EV.HTTPRoot.", typeof(EV).Assembly),
               ...)
    { ... }
}
```

The five names are five because they are read in five places and spelt for
each. `Name` is read in a sentence - "The electric vehicle is shutting down." -
and is lower case for that reason; it is what the node calls itself in
everything it says, "the clock of this charging station" rather than "the
clock of this node". `Tag` is the word in square brackets on every entry
about the node itself. `Product` follows "OpenChargingCloud" in the name the
HTTP server and the accounts go by: what the Configuration page shows as the
server's name, and what the few answers Hermod gives by itself - the
accounts' refusals among them - carry as their `Server` header. The node's
own answers, the web interface and a kind's JSON API, carry none.
`LogFilePrefix` is what a day's log
file is called before its date. And `Organization` is the identifier of the
one organization the accounts are in, which is written into the accounts file
at the first start and read back at every start after it - so it is the one
of the five that must never change once a node has run.

The port is the kind's to give and to pass, not the node's to guess: a node
that took a default of its own for a kind that forgot to pass one would
listen somewhere nobody expects.

Beyond the names, a kind of node adds to the node in eight places:

* **Its own sections of the configuration file.** The node reads the file
  once and keeps the whole document as `ConfigurationDocument`; the kind
  takes its sections from there rather than reading the file a second time.
  See below for why one file carries both.
* **Its JSON API**, registered within `HTTPServer` below `HTTPRootPath` -
  `/api` under the base path unless the constructor was told otherwise: a
  class derived from `NodeHTTPAPI`, which has what every node answers, with
  the kind's own routes on top. See "The JSON API" below.
* **What it says once it is up, and what it ends before the server stops:**
  `OnStarted()` and `OnStopping()`. The event streams of its JSON API are not
  the kind's to end: `Stop()` ends them itself, before `OnStopping()`, because
  the server waits for every request it started and a request waiting for the
  next log entry is not woken by closing the sockets. A local controller hangs
  up on its CSMS there, and closes the port its stations connect to.
* **What it listens on beside the node's own port:** `OnListening()`, asked
  once the node's port is had and before the node calls itself started. A
  charging station takes its display's port there - a second server, so that
  the screen in the car park and the administration are two sockets bound to
  two addresses. A port it cannot have is a `PortUnavailableException` that
  names what the port was for, a `NodePort` of the kind's own; the start ends
  with it, and the node lets go of its own port again on the way out.
* **What it overhears:** `TraceTags`, the table the debug bridge tags a line
  by - a needle and the tag it stands for, in place of the default rather
  than on top of it. A local controller hears OCPP going past it in both
  directions, so its table says which side a line is about, the CSMS or a
  station; a kind that hands in none gets `TraceBridge.DefaultTags`, what a
  vehicle and a charging station overhear.
* **What it keeps certificates of:** `CertificateKinds`, the kinds of
  certificate its store keeps - all eleven by default, a vehicle's seven and
  the four of TLS in general. A kind that hands in none has no store
  directory at all: a charging station, a local controller or a gateway keeps
  the keys it dials with in stores of its own, and a store beside every one
  of them holding a vehicle's seven empty directories was a promise nobody
  was keeping. And `CertificateUsages`, what a TLS root or a server
  certificate is offered beside the node's `dns` and `nts` - a backend it
  dials, say - and `CertificateListeners`, which of its listeners a TLS
  identity is offered. A kind of its own is a `CertificateKind.Define` of its
  own.
* **Who may do what:** `Resources`, the names of what it adds for a role to
  read, edit or run, and `RoleDefinitions`, its roles and what each of them
  may do - see below.
* **What it is, for the Configuration page:** `ConfigurationJSON()` is
  virtual and answers with the node's cards - `http`, `web`, `log`, `time`,
  and `assemblies`, one line per repository with the commit it was built
  from, and its assembly only where two repositories share a name - and the
  kind adds its own on top.
* **Its command line:** a kind derives its own from `NodeCLI`, gives it the
  prompt it wants and registers its type, so that its own commands - built
  from that type - are found in its assembly beside the node's. It has a
  second constructor taking a terminal and a caller, and the program sets
  `CommandLines` to it before the start, so that a session over SSH gets the
  kind's commands and not only the node's; it hands its switches' `SSH` to
  the node, which is what serves the command line over SSH at all. Its
  Program.cs prints `BuiltFrom.BannerLines()` in its banner and ends in
  `RunUntilStopped()`: a prompt where somebody can type, waiting where
  nobody can, and the log sharing the screen with the prompt. What it
  refuses of its own switches it says through `NodeProgram.Say(Error, Line)`,
  as the node says its own: at 80 columns, a number with the word before it,
  and a line that begins with a space whole. A banner of its own says a name
  server through `NodeBanner.NameServer(Server)`, as the node's does. Both
  were the node's alone, and the electric vehicle and the energy meter kept
  copies (asked for by the EV and the meter). The node's banner says every
  name server on a line of its own, and a band of time servers on as many
  lines as 80 columns need, the rest below the first at the column: the
  PTB's four, which every node asks where its file names none, made one line
  of 83 (found by the CSMS). A band's priority has a line of its own where
  it would not fit beside the last server (found by the EMSP). Where the web
  interface comes from is broken between its words the same way - 100
  columns at the gateway (found by the gateway and the EV) - and where the
  accounts are is said in full, without a separator at the end, as the other
  files are (found by the EV).

And the bundle: a kind of node hands in an `IStaticContentSource` - the
files webpack built, embedded into its assembly - and the node serves it at
the base path as a single-page application. The page itself is the node's,
`Frontend/src/index.html`: the kind's webpack writes its title, what it is
and the version of its frontend into it, and the node fills in five
placeholders on the way out: `{{ServerVersion}}`, `{{NodeName}}`,
`{{BasePath}}`, `{{APIBase}}` and `{{ExtBase}}`. A bundle that reads where
it is and where its API is out of those, rather than assuming `/` and
`/api/v1`, is one that still works once somebody mounts it below a base
path. A node handed no bundle has no web interface, and says so once, in
an ordinary line.


## One file, and whoever reads it

Everything a node can be told in writing is in one file beside it,
`configuration.json` by default - one file rather than one per subject,
because these settings are read together, changed together and backed up
together, and because "what is this node configured as" should have one
answer that fits on a screen.

The file has sections, and `WWCPConfigFile` knows nothing about what they
mean: it reads and writes sections, and what a section says is the business
of whoever asked for it. `WWCPConfiguration` takes the sections every node
has - `dns`, `nts`, `certificates`, `roles` - and passes the others over
without a word; the kind of node takes its own from the same document. That
is what lets a vehicle keep its battery in the same file its name servers
are in, and what lets a file written by a newer node still start an older
one.

Every section is optional and so is every field inside it. A section that is
absent is not a section set to nothing: it means the file has no opinion, and
whatever the node was handed at construction stands - and a node handed
nothing falls back to the system default. So the order is: system default,
then what the constructor was given, then what the file says, each one only
where it actually speaks. Three rules hold for every field, wherever it is
read from: absent comes back as nothing and the caller leaves what it had;
present but of the wrong kind is an error and never a silent nothing, because
whoever wrote `"useCache": "yes"` deserves to be told; and an explicit `null`
counts as absent, so that a page may send a whole object with the fields it
does not touch left empty.

A save from a page goes through the same door. It merges the fields it was
sent into one section and leaves the rest of that section - and every other
section - exactly as it was, because what a page does not offer it must not
be able to delete: a form with six checkboxes sends six checkboxes, and a save
that replaced the whole section would take the name servers with it. The
document is read from disk for every save rather than kept in memory, so an
edit made by hand since the start is not undone by the next click, and it is
written through a temporary file moved into place, so that a process dying
mid-write leaves the old configuration behind rather than half of the new one.
Nothing in the file is secret. The one secret a node has, the password of its
account, stays where the HTTPExt API keeps it.


## Name resolution and the time

The two sections a vehicle, a charging station and an energy meter share, so
that one file can be written once and copied:

```json
{
  "dns": { "enabled": true, "servers": [ "192.168.1.1" ] },
  "nts": { "enabled": true,
           "servers": [ "ptbtime1.ptb.de", "ptbtime2.ptb.de",
                        "ptbtime3.ptb.de", "ptbtime4.ptb.de" ],
           "minServers": 2,
           "checkEverySeconds": 900,
           "legalTimeAuthority": "PTB" }
}
```

The `dns` block above is one name server, asked over UDP on port 53. An entry
of `servers` is an address or a host name, or an object saying more than
that, which is the form a page writes the list back in:

```json
{ "address": "192.168.1.1", "port": 53, "transport": "UDP", "queryTimeoutSeconds": 2 }
```

`udp://192.168.1.1:53` is how the log names a name server, not a form the
file takes; a file saying it is refused at the start, with the entry named.
Beside the servers the section may set `queryTimeoutSeconds`,
`recursionDesired`, `useCache`, `dnssecOK`, `followCNAMEs`, `maxCNAMEFollows`
and `maxRetries`; what it does not mention keeps what the DNS client was made
with. Switching name resolution off is done by taking the client's servers
away, which is what being switched off actually means for everything holding
that client - and the list waits beside it for being switched back on.

A name server reached over TLS or HTTPS shows a certificate, and is judged by
it at every handshake the way a time server is at its key exchange - see
below: issued for the address it is dialled at, chaining to a root this
machine trusts or to a TLS root of the node's store for `dns`, and, where its
entry says so, one it is held to:

```json
{ "address": "1.1.1.1", "transport": "TLS", "trustOnFirstUse": "root" }
```

The same keys as a time server's - `certificateFingerprint(s)`,
`rootFingerprint(s)`, `onMismatch`, `trustOnFirstUse` - and on an entry asked
over UDP, TCP or plain HTTP they are refused, because such a server shows no
certificate to hold it to. A name server does not bear on the time, so what is
news about one is tagged `security` and goes into the metrological log only
where its entry says `record`. Its connection is kept open between queries, so
a change to what it is held to closes the one it has, and the pin counts from
the next query. The DNS answer says per server what it is held to, what the
node made of its certificate last and what it was last believed with, and a
test of the name servers says what was made of every certificate it met.

The `nts` block above is what a node asks when the file says nothing at all:
the PTB's four, of which two have to answer. Every key of the section, and
what it is when absent:

| Key | Default | |
|---|---|---|
| `enabled` | `true` | whether to ask at all |
| `servers` | the four above | a list, see below |
| `minServers` | `2`, or all of them when fewer | how many must answer for the group to have a time |
| `maxDeviationSeconds` | `60` | how far apart they may be before it is written down |
| `hostname` | - | one server instead of a list |
| `ntsKEPort`, `ntpPort` | `4460`, `123` | for that one server |
| `timeoutSeconds` | `10` | per request |
| `checkEverySeconds` | `900` | how often the clock is checked |
| `legalTimeAuthority` | - | who the operator says stands behind it |
| `legalTimeToleranceSeconds` | `1` | how far off the clock may be |
| `legalTimeMaxAgeSeconds` | `3600` | how old the last check may be |

An entry of `servers` is a host name, or an object saying more than the name:

```json
{ "hostname": "time.local", "priority": 0, "ntsKEPort": 4460, "enabled": true }
```

A server may be held to more than every server is held to - certificates
it may show, roots its chain may end at, each by its SHA-256 fingerprint,
written the way a certificate authority, a browser or openssl writes one:

```json
{ "hostname": "time.local", "rootFingerprint": "4F:1C:…", "onMismatch": "record" }
```

One of a kind is written as above; several are a list under
`certificateFingerprints` or `rootFingerprints`, and the server may show any
of them - two certificates are a renewal that has been announced, two roots a
CA moving to a new one, written down before it happens. A server showing
another certificate is refused - its key exchange ends, and it gives no time -
unless `onMismatch` says otherwise: `record` uses its time all the same and
writes the mismatch into the metrological log, `accept` uses it and says so in
the log. Every one of the three is tagged `security`, and for a time server
the metrological log gets the mismatch whichever it is, because it bears on
the time.

`"trustOnFirstUse": "root"` - or `"certificate"` - holds a server to what it
was first believed with: the root its chain ended at, or its certificate,
written into its entry of the file the moment it is learned, as a pin
somebody typed would be, and changed or taken away there like one. The root
is usually the one to learn: a certificate is renewed every few months, and a
pin on it turns every renewal into a mismatch. It is learned only from a
certificate that was believed anyway - trust on first use narrows what is
believed, and never widens it.

A page sends the whole list back, from what it loaded, and a server may be
held to more by then: what is learned is written at the first key exchange
or handshake after a save, seconds later and with the page still open. So an
entry a page sends may say under `pinsAsShown`, in the keys the entry itself
uses, what the page showed its server held to, and then only what was
changed on the page is changed: a fingerprint the page did not show is kept,
one it showed and no longer sends is taken away, and `onMismatch` and
`trustOnFirstUse` are the page's where the page changed them. The node works
that out under the lock trust on first use writes under, so nothing can be
learned between the two. An entry without `pinsAsShown` is what its server is
held to from then on, as an entry of the file is - and so is a server the
node does not have under that name, or on that transport and port.

The certificate is judged at every key exchange, of the group and of a
detailed test alike, and in this order: is it issued for the server's name;
does its chain end at a root this machine trusts, or at a TLS root of the
node's own store for `nts`, or at a root the server is held to where the
store has that one under whatever kind; and is it one the server is held to.
A pin narrows what is believed and never widens it: a certificate that
matches its pin and chains to nothing is refused, and a server with a
certificate it signed itself is believed by importing that certificate as a
TLS root - which says the same thing, on purpose. A key exchange is reused
for as long as its cookies last, up to half an hour, so a change to what a
server is held to forgets the exchange it has, and the pin counts from the
next round. The same verdict at every round is written down once, and its
end again.

What a server was believed with is remembered, pinned or not, in
`known-servers.json` beside the configuration file - fingerprints and nothing
else, in the spirit of SSH's known_hosts - and a server believed with another
certificate than before is said, with both fingerprints, tagged `security`
and, for a time server, in the metrological log: a certificate renewed on
schedule and one somebody in between presents look alike to a node that holds
its servers to nothing, and here the second is at least a line in the log.
What was refused is not remembered, or the genuine certificate would look
like a change the next time.

The NTS answer says, per server, the fingerprint of the certificate it showed
last - which is what a pin is written down from - what it is held to, what
the node made of it, and what it was last believed with. The judgement is the
same for any server a node connects to - `JudgeServer` - and a name server
reached over TLS or HTTPS goes through it too, handed over by Hermod's DNS
client: see above.

Servers sharing a priority are one band and are asked together; a lower
priority is asked first. The four above share priority 0 because they are
peers, and putting them in separate bands would say something about them that
is not true. A section naming a single `hostname` and no list becomes a group
of one, which is what every file written before there were groups says, and it
keeps working; a group of one is held to a quorum of one, and a section asking
two of it is refused. A lone `hostname` saved from a page replaces the list,
in effect and in the file alike - the file used to keep its list beside the
new name, and the next start made the list again. And `legalTimeAuthority`
sent as `null`, or as nothing between the quotes, takes the authority away,
from the file as well, where a null otherwise means "the file does not say". A quorum the servers could never reach is refused
wherever it arrives: at the start, before anything is asked, and from a page,
before anything is written - and a page's save is checked as the next start
would read it, because the quorum the file holds and a shorter list saved now
can each be fine and together be a file the next start stops over.

The whole group is asked on that interval, authenticated, and **the node's own
clock is never set from the answer**. What is measured is how far the clock is
off, and what is reported is what the servers that answered agree on, with a
line for each of them: two servers that agree catch what one cannot, a server
that is wrong rather than absent. One measurement engine for the life of the
node, because it holds the key exchange of each server between rounds, and a
new one per check would pay a TLS handshake to every server every time.

"Legal time" is not a claim a node can make on its own. It holds only while a
check against a time source **the operator has vouched for** is both recent
enough and close enough; without a named authority this is an ordinary clock
that happens to be checked, and `ClockJSON()` says so in as many words: the
time, the group it is checked against, when it was last checked and how far
off it was then - and `legal`, with a `why` when it is not, `notClaimed` among
them. A kind of node puts that behind a route of its own. `ClockIsSynchronised` is
the one-letter version of it for a signed record: whether a check has found a
time at all since the servers were last replaced.

Against whom it was checked is said for a screen, and a screen speaks the
language it is set to: so the one server of a group of one is named, as
`server`, and a group of more is counted instead - `asked` and `answered` by
the last check - rather than named in a phrase made up here in English. A
charging station's display puts those numbers into its own sentence.

A host name written back into the file carries the root label -
`ptbtime1.ptb.de.` - because that is the absolute form it was parsed into,
and not a stray character. What the node prints for somebody to read drops it
again.


## Certificates, and where they live

Everything a node believes and everything it presents is in one store: a
directory of files with an `index.json` beside them, addressed by a short
handle rather than by a path - for the kinds of certificate its kind of node
keeps, and no directory at all for a kind that keeps none. The directory is
`certificates` beside the configuration file unless the file's
`certificates` section or the constructor says otherwise - beside the file rather than below the working
directory, because a store that moved when somebody typed `dotnet run` from
somewhere else would be a different store, and for a published binary the
working directory is the one `dotnet clean` empties.

Two groups, and they behave differently in every respect that matters. A
**root** is what the node believes: `v2gRoot` for a station's chain, `moRoot`
for a contract's, `oemRoot` for a provisioning chain. Any number of each may
be switched on at once, all of them are believed, and none is ever chosen for
a session; a root is a PEM file with no private key in it, and a sub-CA
offered as a root is refused rather than accepted and useless. A
**credential** is what the node presents: the Vehicle certificate is who it
is, the contract certificate is who pays, the OEM provisioning certificate is
what it was born with, and the tariff certificate is what a station's signed
tariff is checked against. Exactly one of each is chosen, and that choice is
the kind of node's to make.

The store holds private keys **unencrypted**: a PKCS#12 is opened with its
password once, at import, and written back without one, so that any number of
certificates per role work without any number of passwords to carry. A file
that opens only with a password, and was given none - a PKCS#12, or a PEM
whose key is encrypted - is refused with just that, and the command line says
where the password goes: `--certificate-password`, or `<PRODUCT>_CERT_PASSWORD`.
It was refused with .NET's "with the provided password, the password may be
incorrect", where none had been provided (found by the EMSP). A file not built
as a PKCS#12 is not asked for a password at all. A kind that reads a PKCS#12
of its own, outside the store, asks `CertificateStore.OpensOnlyWithAPassword`
the same of it, and says where its own password goes (asked for by the
charging station, for its certificate for V2G). The file
system is what guards them, and the node says so at every start and at every
import. A file somebody copied into the right directory by hand is adopted at
the next reload, because on a machine somebody already has a shell on that is
the shorter way to install a certificate; a file that went away is dropped,
because an entry pointing at nothing would fail at a handshake instead of here.
An expired certificate may be imported - knowing it is there is the point -
and is active and not usable: somebody switches a certificate on, and time
switches it off.

Seven of the kinds are ISO 15118's, which a vehicle keeps. Four are TLS's in
general, which any kind of node may keep: `tlsRoot`, what a server it connects
to may chain to - a time server's key exchange, a backend - and which is
believed beside the machine's roots, not instead of them; `clientRoot`, what a
client connecting to it has to chain to - a root, or the issuing CA below one
that signs the clients and nothing else, since the root would let in whatever
else it signed, and the one trust anchor that may therefore be signed by
somebody else, as long as it is a CA; `tlsServer`, what a server it
connects to shows, kept to be recognised - never with a private key, which
would be that server's key in the wrong place; and `tlsIdentity`, what the
node shows itself, with its key. A kind of node keeps those it has a use for,
and `CertificateKindExtensions.ISO15118` and `.TLS` name the two groups.

A TLS root and a server certificate are told as well what they are for: the
name servers, the time servers, both, or what a kind of node adds, such as a
backend it dials. One root may vouch for several of them, which is why a
certificate has any number of usages. A certificate never told is for every
use, which is what every TLS root was before there were usages, and an index
written then still means it. The time servers are anchored by the TLS roots
for `nts`, and by the root a server is held to whatever it is kept for: naming
it in the server's configuration says the same thing, and more narrowly.

A TLS identity is told the same way where it is shown: a node with more than
one listener - a meter's Modbus/TLS port and its web interface - names them in
`CertificateListeners` and presents on each the identities for it, and one
never told is for every listener. `UsagesFor(kind)` is what the node offers a
kind - the services for a root or a server certificate, the listeners for an
identity, nothing for the rest. The node itself presents none of them: which
one a listener shows, and when it changes, is its kind's to say.

A usage is a `CertificateUsage`, a name - a letter, then letters, digits, `-`
or `_`, in lower case - and the node's own and its kind's are only what it
offers. Whoever looks after a node may mark any certificate, of any kind, with
a usage of their own where it is imported or changed: a mark, which nothing in
the node acts on until a configuration or code names it, and an identity
marked "for dns" is shown on no listener, which a usage does not make it. Such
a usage is offered for as long as a certificate is marked with it -
`KnownUsages(kind)`, the node's first, then the ones made up - and nowhere
remembered but on the certificates: once the last of them is deleted or told
otherwise, it is offered no more. What is still refused is a name that is no
usage name, and an empty list, which is a certificate to switch off.

**One certificate, several kinds.** A self-signed identity may be the root its
peers are judged against as well, and one CA the root of the servers a node
connects to and of its clients alike. So a certificate is kept as any number
of kinds: each a registration of its own - a file in that kind's directory,
written as that kind's reader takes it, switched on and off and told its
usages on its own - and all of them one certificate, under one handle and
one name. `ByKind`, `UsableFor` and a file copied into a kind's directory work
as they always did; `Get(id, kind)` is the certificate as one kind,
`Registrations(id)` as every kind, and `Get(id)` as the first. Switched off or
deleted without a kind, a certificate goes as every kind, so that one
withdrawn is not left believed as the kind somebody forgot; with one, as that
kind alone. An import names its kinds - `Import(content, password, label,
registrations)` - and goes in as all of them or none: whatever can refuse one
of them is asked before anything is written. A trust anchor or a server's
certificate still refuses a key that comes along, unless the same import puts
the certificate in as a kind that presents it: then the key stays with that
kind, and the anchor is kept without it.

**Kinds of one's own.** `CertificateKind` is a name and a group - believed
(`TrustAnchor`), presented (`Credential`) or recognised (`Recognised`) - and
the eleven above are its static definitions, with what each of them does. A
kind of node may define more with `CertificateKind.Define`, and whoever looks
after a node may make one up where they import a certificate,
`CertificateKind.Custom(name, group)`: a mark in its group, as a made-up usage
is - a root of one has to be a CA, a credential of one carries its key - kept
below `custom/<group>/<name>`, where the next start finds it with or without
the index, and forgotten with its last certificate. `KindsKept` is the store's
kinds and the made-up ones it has certificates of.

**Looking before importing.** `InspectFor(content, password)` says what a file
or a text holds without putting anything anywhere: each certificate that no
other one in it was issued by, with the ones above it that came with it and
its private key where it came with one - written out as PEM, as one import's
worth - and the kinds the store keeps it as already. Three roots pasted one
after the other are three; a leaf, its sub-CAs and its key are one, in
whatever order they were written. `Unsuitable(certificate)` says, for each
kind it cannot be kept as, why not.

Anything in the store is found by its SHA-256 fingerprint, whatever kind it
was kept as: `ByFingerprint` takes the whole of it and nothing shorter, in any
of the ways a fingerprint is written. A truncated fingerprint is a handle and
never evidence. What a trust decision rests on is written into the
metrological log, tagged `security` - an import, with the fingerprint; a
certificate switched on or off, or told what it is for; one deleted, or
dropped because its file went.


## Who may sign in

The accounts are Hermod's HTTPExt API, at `/ext` beside the JSON API rather
than under it - it is not the node's API, it has routes and a vocabulary of
its own, and putting it under `/api/v1` would promise that the node versions
it. Nobody can sign in to a web interface whose accounts are empty, and an
unauthenticated setup page would be a door of its own: so at a first start
the node makes one account, `root`, with a password made up on the spot and
shown once, on the console, to whoever started the process. It is never
written down anywhere; what the accounts hold is the hash. With SSH on, the
first start gives `root` a key as well, unless the command line brought one
- see "The command line over SSH" below for that, and why bringing one's own
is the way recommended. It is 24
characters out of 57 - no I or l, no O or 0, which read as each other on a
console - drawn from `RandomNumberGenerator`; it used to come from
`Random.Shared`, which is fast and not secret. A kind of node that keeps
something about its accounts beyond the node's own - a role given another way
before it was a node - is asked in `OnAccountsReady`, once they are read and
the groups made, and before the port opens.

Given a certificate - `ServerCertificateSelector`, and the chain beside it -
a node serves its web interface, its API and its sign-in over TLS, names
itself by `https` URLs and sets a secure session cookie. Without one it
speaks plain HTTP and its cookie is not a secure one, because a browser keeps
no secure cookie over plain HTTP and nobody could stay signed in. A server
that is handed in brings its own TLS or none, and the node goes by it.

A role is a user group under the same name, and membership is what carries
what it may do: a list of permissions, each an operation on a resource and
written `dns:edit`. The operations are three and fixed - `read`, `edit`, and
`run` for asking a server something or running a session - so that "may
read" means the same on every kind of node. The resources are names:
`configuration`, `dns`, `nts` and `certificates` for what every node has,
and whatever a kind of node adds - `vehicle`, `v2g` and `session` for a
vehicle. `*` is every resource there is, the kind's included. The clock, the
log and the event stream are none of them, and for anybody signed in.

The roles are data, put together at every start from three places. The node
brings two: `viewer`, who may read everything, and `systemadmin`, who may do
everything - the first account goes there, and nobody but the node says what
it may do, because a role that could be narrowed could leave nobody able to
put that right. A kind of node hands in its resources and its roles as
`Resources` and `RoleDefinitions` - a vehicle's `driver` and `service` - and
may bring a `viewer` of its own. And the `roles` section of the configuration
file adds roles, or says differently what one of them may do:

```json
"roles": { "support": [ "dns:read", "nts:read" ] }
```

A role there that names a resource the node does not have stops the start,
because a typo in `dns` would otherwise be a role that quietly grants
nothing; what the file added or changed is said in the log at every start,
tagged `security`. A kind of node that still enforces roles of its own hands
in their names as `Roles`, and gets their groups and nothing else - and a
`roles` section in its file stops the start as well, because nobody would
enforce what it says.

The groups are made at every start rather than only the first, because they
are the node's vocabulary and not somebody's data: a group deleted by hand
would otherwise leave a role nobody can ever hold again - and Hermod's floor
for a group's identification is lowered to the shortest role there is,
because it is four characters and a charging station's `cpo` is three.

What an account may do is asked of the node - `IsAllowed`, `RolesOf`,
`PermissionsOf` - on every request rather than once at sign-in, so that
taking somebody out of a group takes effect on their next request. The
HTTPExt API knows users, groups and organizations and has no opinion about
what "may edit the DNS settings" means; it answers who somebody is, and the
node answers what that lets them do. `PermissionsOf` spells `*` out resource
by resource, for a web interface that greys out what its user may not do.
The permissions a vehicle brought here as an enumeration, in
`Web/Permissions.cs` and `Web/UserRoles.cs`, are marked obsolete and stay
until every kind of node that uses them has moved over.

Several of these programs may share one server and one sign-in. A node handed
an `HTTPServer` registers within it and neither starts nor stops it; one
handed an `HTTPExtAPI` signs in against accounts it shares, and the groups it
makes land in the same set - an account in `systemadmin` is an administrator
of every one of them. Told apart by the first path segment rather than by
the port: everything of a node sits below its `BasePath`, which is the root
for a node on a port of its own.


## The command line over SSH

What somebody at the console types at, somebody signed in with PuTTY or
`ssh` can type at too: the same prompt, the same commands, Tab and the
history, and the log above the line being typed. Nothing else is served -
no shell of the machine, no `exec`, no SFTP, no tunnels: the session is the
command line, and the command line is all there is.

It is Hermod's SSH server, on the address the web interface listens on - the
loopback, or every address with `--any`, which is one decision about who may
reach the node and not two - and on a port twenty thousand above the web
interface's: the vehicle's 22347 beside its 2347. The web ports of the kinds
lie close together, and one above each would be the next kind's. Whether it
runs at all is the program's to say: every program hands in its switches'
`SSH`, which is on unless `--no-ssh` says otherwise, while a node made in a
test serves no SSH unless the test asks for it - twenty thousand above a
port of the dynamic range is no port, and a test has no business opening a
second one. Between the two sits the file:

```json
"ssh": { "enabled": true, "port": 22347, "passwords": false }
```

A switch wins over the file, the file over the program's default.

Who signs in is an account of the node, under its name, with a key of its
own - kept with the account, in the HTTPExt API's database, beside its
password and its API keys. A key is a line as OpenSSH's `authorized_keys`
has it, and `from="..."` or `expiry-time="..."` in front of it hold. Who
let it in, and when, is written down with it, as a link of the database's
hash chain. The keys are asked at every sign-in: a key taken out lets nobody
in from that moment on. `--authorize-ssh-key <account>=<file>` puts one in -
an OpenSSH `.pub`, or what PuTTYgen saves - once the accounts are read and
before a port opens, so at a first start too.

`sshKeys` lists, lets in and takes out an account's SSH keys, and `apiKeys`
does the same for its API keys - at the console and over SSH:

```
sshKeys [<account>] [add <authorized_keys line> | remove <fingerprint>]
apiKeys [<account>] [add [readOnly | readWrite] [<description>] | remove <key>]
```

A fingerprint is written as OpenSSH writes it, `SHA256:...`, or by enough of
its beginning to be only one key's; an API key by its beginning, which is
all a list shows of it - the whole key is shown once, when it is made, and
never again, because whoever has it is signed in as its account. An API key
is read-only unless `readWrite` says otherwise. Over SSH the account may be
left out, and is then the one signed in; another account's keys are for
whoever the HTTPExt API lets act for it - as its routes
`/ext/users/{UserId}/SSHKeys` and the API keys' own decide - which is an
admin of its admins' organization, `Admins`. A node does not make that
organization by itself, so until somebody does, another account's keys are
the console's alone. The console names the account, and may do everything.
Every key let in or taken out is in the log, tagged `security`, naming who
did it.

**At a first start, bring `root` a key of your own** - this is the way
recommended:

```
<program> --authorize-ssh-key root=~/.ssh/id_ed25519.pub
```

The private key then never leaves the machine it was made on, and no console
shows it. Where the first start was given no key for `root`, and SSH is on,
the node makes up an Ed25519 key pair for it, lets its public key in and
shows its private key once, below the password in the banner's first-start
box - outside the box, so that it can be copied as it stands, from
`-----BEGIN OPENSSH PRIVATE KEY-----` to the END line, and saved as a file
only its owner can read. `ssh -i <file> ssh://root@<host>:<port>` then signs
in, or PuTTY with the file imported in PuTTYgen. Like the password it is
written down nowhere - but a console may be kept: a service's journal,
`docker logs`, a redirected output. Replace that key with your own and take
it out - `sshKeys root add <your key.pub's line>`, then `sshKeys root remove
<its fingerprint>`; the log names it by its fingerprint and the comment
`root@<kind>-first-start`. An account that is switched off, or holds none of
the node's roles, is not let in; a password only where the file says
`"passwords": true`, and never for an account with a second factor on the
web interface, for which SSH would be the way around it.

What an account may do there is what its roles let it do on the web
interface: a command asks `MayDo` the question its route asks, and is
refused with the roles that would do. The log names it as the web
interface names the account that pressed a button - "'root' at the command
line over SSH asked this electric vehicle to synchronise its time." - tagged
`cli` and `ssh` where the page says `web`. The console may do everything: whoever
is at it has the process.

Each session has a log of its own, from the level the console shows, which
`log debug` or `log off` changes for that session alone. An entry is queued
for it and written by a task of its own, because the log calls its listeners
on the thread that is logging and a session is at the far end of a network:
a client that reads slowly never holds up the node, and what does not fit
in the queue is said to have been left out. `quit`, `exit` and Ctrl+D leave
the session and the node keeps running; Ctrl+C stops the command that is
running, or abandons the line; `who` says who else is there. A node that
stops says so on every session while its channel is still open, and then
ends it.

The node presents a host key of its own, made at the first start that
serves SSH, written into the log book as a certificate is, and kept in
`ssh/` beside the configuration file. The banner says where the server is
and the key's fingerprint, to compare PuTTY's first question with - and,
while no account has a key, how to give one one. A key that is there and
cannot be read stops the start: a new one would be another machine to every
client that knew this one. Who signed in, from where and with which key, who
could not, and what was refused are in the log, tagged `ssh`.


## The log

One log for everything, and everything goes through it - which is the whole
reason there is one: what somebody actually has in front of a node is "what
happened just now", and a log kept somewhere else than the rest of the node
cannot be asked that.

It is a ring buffer of the last two thousand entries in memory, each with an
id, a level from `debug` to `critical`, and tags, so that a page can ask for
what came after the entry it last saw and a kind of node can put the whole
thing on an event stream. Three listeners are attached before anything else
is built, so that what the DNS client and the HTTP server say while they are
being made is already in the log a browser will see later:

* **The console**, at a level chosen to keep it readable - `info` by default.
  A node at a console assumes the console is its own; the moment somebody is
  typing a command on the same screen, `ShareConsoleWith` hands the writing
  over to whoever owns the line, who takes the entry, clears what is being
  typed, writes the entry as one piece and puts the line back.
* **A file per day**, UTC, below `logs/` by default and called
  `ev-2026-09-24.log` for a vehicle - every entry down to `debug`, with the
  timestamp in full, because a file is read long after and often somewhere
  else. A file that cannot be written does not take the node down and is
  said once; every entry is tried again, and the first one that makes it
  brings the size of the gap, written into the file where the gap is.
* **The debug bridge**: everything the libraries below write with Illias'
  DebugX, tagged `trace` and with whatever the kind's table finds in it, so
  that what Hermod or Norn say about a connection ends up in the same place
  as what the node says about it. A name in the table counts where a word of
  its own could begin - at the start, after a sign, at a capital - and not
  inside a word written in lower case: found anywhere, "nts" tagged every
  line that said "accounts".

**The metrological log** is the fourth, and the one that is evidence: what
bears on the time a node stamps things with and on what it trusts, written
entry by entry as metrological by whoever writes it - `Log.Metrological(...)` -
rather than picked out by a tag or a level, because what is metrologically
relevant is a question about what happened, not about how loudly it was said.
The node writes its start and its end there, the plan of its clock check,
every synchronisation with what each server answered, the servers disagreeing,
every change of the NTS configuration and of what legal time rests on, a time
server refused or believed again, and every change of the certificate store;
a kind of node adds its own. They are ordinary entries as well, numbered in
the log's own sequence and marked for the page.

It is a `SignedLog`, below `logs/metrological/` beside the log files unless
it is put elsewhere, and never thinned out: one JSON object per line, one
file per day, each line carrying the hash of the line before it and an ECDSA
P-256 signature by a key kept beside it, whose public half is written beside
it too. `Verify` walks every file and says whether each line still matches
its hash, follows the line before it and carries the key's signature - and
where not, which line and why; a file that could not be written for a while
says what it missed, in a line of the chain like any other. What signing a
file cannot catch is a file cut off at the end, and the key taken with it:
the head of the chain is the one value worth keeping somewhere the node
cannot reach. The Modbus/TLS energy meter's signed log moved here, and a
meter's metrological log carries on its chain. The numbering of the log
carries on after a restart from the highest number the metrological log -
or any store of every entry a kind of node hands in, `IEventLogStore` -
holds.

What bears on trust is tagged `security`, in the log and in the file: a
server's certificate refused, tolerated, recorded, learned or changed; every
change of the certificate store; a role the configuration file adds or says
differently. One tag and not another log, because a page and a `grep` pick it
out either way, and what is also evidence is in the metrological log already.

What the log says about itself - a listener that failed, a file that cannot
be written - cannot go through the log, and goes to stderr. It goes through
the same console block as the entries, so that it cannot land in the middle
of a half-typed command either; and where the block itself fails, because the
thing being complained about is the console, the complaint is written without
it, once.


## Diagnostics

Making the node try something, to find out whether it can - step by step,
as JSON, for a page that shows the steps as they happen:

* `ResolveAsync` asks a name server for a name: the servers in effect or one
  of them, a handful of record types, and what came back, with every step
  said in a sentence. Name resolution switched off is a step, not an
  exception.
* `TestTimeServerAsync` asks one time server for the time the way the group
  would: the NTS-KE handshake, the certificate it presented and the chain
  this machine built - each certificate with both ends of its validity and
  the days it has left, the server's and the root's fingerprints, a verdict
  in words, and what the node made of it beyond the machine: a root of its
  own, and what the server is held to - then the NTP exchange, and how far
  off the node's clock is.
* `SyncTimeAsync` asks the whole group, which is what the clock check does on
  its interval.

None of it sets the clock. Stepping the clock of a running node is a
different decision from measuring it, and not one a page should be able to
make.


## The JSON API

Every node answers the same routes below `/api`, from one class,
`NodeHTTPAPI`. A kind of node derives its own API from it and registers what
only it has on top:

| | |
|---|---|
| `POST v1/auth/logout`, `GET v1/auth/me` | signing out, and who is signed in with what they may do |
| `GET v1/status` | how the node is doing; `service` is its kind's product |
| `GET v1/clock` | what time it is here, and what that is worth |
| `GET v1/configuration` | what the node is made of |
| `GET`/`PUT v1/configuration/dns`, `POST …/dns/query` | name resolution, and one look-up |
| `GET`/`PUT v1/configuration/nts`, `POST …/nts/sync`, `POST …/nts/test` | the time servers, one synchronisation, one server asked everything |
| `GET`/`POST v1/certificates`, `POST …/inspect`, `POST …/reload`, `GET`/`PATCH`/`DELETE …/{id}` | the certificate store: a POST with `kinds` puts every certificate of a file or a text in as every kind given, each answered on its own; `inspect` says what a file or a text holds, PEM and keys included, at the permission to change the store; `kind` in a PATCH and `?kind=` in a DELETE name the kind a certificate kept as several is changed or taken out as |
| `GET v1/logs`, `GET v1/events` | the log's snapshot, and the event stream after it |
| anything else below `/api` | a JSON 404, for every method |

It used to be eight copies - the vehicle's, the charging station's, the local
controller's and five more - and they had begun to differ: the clock at
`v1/configuration/time` on five of them and at `v1/clock` on three, a JSON 404
without PATCH, a `server` or a `host` that one copy refused in a sentence and
another took as it came and threw out of as a 500, and an event stream that
went on after its session had ended. What does differ between the kinds is
said where the kind says it:

* `ProductStatus()` - what the status says beyond every node's, such as the
  identity a local controller has towards its CSMS.
* `ProductMe(User)` - what `auth/me` says beyond every node's, such as the
  name a meter gives the role somebody holds there.
* `ToReadTheClock` and `ToReadTheLog` - what reading the clock, or the log and
  its stream, needs beyond a sign-in: nothing, unless a kind has accounts the
  log is not for.
* The node's `CompleteCertificatesJSON(JSON)` - what the store's answer says
  beyond every node's, such as the certificates a vehicle chose for a session.
* The node's `WhatUses(Handle)` - what of the node names a certificate, as
  the sentence a DELETE of it is refused with, 409. Switching it off is
  still allowed: that is how a vehicle's chosen credential is taken out of
  service.
* The node's `WhatWouldLose(Entry, ActiveAfter, UsagesAfter)` - asked of every
  kind the change touches, the usages as `CertificateUsage`s - what would
  be left without a certificate it needs, were it switched off or told
  other usages, as the sentence a PATCH or a DELETE is refused with, 409 -
  asked before any of the change is made, with the usages as the store
  would keep them. A meter's listener with nothing else to show, say.
* The store's `OnChanged` - sent after anything in the store changed,
  through the API or by the node's own work, and outside the store's lock:
  what a kind derives from its store, such as the identity a listener
  shows, is asked again at once rather than at the next turn of a timer.
* `EventStreamOf(Request, Source, Reader, MayStillRead)` and `StillLetIn` - a
  stream of the kind's own, carried for as long as its reader would still be
  let in.

Who changed something is in the log at Notice, on every kind of node: the
name resolution, the time source, and each change of the certificate store -
"'alice' changed the time source of this charging station." So is who asked
it to synchronise its time, with "Sync now" or `syncNTS`: a request about
the clock that everything it writes down is stamped with. The node says
what changed; only the request knows who. And a certificate's handle may be
written in capitals, as a tool it was copied out of may have written it: the
store spells handles in lower case, and so does the API before it asks.

A change that is fine in itself, and that a file cannot take - the
configuration file, a certificate's file in the store or its index - is
answered 500 with why, and changes nothing, now or at the next start: `PUT`
of `dns` and `nts`, and `POST`, `PATCH` and `DELETE` of the store. It was
the status of a refusal - 400, or 404 for a certificate whose file could not
be deleted - and a label, on or off and what a certificate is for were
answered 200 while the index could not keep them, and were gone at the next
start. What was wrong with a change is answered as it was.

The helpers a kind's own routes use are the same ones: `TryAuthorize`,
`TryGetUser`, `TryParseJSONObject`, `ErrorJSON`, `JSONResponse` - and
`NotChanged(Request, WhatWasWrong, Error, NotSaved)`, which answers a change
that was not made with the status of what was wrong with it, or with 500
where its file refused: the node's stores and its `TryUpdate...` say which
with an `out Boolean NotSaved`, as the local controller's stores do. A stream
opened with a password is asked about the password before every entry, as a
new request with it is; that needs Hermod f4aa17db or newer, which believes
Basic credentials it has verified for a while and forgets them when the
password changes - with an older Hermod it would be 600 000 rounds of PBKDF2
and a turn of the sign-in's rate limit for every line of the log.


## The web interface

What every kind of node shows in a browser - the sign-in, the log, the name
resolution, the time servers, the store - was eight copies too, one per kind,
of the same TypeScript and SCSS, and they had begun to differ as the API had.
`Frontend/src` is where it goes instead, a few files at a time. So far:

| | |
|---|---|
| `view.ts` | how every page and the frame draw: `html` and `render`, with lit-html, which compares a draw with what is on the page and leaves what it does not change - what is typed into another form, the focus, how far a list is scrolled |
| `html.ts` | `must()`: an element, or an error naming the one that is not there - what is left of the tagged template every page was written in, the one file all eight had alike |
| `config.ts` | what the node wrote into the page's `<meta>` tags: where the page and its APIs are, the versions, and the node's name |
| `basePath.ts` | where the page is mounted, added to a route on the way into the address bar and taken off on the way out |
| `router.ts` | which page a path is, and the way from one page to the next |
| `unsaved.ts` | what a page holds that the node has not been told about, and the question before it is left behind |
| `api/client.ts` | how the node is asked - a deadline on every request, a refusal in the node's own words, a 401 handed on to whoever signs out - and the HTTPExt API, where the accounts are: `extRequest()`, with the same deadline over the whole answer, for the sign-in and for what a kind asks there, a sign-up or a change of password; the types of everything every node answers, checked against what `NodeHTTPAPI` sends, and `nodeAPI()`, its routes |
| `ui.ts` | what else the pages share: a form held still while it is saved, a field read as a number, a time and a number as people read them, a key as a label, the way back after the sign-in |
| `cardViews.ts` | the cards of a Configuration page: `cardView()`, a section as the node sent it - a value that is a thing of its own, or a list of them, as a block below its name, inside a block as well - and `librariesCardView()`, one line per repository with its whole commit, naming an assembly only where two lines share a name |
| `logs/order.ts`, `logs/store.ts` | the browser's copy of the log: the snapshot and the stream after it, why a stream stopped - a session gone, an account that may no longer read the log - the stream closed while a page waits in the browser's back/forward cache, and what a kind publishes on the same stream |
| `auth.ts` | who is signed in, what they may do, and the guard that sends everybody else to the sign-in |
| `shell.ts` | the frame every signed-in page sits in: the menu - each entry shown to whoever may open its page, and on a screen too narrow for it beside the page folded away behind a button - who is signed in, and the versions; and what a page says somebody may not do, `mayButNot()` |
| `start.ts` | `startNode()`: the routes, the pages every node has, and following the log while somebody it is for is signed in, and across the browser's back/forward cache - `followAcrossTheCache()`, which a kind with a stream of its own calls for that one too |
| `index.html` | the page itself, which every kind's webpack names itself into - its title, what it is, the version of its frontend - and the node fills in as it serves it |
| `pages/login.ts`, `pages/notFound.ts`, `pages/logs.ts` | the sign-in, the page for an address with none, and the log as it happens |
| `pages/dns.ts`, `pages/nts.ts` | the name servers and the time servers - with what counts as legal time, and the clock - and what each server's certificate is held to (`pins.ts`, `pinViews.ts`, `dnsServers.ts`, `ntsServers.ts`) |
| `pages/certificates.ts` | the certificate store, in three tabs: by usage - what the node believes, presents and recognises, kind by kind (`certificateUsages.ts`); every certificate once, by name or by fingerprint, with every kind it is kept as; and the upload - a box of text certificates are pasted into and files dropped on, which the node reads into PEM, what is in it said certificate by certificate before anything goes in, and the kinds to keep it as, a kind or a usage made up among them |
| `tabs.ts`, `pemBox.ts` | building blocks of a page: tabs that are switched on the page and kept in the address as `?tab=`, every tab drawn so that what is typed into one outlives a look at another; and a box for certificates as text, with a Paste button where the browser lets a page read the clipboard and files dropped on it |
| `styles/` | what all of it looks like, in the kind's colour |

The shared pages say what the node says, in its name: the question before
a page's changes are left behind is "…that the local controller has not been
told about" on a local controller and "…that the charging station has not
been told about" on a station. The node writes its `Kind.Name` into the stub
as it serves it - `{{NodeName}}`, like `{{ServerVersion}}` - and `config.ts`
reads it from `index.html`:

```html
<meta name="node-name" content="{{NodeName}}" />
```

Without the tag a page says "the node".

A kind of node builds its own client from `api/client.ts`: everything every
node answers is re-exported, so its pages go on importing `../api/client`, and
it says what its own of it are - its resources, what its "me", its status and
its configuration say beyond every node's, the kinds its store keeps - and
adds its own routes, which go through the same `request()` - and what it
asks of the HTTPExt API through `extRequest()`, as the e-mobility provider
signs up and the meter changes a password:

```ts
export * from '@node/api/client';

export type Resource = NodeResource | 'csms' | 'stations';
export type Me       = NodeMe<Resource>;

export const api = {
    ...nodeAPI<{ me: Me; status: Status; configuration: Configuration; kind: CertificateKind; store: CertificateStore }>(),
    csms: { get: () => request<CSMSConfiguration>('GET', '/configuration/csms') }
};
```

And its `auth.ts` hands on the one `AuthState` there is - the router's guard
and the shell read the same - typed with its own:

```ts
export const auth = nodeAuth as unknown as AuthState<Me, Resource>;
```

A kind of node starts its web interface with `startNode()`, and says only
what is its own: what it is called, what its menu has, and its own pages.
The sign-in, the log, the name servers, the time servers, the certificate
store, the frame and the page for an address with none come with it - the
local controller's `main.ts`, less its imports:

```ts
startNode({
    name:  'Local Controller',
    icon:  'fa-sitemap',
    menu:  [
        nodeMenu.configuration([
            nodeMenu.dns,
            nodeMenu.nts,
            { path: '/configuration/csms', label: 'CSMS connection', icon: 'fa-satellite-dish', permission: [ 'csms:read' ] },
            { ...nodeMenu.certificates, label: 'Certificate store', icon: 'fa-vault' }
        ]),
        nodeMenu.logs
    ],
    certificates: {
        title:   'Certificate store',
        chosen:  { csmsClientCertificate: { label: 'signs in to the CSMS' } }
    },
    pages: {
        '/configuration':       configurationPage,
        '/configuration/csms':  csmsPage
    }
});
```

A page of its own at a path every node has a page for is the kind's. `"/"`
opens the first page of the menu the person signed in may open - the
configuration for whoever may read it, the name servers for a desk that
may read only those, where a kind's own "/" had shown them a page that
answered 403. An e-mobility provider's sign-up goes into `publicPages`, which
nobody has to be signed in for, and a meter's old bookmarks into `routes`,
which are asked first. `signIn`, `logs`, `certificates` and `who` say what
the sign-in, the Logs page, the certificate store and the foot of the menu
say where the node's words do not fit - the store's `chosen` names what the
node chose a certificate for, on its row.

Each menu entry is shown to whoever may open its page: `permission` is any
one of the permissions the node writes into "me", or a function. Whether the
log is for somebody is the node's to say, not the page's - "me" carries
`mayReadTheLog`, which is what the log itself would answer - and the Logs
entry, the Logs page and following the log all go by it. Every kind had
repeated its own node's rule in its pages - signed in, `configuration:read`,
`log:read` - and a page that asked the wrong one opened a stream the node
refused, and then told the account it may no longer read a log it had never
been let read.

Its stylesheet begins with every node's, in its own colour, and adds what
only its own pages need, with the tokens and the `panel` mixin at hand:

```scss
@use '@node/styles/node' as * with ($color-accent: #1b5f7f, $color-accent-dark: #14495f);
```

A kind of node loads none of it from anywhere when it runs. Its own webpack
bundles these files into its own bundle, as it bundles its own, and its own
build embeds that bundle into its assembly as before - so the files a kind
gets are the ones in the WWCP_Node its repository pins, as with the C#. It
imports them as `@node/...`:

```ts
import { html, render } from '@node/html';
```

and says where that is in three places, each relative to its `Frontend`
directory - `libs/<Kind>/<Kind>/Frontend`, with this repository in
`libs/WWCP_Node`, where its `.csproj` already finds `..\..\WWCP_Node`:

* `webpack.config.js`, for the bundle and its page - the node's
  `index.html`, which the kind names itself into, and which stops the build
  where the kind does not say what it is:
  ```js
  resolve: {
      extensions: ['.ts', '.js'],
      alias:      { '@node': path.resolve(__dirname, '../../../WWCP_Node/Frontend/src') }
  },
  ...
  new HtmlWebpackPlugin({
      template:     path.resolve(__dirname, '../../../WWCP_Node/Frontend/src/index.html'),
      title:        'Local Controller',
      description:  'The web interface of an OpenChargingCloud local controller, served by the Hermod HTTP/1.1 server',
      version:      appVersion,
      ...
  })
  ```
* `tsconfig.json`, for the type checker, which checks the shared files as the
  kind's own - `"paths": { "@node/*": [ "../../../WWCP_Node/Frontend/src/*" ] }`
  among the compiler options, `../../../WWCP_Node/Frontend/src/**/*.ts` in
  `include`, and its tests in `exclude`.
* `package.json`, for the tests, which Node runs, and Node knows neither the
  alias nor the paths - `"imports"` cannot say it either, since it may not
  point out of the package:
  ```
  "test": "node --import ../../../WWCP_Node/Frontend/test/resolve.ts --test \"src/**/*.test.ts\""
  ```
  `test/resolve.ts` tells Node what webpack is told: where `@node/...` is, and
  that a relative import without its extension means the `.ts` file.

A test that draws one of its pages draws it into a document of happy-dom,
against a node that is a stand-in for fetch - `test/node.ts`, which every
kind shares: `open(page, path, permissions, answers, drawn)`, what was
`asked` and `said`, `until`, `field`, `submit`, `change` and `type`. A kind
says in a file of its own who it is, and adds what only it has:

```ts
// test/controller.ts
import { standIn } from '@node/../test/node.ts';
export * from '@node/../test/node.ts';

standIn({ name: 'Local Controller', icon: 'fa-sitemap' });
```

Its own pages are held to what the shared ones are, by the same rules -
`test/pages.ts`, which `src/pages/pages.test.ts` asks of the shared pages -
in its own `src/pages/pages.test.ts`; `@node/..` is `WWCP_Node/Frontend`:

```ts
import { everyPageIn } from '@node/../test/pages.ts';

everyPageIn(new URL('./', import.meta.url), {
    withForms: [ 'csms.ts', 'ocppServer.ts' ]
});
```

Every page with a form says whether it is holding a draft, holds every form
it has - by name, `typedSinceDrawn(content.querySelector('#…'))`, or all at
once, `anyFormTypedSinceDrawn(content)` - and asks before its Reload throws
one away; it draws by comparing, with `html` and `render` from `view.ts`,
which leave what is typed into its other forms where it is when it draws
again after a save, a removal or a row opened for editing - drawn with
innerHTML, every form was drawn anew and what was typed thrown away; its
Reload is `reloadButton()`, which asks for it; every number typed, on every
page, with a form or without, is read with `numberField`, or `numberFrom`
for an input outside a form, not `Number()`, which makes an emptied field 0 -
but where a page says itself what empty means, `=== '' ? ... :` before it. The
rule asked only the pages with a form, and the charging station's power fields,
inputs of their own, were 0 kW once emptied. Every page links through `toURL`,
since `href="/..."` leads past the base the node may be served under in a new
tab or a copied link; and takes its look from the stylesheet, by a class -
`style="..."` is dropped by the policy the pages are served with,
`style-src 'self'`, which the kit asks every kind for. `input.capitals` and a
card heading's `.heading-action` are there for what three partner pages wrote as
style attributes. A table sits in a `<div class="table-scroll">`, which scrolls
it inside its card: outside one, a table wider than its card stood past it on a
phone, and the page scrolled sideways. What somebody may not do, a page says
through `mayButNot('look at the name resolution', 'change it')` - "Signed in as
cpo, which may look at the name resolution but not change it. That needs a role
that may change it." - and it names no role as the one that is needed: which
roles there are, and what each may, is the configuration file's to say.
`withForms` names the pages with a form, so that the rules are not said of
nothing; `dialogForms` names the forms that are a dialog's, which asks for
itself when it is closed; `notDrafts` names a page whose form is none, with
why - signing in is the way in, and nothing typed there is the node's to lose.
So every kind has a frontend test of its own, and the scaffolding with it; one
whose pages have no form yet has `withForms: []`, which says so, and says it
again the day one has.

Asked of every kind's own pages before they were shared, the rules found
pages of five kinds that held nothing at all, or not every form - a flag of
the page's own holds what is added to its list, not what is typed into a
form and not yet added - and one kind's numbers that an emptied field made 0.

And in its `.csproj`, without which a new WWCP_Node changes nothing: the
frontend is built only when an input of `BuildFrontend` changed, and the
shared files have to be among them -

```xml
<FrontendInput Include="$(MSBuildProjectDirectory)\..\..\WWCP_Node\Frontend\src\**\*" />
```

Without it, a WWCP_Node that had changed only shared files left the bundle
up to date, and the old one was embedded - on a machine that keeps `dist/`;
CI, which starts from nothing, would not have noticed. The local
controller's `.csproj` also touches `dist/index.html` after webpack has run:
webpack leaves a file alone whose content did not change, which kept
`index.html` older than what had just been built, so the target was never up
to date again and every build ran npm.

What a shared file may not do:

* Import anything of a kind. What differs between the kinds is handed in,
  or asked of the JSON API - which says per kind already, for one, what the
  store takes.
* Be anything but types to strip: `erasableSyntaxOnly` in
  `Frontend/tsconfig.json`. Node runs the tests with the types stripped, and
  a parameter property in `html.ts` - code to be generated, not a type - was
  why no test of any kind could load a page.
* Import an npm package. webpack would look for it upwards from
  `WWCP_Node/Frontend`, not in the kind's `node_modules`. The day a shared
  file has to, every kind's `webpack.config.js` says first where to look -
  `resolve: { modules: [ path.resolve(__dirname, 'node_modules'), 'node_modules' ] }`,
  which none says yet.

`imports.test.ts` holds every shared file to that: it may import another
shared file and nothing else.

`Frontend/` has a `package.json` of its own, for the type checker; the
workflows run its checks and its tests on the Debian leg:

```
cd Frontend
npm ci
npm run typecheck
npm run typecheck:test
npm test
```


## Testing a kind of node

What every node answers alike is tested once, in `WWCP_Node_TestKit`, and
run by every kind of node against its own: the sign-in, the configuration,
name resolution and the time servers with their diagnostics, the log and its
event stream, stopping with browsers watching, the certificate store, the
web interface, roles the configuration file adds and what a kind starts
with - one hundred and thirteen tests that the suites of the local controller,
the charging station, the CSMS and the e-mobility provider each had a copy
of, and the vehicle, the gateway, the roaming hub and the meter part of one
or none.

What the node's own code does without a web interface in front of it - the
log, the console, the clock, the configuration file and its sections, the
start, a time server's test - is tested once as well, in `WWCP_Node_Tests`,
against a node of no particular kind. Those were copies too: the local
controller's suite, the CSMS's and the e-mobility provider's each carried
the same tests of the same log. A kind's own suite keeps what is about its
wiring - its own sections of the file, the certificates it keeps, the name
of its log files.

A kind's suite references the kit and derives one fixture, which says how a
node of its kind is made:

```csharp
public class LocalControllerConformance : NodeConformanceTests
{
    protected override WWCPNode NewNode(String Directory, JObject Configuration)
        => TestControllers.New(Directory, Configuration);
}
```

- **`NewNode(Directory, Configuration)`** makes a node of the kind, not
  started, on a free port - `TestPorts.Free()` - with its accounts in the
  directory and the given configuration written into its file before it is
  read. The time client is switched off in it, so nothing reaches the
  network.
- **`AdminLogin`, `SignInPath`, `SignInBody(...)`** are the first account and
  the HTTPExt API's form, for a kind that signs in otherwise.
- **One fixture, not one per topic**, so that a test added to the kit is run
  by every kind without any of them adding a line. A test that needs a node
  configured otherwise says so with `[WithNode(NodeSetup...)]`: a name server
  that never answers, servers that learn their root on first use, a time
  client that is on, or roles the file adds.
- **Ports come from `TestPorts` and `ClosedPort`**: a free one, and one held
  closed for as long as a test needs nothing to answer on it. `TestPorts`
  hands out no port twice in a test run - the operating system does: Linux
  picks one at random from some fourteen thousand, and a run that asks a
  thousand times is given the same one again. A kind's own tests take their
  ports from the same two, so that theirs and the kit's never meet. Where
  the machine has no buffer space left for a socket - WSAENOBUFS, 10055,
  seen while the whole suites of several test runs ran at once - `Free()`
  asks again, after a pause that grows, up to five times.
- **A node is started through `TestPorts.StartedOnFreshPorts(() => ...)`**,
  the kit's own as a kind's own: made again on fresh ports and started
  again, up to three times, where another test run on the same machine took
  a port in the gap between its being handed out and its being bound, which
  nothing can close. The accounts a failed first start made go with it, so
  that the next is a first start too; accounts that were there stay. A node
  given up on, or whose start failed for another reason, is let go of
  before the start ends in what it failed with.
- **A stub of a peer is started through
  `TestPorts.StartedOnAFreshPort(port => ..., stub => stub.Start())`**: made
  on a port `Free()` hands out, and made again on a fresh one where starting
  it ends in a `SocketException` that says the port is taken -
  `AddressAlreadyInUse`, or `AccessDenied`, which Windows says of a port
  another socket holds for itself. The stub is `IAsyncDisposable`, and one
  given up on is let go of (proposed by the hub, whose stub OCPI peers had a
  loop of their own for this).
- **What a kind's code says is held to `SourceRules`**, as its pages are to
  `test/pages.ts`: `ArticlesBeforeANameIn(...)` finds "a" or "an" put in
  front of a name that is interpolated. Which article a name takes goes by
  how it is said - "an OEM root" but "a V2G root" - and "A {Node.Kind.Name}"
  read "A electric vehicle" in the kit's own messages (found by the EV).
  A name is said with its article - `CertificateKind.WithArticle()` - or
  without one: "this electric vehicle". An article at the end of a line is
  read with the next one, where the string goes on there with a name, the `+`
  before or after the break: `"is a " +` above `$"{entry.Kind.AsText()} ..."`
  said "is a oemRoot" (found by the EV). A kind asks its own sources - its
  tests' too, if it likes - finding its repository by a file of each project,
  not by their directories: built with `--artifacts-path`, a build's
  `artifacts/bin` holds a directory named after every project, and was taken
  for the repository (found by the charging station). A directory with no C#
  file below it is refused rather than found clean.
  ```csharp
  var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "LocalController/LocalController.csproj",
                                                                         "LocalControllerTests/LocalControllerTests.csproj");

  Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(repository, "LocalController")), Is.Empty);
  ```
- **What a kind does not have is not failed.** A store that keeps no TLS root
  or identity, or a node built without its web interface, makes the tests of
  those inconclusive, saying why; a kind that refuses to lose an identity it
  needs - `WhatWouldLose` - is not asked to.

Its first run against a node of no particular kind found that such a node's
stub said "v" where it says its version - the constructor's argument of that
name, rather than the node's - and that the stop tests had passed against a
node that leaves its event streams open, since a heartbeat ends them fifteen
seconds later; they run without one now. The roaming hub's run found that
they still passed against such a node one time in eight: the line a stop
begins with woke the stream, and where its write came after the socket was
closed, it failed and ended the stream. They hold the stop at that line now,
until every stream has been sent it.


## Building it

This repository cannot be built on its own. `WWCP_Node.csproj` references
`..\..\Hermod\Hermod\Hermod.csproj`, `..\..\Norn\...`, `..\..\Styx\...` and
`..\..\Urdr\...` - sibling directories - and Norn and Hermod reach for their
own siblings the same way. So the five are checked out side by side:

```
Styx/
Hermod/
Norn/
Urdr/
WWCP_Node/
```

and then:

```
dotnet build WWCP_Node_Tests/WWCP_Node_Tests.csproj
dotnet test  WWCP_Node_Tests/WWCP_Node_Tests.csproj --no-build
```

`Directory.Build.props` stamps every assembly with the repository and the
commit it was compiled from, `-dirty` where the tree was not clean, so that a
bug report names the code that ran rather than the code that was checked
out. The workflows in `.github/` do the same checkout on Windows and in a
Debian 13 container, on every push and once a night; nothing in them pins the
four libraries, so a breaking change in one of them turns this red on the day
it lands. [EVCLI](https://github.com/OpenChargingCloud/EVCLI) pins all of them
as submodules and asks the other question.


## What it is not

A node of any kind. On its own it has the JSON API every node has and
nothing else to serve; it listens, signs people in, keeps a log and a clock,
and waits for a kind of node to make something of that.

And not yet as general as its name. The certificate kinds are ISO 15118's
and a vehicle's - they came here with the rest. The second kind, the charging station, has said what of
it is every node's so far: the roles are the kind's, a node may listen on
more than one port, and a clock check is counted for a screen rather than
described to it. It has its own certificates for the back ends it dials, and
keeps none in the store - which is why the kinds a store keeps are the kind's
to say too, and why a node that keeps none says it in its own name rather
than as "this node". The third, the local controller, has added that what is
worth a tag in the debug bridge is the kind's to say, as its roles are - and
it keeps the keys of its station port and the chains it accepts from
stations in stores of its own too.


## Your participation

This software is free and Open Source under [GNU Affero General Public License (AGPL)](LICENSE).
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to request
a feature or send us a pull request, feel free to use the normal GitHub
features to do so. For this please read the Contributor License Agreement
carefully and send us a signed copy or use a similar free and open license.
