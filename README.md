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
that adds its own sections to the same configuration file, its own JSON API
below `/api` and its own bundle to serve. [EV](https://github.com/OpenChargingCloud/EV)
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
| `PortUnavailableException.cs` | a port the node has to have, and cannot get - which one, and what it was for, said in a sentence rather than in a stack trace |
| `Certificates/` | the store: what a certificate is for, what may go in, and what survives a restart |
| `Configuration/` | the file, and one record per section of it that every node has: `dns`, `nts`, `certificates`, `roles` |
| `Logging/` | one log for everything: in memory, on the console, in a file, what the libraries below say through it - and, signed, what bears on the time and the trust |
| `Web/` | who may do what: the resources of a node, the three operations on them, and the roles that carry them |
| `WWCP_Node_Tests/` | two hundred and twenty-seven tests, none of which constructs a vehicle, a station or a controller - four of them over a real key exchange with a time server of Norn's own |


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
each. `Name` is read in a sentence - "The electric vehicle is shutting down."
- and is lower case for that reason; it is what the node calls itself in
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
  `/api` under the base path unless the constructor was told otherwise. The
  node puts nothing there itself.
* **What it says once it is up, and what it ends before the server stops:**
  `OnStarted()` and `OnStopping()`. The vehicle uses the second to close its
  event streams, because the server waits for every request it started and a
  request waiting for the next log entry is not woken by closing the sockets.
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
  certificate its store keeps - all seven by default, which is what a vehicle
  keeps. A kind that hands in none has no store directory at all: a charging
  station, a local controller or a gateway keeps the keys it dials with in
  stores of its own, and a store beside every one of them holding a vehicle's
  seven empty directories was a promise nobody was keeping.
* **Who may do what:** `Resources`, the names of what it adds for a role to
  read, edit or run, and `RoleDefinitions`, its roles and what each of them
  may do - see below.
* **What it is, for the Configuration page:** `ConfigurationJSON()` is
  virtual and answers with the node's cards - `http`, `web`, `log`, `time` -
  and the kind adds its own on top.

And the bundle: a kind of node hands in an `IStaticContentSource` - the
files webpack built, embedded into its assembly - and the node serves it at
the base path as a single-page application, with four placeholders in
`index.html` filled in on the way out: `{{ServerVersion}}`, `{{BasePath}}`,
`{{APIBase}}` and `{{ExtBase}}`. A bundle that reads where it is and where
its API is out of those, rather than assuming `/` and `/api/v1`, is one that
still works once somebody mounts it below a base path. A node handed no
bundle has no web interface, and says so once, in an ordinary line.


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

A server may be held to more than every server is held to - its own
certificate, or the root its chain ends at, each by its SHA-256 fingerprint,
written the way a certificate authority, a browser or openssl writes one:

```json
{ "hostname": "time.local", "rootFingerprint": "4F:1C:…", "onMismatch": "record" }
```

A server showing another certificate is refused - its key exchange ends, and
it gives no time - unless `onMismatch` says `record`, when its time is used
all the same; either way the metrological log says which certificate it
showed and what it is held to. The certificate is judged at every key
exchange, of the group and of a detailed test alike, and in this order: is
it issued for the server's name; does its chain end at a root this machine
trusts, or at a TLS root of the node's own store, or at the root the server
is held to where the store has that one under whatever kind; and is it what
the server is held to. A pin narrows what is believed and never widens it:
a certificate that matches its pin and chains to nothing is refused, and a
server with a certificate it signed itself is believed by importing that
certificate as a TLS root - which says the same thing, on purpose. A key
exchange is reused for as long as its cookies last, up to half an hour, so a
change to what a server is held to forgets the exchange it has, and the pin
counts from the next round. The same verdict at every round is written into
the metrological log once, and its end again. The NTS answer says, per
server, the fingerprint of the certificate it showed last - which is what a
pin is written down from - what it is held to, and what the node made of it.

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
certificates per role work without any number of passwords to carry. The file
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
client connecting to it has to chain to; `tlsServer`, what a server it
connects to shows, kept to be recognised - never with a private key, which
would be that server's key in the wrong place; and `tlsIdentity`, what the
node shows itself, with its key. A kind of node keeps those it has a use for,
and `CertificateKindExtensions.ISO15118` and `.TLS` name the two groups.

Anything in the store is found by its SHA-256 fingerprint, whatever kind it
was kept as: `ByFingerprint` takes the whole of it and nothing shorter, in any
of the ways a fingerprint is written. A truncated fingerprint is a handle and
never evidence. What a trust decision rests on is written into the
metrological log - an import, with the fingerprint; a certificate switched on
or off; one deleted, or dropped because its file went.


## Who may sign in

The accounts are Hermod's HTTPExt API, at `/ext` beside the JSON API rather
than under it - it is not the node's API, it has routes and a vocabulary of
its own, and putting it under `/api/v1` would promise that the node versions
it. Nobody can sign in to a web interface whose accounts are empty, and an
unauthenticated setup page would be a door of its own: so at a first start
the node makes one account, `root`, with a password made up on the spot and
shown once, on the console, to whoever started the process. It is never
written down anywhere; what the accounts hold is the hash. It is 24
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
entry by entry as metrological by whoever writes it - `Log.Metrological(...)`
- rather than picked out by a tag or a level, because what is metrologically
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

A node of any kind. On its own it has no JSON API and nothing to serve; it
listens, signs people in, keeps a log and a clock, and waits for a kind of
node to make something of that.

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
