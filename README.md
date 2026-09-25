# WWCP Node

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
| `NodeKind.cs` | the five names a kind of node goes by |
| `PortUnavailableException.cs` | a port the node has to have, and cannot get - which one, and what it was for, said in a sentence rather than in a stack trace |
| `Certificates/` | the store: what a certificate is for, what may go in, and what survives a restart |
| `Configuration/` | the file, and one record per section of it that every node has: `dns`, `nts`, `certificates` |
| `Logging/` | one log for everything: in memory, on the console, in a file, and what the libraries below say through it |
| `Web/` | who may sign in, and what each role may do |
| `WWCP_Node_Tests/` | ninety-five tests, each of them constructing the node rather than a vehicle, a station or a controller |


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
- and is lower case for that reason. `Tag` is the word in square brackets on
every entry about the node itself. `Product` follows "OpenChargingCloud" in
the `Server` header of every response. `LogFilePrefix` is what a day's log
file is called before its date. And `Organization` is the identifier of the
one organization the accounts are in, which is written into the accounts file
at the first start and read back at every start after it - so it is the one
of the five that must never change once a node has run.

The port is the kind's to give and to pass, not the node's to guess: a node
that took a default of its own for a kind that forgot to pass one would
listen somewhere nobody expects.

Beyond the names, a kind of node adds to the node in six places:

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
has - `dns`, `nts`, `certificates` - and passes the others over without a
word; the kind of node takes its own from the same document. That is what
lets a vehicle keep its battery in the same file its name servers are in,
and what lets a file written by a newer node still start an older one.

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

Servers sharing a priority are one band and are asked together; a lower
priority is asked first. The four above share priority 0 because they are
peers, and putting them in separate bands would say something about them that
is not true. A section naming a single `hostname` and no list becomes a group
of one, which is what every file written before there were groups says, and it
keeps working; a group of one is held to a quorum of one, and a section asking
two of it is refused. A quorum the servers could never reach is refused
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
them. A kind of node puts that behind a route of its own.

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
handle rather than by a path. The directory is `certificates` beside the
configuration file unless the file's `certificates` section or the
constructor says otherwise - beside the file rather than below the working
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

The kinds are ISO 15118's, and so the vehicle's, today. See below.


## Who may sign in

The accounts are Hermod's HTTPExt API, at `/ext` beside the JSON API rather
than under it - it is not the node's API, it has routes and a vocabulary of
its own, and putting it under `/api/v1` would promise that the node versions
it. Nobody can sign in to a web interface whose accounts are empty, and an
unauthenticated setup page would be a door of its own: so at a first start
the node makes one account, `root`, with a password made up on the spot and
shown once, on the console, to whoever started the process. It is never
written down anywhere; what the accounts hold is the hash.

A role is a user group under the same name, and membership is what carries
its permissions. The roles are the kind of node's, handed in as `Roles` - a
vehicle's are `viewer`, `driver`, `service` and `systemadmin`, a charging
station's `viewer`, `cpo`, `installer` and `systemadmin` - and a node handed
none knows the vehicle's, which came here with the rest of the vehicle.
`systemadmin` is one of them whatever the kind says: the first account goes
there. The groups are made at every start rather than only the first,
because they are the node's vocabulary and not somebody's data: a group
deleted by hand would otherwise leave a role nobody can ever hold again - and
Hermod's floor for a group's identification is lowered to the shortest role
handed in, because it is four characters and `cpo` is three.

What a role lets somebody do is the kind's to say and to enforce: the HTTPExt
API knows users, groups and organizations and has no opinion about what "may
run a session" or "may raise a power limit" means; it answers who somebody
is, and the kind of node answers what that lets them do. `Web/UserRoles.cs`
is the vehicle's answer. A closed set, deliberately: a role a node has never
heard of grants nothing, rather than quietly granting something.

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
  the days it has left, the root with its fingerprint, and a verdict in words
  - then the NTP exchange, and how far off the node's clock is.
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
and a vehicle's, and so are the permissions in `Web/UserRoles.cs` - they came
here with the rest. The second kind, the charging station, has said what of
it is every node's so far: the roles are the kind's, a node may listen on
more than one port, and a clock check is counted for a screen rather than
described to it. It has its own certificates for the back ends it dials, and
has not asked the store for anything yet. The third, the local controller,
has added that what is worth a tag in the debug bridge is the kind's to say,
as its roles are - and it keeps the keys of its station port and the chains
it accepts from stations in stores of its own too.


## Your participation

This software is free and Open Source under [GNU Affero General Public License (AGPL)](LICENSE).
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to request
a feature or send us a pull request, feel free to use the normal GitHub
features to do so. For this please read the Contributor License Agreement
carefully and send us a signed copy or use a similar free and open license.
