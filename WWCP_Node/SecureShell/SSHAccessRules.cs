/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP_Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net;
using System.Net.Sockets;
using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.SecureShell
{

    /// <summary>
    /// What a rule does with the sessions it matches.
    /// </summary>
    public enum SSHAccessAction
    {

        /// <summary>
        /// On to what the node lets in anyway: its accounts, their roles and keys. A rule never lets in
        /// what that does not.
        /// </summary>
        Allow,

        /// <summary>
        /// Refused.
        /// </summary>
        Deny

    }


    /// <summary>
    /// Who is asking, as the rules see it: an account of the node - or, where a kind of node lets others
    /// sign in, one of those, e.g. a charging station - with the groups it is in.
    /// </summary>
    /// <param name="Kind">"account", "station", ...</param>
    /// <param name="Name">The account's name, the station's id.</param>
    /// <param name="Groups">For an account its roles, for a station its login group.</param>
    public sealed record SSHPrincipal(String                 Kind,
                                      String                 Name,
                                      IReadOnlyList<String>  Groups)
    {

        /// <summary>
        /// The kind of principal an account of the node is.
        /// </summary>
        public const String Account = "account";

        /// <summary>
        /// "account:root", as the rules and the log write it.
        /// </summary>
        public override String ToString()
            => $"{Kind}:{Name}";

    }


    /// <summary>
    /// What the rules are asked about: who, for what, from where, to where, and how they signed in.
    /// </summary>
    /// <param name="Principal">Who.</param>
    /// <param name="Service">"shell", "sftp", "subsystem:&lt;name&gt;" - or null, when asked at sign-in.</param>
    /// <param name="Source">The client's address, where known.</param>
    /// <param name="Local">This node's address the client connected to, where known.</param>
    /// <param name="AuthMethod">"publickey", "password", "keyboard-interactive".</param>
    public sealed record SSHAccessRequest(SSHPrincipal  Principal,
                                          String?       Service,
                                          IPAddress?    Source,
                                          IPAddress?    Local,
                                          String        AuthMethod);


    /// <summary>
    /// What the rules decided, and which rule did: null where none matched, and what the node lets in
    /// anyway decides alone.
    /// </summary>
    /// <param name="Allowed">Whether the request may go on.</param>
    /// <param name="Number">The rule's number, counted from 1 as the rules are listed; null where none matched.</param>
    /// <param name="Rule">The rule, where one matched.</param>
    public sealed record SSHAccessDecision(Boolean         Allowed,
                                           Int32?          Number,
                                           SSHAccessRule?  Rule)
    {

        /// <summary>
        /// No rule matched.
        /// </summary>
        public static SSHAccessDecision NoRule { get; } = new (true, null, null);

        /// <summary>
        /// "rule 3 (deny account:* service=shell local=10.10.0.1)", or "no rule".
        /// </summary>
        public override String ToString()
            => Number is Int32 number
                   ? $"rule {number} ({Rule})"
                   : "no rule";

    }


    /// <summary>
    /// One SSH access rule: an action, and what it applies to. Every condition left out matches
    /// everything; a rule matches where all its conditions do.
    /// </summary>
    /// <remarks>
    /// <para>
    /// In the configuration file a rule is a JSON object - see <see cref="TryParse"/> - and at the command
    /// line one line: <c>deny principal=account:* service=shell source=10.0.0.0/8 local=10.10.0.1 auth=password # why</c>.
    /// </para>
    /// <para>
    /// An address a condition cannot be asked about - a client whose address is unknown - matches a rule
    /// that denies and no rule that allows: a restriction that cannot be evaluated is not a pass.
    /// </para>
    /// </remarks>
    public sealed record SSHAccessRule
    {

        #region Data

        /// <summary>
        /// The services a rule may name; "subsystem:&lt;name&gt;" besides.
        /// </summary>
        public static readonly IReadOnlyList<String>  Services     = [ "shell", "sftp" ];

        /// <summary>
        /// The sign-in methods a rule may name.
        /// </summary>
        public static readonly IReadOnlyList<String>  AuthMethods  = [ "publickey", "password", "keyboard-interactive" ];

        /// <summary>
        /// The most addresses or networks one condition may list.
        /// </summary>
        public const Int32 MaxAddresses = 64;

        /// <summary>
        /// The longest comment.
        /// </summary>
        public const Int32 MaxComment   = 200;

        private static readonly HashSet<String> Properties = [ "action", "principal", "service", "source", "localAddress", "authMethod", "comment" ];

        #endregion

        #region Properties

        /// <summary>
        /// What the rule does with the sessions it matches.
        /// </summary>
        public SSHAccessAction        Action          { get; }

        /// <summary>
        /// Whom it applies to: "account:&lt;name&gt;", "station:&lt;id&gt;", "group:&lt;name&gt;" -
        /// with * and ? as wildcards, letter case ignored; null for everybody.
        /// </summary>
        public String?                Principal       { get; }

        /// <summary>
        /// What it applies to: "shell", "sftp", "subsystem:&lt;name&gt;" (wildcards allowed) - or null for
        /// everything, signing in included.
        /// </summary>
        public String?                Service         { get; }

        /// <summary>
        /// The client addresses it applies to, as written; null for every address.
        /// </summary>
        public IReadOnlyList<String>? Sources         { get; }

        /// <summary>
        /// This node's addresses it applies to - which network the client came in on - as written; null for
        /// every address.
        /// </summary>
        public IReadOnlyList<String>? LocalAddresses  { get; }

        /// <summary>
        /// The sign-in methods it applies to; null for every method.
        /// </summary>
        public IReadOnlyList<String>? AuthMethodsOf   { get; }

        /// <summary>
        /// Why the rule is there.
        /// </summary>
        public String?                Comment         { get; }

        private readonly IReadOnlyList<IpCidr>? sources;
        private readonly IReadOnlyList<IpCidr>? locals;

        #endregion

        #region Constructor(s)

        private SSHAccessRule(SSHAccessAction         Action,
                              String?                 Principal,
                              String?                 Service,
                              IReadOnlyList<String>?  Sources,
                              IReadOnlyList<IpCidr>?  ParsedSources,
                              IReadOnlyList<String>?  LocalAddresses,
                              IReadOnlyList<IpCidr>?  ParsedLocals,
                              IReadOnlyList<String>?  AuthMethods,
                              String?                 Comment)
        {

            this.Action          = Action;
            this.Principal       = Principal;
            this.Service         = Service;
            this.Sources         = Sources;
            this.sources         = ParsedSources;
            this.LocalAddresses  = LocalAddresses;
            this.locals          = ParsedLocals;
            this.AuthMethodsOf   = AuthMethods;
            this.Comment         = Comment;

        }

        #endregion


        #region (static) TryCreate(Action, Principal, Service, Sources, LocalAddresses, AuthMethods, Comment, Path, out Rule, out Error)

        /// <summary>
        /// A rule, checked: the principal and the service as the rules write them, the addresses as networks
        /// whose host bits are zero, the methods among <see cref="AuthMethods"/>.
        /// </summary>
        public static Boolean TryCreate(SSHAccessAction                         Action,
                                        String?                                 Principal,
                                        String?                                 Service,
                                        IReadOnlyList<String>?                  Sources,
                                        IReadOnlyList<String>?                  LocalAddresses,
                                        IReadOnlyList<String>?                  AuthMethods,
                                        String?                                 Comment,
                                        String                                  Path,
                                        [NotNullWhen(true)]  out SSHAccessRule?  Rule,
                                        [NotNullWhen(false)] out String?         Error)
        {

            Rule  = null;
            Error = null;

            if (Principal is not null)
            {

                var colon = Principal.IndexOf(':');

                if (colon <= 0 || colon == Principal.Length - 1 || !IsName(Principal[..colon]) || !IsPattern(Principal[(colon + 1)..]))
                {
                    Error = $"'{Path}.principal' must be written \"account:<name>\", \"station:<id>\" or \"group:<name>\" - * and ? as wildcards - not '{Principal}'.";
                    return false;
                }

                Principal = Principal[..colon].ToLowerInvariant() + Principal[colon..];

            }

            if (Service is not null)
            {

                Service = Service.Trim();

                var known = Services.Contains(Service, StringComparer.OrdinalIgnoreCase)
                                ? Service.ToLowerInvariant()
                                : Service.StartsWith("subsystem:", StringComparison.OrdinalIgnoreCase) && Service.Length > "subsystem:".Length && IsPattern(Service["subsystem:".Length..])
                                      ? "subsystem:" + Service["subsystem:".Length..]
                                      : null;

                if (known is null)
                {
                    Error = $"'{Path}.service' must be \"shell\", \"sftp\" or \"subsystem:<name>\", not '{Service}'.";
                    return false;
                }

                Service = known;

            }

            if (!TryParseAddresses(Sources,        $"{Path}.source",       out var parsedSources, out Error) ||
                !TryParseAddresses(LocalAddresses, $"{Path}.localAddress", out var parsedLocals,  out Error))
                return false;

            if (AuthMethods is not null)
            {

                if (AuthMethods.Count == 0)
                {
                    Error = $"'{Path}.authMethod' names no method: leave it out for every method.";
                    return false;
                }

                foreach (var method in AuthMethods)
                {
                    if (!SSHAccessRule.AuthMethods.Contains(method, StringComparer.OrdinalIgnoreCase))
                    {
                        Error = $"'{Path}.authMethod' may name {String.Join(", ", SSHAccessRule.AuthMethods.Select(m => $"\"{m}\""))}, not '{method}'.";
                        return false;
                    }
                }

                AuthMethods = [ .. AuthMethods.Select(method => method.ToLowerInvariant()).Distinct() ];

            }

            if (Comment is { Length: > MaxComment })
            {
                Error = $"'{Path}.comment' may be at most {MaxComment} characters long.";
                return false;
            }

            Rule = new SSHAccessRule(Action, Principal, Service, Sources, parsedSources, LocalAddresses, parsedLocals, AuthMethods, Comment);
            return true;

        }

        #endregion

        #region (static) TryParse(JSON, Path, out Rule, out Error)

        /// <summary>
        /// A rule as the configuration file writes it:
        /// <code>{ "action": "deny", "principal": "account:*", "service": "shell", "source": [ "10.0.0.0/8" ],
        ///   "localAddress": [ "10.10.0.1" ], "authMethod": [ "password" ], "comment": "why" }</code>
        /// "action" is needed; every other property may be left out. A property the rules do not know is
        /// refused, as a condition that is misspelt and ignored would let in what it was to keep out.
        /// </summary>
        public static Boolean TryParse(JObject                                  JSON,
                                       String                                   Path,
                                       [NotNullWhen(true)]  out SSHAccessRule?  Rule,
                                       [NotNullWhen(false)] out String?         Error)
        {

            Rule = null;

            if (JSON.Properties().FirstOrDefault(property => !Properties.Contains(property.Name)) is JProperty unknown)
            {
                Error = $"'{Path}' has a property no rule knows: '{unknown.Name}'. A rule has {String.Join(", ", Properties.Select(p => $"\"{p}\""))}.";
                return false;
            }

            if (!JSON.TryGetValue("action", out var actionToken) || actionToken.Type != JTokenType.String ||
                !TryParseAction(actionToken.Value<String>(), out var action))
            {
                Error = $"'{Path}.action' must be \"allow\" or \"deny\".";
                return false;
            }

            if (!TryReadOptionalString(JSON, "principal", Path, out var principal, out Error) ||
                !TryReadOptionalString(JSON, "service",   Path, out var service,   out Error) ||
                !TryReadOptionalString(JSON, "comment",   Path, out var comment,   out Error) ||
                !TryReadOptionalStrings(JSON, "source",       Path, out var sources, out Error) ||
                !TryReadOptionalStrings(JSON, "localAddress", Path, out var locals,  out Error) ||
                !TryReadOptionalStrings(JSON, "authMethod",   Path, out var methods, out Error))
                return false;

            return TryCreate(action, principal, service, sources, locals, methods, comment, Path, out Rule, out Error);

        }

        #endregion

        #region (static) TryParseLine(Text, out Rule, out Error)

        /// <summary>
        /// A rule as the command line writes it: the action, then name=value pairs, then # and a comment -
        /// <c>deny principal=account:* service=shell source=10.0.0.0/8,192.168.1.0/24 local=10.10.0.1 auth=password # why</c>.
        /// </summary>
        public static Boolean TryParseLine(String                                   Text,
                                           [NotNullWhen(true)]  out SSHAccessRule?  Rule,
                                           [NotNullWhen(false)] out String?         Error)

            => TryParseLine(Text, "rule", out Rule, out Error);

        /// <summary>
        /// A rule as the command line writes it, its errors said as at the given place.
        /// </summary>
        public static Boolean TryParseLine(String                                   Text,
                                           String                                   Path,
                                           [NotNullWhen(true)]  out SSHAccessRule?  Rule,
                                           [NotNullWhen(false)] out String?         Error)
        {

            Rule = null;

            var hash     = Text.IndexOf('#');
            var comment  = hash >= 0 ? Text[(hash + 1)..].Trim() : null;
            var words    = (hash >= 0 ? Text[..hash] : Text).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (words.Length == 0 || !TryParseAction(words[0], out var action))
            {
                Error = $"'{Path}' begins with allow or deny, not '{(words.Length == 0 ? "" : words[0])}'.";
                return false;
            }

            String? principal = null, service = null;
            IReadOnlyList<String>? sources = null, locals = null, methods = null;

            foreach (var word in words[1..])
            {

                var equals = word.IndexOf('=');

                if (equals <= 0)
                {
                    Error = $"'{Path}': '{word}' is no name=value: principal=, service=, source=, local= or auth=.";
                    return false;
                }

                var value = word[(equals + 1)..];
                var list  = (IReadOnlyList<String>) value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                switch (word[..equals].ToLowerInvariant())
                {
                    case "principal":  principal = value;  break;
                    case "service":    service   = value;  break;
                    case "source":     sources   = list;   break;
                    case "local":      locals    = list;   break;
                    case "auth":       methods   = list;   break;
                    default:
                        Error = $"'{Path}': '{word[..equals]}' is no condition of a rule: principal=, service=, source=, local= or auth=.";
                        return false;
                }

            }

            return TryCreate(action, principal, service, sources, locals, methods, comment is { Length: > 0 } ? comment : null, Path, out Rule, out Error);

        }

        #endregion


        #region AppliesTo(Service)

        /// <summary>
        /// Whether the rule's service condition matches the given service - which a rule without one does
        /// for every service.
        /// </summary>
        public Boolean AppliesTo(String Service)

            => this.Service is null ||
               (this.Service.StartsWith("subsystem:", StringComparison.Ordinal)
                    ? Service.StartsWith("subsystem:", StringComparison.Ordinal) && Glob(this.Service["subsystem:".Length..], Service["subsystem:".Length..], StringComparison.Ordinal)
                    : this.Service == Service);

        #endregion

        #region MatchesWhoAndWhere(Request)

        /// <summary>
        /// Whether everything but the service matches: who, from where, to where, how they signed in.
        /// </summary>
        public Boolean MatchesWhoAndWhere(SSHAccessRequest Request)
        {

            if (Principal is not null && !PrincipalMatches(Principal, Request.Principal))
                return false;

            if (AuthMethodsOf is not null && !AuthMethodsOf.Contains(Request.AuthMethod, StringComparer.OrdinalIgnoreCase))
                return false;

            return AddressMatches(sources, Request.Source) &&
                   AddressMatches(locals,  Request.Local);

        }

        /// <summary>
        /// Whether an address is among the given networks. An address that is not known matches a rule that
        /// denies and none that allows.
        /// </summary>
        private Boolean AddressMatches(IReadOnlyList<IpCidr>?  Networks,
                                       IPAddress?              Address)
        {

            if (Networks is null)
                return true;

            if (Address is null)
                return Action == SSHAccessAction.Deny;

            var address = Address.IsIPv4MappedToIPv6
                              ? Address.MapToIPv4()
                              : Address;

            return Networks.Any(network => network.Contains(address));

        }

        private static Boolean PrincipalMatches(String        Pattern,
                                                SSHPrincipal  Principal)
        {

            var colon  = Pattern.IndexOf(':');
            var kind   = Pattern[..colon];
            var name   = Pattern[(colon + 1)..];

            return kind == "group"
                       ? Principal.Groups.Any(group => Glob(name, group, StringComparison.OrdinalIgnoreCase))
                       : String.Equals(kind, Principal.Kind, StringComparison.OrdinalIgnoreCase) &&
                         Glob(name, Principal.Name, StringComparison.OrdinalIgnoreCase);

        }

        #endregion


        #region ToJSON()

        /// <summary>
        /// The rule as the configuration file writes it.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject { ["action"] = Action == SSHAccessAction.Allow ? "allow" : "deny" };

            if (Principal      is not null)  json["principal"]     = Principal;
            if (Service        is not null)  json["service"]       = Service;
            if (Sources        is not null)  json["source"]        = new JArray(Sources);
            if (LocalAddresses is not null)  json["localAddress"]  = new JArray(LocalAddresses);
            if (AuthMethodsOf  is not null)  json["authMethod"]    = new JArray(AuthMethodsOf);
            if (Comment        is not null)  json["comment"]       = Comment;

            return json;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// The rule as the command line writes it.
        /// </summary>
        public override String ToString()

            => String.Join(" ", new[] {
                   Action == SSHAccessAction.Allow ? "allow" : "deny",
                   Principal      is not null ? $"principal={Principal}"                    : null,
                   Service        is not null ? $"service={Service}"                        : null,
                   Sources        is not null ? $"source={String.Join(",", Sources)}"       : null,
                   LocalAddresses is not null ? $"local={String.Join(",", LocalAddresses)}" : null,
                   AuthMethodsOf  is not null ? $"auth={String.Join(",", AuthMethodsOf)}"   : null,
                   Comment        is not null ? $"# {Comment}"                              : null
               }.Where(part => part is not null));

        #endregion


        #region (private static) helpers

        private static Boolean TryParseAction(String? Text, out SSHAccessAction Action)
        {
            switch (Text?.Trim().ToLowerInvariant())
            {
                case "allow":  Action = SSHAccessAction.Allow;  return true;
                case "deny":   Action = SSHAccessAction.Deny;   return true;
                default:       Action = default;                return false;
            }
        }

        /// <summary>
        /// Networks written as a bare address or a CIDR whose host bits are zero: "10.0.0.1/8" is refused,
        /// as whoever wrote it meant either 10.0.0.1 or 10.0.0.0/8, and the rule cannot know which.
        /// </summary>
        private static Boolean TryParseAddresses(IReadOnlyList<String>?                Texts,
                                                 String                                Path,
                                                 out IReadOnlyList<IpCidr>?            Networks,
                                                 [NotNullWhen(false)] out String?      Error)
        {

            Networks = null;
            Error    = null;

            if (Texts is null)
                return true;

            if (Texts.Count == 0)
            {
                Error = $"'{Path}' names no address: leave it out for every address.";
                return false;
            }

            if (Texts.Count > MaxAddresses)
            {
                Error = $"'{Path}' may name at most {MaxAddresses} addresses or networks.";
                return false;
            }

            var networks = new List<IpCidr>();

            foreach (var text in Texts)
            {

                var slash   = text.IndexOf('/');
                var address = slash < 0 ? text : text[..slash];

                if (!IPAddress.TryParse(address, out var parsed) ||
                    parsed.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
                    (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.ScopeId != 0) ||
                    address.Contains('%'))
                {
                    Error = $"'{Path}': '{text}' is no IP address or network.";
                    return false;
                }

                var bits = parsed.GetAddressBytes().Length * 8;

                if (slash >= 0 && (!Int32.TryParse(text[(slash + 1)..], out var prefix) || prefix < 0 || prefix > bits || text[(slash + 1)..].Any(c => !Char.IsAsciiDigit(c))))
                {
                    Error = $"'{Path}': '{text}' has no prefix length between 0 and {bits}.";
                    return false;
                }

                // IpCidr.Parse zeroes host bits without a word; a rule must not.
                if (slash >= 0 && !IsNetworkAddress(parsed, Int32.Parse(text[(slash + 1)..])))
                {
                    Error = $"'{Path}': '{text}' is no network - its host bits are not zero. Write the address alone, or the network it is in.";
                    return false;
                }

                // An IPv4-mapped address is written as the IPv4 address it is, as a client's is compared.
                networks.Add(parsed.IsIPv4MappedToIPv6 && slash < 0
                                 ? IpCidr.Parse(parsed.MapToIPv4().ToString())
                                 : IpCidr.Parse(text));

            }

            Networks = networks;
            return true;

        }

        private static Boolean IsNetworkAddress(IPAddress Address, Int32 Prefix)
        {

            var bytes = Address.GetAddressBytes();

            for (var bit = Prefix; bit < bytes.Length * 8; bit++)
                if ((bytes[bit / 8] & (0x80 >> (bit % 8))) != 0)
                    return false;

            return true;

        }

        private static Boolean TryReadOptionalString(JObject                           JSON,
                                                     String                            Name,
                                                     String                            Path,
                                                     out String?                       Value,
                                                     [NotNullWhen(false)] out String?  Error)
        {

            Value = null;
            Error = null;

            if (!JSON.TryGetValue(Name, out var token) || token.Type == JTokenType.Null)
                return true;

            if (token.Type != JTokenType.String || token.Value<String>()?.Trim() is not { Length: > 0 } text)
            {
                Error = $"'{Path}.{Name}' must be a string that is not empty.";
                return false;
            }

            Value = text;
            return true;

        }

        private static Boolean TryReadOptionalStrings(JObject                           JSON,
                                                      String                            Name,
                                                      String                            Path,
                                                      out IReadOnlyList<String>?        Value,
                                                      [NotNullWhen(false)] out String?  Error)
        {

            Value = null;
            Error = null;

            if (!JSON.TryGetValue(Name, out var token) || token.Type == JTokenType.Null)
                return true;

            // One value may be written without the array.
            if (token.Type == JTokenType.String)
                token = new JArray(token);

            if (token is not JArray array || array.Any(item => item.Type != JTokenType.String || item.Value<String>()?.Trim() is not { Length: > 0 }))
            {
                Error = $"'{Path}.{Name}' must be a string, or an array of strings that are not empty.";
                return false;
            }

            Value = [ .. array.Select(item => item.Value<String>()!.Trim()) ];
            return true;

        }

        private static Boolean IsName(String Text)
            => Text.Length is > 0 and <= 32 && Text.All(c => Char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

        private static Boolean IsPattern(String Text)
            => Text.Length is > 0 and <= 256 && !Text.Any(c => Char.IsWhiteSpace(c) || Char.IsControl(c));

        /// <summary>
        /// * for any run of characters, ? for any one.
        /// </summary>
        internal static Boolean Glob(String            Pattern,
                                     String            Text,
                                     StringComparison  Comparison)
        {

            Int32 p = 0, t = 0, star = -1, mark = 0;

            while (t < Text.Length)
            {
                if (p < Pattern.Length && (Pattern[p] == '?' || String.Compare(Pattern, p, Text, t, 1, Comparison) == 0) && Pattern[p] != '*')
                {
                    p++; t++;
                }
                else if (p < Pattern.Length && Pattern[p] == '*')
                {
                    star = p++; mark = t;
                }
                else if (star >= 0)
                {
                    p = star + 1; t = ++mark;
                }
                else
                    return false;
            }

            while (p < Pattern.Length && Pattern[p] == '*')
                p++;

            return p == Pattern.Length;

        }

        #endregion

    }


    /// <summary>
    /// The SSH access rules of a node, in order: the first that matches decides. They can only restrict:
    /// what the node lets in anyway - its accounts, their roles and keys - is what a rule that allows lets
    /// on, and a rule that denies refuses. Where no rule matches, that alone decides.
    /// </summary>
    public sealed class SSHAccessRules
    {

        #region Data

        /// <summary>
        /// The most rules a node keeps.
        /// </summary>
        public const Int32 MaxRules = 256;

        /// <summary>
        /// No rules: what the node lets in anyway decides alone.
        /// </summary>
        public static SSHAccessRules None { get; } = new ([]);

        #endregion

        #region Properties

        /// <summary>
        /// The rules, in the order they are asked.
        /// </summary>
        public IReadOnlyList<SSHAccessRule> Rules { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The given rules, in the given order.
        /// </summary>
        public SSHAccessRules(IReadOnlyList<SSHAccessRule> Rules)
        {
            this.Rules = Rules;
        }

        #endregion


        #region ForSignIn(Request)

        /// <summary>
        /// Whether a client that has just signed in may come in at all. A rule without a service decides,
        /// where it is the first that matches. A matching rule with a service ends the asking and lets the
        /// client in: what it may use is asked again for every service, and a rule that would refuse it
        /// every one of them still does so there.
        /// </summary>
        /// <remarks>
        /// So "allow principal=station:* service=subsystem:ocpp@open.charging.cloud", then
        /// "deny principal=station:*", lets a station in, and then OCPP alone - rather than refusing it at
        /// the door because the second rule names no service.
        /// </remarks>
        public SSHAccessDecision ForSignIn(SSHAccessRequest Request)
        {

            for (var index = 0; index < Rules.Count; index++)
            {

                var rule = Rules[index];

                if (!rule.MatchesWhoAndWhere(Request))
                    continue;

                if (rule.Service is not null)
                    return new SSHAccessDecision(true, index + 1, rule);

                return new SSHAccessDecision(rule.Action == SSHAccessAction.Allow, index + 1, rule);

            }

            return SSHAccessDecision.NoRule;

        }

        #endregion

        #region For(Request)

        /// <summary>
        /// Whether the given service may be used: the first rule that applies to it and matches decides.
        /// </summary>
        public SSHAccessDecision For(SSHAccessRequest Request)
        {

            if (Request.Service is not String service)
                return ForSignIn(Request);

            for (var index = 0; index < Rules.Count; index++)
            {

                var rule = Rules[index];

                if (rule.AppliesTo(service) && rule.MatchesWhoAndWhere(Request))
                    return new SSHAccessDecision(rule.Action == SSHAccessAction.Allow, index + 1, rule);

            }

            return SSHAccessDecision.NoRule;

        }

        #endregion


        #region (static) TryParse(JSON, Path, out Rules, out Error)

        /// <summary>
        /// The rules as the configuration file writes them: an array of rule objects - or of rules as the
        /// command line writes them, one string each, which is what the web page sends.
        /// </summary>
        public static Boolean TryParse(JToken                                    JSON,
                                       String                                    Path,
                                       [NotNullWhen(true)]  out SSHAccessRules?  Rules,
                                       [NotNullWhen(false)] out String?          Error)
        {

            Rules = null;

            if (JSON is not JArray array)
            {
                Error = $"'{Path}' must be an array of rules.";
                return false;
            }

            if (array.Count > MaxRules)
            {
                Error = $"'{Path}' may hold at most {MaxRules} rules.";
                return false;
            }

            var rules = new List<SSHAccessRule>();

            for (var index = 0; index < array.Count; index++)
            {

                SSHAccessRule? rule;

                if (array[index] is JValue { Type: JTokenType.String } line)
                {
                    if (!SSHAccessRule.TryParseLine(line.Value<String>() ?? "", $"{Path}[{index}]", out rule, out Error))
                        return false;
                }

                else if (array[index] is JObject json)
                {
                    if (!SSHAccessRule.TryParse(json, $"{Path}[{index}]", out rule, out Error))
                        return false;
                }

                else
                {
                    Error = $"'{Path}[{index}]' must be a rule: an object, or a line as the command line writes it.";
                    return false;
                }

                rules.Add(rule);

            }

            Rules = new SSHAccessRules(rules);
            Error = null;
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The rules as the configuration file writes them.
        /// </summary>
        public JArray ToJSON()
            => new (Rules.Select(rule => rule.ToJSON()));

        #endregion

    }

}
