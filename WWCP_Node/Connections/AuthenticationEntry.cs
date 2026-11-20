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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Connections
{

    /// <summary>
    /// Which of the ways of proving who this node is a set of credentials is
    /// for.
    /// </summary>
    public enum AuthenticationKind
    {

        /// <summary>
        /// HTTP Basic: a name and a password, sent on every request.
        /// </summary>
        Basic,

        /// <summary>
        /// HTTP TOTP: a name and a secret that never travels, from which a
        /// password good for the next half minute is worked out at each
        /// connection.
        /// </summary>
        TOTP,

        /// <summary>
        /// HTTP Token: a token and nothing else, sent on every request.
        /// </summary>
        Token

    }


    /// <summary>
    /// One set of credentials this node can prove itself with, and what
    /// somebody meant it for.
    /// </summary>
    /// <remarks>
    /// The credentials themselves are an HTTP authentication of Hermod's -
    /// HTTP Basic, HTTP TOTP with its configuration, or HTTP Token - and this
    /// entry is what is written down beside them: what they are called here,
    /// what they are for and when they were written down.
    ///
    /// The description is the point of having several. A station in a fleet
    /// frequently has one login for the back end and another for the local
    /// controller in the same cabinet, and the two are not interchangeable -
    /// so whoever configured them writes down which is which, and whoever
    /// reads the page a year later does not have to guess from a URL.
    ///
    /// <b>The secret half never leaves this node.</b> The password, the shared
    /// secret and the token are written into a file only their owner may read,
    /// and <see cref="ToJSON"/> leaves them out unless it is being asked for the
    /// file itself. The web interface is told whether a secret is set, never
    /// what it is - the same rule the private keys next door live under, and
    /// for the same reason: a secret that can be read back out of a page is a
    /// secret anybody who ever borrows that page has.
    /// </remarks>
    public sealed class AuthenticationEntry
    {

        #region Data

        /// <summary>
        /// The longest a description may be written.
        /// </summary>
        public const Int32   MaxDescriptionLength   = 120;

        /// <summary>
        /// The longest a login may be written.
        /// </summary>
        public const Int32   MaxLoginLength         = 200;

        /// <summary>
        /// The shortest a TOTP shared secret may be.
        /// </summary>
        /// <remarks>
        /// Hermod's generator refuses anything shorter, so refusing it here as
        /// well turns an exception at the first connection into a sentence on
        /// the page while somebody is still looking at it.
        /// </remarks>
        public const Int32   MinSharedSecretLength  = 16;

        /// <summary>
        /// The longest a shared secret may be written.
        /// </summary>
        public const Int32   MaxSharedSecretLength  = 512;

        /// <summary>
        /// The longest a password may be written.
        /// </summary>
        public const Int32   MaxPasswordLength      = 512;

        /// <summary>
        /// The longest a token may be written.
        /// </summary>
        public const Int32   MaxTokenLength         = 512;

        /// <summary>
        /// How long one time-based password is good for, when nothing says
        /// otherwise - the same half minute Hermod's generator assumes.
        /// </summary>
        public static readonly TimeSpan DefaultValidity = TimeSpan.FromSeconds(30);

        /// <summary>
        /// How many characters a time-based password has, when nothing says
        /// otherwise.
        /// </summary>
        public const UInt32  DefaultLength          = 12;

        /// <summary>
        /// The characters a time-based password is drawn from, when nothing
        /// says otherwise.
        /// </summary>
        public const String  DefaultAlphabet        = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        #endregion

        #region Properties

        /// <summary>
        /// What this set of credentials is called here.
        /// </summary>
        public String               Id                  { get; }

        /// <summary>
        /// What somebody wrote down that it is for, e.g. "CSMS login" - in as
        /// many languages as it is said in.
        /// </summary>
        public I18NString           Description         { get; internal set; }

        /// <summary>
        /// The credentials themselves: an HTTP Basic, an HTTP TOTP - with the
        /// TOTP configuration to work a password out from - or an HTTP Token
        /// authentication.
        /// </summary>
        public IHTTPAuthentication  Authentication      { get; internal set; }

        /// <summary>
        /// When this was written down.
        /// </summary>
        public DateTimeOffset       CreatedAt           { get; }

        /// <summary>
        /// When these credentials were last changed, or when they were written
        /// down where they never were.
        /// </summary>
        public DateTimeOffset       LastChangeAt        { get; internal set; }


        /// <summary>
        /// Which of the ways of proving it this is.
        /// </summary>
        public AuthenticationKind   Kind

            => Authentication switch {
                   HTTPTOTPAuthentication   => AuthenticationKind.TOTP,
                   HTTPTokenAuthentication  => AuthenticationKind.Token,
                   _                        => AuthenticationKind.Basic
               };

        /// <summary>
        /// The name the other end knows this node by, or null for a token,
        /// which names nobody.
        /// </summary>
        /// <remarks>
        /// A login and not a user name: it names a role - a charging station,
        /// a service - and nothing about it implies a natural person. Hermod's
        /// TOTP scheme says so in as many words, and HTTP Basic is used the
        /// same way here.
        /// </remarks>
        public String?              Login

            => Authentication switch {
                   HTTPBasicAuthentication  basic  => basic.Username,
                   HTTPTOTPAuthentication   totp   => totp. Login,
                   _                               => null
               };

        /// <summary>
        /// The password, for HTTP Basic. Null otherwise, and left out of
        /// everything this node hands to a web interface.
        /// </summary>
        public String?              Password

            => (Authentication as HTTPBasicAuthentication)?.Password;

        /// <summary>
        /// The TOTP configuration, for HTTP TOTP: the shared secret and how a
        /// password is worked out from it. Null otherwise.
        /// </summary>
        public TOTPConfig?          TOTPConfig

            => (Authentication as HTTPTOTPAuthentication)?.TOTPConfig;

        /// <summary>
        /// The shared secret, for TOTP. Never sent anywhere - a time-based
        /// password is worked out from it and that is what travels.
        /// </summary>
        public String?              SharedSecret        => TOTPConfig?.SharedSecret;

        /// <summary>
        /// How long one time-based password is good for. Null means the
        /// default.
        /// </summary>
        public TimeSpan?            Validity            => TOTPConfig?.ValidityTime;

        /// <summary>
        /// How many characters it has. Null means the default.
        /// </summary>
        public UInt32?              Length              => TOTPConfig?.Length;

        /// <summary>
        /// Which characters it is drawn from. Null means the default.
        /// </summary>
        public String?              Alphabet            => TOTPConfig?.Alphabet;

        /// <summary>
        /// Which HMAC the password is derived with. Null means HMAC-SHA256,
        /// which is what both ends assume.
        /// </summary>
        public TOTPHashAlgorithm?   HashAlgorithm       => TOTPConfig?.HashAlgorithm;

        /// <summary>
        /// Whether the password is bound to the TLS session it is sent over.
        /// </summary>
        /// <remarks>
        /// False by default, because true can be done on some connections
        /// only. Binding needs keying material exported from the TLS session.
        /// The TLS of QUIC exports it, so a connection that names HTTP/3 and
        /// nothing else binds its password; .NET's SslStream, which is the
        /// node's TLS over HTTP/1.1 and HTTP/2, exports none. A connection of
        /// those whose credentials ask for the binding - one left the choice
        /// of the version among them - is not connected at all, and says why:
        /// sending the password unbound instead would be less than what was
        /// configured, quietly.
        ///
        /// A bound password is the better choice where it can be had: it is
        /// no use to anybody who copies it off one connection and tries it on
        /// another.
        /// </remarks>
        public Boolean              TLSChannelBinding   => TOTPConfig?.TLSChannelBinding == true;

        /// <summary>
        /// The token, for HTTP Token. Null otherwise, and left out of
        /// everything this node hands to a web interface.
        /// </summary>
        public String?              Token

            => (Authentication as HTTPTokenAuthentication)?.Token;

        /// <summary>
        /// Whether the secret half is set at all.
        /// </summary>
        /// <remarks>
        /// What the web interface is told in place of the secret itself, so
        /// that a page can show the difference between "not configured yet"
        /// and "configured, and you are not being shown it".
        /// </remarks>
        public Boolean              HasSecret

            => Kind switch {
                   AuthenticationKind.TOTP   => !String.IsNullOrEmpty(SharedSecret),
                   AuthenticationKind.Token  => !String.IsNullOrEmpty(Token),
                   _                         => !String.IsNullOrEmpty(Password)
               };

        #endregion

        #region Constructor(s)

        /// <summary>
        /// One set of credentials.
        /// </summary>
        /// <param name="Id">What the credentials are called here.</param>
        /// <param name="Description">What somebody wrote down that they are for.</param>
        /// <param name="Authentication">The credentials themselves.</param>
        /// <param name="CreatedAt">When they were written down.</param>
        /// <param name="LastChangeAt">When they were last changed; when they were written down, where left out.</param>
        public AuthenticationEntry(String               Id,
                                   I18NString           Description,
                                   IHTTPAuthentication  Authentication,
                                   DateTimeOffset       CreatedAt,
                                   DateTimeOffset?      LastChangeAt   = null)
        {

            this.Id              = Id;
            this.Description     = Description;
            this.Authentication  = Authentication;
            this.CreatedAt       = CreatedAt;
            this.LastChangeAt    = LastChangeAt ?? CreatedAt;

        }

        #endregion


        #region (static) Written(Text)

        /// <summary>
        /// When a record says it was written down, or now.
        /// </summary>
        /// <remarks>
        /// Read as text and parsed, rather than asked for as a timestamp:
        /// Newtonsoft turns an ISO 8601 string into a DateTime token and then
        /// refuses to hand it over as a DateTimeOffset, which is an
        /// InvalidCastException out of the middle of reading a file - and a
        /// file that cannot be read is a station that comes back without its
        /// credentials.
        /// </remarks>
        public static DateTimeOffset Written(String? Text)

            => DateTimeOffset.TryParse(Text,
                                       System.Globalization.CultureInfo.InvariantCulture,
                                       System.Globalization.DateTimeStyles.AdjustToUniversal |
                                       System.Globalization.DateTimeStyles.AssumeUniversal,
                                       out var when)
                   ? when
                   : DateTimeOffset.UtcNow;

        #endregion

        #region (static) ValidateDescription(Description, out Error)

        /// <summary>
        /// What can be wrong with the description of a set of credentials,
        /// whatever kind they are: it has to say something, in each language
        /// it is said in at most <see cref="MaxDescriptionLength"/> characters.
        /// </summary>
        public static Boolean ValidateDescription(I18NString?                       Description,
                                                  [NotNullWhen(false)] out String?  Error)

            => Descriptions.TryCheckRequired(
                   Description,
                   MaxDescriptionLength,
                   "Say what these credentials are for - that is what tells them apart later.",
                   out _,
                   out Error
               );

        #endregion

        #region (static) Kept(Description)

        /// <summary>
        /// A description as it is kept: its texts trimmed, those that say
        /// nothing left out. Asked after <see cref="ValidateDescription"/>.
        /// </summary>
        public static I18NString Kept(I18NString Description)

            => Descriptions.Normalized(Description) ?? Description;

        #endregion

        #region (static) ValidateBasic(Description, Login, Password, out Error)

        /// <summary>
        /// Everything that can be said to be wrong with HTTP Basic credentials
        /// before they are written down, in the words somebody typing them
        /// should read.
        /// </summary>
        /// <remarks>
        /// One place rather than two, because adding one and changing one have
        /// to agree about what is allowed - and a rule enforced on the way in
        /// but not on the way through an edit is not a rule.
        ///
        /// An empty password is allowed here and means "leave whatever is
        /// already there alone". Credentials that end up with no password at
        /// all are caught by the store, which is the only place that knows
        /// whether there was one before.
        /// </remarks>
        public static Boolean ValidateBasic(I18NString?                       Description,
                                            String?                           Login,
                                            String?                           Password,
                                            [NotNullWhen(false)] out String?  Error)
        {

            if (!ValidateDescription(Description, out Error) ||
                !ValidateLogin      (Login,       out Error))
            {
                return false;
            }

            if ((Password ?? "").Trim().Length > MaxPasswordLength)
            {
                Error = $"A password may be at most {MaxPasswordLength} characters.";
                return false;
            }

            return true;

        }

        #endregion

        #region (static) ValidateTOTP (Description, Login, SharedSecret, Alphabet, Length, out Error)

        /// <summary>
        /// Everything that can be said to be wrong with HTTP TOTP credentials
        /// before they are written down. An empty shared secret is allowed,
        /// see <see cref="ValidateBasic"/>.
        /// </summary>
        public static Boolean ValidateTOTP(I18NString?                       Description,
                                           String?                           Login,
                                           String?                           SharedSecret,
                                           String?                           Alphabet,
                                           UInt32?                           Length,
                                           [NotNullWhen(false)] out String?  Error)
        {

            if (!ValidateDescription(Description, out Error) ||
                !ValidateLogin      (Login,       out Error))
            {
                return false;
            }

            var secret = (SharedSecret ?? "").Trim();

            // The shared secret has rules of its own - Hermod's generator
            // throws on all of these, and throwing at the first connection is
            // far away from whoever typed it.
            if (secret.Length > 0)
            {

                if (secret.Length < MinSharedSecretLength)
                {
                    Error = $"A shared secret must be at least {MinSharedSecretLength} characters.";
                    return false;
                }

                if (secret.Length > MaxSharedSecretLength)
                {
                    Error = $"A shared secret may be at most {MaxSharedSecretLength} characters.";
                    return false;
                }

                if (secret.Any(Char.IsWhiteSpace))
                {
                    Error = "A shared secret may not contain spaces - both ends have to agree on it character for character.";
                    return false;
                }

            }

            if (Length is not null && (Length < 4 || Length > 64))
            {
                Error = "A time-based password has between 4 and 64 characters.";
                return false;
            }

            if (Alphabet is not null)
            {

                var alphabet = Alphabet.Trim();

                if (alphabet.Length > 0 && alphabet.Distinct().Count() < 2)
                {
                    Error = "An alphabet of fewer than two different characters makes the same password every time.";
                    return false;
                }

            }

            return true;

        }

        #endregion

        #region (static) ValidateToken(Description, Token, out Error)

        /// <summary>
        /// Everything that can be said to be wrong with HTTP Token credentials
        /// before they are written down. An empty token is allowed, see
        /// <see cref="ValidateBasic"/>.
        /// </summary>
        public static Boolean ValidateToken(I18NString?                       Description,
                                            String?                           Token,
                                            [NotNullWhen(false)] out String?  Error)
        {

            if (!ValidateDescription(Description, out Error))
                return false;

            var token = (Token ?? "").Trim();

            if (token.Length > MaxTokenLength)
            {
                Error = $"A token may be at most {MaxTokenLength} characters.";
                return false;
            }

            // "Authorization: Token <token>" ends at the first space.
            if (token.Any(Char.IsWhiteSpace))
            {
                Error = "A token may not contain spaces - it is sent as it is, in one piece.";
                return false;
            }

            return true;

        }

        #endregion

        #region (private static) ValidateLogin(Login, out Error)

        private static Boolean ValidateLogin(String?                           Login,
                                             [NotNullWhen(false)] out String?  Error,
                                             String?                           NodeNoun   = null)
        {

            var login = (Login ?? "").Trim();

            if (login.Length == 0)
            {
                Error = $"A login is needed: it is the name the other end knows this {NodeNoun ?? NodeWording.Noun} by.";
                return false;
            }

            if (login.Length > MaxLoginLength)
            {
                Error = $"A login may be at most {MaxLoginLength} characters.";
                return false;
            }

            Error = null;
            return true;

        }

        #endregion

        #region (static) TryParse(JSON, out Entry, out Error)

        /// <summary>
        /// One set of credentials as it stands in the file, or the one
        /// sentence that says what is wrong with it.
        /// </summary>
        public static Boolean TryParse(JObject                                        JSON,
                                       [NotNullWhen(true)]  out AuthenticationEntry?  Entry,
                                       [NotNullWhen(false)] out String?               Error,
                                       String?                                        NodeNoun   = null)
        {

            Entry = null;
            Error = null;

            var id = JSON.Value<String>("id")?.Trim();

            if (String.IsNullOrEmpty(id))
            {
                Error = "A set of credentials without an identification.";
                return false;
            }

            var kindText  = JSON.Value<String>("kind")?.Trim().ToLowerInvariant();
            var login     = JSON.Value<String>("login")?.Trim() ?? "";

            IHTTPAuthentication? authentication = null;

            switch (kindText)
            {

                // A password or a shared secret missing from the file is read
                // as none: a file edited by hand is a real thing, and these
                // credentials are then said to have no secret set rather than
                // the station refusing to start.
                case "basic":
                    if (HTTPBasicAuthentication.TryCreate(login,
                                                          JSON.Value<String>("password") ?? "",
                                                          out var basic))
                    {
                        authentication = basic;
                    }
                    break;

                case "totp":
                    if (HTTPTOTPAuthentication.TryCreate(login,
                                                         TOTPConfigOf(JSON.Value<String>("sharedSecret") ?? "",
                                                                      JSON.Value<Double?>("validitySeconds"),
                                                                      JSON.Value<UInt32?>("length"),
                                                                      JSON.Value<String>("alphabet"),
                                                                      JSON.Value<String>("hashAlgorithm"),
                                                                      JSON.Value<Boolean?>("tlsChannelBinding") ?? false),
                                                         out var totp))
                    {
                        authentication = totp;
                    }
                    break;

                case "token":
                    if (HTTPTokenAuthentication.TryCreate(JSON.Value<String>("token") ?? "",
                                                          out var token))
                    {
                        authentication = token;
                    }
                    break;

                default:
                    Error = $"'{kindText}' is not a kind of authentication this {NodeNoun ?? NodeWording.Noun} knows.";
                    return false;

            }

            if (authentication is null)
            {
                Error = $"The credentials '{id}' have no {(kindText == "token" ? "token" : "login")}.";
                return false;
            }

            var createdAt = Written(JSON.Value<String>("createdAt"));

            Entry = new AuthenticationEntry(
                        id,
                        JSON["description"] is JObject descriptionJSON &&
                        I18NString.TryParse(descriptionJSON, out I18NString? description, out _)
                            ? description
                            : I18NString.Empty,
                        authentication,
                        createdAt,
                        JSON.Value<String>("lastChangeAt") is String lastChangeAt
                            ? Written(lastChangeAt)
                            : createdAt
                    );

            return true;

        }

        #endregion

        #region (static) TOTPConfigOf(SharedSecret, ValiditySeconds, Length, Alphabet, HashAlgorithm, TLSChannelBinding)

        /// <summary>
        /// The TOTP configuration of a shared secret and how a password is to
        /// be worked out from it, as they are typed or written down: a validity
        /// of no seconds and an alphabet of nothing are the defaults, and so is
        /// a hash algorithm this node does not know.
        /// </summary>
        public static TOTPConfig TOTPConfigOf(String    SharedSecret,
                                              Double?   ValiditySeconds,
                                              UInt32?   Length,
                                              String?   Alphabet,
                                              String?   HashAlgorithm,
                                              Boolean   TLSChannelBinding)

            => new (
                   SharedSecret.Trim(),
                   ValiditySeconds is Double seconds && seconds > 0
                       ? TimeSpan.FromSeconds(seconds)
                       : null,
                   Length,
                   String.IsNullOrWhiteSpace(Alphabet)
                       ? null
                       : Alphabet.Trim(),
                   HashAlgorithm?.Trim().ToUpperInvariant() switch {
                       "SHA256"  => TOTPHashAlgorithm.SHA256,
                       "SHA384"  => TOTPHashAlgorithm.SHA384,
                       "SHA512"  => TOTPHashAlgorithm.SHA512,
                       _         => null
                   },
                   TLSChannelBinding
               );

        #endregion

        #region ToJSON(IncludeSecrets = false)

        /// <summary>
        /// What this set of credentials looks like from outside.
        /// </summary>
        /// <param name="IncludeSecrets">
        /// True only for the file on disk. The web interface never gets this
        /// set, which is why it is a parameter with a safe default rather than
        /// two nearly identical methods somebody picks the wrong one of.
        /// </param>
        public JObject ToJSON(Boolean IncludeSecrets = false)
        {

            var json = new JObject(
                           new JProperty("id",            Id),
                           new JProperty("description",   Description.ToJSON()),
                           new JProperty("kind",          Kind switch {
                                                              AuthenticationKind.TOTP   => "totp",
                                                              AuthenticationKind.Token  => "token",
                                                              _                         => "basic"
                                                          }),
                           new JProperty("createdAt",     CreatedAt.   UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                           new JProperty("lastChangeAt",  LastChangeAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                           new JProperty("hasSecret",     HasSecret)
                       );

            if (Login is not null)
                json.Add(new JProperty("login", Login));

            if (TOTPConfig is TOTPConfig totp)
            {

                json.Add(new JProperty("tlsChannelBinding",  TLSChannelBinding));

                // The parameters of a time-based password are not secret -
                // both ends have to agree on them, and somebody comparing two
                // configurations needs to see them. Only the secret is left
                // out.
                if (totp.ValidityTime  is not null)  json.Add(new JProperty("validitySeconds",  totp.ValidityTime.Value.TotalSeconds));
                if (totp.Length        is not null)  json.Add(new JProperty("length",           totp.Length.Value));
                if (totp.Alphabet      is not null)  json.Add(new JProperty("alphabet",         totp.Alphabet));
                if (totp.HashAlgorithm is not null)  json.Add(new JProperty("hashAlgorithm",    totp.HashAlgorithm.Value.ToString()));

            }

            if (IncludeSecrets)
            {
                if (Password     is not null)  json.Add(new JProperty("password",      Password));
                if (SharedSecret is not null)  json.Add(new JProperty("sharedSecret",  SharedSecret));
                if (Token        is not null)  json.Add(new JProperty("token",         Token));
            }

            return json;

        }

        #endregion

        #region ToBasicAuthentication() / ToTOTPConfig() / ToTokenAuthentication()

        /// <summary>
        /// These credentials as an HTTP Basic authentication, or null when
        /// they are not that kind or have no password.
        /// </summary>
        public HTTPBasicAuthentication? ToBasicAuthentication()

            => Authentication is HTTPBasicAuthentication { Password.Length: > 0 } basic
                   ? basic
                   : null;

        /// <summary>
        /// These credentials as a TOTP configuration, or null when they are
        /// not that kind or have no shared secret.
        /// </summary>
        /// <remarks>
        /// What the HTTP client is handed: it works out a password from this
        /// at each connection, rather than being given one that was already
        /// stale when it was written down.
        /// </remarks>
        public TOTPConfig? ToTOTPConfig()

            => TOTPConfig is { SharedSecret.Length: > 0 } totp
                   ? totp
                   : null;

        /// <summary>
        /// These credentials as an HTTP Token authentication, or null when
        /// they are not that kind.
        /// </summary>
        public HTTPTokenAuthentication? ToTokenAuthentication()

            => Authentication as HTTPTokenAuthentication;

        #endregion

        #region (internal) Copy()

        /// <summary>
        /// These credentials as they are now, in an entry of their own: what
        /// the store puts back where a change of them could not be written.
        /// </summary>
        public AuthenticationEntry Copy()

            => (AuthenticationEntry) MemberwiseClone();

        #endregion

        #region (override) ToString()

        public override String ToString()

            => Kind switch {
                   AuthenticationKind.TOTP   => $"{Description.FirstText()} (HTTP TOTP, '{Login}')",
                   AuthenticationKind.Token  => $"{Description.FirstText()} (HTTP Token)",
                   _                         => $"{Description.FirstText()} (HTTP Basic, '{Login}')"
               } +
               (HasSecret ? "" : ", no secret yet");

        #endregion

    }

}
