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

using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

using cloud.charging.open.protocols.WWCP.WebSockets;
using cloud.charging.open.protocols.WWCP.NetworkingNode;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Connections;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Logins
{

    /// <summary>
    /// Who comes in at a WebSocket port of a node, by its WebSocket login: the
    /// door of the port, as <see cref="LoginSSHSignIns"/> is the door of the
    /// SSH server.
    /// </summary>
    /// <remarks>
    /// <b>Every way in, decided in one place.</b> A TLS client certificate -
    /// by its chain or by its key pin -, a password, a one-time password as
    /// the password, "Authorization: TOTP", and a one-time token in a header
    /// of its own; the node's sign-in brake before any of them; and, once a
    /// login is let in, whether it is a connection the other end makes or one
    /// of the others the kind lets in.
    ///
    /// <b>The kind says the rest.</b> Which ways its port allows, whether it
    /// speaks TLS, whether sign-ins are logged, which connection the other
    /// end makes comes under a name at which server, and what becomes of a
    /// login that is none: the kind hands that over, and these checks ask it
    /// whenever they need it - so a change of the port's settings is in
    /// effect at the next sign-in. What the checks call the port and who
    /// comes to it in what they say is the kind's as well - see
    /// <see cref="WebSocketSignInWords"/>.
    ///
    /// <b>Moved here from WWCP_OCPP_Node</b>, where it was the door of the
    /// station port of a local controller, a gateway and a CSMS, so that a
    /// node that serves no OCPP lets in what connects to it by the very same
    /// checks.
    /// </remarks>
    public sealed class WebSocketSignIns
    {

        #region Delegates

        /// <summary>
        /// Let in under the given WebSocket login what is no connection the
        /// other end makes - a charging station, at a node of OCPP - or say why
        /// not.
        /// </summary>
        /// <param name="Connection">The connection, before its 101 goes out.</param>
        /// <param name="Login">The WebSocket login it is let in under.</param>
        /// <param name="How">What it signed in with, in words: "a password".</param>
        /// <param name="Detail">The way it authenticated, and what that means: "security profile 2".</param>
        /// <param name="ByCertificate">The certificate it signed in with, where it did.</param>
        /// <returns>Null where it is let in; why not otherwise.</returns>
        public delegate String? LetInOthersDelegate(WebSocketServerConnection  Connection,
                                                    String                     Login,
                                                    String                     How,
                                                    String                     Detail,
                                                    X509Certificate2?          ByCertificate);

        #endregion

        #region Data

        private readonly EventLog                                                  log;
        private readonly Func<IEnumerable<WebSocketClientAuthentication>>          authentications;
        private readonly Func<Boolean>                                             overTLS;
        private readonly Func<Boolean>                                             checksRevocation;
        private readonly Func<Boolean>                                             saysSignIns;
        private readonly Func<AWebSocketEndpoint, String, ConnectionEntry?>        inboundConnectionOf;
        private readonly Action<IMessageConnection, ConnectionEntry>               letInAsInbound;
        private readonly LetInOthersDelegate                                       letInOthers;

        #endregion

        #region Properties

        /// <summary>
        /// Which logins may sign in, and with what.
        /// </summary>
        public WebSocketLogins       Logins         { get; }

        /// <summary>
        /// Which chains a client's own certificate may lead to.
        /// </summary>
        public ClientTrustStore      ClientTrust    { get; }

        /// <summary>
        /// The node's sign-in brake: an address that guessed wrong too often
        /// is told to wait.
        /// </summary>
        public SignInBrake           SignInBrake    { get; }

        /// <summary>
        /// What the port and who comes to it are called in what these checks
        /// say.
        /// </summary>
        public WebSocketSignInWords  Words          { get; }

        /// <summary>
        /// What the node calls itself: "local controller".
        /// </summary>
        public String                NodeNoun
            => Logins.NodeNoun;

        /// <summary>
        /// What the log says a sign-in at the port, its TLS handshake, and a
        /// sign-in of a connection the other end makes are about.
        /// </summary>
        private String[]             AuthTags
            => [ .. Words.Tags, "auth" ];

        private String[]             TLSTags
            => [ .. Words.Tags, "tls" ];

        private String[]             InboundAuthTags
            => [ .. Words.InboundTags, "auth" ];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The sign-in checks of a WebSocket port of a node.
        /// </summary>
        /// <param name="Logins">Which logins may sign in, and with what.</param>
        /// <param name="ClientTrust">Which chains a client's own certificate may lead to.</param>
        /// <param name="SignInBrake">The node's sign-in brake.</param>
        /// <param name="Log">The node's event log.</param>
        /// <param name="Authentications">The ways a client may authenticate at the port now.</param>
        /// <param name="OverTLS">Whether the port speaks TLS, as decided when it started.</param>
        /// <param name="ChecksRevocation">Whether a client certificate is checked for revocation now.</param>
        /// <param name="SaysSignIns">Whether who signs in, and who is turned away, is said in the log now.</param>
        /// <param name="InboundConnectionOf">The connection the other end makes that comes under the given name at the given server, or null.</param>
        /// <param name="LetInAsInbound">Take what came in over a connection as the given connection the other end makes.</param>
        /// <param name="LetInOthers">Let in a login that is no connection the other end makes, or say why not.</param>
        /// <param name="Words">What the port and who comes to it are called; generic words where null.</param>
        public WebSocketSignIns(WebSocketLogins                                     Logins,
                                ClientTrustStore                                    ClientTrust,
                                SignInBrake                                         SignInBrake,
                                EventLog                                            Log,
                                Func<IEnumerable<WebSocketClientAuthentication>>    Authentications,
                                Func<Boolean>                                       OverTLS,
                                Func<Boolean>                                       ChecksRevocation,
                                Func<Boolean>                                       SaysSignIns,
                                Func<AWebSocketEndpoint, String, ConnectionEntry?>  InboundConnectionOf,
                                Action<IMessageConnection, ConnectionEntry>         LetInAsInbound,
                                LetInOthersDelegate                                 LetInOthers,
                                WebSocketSignInWords?                               Words   = null)
        {

            this.Logins               = Logins;
            this.ClientTrust          = ClientTrust;
            this.SignInBrake          = SignInBrake;
            this.log                  = Log;
            this.authentications      = Authentications;
            this.overTLS              = OverTLS;
            this.checksRevocation     = ChecksRevocation;
            this.saysSignIns          = SaysSignIns;
            this.inboundConnectionOf  = InboundConnectionOf;
            this.letInAsInbound       = LetInAsInbound;
            this.letInOthers          = LetInOthers;
            this.Words                = Words ?? new WebSocketSignInWords();

        }

        #endregion


        #region Guard(Server)

        /// <summary>
        /// Put the given server behind this door: a certificate let in by its
        /// key pin is told to it, what asks for a WebSocket is decided by
        /// <see cref="Validate"/>, and the logins with a password are put into
        /// it.
        /// </summary>
        /// <remarks>
        /// The TLS handshake is the server's own, and asked when it is built:
        /// hand it <see cref="ValidateCertificate"/> as its client certificate
        /// validator, where it speaks TLS.
        ///
        /// A certificate let in by its key pin names nobody: the client is the
        /// one the pin is listed for, and its path has to say so - see
        /// <see cref="Validate"/>. Told to the server as well, or it would read
        /// the common name, register the connection under it, and turn a client
        /// whose certificate names another away with a 403.
        /// </remarks>
        /// <param name="Server">A WebSocket server of the port.</param>
        public void Guard(WWCPWebSocketServer Server)
        {

            Server.AcceptedByKeyPin               = AcceptedByKeyPin;

            Server.OnValidateWebSocketConnection += Validate;

            ApplyLogins(Server);

        }

        #endregion

        #region ApplyLogins(Server)

        /// <summary>
        /// Put the logins with a password into the server, and take out the
        /// ones that are no longer there.
        /// </summary>
        /// <remarks>
        /// Removed and not only added: a client whose password was taken away
        /// must stop being able to use it now, and a dictionary that is only
        /// ever added to would let it in until the next start.
        /// </remarks>
        /// <param name="Server">A WebSocket server of the port.</param>
        public void ApplyLogins(AWebSocketServer Server)
        {

            var wanted = Logins.SecurePasswords();

            foreach (var gone in Server.ClientLogins.Keys.Where(id => !wanted.ContainsKey(id)).ToArray())
                Server.ClientLogins.TryRemove(gone, out _);

            foreach (var login in wanted)
                Server.ClientLogins[login.Key] = login.Value;

        }

        #endregion

        #region AcceptedByKeyPin(Certificate)

        /// <summary>
        /// Whether the key of the given certificate is pinned for a WebSocket
        /// login - which then names the client, and not the certificate.
        /// </summary>
        /// <param name="Certificate">A client certificate of a TLS handshake.</param>
        public Boolean AcceptedByKeyPin(X509Certificate2 Certificate)

            => Logins.FindKeyPin(KeyPin.FromCertificate(Certificate)) is not null;

        #endregion

        #region ValidateCertificate(...)

        /// <summary>
        /// Whether the certificate a client presented during the TLS handshake
        /// leads to a chain this node accepts.
        /// </summary>
        /// <remarks>
        /// A client that presents no certificate is let through here and
        /// judged by <see cref="Validate"/>, which knows whether a password
        /// would do instead.
        ///
        /// A client that presents one this node does not accept is turned away
        /// here rather than allowed to fall back to a password: a client sends
        /// a certificate because it was configured to authenticate with one -
        /// OCPP's security profile 3 -, so it has no password to fall back to,
        /// and a certificate that does not check out is worth a line in the log
        /// rather than a quiet second attempt.
        ///
        /// <b>Or by its key pin.</b> A certificate whose key pin is listed for a
        /// login that is switched on is let through by that pin alone, and its
        /// chain, name and dates are not looked at - that is what a client
        /// without a certificate authority behind it relies on. Which login it
        /// is, and whether it may come in as the one it asks to be, is decided
        /// in <see cref="Validate"/>. Every other certificate is held against
        /// the accepted chains as before; a key pin of a login that is switched
        /// off opens nothing here.
        /// </remarks>
        public TLSValidationResult ValidateCertificate(Object                                                             Sender,
                                                       System.Security.Cryptography.X509Certificates.X509Certificate2?    Certificate,
                                                       System.Security.Cryptography.X509Certificates.X509Chain?           Chain,
                                                       org.GraphDefined.Vanaheimr.Hermod.TCP.ITCPServer                   Server,
                                                       System.Net.Security.SslPolicyErrors                                PolicyErrors)
        {

            if (Certificate is null)
                return new TLSValidationResult(IsValid: true, Errors: null, Warnings: null);

            #region By its key pin

            if (Logins.FindKeyPin(KeyPin.FromCertificate(Certificate)) is WebSocketLogin pinned &&
                pinned.Enabled)
            {

                // Hermod's validator rather than a comparison here: it also
                // refuses a key that cannot be one - a malformed key, an
                // unknown algorithm, a point that is not on its curve - before
                // any pin is compared (EVQI Transport, key pins, 10.7).
                var validation = KeyPinValidator.Validate(
                                     new KeyPinPolicy(pinned.Pins.Select(keyPin => keyPin.Pin)),
                                     Certificate
                                 );

                if (saysSignIns())
                    log.Log(
                        validation.IsAccepted ? LogLevel.Debug : LogLevel.Warning,
                        validation.IsAccepted
                            ? $"The certificate of '{Certificate.Subject}' was accepted by its key pin {validation.Pin}, which is {Words.PinnedLogin} '{pinned.Login}''s."
                            : $"The certificate of '{Certificate.Subject}' was refused: {validation.Reason}",
                        TLSTags
                    );

                return validation.IsAccepted
                           ? TLSValidationResult.Success()
                           : TLSValidationResult.Failed(validation.Reason ?? "The key was refused.");

            }

            #endregion

            var result = ClientTrust.Validate(
                             Certificate,
                             Chain,
                             checksRevocation()
                         );

            if (saysSignIns())
                log.Log(
                    result.Accepted ? LogLevel.Debug : LogLevel.Warning,
                    result.Accepted
                        ? $"The certificate of '{result.Subject}' was {result.Reason}."
                        : $"The certificate of '{result.Subject}' was refused: {result.Reason}.",
                    TLSTags
                );

            return new TLSValidationResult(
                       IsValid:   result.Accepted,
                       Errors:    result.Accepted ? null : [ Error.Create(result.Reason) ],
                       Warnings:  null
                   );

        }

        #endregion

        #region Validate(...)

        /// <summary>
        /// Whether what asks for a WebSocket at the port may come in - a client
        /// of the kind, or a connection the other end makes - by its WebSocket
        /// login: the ways the port allows and the login groups, decided in one
        /// place.
        /// </summary>
        /// <remarks>
        /// <b>One way to sign in.</b> A client of the kind and a back end whose
        /// connection the other end makes sign in alike, with a WebSocket
        /// login; the name decides afterwards which of the two it is - see
        /// LetIn below.
        ///
        /// <b>Three ways in, and each is checked twice.</b> A certificate, a
        /// password or a one-time token; and whichever it is, the port as a
        /// whole has to allow the way it arrives on, and the group the login
        /// belongs to has to allow both the way and the method. The group can
        /// only narrow what the port allows, never widen it.
        ///
        /// <b>A certificate first.</b> A client that authenticated with a
        /// certificate has already been checked against the accepted chains by
        /// the time this runs; it needs no password and is not asked for one.
        /// If it is also listed as a login, its group has its say - which is
        /// how a certificate client is put under the same rules as the rest.
        /// If it is not listed, the accepted chains are the whole of the
        /// decision, as they were before there were groups.
        ///
        /// <b>Then a password or a token</b>, which are the same question over
        /// the same transport: is this the credential this identification
        /// should be showing? What decides the way is whether the port is
        /// encrypted, and that was settled when the server started. TOTP is not
        /// a way of its own - in OCPP no security profile -, so it is judged
        /// under the way its transport would have had.
        ///
        /// A refusal says as little as it can to the client and as much as it
        /// can to the log. "Unauthorized" back over the wire; which
        /// identification it was, where it came from and what was wrong with it
        /// into the log, where somebody who is allowed to know may read it.
        /// </remarks>
        public Task<HTTPResponse?> Validate(DateTimeOffset             Timestamp,
                                            AWebSocketEndpoint         Server,
                                            WebSocketServerConnection  Connection,
                                            EventTracking_Id           EventTrackingId,
                                            CancellationToken          CancellationToken)
        {

            var allowed  = authentications().ToArray();
            var from     = Connection.RemoteSocket.ToString();
            var tls      = overTLS();

            #region An address that guessed too often is told to wait

            // Whatever it comes with now - but for a client certificate, which
            // is no guess.
            if (Connection.ClientCertificate is null &&
                SignInBrake.IsHeldBack(Connection.RemoteSocket.IPAddress.ToString()))
            {
                return TooManyGuesses(Server, Connection);
            }

            #endregion

            #region A TLS client certificate: it brought one

            if (Connection.ClientCertificate is not null)
            {

                if (!allowed.Contains(WebSocketClientAuthentication.TLSClientCertificate))
                    return Refuse(Connection, $"it authenticated with a certificate, and {Words.Authentication(WebSocketClientAuthentication.TLSClientCertificate)} is not allowed here");

                var keyPin = KeyPin.FromCertificate(Connection.ClientCertificate);

                #region By its key pin: the login the pin is listed for, on its own path, and nobody else

                // A certificate whose key pin is listed was let through the
                // handshake by the pin alone, and its chain, its name and its
                // dates were never looked at: anybody can wrap a key in a
                // certificate that says anything. So its common name names
                // nobody, and the login it is let in as is the one the pin is
                // listed for - only on that login's own path, the last segment
                // of the URL, which is what the CN check of OCPP's security
                // profile 3 is for a certificate (A00.FR.511).
                if (Logins.FindKeyPin(keyPin) is WebSocketLogin pinned)
                {

                    var path = NameOfPath(Connection.HTTPRequest);

                    if (path != pinned.Login.ToString())
                        return Refuse(Connection, $"its key pin {keyPin} is the WebSocket login '{pinned.Login}''s, and it asked to connect as " +
                                                  (path is null ? "nobody in particular" : $"'{path}'"));

                    if (!pinned.Enabled)
                        return Refuse(Connection, $"the WebSocket login '{pinned.Login}' is switched off here");

                    if (!GroupAllows(pinned, AuthMethod.KeyPin, WebSocketClientAuthentication.TLSClientCertificate, out var whyNot))
                        return Refuse(Connection, $"the WebSocket login '{pinned.Login}' {whyNot}");

                    return LetIn(pinned.Login.ToString(), $"its key pin {keyPin}", Words.Authentication(WebSocketClientAuthentication.TLSClientCertificate));

                }

                // Its pin was listed once and is no longer: the handshake may
                // have let it through by that pin, before the pin was taken
                // away - the client decides how long it waits between the two.
                // Such a certificate skipped the accepted chains, so it is held
                // against them now, rather than read as one that passed them.
                if (Logins.WasEverListed(keyPin) &&
                    !ClientTrust.Validate(Connection.ClientCertificate, null, checksRevocation()).Accepted)
                {
                    return Refuse(Connection, $"its key pin {keyPin} is no WebSocket login's any more, and its certificate does not lead to an accepted chain");
                }

                #endregion

                // The certificate itself was held against the accepted chains
                // during the handshake; a connection that got this far with one
                // has passed.
                var named  = Connection.ClientCertificate.GetNameInfo(X509NameType.SimpleName, false);
                var who    = named.IsNullOrEmpty() ? Connection.ClientCertificate.Subject : named;

                // Listed as a login as well? Then it is in a group, and the
                // group decides. Not listed is not an error: the chain was the
                // whole decision before groups existed and still is - for a
                // client of the kind, and for a back end that connects alike.
                if (!named.IsNullOrEmpty() &&
                    Logins.TryGet(WebSocketLogins.LoginOf(named), out var certificateLogin))
                {

                    if (!certificateLogin.Enabled)
                        return Refuse(Connection, $"the WebSocket login '{named}' is switched off here");

                    // Either by key pin or by certificate authority, never both
                    // (EVQI Transport, key pins, 5.4): a login listed with key
                    // pins is let in by them, and a certificate an authority
                    // issued to its name with another key is a key it was never
                    // given - the very thing a pin is there to refuse.
                    if (certificateLogin.HasKeyPin)
                        return Refuse(Connection, $"the WebSocket login '{named}' is let in by its key pins, and the key of this certificate is none of them");

                    if (!GroupAllows(certificateLogin, AuthMethod.Certificate, WebSocketClientAuthentication.TLSClientCertificate, out var why))
                        return Refuse(Connection, $"the WebSocket login '{named}' {why}");

                }

                return LetIn(who, "a certificate", Words.Authentication(WebSocketClientAuthentication.TLSClientCertificate), ByCertificate: Connection.ClientCertificate);

            }

            if (!allowed.Contains(WebSocketClientAuthentication.HTTPAuthWithoutTLS) &&
                !allowed.Contains(WebSocketClientAuthentication.HTTPAuthOverTLS))
            {
                return Refuse(Connection, $"only {Words.Authentication(WebSocketClientAuthentication.TLSClientCertificate)} is allowed here and it presented no certificate");
            }

            #endregion

            #region Which way a credential on this port would be

            var way = tls
                          ? WebSocketClientAuthentication.HTTPAuthOverTLS
                          : WebSocketClientAuthentication.HTTPAuthWithoutTLS;

            if (!allowed.Contains(way))
                return Refuse(
                           Connection,
                           tls
                               ? $"{Words.Port} is encrypted, so this would be {Words.Authentication(way)}, which is not allowed here"
                               : $"{Words.Port} is unencrypted, so this would be {Words.Authentication(way)}, which is not allowed here"
                       );

            #endregion

            #region A password

            if (Connection.HTTPRequest?.Authorization is HTTPBasicAuthentication basicAuthentication)
            {

                var id = basicAuthentication.Username;

                // Verified before the group is consulted, and always. The
                // store hashes a fixed word for an identification it does not
                // have, so that an unknown one does not answer faster than a
                // known one - and asking the group first would put that back:
                // a login in a group that forbids passwords would be refused
                // without the hashing, and the difference is measurable.
                var right   = Logins.Verify(WebSocketLogins.LoginOf(id), basicAuthentication.Password);
                var known   = Logins.TryGet(WebSocketLogins.LoginOf(id), out var login);
                var method  = AuthMethod.Basic;

                // What a client that knows nothing but Basic has of a TOTP
                // secret: the one-time password, as its password - where the
                // secret is not bound to the TLS session, which Basic can not
                // say. Checked as a one-time password, and held to the group as
                // one.
                if (!right && known && login!.HasTOTP && login.TOTP?.TLSChannelBinding != true &&
                    Logins.VerifyTOTP(WebSocketLogins.LoginOf(id), basicAuthentication.Password, false, null))
                {
                    right   = true;
                    method  = AuthMethod.TOTP;
                }

                if (!known || !login!.Enabled || !right)
                    return Refuse(Connection, $"'{id}' is no WebSocket login that may sign in, or the password is wrong");

                if (!GroupAllows(login, method, way, out var why))
                    return Refuse(Connection, $"the WebSocket login '{id}' {why}");

                return LetIn(id, method == AuthMethod.TOTP ? "a one-time password, as its password" : "a password",
                             Words.Authentication(way) +
                             (tls ? "" : ", on an unencrypted port, so what it signed in with crossed the network in the clear"));

            }

            #endregion

            #region A one-time token

            if (Connection.HTTPRequest?.Authorization is HTTPTOTPAuthentication totpAuthentication)
            {

                var id = totpAuthentication.Login;

                // "Authorization: TOTP" does not say whether its token is bound
                // to the TLS session: the login says it. A bound one is checked
                // with keying material of the connection it came over, and only
                // the TLS of QUIC - a WebSocket over HTTP/3 - exports any: .NET
                // does not offer it on an SslStream. Over HTTP/1.1 and HTTP/2
                // such a token cannot be checked at all. Said out loud, because
                // the alternative is a login whose token is computed correctly
                // and refused anyway, with nothing in the log to explain it.
                var known     = Logins.TryGet(WebSocketLogins.LoginOf(id), out var login);
                var bound     = login?.TOTP?.TLSChannelBinding == true;
                var material  = Connection.TOTPTLSExporterMaterial;

                // Derived before the group is consulted, and always, for the
                // same reason as the password above.
                var right = Logins.VerifyTOTP(WebSocketLogins.LoginOf(id), totpAuthentication.TOTP, bound, material);

                if (!known || !login!.Enabled || !right)
                    return Refuse(Connection, WhyNotThisToken(id, login, bound, material, "the one-time token is wrong"));

                if (!GroupAllows(login, AuthMethod.TOTP, way, out var why))
                    return Refuse(Connection, $"the WebSocket login '{id}' {why}");

                return LetIn(id, $"a one-time token{(bound ? " bound to its connection" : "")}",
                             Words.Authentication(way) +
                             (tls ? "" : ", on an unencrypted port, so the token is replayable while it stands"));

            }

            #endregion

            #region A one-time token in a header of its own, under the name of its path

            // What says nothing of who sends it: the login is the one the path
            // names, and the header says whether the token is bound to the TLS
            // session - which has to be what the login says.
            if (Connection.HTTPRequest?.Authorization is null &&
                Connection.HTTPRequest?.TOTP is TOTPHTTPHeader header &&
                NameOfPath(Connection.HTTPRequest) is String byPath)
            {

                var known     = Logins.TryGet(WebSocketLogins.LoginOf(byPath), out var login);
                var bound     = header.Type == TOTPHTTPHeaderType.TLSChannelBinding;
                var material  = Connection.TOTPTLSExporterMaterial;

                var right     = Logins.VerifyTOTP(WebSocketLogins.LoginOf(byPath), header.Value, bound, material);

                if (!known || !login!.Enabled || !right)
                    return Refuse(Connection, WhyNotThisToken(byPath, login, bound, material, "the one-time token is wrong"));

                if (!GroupAllows(login, AuthMethod.TOTP, way, out var why))
                    return Refuse(Connection, $"the WebSocket login '{byPath}' {why}");

                return LetIn(byPath, $"a one-time password{(bound ? " bound to its TLS session" : "")}",
                             Words.Authentication(way) +
                             (tls ? "" : ", on an unencrypted port, so the token is replayable while it stands"));

            }

            #endregion

            return Refuse(Connection, "it sent no credentials");


            #region (local) WhyNotThisToken(Id, Login, Bound, Material, Otherwise)

            // Why a one-time token was refused, said out loud where the binding
            // is the reason: the alternative is a token that is computed right
            // and refused all the same, with nothing in the log to say why.
            String WhyNotThisToken(String           Id,
                                   WebSocketLogin?  Login,
                                   Boolean          Bound,
                                   Byte[]?          Material,
                                   String           Otherwise)
            {

                var bindingAsked = Login?.TOTP?.TLSChannelBinding == true;

                if (Login is { Enabled: true } && bindingAsked && Material is not { Length: > 0 })
                    return $"'{Id}' has a one-time token bound to the TLS session of its connection, and came over a connection whose TLS exports nothing to check it with: " +
                            "that is checked over HTTP/3 only. It has to open its WebSocket over HTTP/3";

                // "Authorization: TOTP" does not say whether its token is bound,
                // so a raw one is told from a wrong one by nothing: both are not
                // the token bound to this connection.
                if (Login is { Enabled: true } && bindingAsked)
                    return $"'{Id}' has a one-time token bound to the TLS session of its connection, and " +
                           (Bound ? "what it sent is not the one bound to this connection" : "sent one that is not bound") +
                            ": it has to open its WebSocket over HTTP/3 and bind its one-time password";

                return $"'{Id}' is no WebSocket login that may sign in, or {Otherwise}";

            }

            #endregion

            #region (local) LetIn(LoginId, How, Detail, ByCertificate)

            // Let in under the given WebSocket login: as the back end whose
            // connection the other end makes comes under its name, or as one
            // of the others the kind lets in. The name decides which: what
            // comes under the name of a connection the other end makes is let
            // in as that or not at all - only on its own path, and while it is
            // switched on - and the rest is the kind's to say.
            Task<HTTPResponse?> LetIn(String             LoginId,
                                      String             How,
                                      String             Detail,
                                      X509Certificate2?  ByCertificate = null)
            {

                var path     = NameOfPath(Connection.HTTPRequest);
                var backEnd  = inboundConnectionOf(Server, LoginId) ??
                               (path is not null ? inboundConnectionOf(Server, path) : null);

                if (backEnd is not null)
                {

                    if (backEnd.IsSSH)
                        return Refuse(Connection, $"'{backEnd.InboundName}' is a back end that connects to this {NodeNoun} over SSH, and came over a WebSocket");

                    if (backEnd.InboundName != LoginId)
                        return Refuse(Connection, $"'{path}' is the name '{backEnd.Description.FirstText()}' comes under, and it signed in as '{LoginId}'");

                    if (path != LoginId)
                        return Refuse(Connection, $"'{LoginId}' is a back end that connects to this {NodeNoun}, and asked to connect as " +
                                                  (path is null ? "nobody in particular" : $"'{path}'"));

                    if (!backEnd.AutoConnect)
                        return Refuse(Connection, $"'{LoginId}' is the name '{backEnd.Description.FirstText()}' comes under, a connection that is switched off");

                    letInAsInbound(Connection, backEnd);

                    if (saysSignIns())
                        log.Info($"The back end '{LoginId}' connected to this {NodeNoun} from {from} and signed in with {How} ({Detail}).",
                                 InboundAuthTags);

                    return Task.FromResult<HTTPResponse?>(null);

                }

                if (letInOthers(Connection, LoginId, How, Detail, ByCertificate) is String whyNot)
                    return Refuse(Connection, whyNot);

                return Task.FromResult<HTTPResponse?>(null);

            }

            #endregion

            #region (local) GroupAllows(Login, Method, Way, out Why)

            // Whether the group of this login lets it in this way, on this
            // way of the port.
            Boolean GroupAllows(WebSocketLogin                 Login,
                                AuthMethod                     Method,
                                WebSocketClientAuthentication  Way,
                                out String                     Why)
            {

                Why = "";

                var group = Logins.GroupOf(Login);

                // A login whose group has gone missing is refused rather than
                // waved through: the group is what decides about it, and a
                // decision that cannot be found is not a yes.
                if (group is null)
                {
                    Why = $"belongs to the login group '{Login.GroupId}', which this {NodeNoun} does not have";
                    return false;
                }

                if (!group.Enabled)
                {
                    Why = $"is in the login group '{group.Id}', which is switched off";
                    return false;
                }

                if (!group.Allows(Method))
                {
                    Why = $"is in the login group '{group.Id}', which does not accept {Method.AsText()}";
                    return false;
                }

                if (!group.Allows(Way))
                {
                    Why = $"is in the login group '{group.Id}', which does not accept {Way.ToText()} ({Words.Authentication(Way)})";
                    return false;
                }

                return true;

            }

            #endregion


            Task<HTTPResponse?> Refuse(WebSocketServerConnection Connection, String Because)
            {

                // A guess, where it came with something: counted against its
                // address, by the node's sign-in brake.
                if (Connection.HTTPRequest is { Authorization: not null } or { TOTP: not null })
                    SignInBrake.CountFailed(Connection.RemoteSocket.IPAddress.ToString());

                if (saysSignIns())
                    log.Warning($"{Words.Who} at {Connection.RemoteSocket} was turned away: {Because}.",
                                AuthTags);

                // Hermod sets the request on the connection before it asks any
                // validator, so this is never null in practice. If it ever is,
                // the answer is still no: returning null here would mean "let
                // them in", and a refusal that cannot be written is a refusal
                // all the same.
                if (Connection.HTTPRequest is null)
                    throw new InvalidOperationException(
                              $"A connection reached the door of {Words.Port} without an HTTP request; refusing it."
                          );

                var refusal = new HTTPResponse.Builder(Connection.HTTPRequest) {
                                  HTTPStatusCode  = HTTPStatusCode.Unauthorized,
                                  Server          = Server.HTTPServiceName,
                                  Connection      = org.GraphDefined.Vanaheimr.Hermod.HTTP.ConnectionType.Close
                              };

                // What this port takes, and nothing about who asked: the
                // schemes its enabled login groups allow for the way a
                // credential here would be. A port that takes certificates and
                // nothing else challenges with nothing.
                var asWay     = tls
                                    ? WebSocketClientAuthentication.HTTPAuthOverTLS
                                    : WebSocketClientAuthentication.HTTPAuthWithoutTLS;

                var taken     = allowed.Contains(asWay)
                                    ? Logins.Groups.
                                          Where     (group => group.Allows(asWay)).
                                          SelectMany(group => group.AuthMethods).
                                          ToHashSet ()
                                    : [];

                var basic     = taken.Contains(AuthMethod.Basic) ? WWWAuthenticate.Basic(Words.Realm) : null;
                var totp      = taken.Contains(AuthMethod.TOTP)  ? WWWAuthenticate.TOTP (Words.Realm) : null;

                if ((basic is not null && totp is not null ? basic.And(totp) : basic ?? totp) is WWWAuthenticate challenge)
                    refusal.WWWAuthenticate = challenge;

                return Task.FromResult<HTTPResponse?>(refusal.AsImmutable);

            }

        }

        #endregion

        #region LoginLetsIn(Name)

        /// <summary>
        /// Whether the WebSocket login of the given name is switched on - or
        /// there is none: then a certificate issued to that name, of a chain
        /// the port accepts, is what lets it in, as it lets in a client of the
        /// kind without a login.
        /// </summary>
        /// <param name="Name">The name a connection the other end makes comes under.</param>
        public Boolean LoginLetsIn(String Name)

            => !Logins.TryGet(WebSocketLogins.LoginOf(Name), out var login) || login.Enabled;

        #endregion

        #region WhyCanNotSignIn(Name, Listening, Server)

        /// <summary>
        /// Why what comes under the given name can not sign in at the given
        /// server of the port, as its WebSocket login and the port are now - or
        /// null.
        /// </summary>
        /// <param name="Name">The name a connection the other end makes comes under.</param>
        /// <param name="Listening">Whether the port listens now.</param>
        /// <param name="Server">The server of the port it comes to.</param>
        public String? WhyCanNotSignIn(String       Name,
                                       Boolean      Listening,
                                       IWWCPServer  Server)
        {

            // Without a login, nothing but a certificate issued to its name
            // lets it in: one of a chain the port accepts, over TLS.
            if (!Logins.TryGet(WebSocketLogins.LoginOf(Name), out var login))
                return Listening && overTLS() && ClientTrust.EnabledCount > 0
                           ? null
                           : $"there is no WebSocket login '{Name}' it could sign in with" +
                             (Listening && !overTLS()
                                  ? ", and without TLS no certificate either"
                                  : ", and no accepted chain a certificate issued to its name could lead to") +
                             ". Add one under WebSocket logins, with what it signs in with.";

            if (!login.Enabled)
                return $"its WebSocket login '{Name}' is switched off.";

            if (Logins.GroupOf(login) is not { } group)
                return $"its WebSocket login '{Name}' belongs to the login group '{login.GroupId}', which this {NodeNoun} does not have.";

            if (!group.Enabled)
                return $"its WebSocket login '{Name}' is in the login group '{group.Id}', which is switched off.";

            // Bound to the TLS session: checked with keying material only the
            // TLS of HTTP/3 exports.
            if (!login.HasPassword && login.TOTP?.TLSChannelBinding == true &&
                Server is WWCPWebSocketServer { AcceptHTTP3: false })
                return $"its one-time password is bound to its TLS session, which is checked over HTTP/3 only, and {Words.Port} takes no WebSockets over HTTP/3.";

            return null;

        }

        #endregion


        #region (private) TooManyGuesses(Server, Connection)

        /// <summary>
        /// "Too Many Requests", to an address that signed in wrong too often
        /// within a minute.
        /// </summary>
        private Task<HTTPResponse?> TooManyGuesses(AWebSocketEndpoint         Server,
                                                   WebSocketServerConnection  Connection)
        {

            // Hermod sets the request before it asks: without one the answer
            // is still no, and null would be yes.
            if (Connection.HTTPRequest is not HTTPRequest request)
                throw new InvalidOperationException($"A connection reached the door of {Words.Port} without an HTTP request; refusing it.");

            log.Warning($"{Connection.RemoteSocket} is told to wait at {Words.Port}: it signed in wrong {SignInBrake.MaxFailedPerMinute} times within a minute.",
                        AuthTags);

            return Task.FromResult<HTTPResponse?>(
                       new HTTPResponse.Builder(request) {
                           HTTPStatusCode  = HTTPStatusCode.TooManyRequests,
                           Server          = Server.HTTPServiceName,
                           Connection      = org.GraphDefined.Vanaheimr.Hermod.HTTP.ConnectionType.Close
                       }.AsImmutable
                   );

        }

        #endregion

        #region (static) NameOfPath(Request)

        /// <summary>
        /// The name the URL of an upgrade comes under: its last segment,
        /// percent-decoded, as OCPP 2.1 Part 4, 3.1.1 has it for a charging
        /// station - or null where it names none.
        /// </summary>
        /// <remarks>
        /// Read the way the WebSocket server reads it when it registers the
        /// connection, so that the login this node let in and the one the
        /// connection is registered as cannot be two.
        /// </remarks>
        public static String? NameOfPath(HTTPRequest? Request)
        {

            if (Request is null)
                return null;

            var path  = Request.Path.ToString();
            var name  = path[(path.LastIndexOf('/') + 1)..];

            return name.Length > 0 ? name : null;

        }

        #endregion

    }

}
