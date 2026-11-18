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

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Certificates
{

    /// <summary>
    /// A server key of one listener of this node: a key made here that the
    /// clients of that listener may pin, presented in a self-signed carrier
    /// certificate made from it until - and after - a certificate authority
    /// issues one for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What a certificate cannot say about itself, and the index therefore
    /// has to: which listener the key is for, whether it is the one shown
    /// now or the one announced for later, and since when. Everything else -
    /// the key, its carrier, whatever was issued for it - is a TLS server
    /// identity of the store like any other, and found by its key pin.
    /// </para>
    /// <para>
    /// Keyed by the key pin and not by a certificate, because the key is what
    /// the clients pinned: it outlives every certificate issued for it, and
    /// is the same in its carrier and in each of them.
    /// </para>
    /// </remarks>
    /// <param name="KeyPin">The key pin of the key: SHA-256 over its SubjectPublicKeyInfo.</param>
    /// <param name="Listener">The listener it is a server key of, e.g. "ocpp".</param>
    /// <param name="Algorithm">What kind of key it is, as <see cref="org.GraphDefined.Vanaheimr.Hermod.PKI.KeyAlgorithm"/> names it, e.g. "ecdsa-p256".</param>
    /// <param name="CreatedAt">When it was made, by the clock of the store.</param>
    /// <param name="CarrierId">The handle of its carrier certificate in the store.</param>
    /// <param name="IsNext">Whether it is the announced next key: made ahead of a rollover, its key pin handed to the clients, and shown only once somebody switches to it.</param>
    /// <param name="CurrentSince">Since when it is the current key - made as the first, or switched to - or null for one that never was.</param>
    public sealed record ServerKey(KeyPin            KeyPin,
                                   CertificateUsage  Listener,
                                   String            Algorithm,
                                   DateTimeOffset    CreatedAt,
                                   String            CarrierId,
                                   Boolean           IsNext,
                                   DateTimeOffset?   CurrentSince)
    {

        #region Properties

        /// <summary>
        /// What the key is called: the first sixteen hexadecimal digits of its
        /// key pin - which is what a signing request made here for a key is
        /// called as well, so that one key never answers to two names.
        /// </summary>
        public String Id
            => KeyPin.ToHex()[..CertificateEntry.IdLength];

        #endregion


        #region (static) TryParse(KeyPinText, JSON, out Key, out Error)

        /// <summary>
        /// One server key as the index holds it - under its key pin - or the
        /// one sentence that says what is wrong with it.
        /// </summary>
        /// <param name="KeyPinText">The key pin it is held under, in hexadecimal.</param>
        /// <param name="JSON">What the index says of it.</param>
        /// <param name="Key">The server key.</param>
        /// <param name="Error">What is wrong with it.</param>
        public static Boolean TryParse(String                               KeyPinText,
                                       JObject                              JSON,
                                       [NotNullWhen(true)]  out ServerKey?  Key,
                                       [NotNullWhen(false)] out String?     Error)
        {

            Key    = null;
            Error  = null;

            if (!KeyPin.TryParse(KeyPinText, out var keyPin))
            {
                Error = $"a server key under '{KeyPinText}', which is no key pin.";
                return false;
            }

            if (!CertificateUsage.TryParse(JSON.Value<String>("listener"), out var listener))
            {
                Error = $"the server key '{keyPin.ToHex()}' has no 'listener'.";
                return false;
            }

            var carrier = JSON.Value<String>("carrier")?.Trim();

            if (carrier is null or { Length: 0 })
            {
                Error = $"the server key '{keyPin.ToHex()}' has no 'carrier'.";
                return false;
            }

            Key = new ServerKey(
                      keyPin,
                      listener,
                      JSON.Value<String>("algorithm") ?? "",
                      Moment(JSON, "createdAt") ?? DateTimeOffset.MinValue,
                      carrier,
                      JSON.Value<Boolean?>("next") ?? false,
                      Moment(JSON, "currentSince")
                  );

            return true;

        }

        #endregion

        #region (private static) Moment(JSON, Name)

        /// <summary>
        /// One moment out of the index, as written by <see cref="ToJSON"/>: a
        /// string in ISO 8601, which the JSON reader may have turned into a date
        /// already - see <see cref="CertificateEntry"/> for why that is taken as
        /// it comes rather than cast.
        /// </summary>
        private static DateTimeOffset? Moment(JObject  JSON,
                                              String   Name)
        {

            if (!JSON.TryGetValue(Name, out var token) || token.Type == JTokenType.Null)
                return null;

            if (token.Type == JTokenType.Date)
                return token.ToObject<Object>() switch {
                           DateTime       moment  => new DateTimeOffset(moment.ToUniversalTime(), TimeSpan.Zero),
                           DateTimeOffset moment  => moment,
                           _                      => null
                       };

            return DateTimeOffset.TryParse(token.Value<String>(),
                                           System.Globalization.CultureInfo.InvariantCulture,
                                           System.Globalization.DateTimeStyles.AdjustToUniversal |
                                           System.Globalization.DateTimeStyles.AssumeUniversal,
                                           out var parsed)
                       ? parsed
                       : null;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// This server key as the index holds it, under its key pin - which is
        /// therefore not in it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("listener",      Listener.ToString()),
                   new JProperty("algorithm",     Algorithm),
                   new JProperty("createdAt",     CreatedAt.ToString("o")),
                   new JProperty("carrier",       CarrierId),
                   new JProperty("next",          IsNext),
                   new JProperty("currentSince",  CurrentSince?.ToString("o"))
               );

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"{Id} ({Algorithm}) of '{Listener}', key pin {KeyPin.ToHex()}{(IsNext ? ", the next key" : CurrentSince.HasValue ? $", made current {CurrentSince:o}" : "")}";

        #endregion

    }

}
