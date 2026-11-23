/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP Node <https://github.com/OpenChargingCloud/WWCP_Node>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.PKI
{

    #region PKIActions

    /// <summary>
    /// What a registration authority may ask a PKI, as the action of a request.
    /// </summary>
    public static class PKIActions
    {

        /// <summary>
        /// Sign a certificate signing request - of a charging station, say - as
        /// the PKI signs one over EST, at the label given or without one.
        /// </summary>
        public const String SignCertificate       = "SignCertificate";

        /// <summary>
        /// The CA certificates a certificate signed at the label given chains to.
        /// </summary>
        public const String GetCACertificates     = "GetCACertificates";

        /// <summary>
        /// Whether a certificate of the PKI is valid, revoked or expired.
        /// </summary>
        public const String GetCertificateStatus  = "GetCertificateStatus";

        /// <summary>
        /// The CRL of a CA of the PKI.
        /// </summary>
        public const String GetCRL                = "GetCRL";

        /// <summary>
        /// Revoke a certificate the registration authority had signed.
        /// </summary>
        public const String RevokeCertificate     = "RevokeCertificate";

        /// <summary>
        /// Every one of them.
        /// </summary>
        public static readonly IReadOnlyList<String> All = [ SignCertificate, GetCACertificates, GetCertificateStatus, GetCRL, RevokeCertificate ];

    }

    #endregion

    #region PKIErrorCodes

    /// <summary>
    /// The codes of an error, as OCPP-J has them.
    /// </summary>
    public static class PKIErrorCodes
    {
        public const String NotImplemented     = "NotImplemented";
        public const String NotSupported       = "NotSupported";
        public const String FormatViolation    = "FormatViolation";
        public const String SecurityError      = "SecurityError";
        public const String InternalError      = "InternalError";
        public const String ProtocolError      = "ProtocolError";
        public const String GenericError       = "GenericError";
    }

    #endregion

    #region PKIStatus / PKIStatusInfo

    /// <summary>
    /// Whether the PKI did what it was asked: "Accepted" or "Rejected".
    /// </summary>
    public enum PKIStatus
    {
        Accepted,
        Rejected
    }

    /// <summary>
    /// Why the PKI did not do what it was asked - or more of what it did -, as
    /// the statusInfo of OCPP says it.
    /// </summary>
    /// <param name="ReasonCode">A word: "UnknownLabel", "InvalidCSR", "NotFound", "NotYours", ...</param>
    /// <param name="AdditionalInfo">The sentence that says it.</param>
    public sealed record PKIStatusInfo(String   ReasonCode,
                                       String?  AdditionalInfo = null)
    {

        public JObject ToJSON()
        {

            var json = new JObject(new JProperty("reasonCode", ReasonCode));

            if (AdditionalInfo is not null)
                json.Add("additionalInfo", AdditionalInfo);

            return json;

        }

        public static PKIStatusInfo? Parse(JToken? JSON)

            => JSON is JObject json && json.Value<String>("reasonCode") is String reasonCode
                   ? new PKIStatusInfo(reasonCode, json.Value<String>("additionalInfo"))
                   : null;

    }

    #endregion

    #region PKIMessage

    /// <summary>
    /// What a message of a PKI is: a request, a response, or an error.
    /// </summary>
    public enum PKIMessageType
    {
        Request   = 2,
        Response  = 3,
        Error     = 4
    }

    /// <summary>
    /// One message of a PKI, framed as OCPP-J frames one.
    /// </summary>
    /// <param name="Type">A request, a response or an error.</param>
    /// <param name="Id">What a response or an error answers: the id of its request.</param>
    /// <param name="Action">The action of a request.</param>
    /// <param name="Payload">What a request asks or a response answers - the details of an error.</param>
    /// <param name="ErrorCode">The code of an error.</param>
    /// <param name="ErrorDescription">What an error says.</param>
    public sealed record PKIMessage(PKIMessageType  Type,
                                    String          Id,
                                    String?         Action,
                                    JObject         Payload,
                                    String?         ErrorCode         = null,
                                    String?         ErrorDescription  = null)
    {

        #region Request(Id, Action, Payload) / Response(Id, Payload) / Error(Id, Code, Description, Details)

        public static PKIMessage Request(String Id, String Action, JObject Payload)
            => new (PKIMessageType.Request,  Id, Action, Payload);

        public static PKIMessage Response(String Id, JObject Payload)
            => new (PKIMessageType.Response, Id, null,   Payload);

        public static PKIMessage Error(String Id, String Code, String Description, JObject? Details = null)
            => new (PKIMessageType.Error,    Id, null,   Details ?? [], Code, Description);

        #endregion

        #region ToJSON() / ToLine()

        /// <summary>
        /// The message as its JSON array.
        /// </summary>
        public JArray ToJSON()

            => Type switch {
                   PKIMessageType.Request   => new JArray((Int32) Type, Id, Action, Payload),
                   PKIMessageType.Response  => new JArray((Int32) Type, Id, Payload),
                   _                        => new JArray((Int32) Type, Id, ErrorCode ?? PKIErrorCodes.GenericError, ErrorDescription ?? "", Payload)
               };

        /// <summary>
        /// The message as it goes over the wire: its JSON array on one line.
        /// </summary>
        public String ToLine()

            => ToJSON().ToString(Formatting.None);

        #endregion

        #region TryParse(Text, out Message, out Id, out Error)

        /// <summary>
        /// One message from the line it came as - or why it is none, and the id
        /// it named, where it named one, for an error to answer it with.
        /// </summary>
        public static Boolean TryParse(String                                 Text,
                                       [NotNullWhen(true)]  out PKIMessage?   Message,
                                       out String?                            Id,
                                       [NotNullWhen(false)] out String?       Error)
        {

            Message  = null;
            Id       = null;
            Error    = null;

            JArray array;

            try
            {
                using var reader = new JsonTextReader(new StringReader(Text)) { DateParseHandling = DateParseHandling.None, MaxDepth = 32 };
                array = JArray.Load(reader);
            }
            catch (Exception e)
            {
                Error = $"The message is no JSON array: {e.Message}";
                return false;
            }

            if (array.Count < 3 || array[0].Type != JTokenType.Integer || array[1].Type != JTokenType.String)
            {
                Error = "A message is [ <type>, \"<id>\", ... ].";
                return false;
            }

            Id = array[1].Value<String>()!;

            if (Id.Length == 0 || Id.Length > 36)
            {
                Error = "The id of a message is 1 to 36 characters.";
                return false;
            }

            switch (array[0].Value<Int32>())
            {

                case 2:

                    if (array.Count != 4 || array[2].Type != JTokenType.String || array[3] is not JObject requestPayload)
                    {
                        Error = "A request is [ 2, \"<id>\", \"<Action>\", { ... } ].";
                        return false;
                    }

                    Message = Request(Id, array[2].Value<String>()!, requestPayload);
                    return true;

                case 3:

                    if (array.Count != 3 || array[2] is not JObject responsePayload)
                    {
                        Error = "A response is [ 3, \"<id>\", { ... } ].";
                        return false;
                    }

                    Message = Response(Id, responsePayload);
                    return true;

                case 4:

                    if (array.Count != 5 || array[2].Type != JTokenType.String || array[3].Type != JTokenType.String || array[4] is not JObject details)
                    {
                        Error = "An error is [ 4, \"<id>\", \"<Code>\", \"<Text>\", { ... } ].";
                        return false;
                    }

                    Message = PKIMessage.Error(Id, array[2].Value<String>()!, array[3].Value<String>()!, details);
                    return true;

                default:
                    Error = "The type of a message is 2, a request, 3, a response, or 4, an error.";
                    return false;

            }

        }

        #endregion

    }

    #endregion

    #region PKIException

    /// <summary>
    /// An error the other end answered a request with - or one that is answered
    /// to a request with.
    /// </summary>
    public sealed class PKIException(String    Code,
                                     String    Description,
                                     JObject?  Details = null) : Exception($"{Code}: {Description}")
    {
        public String   Code         { get; } = Code;
        public String   Description  { get; } = Description;
        public JObject  Details      { get; } = Details ?? [];
    }

    #endregion


    #region (internal) PKIJSON

    internal static class PKIJSON
    {

        public static JObject With(this JObject JSON, String Name, Object? Value)
        {
            if (Value is not null)
                JSON.Add(Name, JToken.FromObject(Value));
            return JSON;
        }

        public static PKIStatus StatusOf(JObject JSON)

            => Enum.TryParse<PKIStatus>(JSON.Value<String>("status"), out var status)
                   ? status
                   : throw new PKIException(PKIErrorCodes.FormatViolation, "A response says its \"status\": \"Accepted\" or \"Rejected\".");

        public static String Required(JObject JSON, String Name)

            => JSON.Value<String>(Name) is String text && text.Length > 0
                   ? text
                   : throw new PKIException(PKIErrorCodes.FormatViolation, $"\"{Name}\" is missing.");

        public static String? Optional(JObject JSON, String Name)
        {

            var token = JSON[Name];

            if (token is null || token.Type == JTokenType.Null)
                return null;

            if (token.Type != JTokenType.String)
                throw new PKIException(PKIErrorCodes.FormatViolation, $"\"{Name}\" is a text.");

            return token.Value<String>();

        }

    }

    #endregion


    #region SignCertificate

    /// <summary>
    /// Sign a certificate signing request, as the PKI signs one over EST at the
    /// given label - or without one.
    /// </summary>
    /// <param name="CSR">The request, as PEM.</param>
    /// <param name="Label">The label of EST it is signed as, or null for the PKI's default.</param>
    public sealed record SignCertificateRequest(String   CSR,
                                                String?  Label = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("csr", CSR)).With("label", Label);

        public static SignCertificateRequest Parse(JObject JSON)
            => new (PKIJSON.Required(JSON, "csr"), PKIJSON.Optional(JSON, "label"));

    }

    /// <summary>
    /// The certificate signed, with the chain to its root - or why it is none.
    /// </summary>
    /// <param name="Status">Whether it was signed.</param>
    /// <param name="CertificateChain">The certificate and its CAs as PEM, the certificate first.</param>
    /// <param name="CertificateId">The certificate, by its SHA-256 fingerprint: what it is asked about and revoked as.</param>
    /// <param name="StatusInfo">Why it was not signed.</param>
    public sealed record SignCertificateResponse(PKIStatus       Status,
                                                 String?         CertificateChain  = null,
                                                 String?         CertificateId     = null,
                                                 PKIStatusInfo?  StatusInfo        = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("status", Status.ToString())).
                   With("certificateChain", CertificateChain).
                   With("certificateId",    CertificateId).
                   With("statusInfo",       StatusInfo?.ToJSON());

        public static SignCertificateResponse Parse(JObject JSON)
            => new (PKIJSON.StatusOf(JSON), PKIJSON.Optional(JSON, "certificateChain"), PKIJSON.Optional(JSON, "certificateId"), PKIStatusInfo.Parse(JSON["statusInfo"]));

    }

    #endregion

    #region GetCACertificates

    /// <summary>
    /// The CA certificates a certificate signed at the given label chains to.
    /// </summary>
    /// <param name="Label">The label of EST, or null for the PKI's default.</param>
    public sealed record GetCACertificatesRequest(String? Label = null)
    {

        public JObject ToJSON()
            => new JObject().With("label", Label);

        public static GetCACertificatesRequest Parse(JObject JSON)
            => new (PKIJSON.Optional(JSON, "label"));

    }

    /// <summary>
    /// The CA certificates as PEM, the signing CA first, its root last.
    /// </summary>
    public sealed record GetCACertificatesResponse(PKIStatus       Status,
                                                   String?         CertificateChain  = null,
                                                   PKIStatusInfo?  StatusInfo        = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("status", Status.ToString())).
                   With("certificateChain", CertificateChain).
                   With("statusInfo",       StatusInfo?.ToJSON());

        public static GetCACertificatesResponse Parse(JObject JSON)
            => new (PKIJSON.StatusOf(JSON), PKIJSON.Optional(JSON, "certificateChain"), PKIStatusInfo.Parse(JSON["statusInfo"]));

    }

    #endregion

    #region GetCertificateStatus

    /// <summary>
    /// Whether a certificate of the PKI is valid, revoked or expired - named by
    /// its SHA-256 fingerprint, or by its serial number.
    /// </summary>
    public sealed record GetCertificateStatusRequest(String?  CertificateId  = null,
                                                     String?  SerialNumber   = null)
    {

        public JObject ToJSON()
            => new JObject().With("certificateId", CertificateId).With("serialNumber", SerialNumber);

        public static GetCertificateStatusRequest Parse(JObject JSON)
        {

            var request = new GetCertificateStatusRequest(PKIJSON.Optional(JSON, "certificateId"), PKIJSON.Optional(JSON, "serialNumber"));

            return request.CertificateId is null && request.SerialNumber is null
                       ? throw new PKIException(PKIErrorCodes.FormatViolation, "Name the certificate by its \"certificateId\" - its SHA-256 fingerprint - or by its \"serialNumber\".")
                       : request;

        }

    }

    /// <summary>
    /// What a certificate is now: "valid", "revoked", "expired", "notYetValid" -
    /// or "unknown", where the PKI has none of that name.
    /// </summary>
    public sealed record GetCertificateStatusResponse(PKIStatus        Status,
                                                      String           CertificateStatus,
                                                      String?          CertificateId     = null,
                                                      DateTimeOffset?  RevokedAt         = null,
                                                      String?          RevocationReason  = null,
                                                      PKIStatusInfo?   StatusInfo        = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("status",            Status.ToString()),
                           new JProperty("certificateStatus", CertificateStatus)).
                   With("certificateId",     CertificateId).
                   With("revokedAt",         RevokedAt?.ToString("o")).
                   With("revocationReason",  RevocationReason).
                   With("statusInfo",        StatusInfo?.ToJSON());

        public static GetCertificateStatusResponse Parse(JObject JSON)
            => new (PKIJSON.StatusOf(JSON),
                    PKIJSON.Required(JSON, "certificateStatus"),
                    PKIJSON.Optional(JSON, "certificateId"),
                    DateTimeOffset.TryParse(PKIJSON.Optional(JSON, "revokedAt"), out var revokedAt) ? revokedAt : null,
                    PKIJSON.Optional(JSON, "revocationReason"),
                    PKIStatusInfo.Parse(JSON["statusInfo"]));

    }

    #endregion

    #region GetCRL

    /// <summary>
    /// The CRL of a CA of the PKI: the CA given by its SHA-256 fingerprint, or
    /// the one that signs at the given label - or without one.
    /// </summary>
    public sealed record GetCRLRequest(String?  IssuerId  = null,
                                       String?  Label     = null)
    {

        public JObject ToJSON()
            => new JObject().With("issuerId", IssuerId).With("label", Label);

        public static GetCRLRequest Parse(JObject JSON)
            => new (PKIJSON.Optional(JSON, "issuerId"), PKIJSON.Optional(JSON, "label"));

    }

    /// <summary>
    /// The CRL as PEM.
    /// </summary>
    public sealed record GetCRLResponse(PKIStatus       Status,
                                        String?         CRL         = null,
                                        String?         IssuerId    = null,
                                        PKIStatusInfo?  StatusInfo  = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("status", Status.ToString())).
                   With("crl",         CRL).
                   With("issuerId",    IssuerId).
                   With("statusInfo",  StatusInfo?.ToJSON());

        public static GetCRLResponse Parse(JObject JSON)
            => new (PKIJSON.StatusOf(JSON), PKIJSON.Optional(JSON, "crl"), PKIJSON.Optional(JSON, "issuerId"), PKIStatusInfo.Parse(JSON["statusInfo"]));

    }

    #endregion

    #region RevokeCertificate

    /// <summary>
    /// Revoke a certificate the registration authority had signed - named by
    /// its SHA-256 fingerprint, or by its serial number -, for the reason of RFC
    /// 5280: "keyCompromise", "superseded", "cessationOfOperation", ...
    /// </summary>
    public sealed record RevokeCertificateRequest(String?  CertificateId  = null,
                                                  String?  SerialNumber   = null,
                                                  String?  Reason         = null)
    {

        public JObject ToJSON()
            => new JObject().With("certificateId", CertificateId).With("serialNumber", SerialNumber).With("reason", Reason);

        public static RevokeCertificateRequest Parse(JObject JSON)
        {

            var request = new RevokeCertificateRequest(PKIJSON.Optional(JSON, "certificateId"), PKIJSON.Optional(JSON, "serialNumber"), PKIJSON.Optional(JSON, "reason"));

            return request.CertificateId is null && request.SerialNumber is null
                       ? throw new PKIException(PKIErrorCodes.FormatViolation, "Name the certificate by its \"certificateId\" - its SHA-256 fingerprint - or by its \"serialNumber\".")
                       : request;

        }

    }

    /// <summary>
    /// Whether the certificate is revoked now.
    /// </summary>
    public sealed record RevokeCertificateResponse(PKIStatus       Status,
                                                   PKIStatusInfo?  StatusInfo = null)
    {

        public JObject ToJSON()
            => new JObject(new JProperty("status", Status.ToString())).
                   With("statusInfo", StatusInfo?.ToJSON());

        public static RevokeCertificateResponse Parse(JObject JSON)
            => new (PKIJSON.StatusOf(JSON), PKIStatusInfo.Parse(JSON["statusInfo"]));

    }

    #endregion

}
