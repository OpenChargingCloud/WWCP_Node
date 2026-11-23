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

using System.Net;
using System.Net.Sockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.PKI;
using cloud.charging.open.protocols.WWCP.Node.Connections;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The messages of a PKI: their frames, as OCPP-J has them, a request
    /// answered over one stream of lines - or answered with an error -, and the
    /// two kinds of connection that carry them.
    /// </summary>
    public class PKIMessagesTests
    {

        #region (private static) TwoEnds()

        /// <summary>
        /// Two ends of one TCP connection on this machine: a stream of lines
        /// either way.
        /// </summary>
        private static async Task<(TcpClient, TcpClient)> TwoEnds()
        {

            var listener  = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var client    = new TcpClient();
            var accept    = listener.AcceptTcpClientAsync();

            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint) listener.LocalEndpoint).Port);

            var server    = await accept;
            listener.Stop();

            return (client, server);

        }

        #endregion


        #region Frames_GoBothWays()

        /// <summary>
        /// A request, a response and an error are written as OCPP-J writes them,
        /// and read back as they were.
        /// </summary>
        [Test]
        public void Frames_GoBothWays()
        {

            var request   = PKIMessage.Request ("1", PKIActions.SignCertificate, new JObject(new JProperty("csr", "x")));
            var response  = PKIMessage.Response("1", new JObject(new JProperty("status", "Accepted")));
            var error     = PKIMessage.Error   ("1", PKIErrorCodes.FormatViolation, "no");

            Assert.Multiple(() => {

                Assert.That(request. ToLine(), Is.EqualTo("[2,\"1\",\"SignCertificate\",{\"csr\":\"x\"}]"));
                Assert.That(response.ToLine(), Is.EqualTo("[3,\"1\",{\"status\":\"Accepted\"}]"));
                Assert.That(error.   ToLine(), Is.EqualTo("[4,\"1\",\"FormatViolation\",\"no\",{}]"));

                foreach (var message in new[] { request, response, error })
                {
                    Assert.That(PKIMessage.TryParse(message.ToLine(), out var again, out _, out var problem), Is.True, problem);
                    Assert.That(again!.ToLine(), Is.EqualTo(message.ToLine()));
                }

                Assert.That(PKIMessage.TryParse("[5,\"1\",{}]",  out _, out var id, out _), Is.False);
                Assert.That(id, Is.EqualTo("1"), "The id of what is no message is kept, to answer it with an error.");
                Assert.That(PKIMessage.TryParse("{}",            out _, out _,      out _), Is.False);
                Assert.That(PKIMessage.TryParse("[2,\"1\",\"A\"]", out _, out _,    out _), Is.False);

            });

        }

        #endregion

        #region Channel_AsksAndIsAnswered()

        /// <summary>
        /// A request over one end is answered by the handler of the other - its
        /// response, or its error as a <see cref="PKIException"/> -, and a line
        /// that is no message is answered with FormatViolation, the channel
        /// staying up.
        /// </summary>
        [Test]
        public async Task Channel_AsksAndIsAnswered()
        {

            var (client, server) = await TwoEnds();

            using var _client = client;
            using var _server = server;

            await using var answering = new PKIMessageChannel(
                                            server.GetStream(),
                                            (action, payload, cancellationToken) =>
                                                action == PKIActions.GetCRL
                                                    ? Task.FromResult(new GetCRLResponse(PKIStatus.Accepted, "crl", payload.Value<String>("issuerId")).ToJSON())
                                                    : throw new PKIException(PKIErrorCodes.NotImplemented, $"not {action}")
                                        );

            await using var asking = new PKIMessageChannel(client.GetStream());

            var crl = GetCRLResponse.Parse(await asking.Request(PKIActions.GetCRL, new GetCRLRequest(IssuerId: "ab").ToJSON()));

            Assert.Multiple(() => {
                Assert.That(crl.Status,    Is.EqualTo(PKIStatus.Accepted));
                Assert.That(crl.CRL,       Is.EqualTo("crl"));
                Assert.That(crl.IssuerId,  Is.EqualTo("ab"));
            });

            var problem = await Assert.ThrowsAsync<PKIException>(async () => await asking.Request("Nothing", []));

            Assert.That(problem!.Code, Is.EqualTo(PKIErrorCodes.NotImplemented));

            // A line that is no message, but names an id: answered with an error
            // the asking end has nobody waiting for - and the channel lives on.
            await client.GetStream().WriteAsync(Encoding.UTF8.GetBytes("[9,\"x\"]\n"));

            crl = GetCRLResponse.Parse(await asking.Request(PKIActions.GetCRL, new GetCRLRequest(IssuerId: "cd").ToJSON()));

            Assert.That(crl.IssuerId, Is.EqualTo("cd"));

        }

        #endregion

        #region Channel_EndsWhenTheOtherEndGoes()

        /// <summary>
        /// The other end gone, the channel ends, and a request waiting is told so.
        /// </summary>
        [Test]
        public async Task Channel_EndsWhenTheOtherEndGoes()
        {

            var (client, server) = await TwoEnds();

            using var _client = client;

            await using var asking = new PKIMessageChannel(client.GetStream());

            var waiting = asking.Request(PKIActions.GetCRL, [], TimeSpan.FromSeconds(30));

            server.Dispose();

            Assert.That(async () => await waiting,               Throws.InstanceOf<IOException>());
            Assert.That(asking.Ended.Wait(TimeSpan.FromSeconds(5)), Is.True);

        }

        #endregion

        #region Connections_OfAPKI()

        /// <summary>
        /// A PKI is connected to, and a registration authority connects: both
        /// carry the messages of a PKI, and neither the other way round.
        /// </summary>
        [Test]
        public void Connections_OfAPKI()
        {

            var rules = new ConnectionRules();

            Assert.Multiple(() => {

                Assert.That(ConnectionEntry.UseOf(ConnectionType.PKI),                    Is.EqualTo(ConnectionUse.PKI));
                Assert.That(ConnectionEntry.UseOf(ConnectionType.RegistrationAuthority),  Is.EqualTo(ConnectionUse.PKI));
                Assert.That(ConnectionRules.Every,                                        Does.Contain(ConnectionType.PKI));

                Assert.That(ConnectionEntry.TryParseType("pki",                    out var pki), Is.True);
                Assert.That(ConnectionEntry.TryParseType("RegistrationAuthority",  out var ra),  Is.True);
                Assert.That(pki,  Is.EqualTo(ConnectionType.PKI));
                Assert.That(ra,   Is.EqualTo(ConnectionType.RegistrationAuthority));

                Assert.That(ProtocolVersion.PKI.ToString(), Is.EqualTo("PKI"));

            });

        }

        #endregion

        #region GetOCSPResponse_CarriesDERInBase64()

        /// <summary>
        /// GetOCSPResponse carries an OCSP request and its answer as the DER in
        /// Base64, and is refused what is no Base64 or too long.
        /// </summary>
        [Test]
        public void GetOCSPResponse_CarriesDERInBase64()
        {

            var der       = new Byte[] { 0x30, 0x03, 0x02, 0x01, 0x07 };
            var request   = GetOCSPResponseRequest.Parse(GetOCSPResponseRequest.Of(der).ToJSON());
            var response  = GetOCSPResponseResponse.Parse(new GetOCSPResponseResponse(PKIStatus.Rejected, Convert.ToBase64String(der), new PKIStatusInfo("UnknownCA")).ToJSON());

            Assert.Multiple(() => {

                Assert.That(PKIActions.All,                Does.Contain(PKIActions.GetOCSPResponse));
                Assert.That(request.DER,                   Is.EqualTo(der));
                Assert.That(response.Status,               Is.EqualTo(PKIStatus.Rejected));
                Assert.That(response.DER,                  Is.EqualTo(der));
                Assert.That(response.StatusInfo?.ReasonCode, Is.EqualTo("UnknownCA"));

                Assert.That(() => GetOCSPResponseRequest.Parse(new JObject(new JProperty("ocspRequest", "no base64!"))),
                            Throws.TypeOf<PKIException>());
                Assert.That(() => GetOCSPResponseRequest.Parse(new JObject(new JProperty("ocspRequest", new String('A', GetOCSPResponseRequest.MaxLength + 4)))),
                            Throws.TypeOf<PKIException>());
                Assert.That(() => GetOCSPResponseRequest.Parse(new JObject()),
                            Throws.TypeOf<PKIException>());
                Assert.That(() => GetOCSPResponseResponse.Parse(new JObject(new JProperty("status", "Accepted"), new JProperty("ocspResponse", "%%%"))),
                            Throws.TypeOf<PKIException>());

            });

        }

        #endregion

    }

}
