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

using NUnit.Framework;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.SecureShell;

#endregion

namespace cloud.charging.open.protocols.WWCP.Node.Tests
{

    /// <summary>
    /// The SSH access rules on their own: read strictly - a condition misspelt and ignored would let in
    /// what it was to keep out - and asked in order, the first that matches deciding; at sign-in, a rule
    /// that names a service lets the client in, to be asked again service by service.
    /// </summary>
    [TestFixture]
    public class SSHAccessRulesTests
    {

        #region (private) helpers

        private static SSHAccessRules Rules(params String[] Lines)

            => new ([ .. Lines.Select(line => SSHAccessRule.TryParseLine(line, out var rule, out var error)
                                                  ? rule
                                                  : throw new AssertionException($"'{line}': {error}")) ]);

        private static SSHAccessRequest Asking(String      Principal,
                                               String?     Service  = null,
                                               String?     Source   = "192.0.2.7",
                                               String?     Local    = "10.10.0.1",
                                               String      Auth     = "publickey",
                                               params String[] Groups)
        {

            var colon = Principal.IndexOf(':');

            return new SSHAccessRequest(new SSHPrincipal(Principal[..colon], Principal[(colon + 1)..], Groups),
                                        Service,
                                        Source is null ? null : IPAddress.Parse(Source),
                                        Local  is null ? null : IPAddress.Parse(Local),
                                        Auth);

        }

        private static String? Refusal(JObject JSON)
            => SSHAccessRule.TryParse(JSON, "ssh.accessRules[0]", out _, out var error) ? null : error;

        #endregion


        #region Rule_RoundTrips_AsJSON_AndAsALine

        [Test]
        public void Rule_RoundTrips_AsJSON_AndAsALine()
        {

            var json = JObject.Parse("""
                       { "action": "deny", "principal": "account:*", "service": "shell", "source": [ "10.0.0.0/8", "2001:db8::/32" ],
                         "localAddress": [ "10.10.0.1" ], "authMethod": [ "password" ], "comment": "the device network" }
                       """);

            Assert.That(SSHAccessRule.TryParse(json, "rule", out var rule, out var error), Is.True, error);
            Assert.That(SSHAccessRule.TryParseLine(rule!.ToString(), out var again, out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(rule.ToJSON().ToString(),  Is.EqualTo(json.ToString()));
                Assert.That(rule.ToString(),           Is.EqualTo("deny principal=account:* service=shell source=10.0.0.0/8,2001:db8::/32 local=10.10.0.1 auth=password # the device network"));
                Assert.That(again!.ToJSON().ToString(), Is.EqualTo(json.ToString()));
            });

        }

        #endregion

        #region Rules_MayBeWrittenAsLines_InTheFile

        [Test]
        public void Rules_MayBeWrittenAsLines_InTheFile()
        {

            Assert.That(SSHAccessRules.TryParse(JArray.Parse("""[ "deny principal=account:* local=10.10.0.1", { "action": "allow" } ]"""), "ssh.accessRules", out var rules, out var error), Is.True, error);

            Assert.That(rules!.Rules.Select(rule => rule.ToString()), Is.EqualTo(new[] { "deny principal=account:* local=10.10.0.1", "allow" }));

        }

        #endregion

        #region Rule_ThatCannotBeRead_IsRefused_AndSaysWhy

        [TestCase("""{ "action": "deny", "sourse": [ "10.0.0.0/8" ] }""",       "sourse",            TestName = "Refused_AMisspeltCondition")]
        [TestCase("""{ "principal": "account:*" }""",                            "action",            TestName = "Refused_NoAction")]
        [TestCase("""{ "action": "drop" }""",                                    "action",            TestName = "Refused_AnUnknownAction")]
        [TestCase("""{ "action": "deny", "principal": "root" }""",               "principal",         TestName = "Refused_APrincipalWithoutItsKind")]
        [TestCase("""{ "action": "deny", "principal": "account:" }""",           "principal",         TestName = "Refused_APrincipalWithoutAName")]
        [TestCase("""{ "action": "deny", "principal": "acc ount:x" }""",         "principal",         TestName = "Refused_APrincipalKindWithASpace")]
        [TestCase("""{ "action": "deny", "service": "telnet" }""",               "telnet",            TestName = "Refused_AnUnknownService")]
        [TestCase("""{ "action": "deny", "service": "subsystem:" }""",           "service",           TestName = "Refused_ASubsystemWithoutAName")]
        [TestCase("""{ "action": "deny", "source": [ "10.0.0.1/8" ] }""",        "host bits",         TestName = "Refused_ANetworkWithHostBits")]
        [TestCase("""{ "action": "deny", "source": [ "10.0.0.0/33" ] }""",       "prefix",            TestName = "Refused_APrefixTooLong")]
        [TestCase("""{ "action": "deny", "source": [ "10.0.0.0/+8" ] }""",       "prefix",            TestName = "Refused_APrefixWithASign")]
        [TestCase("""{ "action": "deny", "source": [ "fe80::1%3" ] }""",         "no IP address",     TestName = "Refused_AScopedAddress")]
        [TestCase("""{ "action": "deny", "source": [ "lc.example.org" ] }""",    "no IP address",     TestName = "Refused_AName")]
        [TestCase("""{ "action": "deny", "source": [] }""",                      "names no address",  TestName = "Refused_NoAddressAtAll")]
        [TestCase("""{ "action": "deny", "localAddress": [ 7 ] }""",             "localAddress",      TestName = "Refused_ANumberForAnAddress")]
        [TestCase("""{ "action": "deny", "authMethod": [ "hostbased" ] }""",     "hostbased",         TestName = "Refused_AnUnknownMethod")]
        public void Rule_ThatCannotBeRead_IsRefused_AndSaysWhy(String JSON, String Said)
        {

            var error = Refusal(JObject.Parse(JSON));

            Assert.Multiple(() => {
                Assert.That(error, Is.Not.Null, "the rule was taken");
                Assert.That(error, Does.Contain(Said));
                Assert.That(error, Does.Contain("ssh.accessRules[0]"), "the error does not say which rule");
            });

        }

        [Test]
        public void Rules_TooManyOrNotRules_AreRefused()
        {

            var many = new JArray(Enumerable.Range(0, SSHAccessRules.MaxRules + 1).Select(_ => new JObject { ["action"] = "allow" }));

            Assert.Multiple(() => {
                Assert.That(SSHAccessRules.TryParse(many,                      "ssh.accessRules", out _, out var tooMany), Is.False);
                Assert.That(SSHAccessRules.TryParse(JArray.Parse("[ 7 ]"),     "ssh.accessRules", out _, out var notARule), Is.False);
                Assert.That(SSHAccessRules.TryParse(new JObject(),             "ssh.accessRules", out _, out var notAList), Is.False);
                Assert.That(SSHAccessRule.TryParseLine("deny colour=red",      out _, out var unknownWord), Is.False);
                Assert.That(SSHAccessRule.TryParseLine("deny account:*",       out _, out var noEquals),    Is.False);
                Assert.That(SSHAccessRule.TryParseLine("drop principal=a:b",   out _, out var noAction),    Is.False);
                Assert.That(unknownWord, Does.Contain("colour"));
                Assert.That(noEquals,    Does.Contain("account:*"));
                Assert.That(noAction,    Does.Contain("allow or deny"));
            });

        }

        #endregion


        #region TheFirstRuleThatMatches_Decides

        [Test]
        public void TheFirstRuleThatMatches_Decides()
        {

            var rules = Rules("allow principal=account:root",
                              "deny principal=account:*",
                              "allow");

            Assert.Multiple(() => {
                Assert.That(rules.For(Asking("account:root",   "shell")).Allowed, Is.True,  "the first rule, not the second");
                Assert.That(rules.For(Asking("account:viewer", "shell")).Number,  Is.EqualTo(2));
                Assert.That(rules.For(Asking("account:viewer", "shell")).Allowed, Is.False);
                Assert.That(rules.For(Asking("station:cs001",  "shell")).Number,  Is.EqualTo(3));
                Assert.That(Rules().For(Asking("account:root", "shell")),         Is.EqualTo(SSHAccessDecision.NoRule));
            });

        }

        #endregion

        #region AtSignIn_ARuleWithAServiceLetsIn_ToBeAskedServiceByService

        /// <summary>
        /// A station let in for OCPP alone: at the door the first rule names a service, so it is let in -
        /// and then has OCPP, and nothing else.
        /// </summary>
        [Test]
        public void AtSignIn_ARuleWithAServiceLetsIn_ToBeAskedServiceByService()
        {

            var rules = Rules("allow principal=station:* service=subsystem:ocpp@open.charging.cloud",
                              "deny principal=station:*");

            Assert.Multiple(() => {
                Assert.That(rules.ForSignIn(Asking("station:cs001")).Allowed,                                         Is.True,  "refused at the door");
                Assert.That(rules.For(Asking("station:cs001", "subsystem:ocpp@open.charging.cloud")).Allowed,         Is.True);
                Assert.That(rules.For(Asking("station:cs001", "shell")).Allowed,                                      Is.False, "the shell");
                Assert.That(rules.For(Asking("station:cs001", "sftp")).Allowed,                                       Is.False, "SFTP");
                Assert.That(rules.For(Asking("station:cs001", "subsystem:wwcp@open.charging.cloud")).Allowed,         Is.False, "another subsystem");
            });

        }

        [Test]
        public void AtSignIn_ARuleWithoutAServiceDecides()
        {

            var rules = Rules("deny principal=account:* local=10.10.0.1 # not on the device network");

            Assert.Multiple(() => {
                Assert.That(rules.ForSignIn(Asking("account:root", Local: "10.10.0.1")).Allowed,  Is.False);
                Assert.That(rules.ForSignIn(Asking("account:root", Local: "192.0.2.10")).Allowed, Is.True);
                Assert.That(rules.ForSignIn(Asking("station:cs001", Local: "10.10.0.1")).Allowed, Is.True);
            });

        }

        #endregion

        #region AnAddressNotKnown_MatchesADenyAndNoAllow

        [Test]
        public void AnAddressNotKnown_MatchesADenyAndNoAllow()
        {

            var denying  = Rules("deny source=10.0.0.0/8");
            var allowing = Rules("allow principal=account:root source=10.0.0.0/8", "deny principal=account:root");

            Assert.Multiple(() => {
                Assert.That(denying. For(Asking("account:root", "shell", Source: null)).Allowed, Is.False, "an unknown address passed a deny");
                Assert.That(allowing.For(Asking("account:root", "shell", Source: null)).Number,  Is.EqualTo(2), "an unknown address passed an allow");
            });

        }

        #endregion

        #region Addresses_Networks_AndIPv4Mapped

        [Test]
        public void Addresses_Networks_AndIPv4Mapped()
        {

            var rules = Rules("deny source=10.0.0.0/8,2001:db8::/32", "deny local=::ffff:192.0.2.10");

            Assert.Multiple(() => {
                Assert.That(rules.For(Asking("account:a", "shell", Source: "10.200.1.1")).Number,          Is.EqualTo(1));
                Assert.That(rules.For(Asking("account:a", "shell", Source: "::ffff:10.200.1.1")).Number,   Is.EqualTo(1), "an IPv4-mapped client slipped past an IPv4 network");
                Assert.That(rules.For(Asking("account:a", "shell", Source: "2001:db8:1::5")).Number,       Is.EqualTo(1));
                Assert.That(rules.For(Asking("account:a", "shell", Source: "11.0.0.1")).Number,            Is.Null);
                Assert.That(rules.For(Asking("account:a", "shell", Source: "11.0.0.1", Local: "192.0.2.10")).Number, Is.EqualTo(2), "a rule written IPv4-mapped did not match the IPv4 address");
            });

        }

        #endregion

        #region Principals_Wildcards_LetterCase_AndGroups

        [Test]
        public void Principals_Wildcards_LetterCase_AndGroups()
        {

            var rules = Rules("deny principal=account:adm*",
                              "deny principal=station:cs00?",
                              "deny principal=group:support",
                              "deny service=subsystem:*@open.charging.cloud");

            Assert.Multiple(() => {
                Assert.That(rules.For(Asking("account:ADMIN",   "shell")).Number,                          Is.EqualTo(1), "letter case");
                Assert.That(rules.For(Asking("account:xadmin", "shell")).Number,                          Is.Null,       "a wildcard matched in the middle");
                Assert.That(rules.For(Asking("station:cs007",  "shell")).Number,                          Is.EqualTo(2));
                Assert.That(rules.For(Asking("station:cs0071", "shell")).Number,                          Is.Null,       "? matched two characters");
                Assert.That(rules.For(Asking("account:bob",    "shell", Groups: [ "Support" ])).Number,   Is.EqualTo(3), "a group");
                Assert.That(rules.For(Asking("account:bob",    "subsystem:ocpp@open.charging.cloud")).Number, Is.EqualTo(4));
                Assert.That(rules.For(Asking("account:bob",    "subsystem:sftp-ext@example.org")).Number, Is.Null);
                Assert.That(rules.For(Asking("account:bob",    "sftp")).Number,                           Is.Null,       "a subsystem rule matched SFTP");
            });

        }

        #endregion

        #region AuthMethods

        [Test]
        public void AuthMethods()
        {

            var rules = Rules("deny auth=password");

            Assert.Multiple(() => {
                Assert.That(rules.For(Asking("account:a", "shell", Auth: "password")).Allowed,   Is.False);
                Assert.That(rules.For(Asking("account:a", "shell", Auth: "publickey")).Allowed,  Is.True);
            });

        }

        #endregion

    }

}
