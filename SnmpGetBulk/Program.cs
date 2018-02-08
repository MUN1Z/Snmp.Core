// typical usage
// snmpget -c=public -v=1 localhost 1.3.6.1.2.1.1.1.0
// snmpget -v=3 -l=authPriv -a=MD5 -A=authentication -x=DES -X=privacy -u=user localhost 1.3.6.1.2.1.1.1.0
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Snmp.Core;
using Snmp.Core.Security;
using Snmp.Core.Messaging;

namespace SnmpGetBulk
{
    class Program
    {
        static void Main(string[] args)
        {
            string community = "public";
            bool showVersion = false;
            VersionCode version = VersionCode.V2;
            int timeout = 10000;
            Levels level = Levels.Reportable;
            string user = string.Empty;
            string authentication = string.Empty;
            string authPhrase = string.Empty;
            string privacy = string.Empty;
            string privPhrase = string.Empty;
            bool dump = false;

            int maxRepetitions = 10;
            int nonRepeaters = 0;

            if (showVersion)
            {
                Console.WriteLine(System.Reflection.Assembly.GetEntryAssembly().GetName().Version);
                return;
            }
            
            try
            {
                List<String> extra = new List<String>();
                extra.Add("1.3.6.1.2.1.1.1.0");
                extra.Add("1.3.6.1.2.1.1.2.0");
                //extra.Add("1.3.6.1.2.1.1.3.0");
                extra.Add("1.3.6.1.2.1.1.5.0");
                //extra.Add("1.3.6.1.2.1.1.6.0");
                //extra.Add("1.3.6.1.2.1.1.7.0");

                List<Variable> vList = new List<Variable>();
                for (int i = 0; i < extra.Count; i++)
                {
                    Variable test = new Variable(new Oid(extra[i]));
                    vList.Add(test);
                }

                IPEndPoint receiver = new IPEndPoint(IPAddress.Parse("10.60.13.7"), 161);
                if (version != VersionCode.V3)
                {
                    GetBulkRequestMessage message = new GetBulkRequestMessage(0, version,
                                                                              new OctetString(community),
                                                                              nonRepeaters,
                                                                              maxRepetitions,
                                                                              vList);

                    ISnmpMessage response = message.GetResponse(timeout, receiver);
                    if (response.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                    {
                        throw ErrorException.Create(
                            "error in response",
                            receiver.Address,
                            response);
                    }

                    foreach (Variable variable in response.Pdu().Variables)
                    {
                        Console.WriteLine(variable);
                    }

                    return;
                }
            

                if (string.IsNullOrEmpty(user))
                {
                    Console.WriteLine("User name need to be specified for v3.");
                    return;
                }

                IAuthenticationProvider auth = (level & Levels.Authentication) == Levels.Authentication
                                                   ? GetAuthenticationProviderByName(authentication, authPhrase)
                                                   : DefaultAuthenticationProvider.Instance;

                IPrivacyProvider priv;
                if ((level & Levels.Privacy) == Levels.Privacy)
                {
                    priv = new DESPrivacyProvider(new OctetString(privPhrase), auth);
                }
                else
                {
                    priv = new DefaultPrivacyProvider(auth);
                }

                Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                ReportMessage report = discovery.GetResponse(timeout, receiver);

                GetRequestMessage request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(user), vList, priv, Messenger.MaxMessageSize, report);
                ISnmpMessage reply = request.GetResponse(timeout, receiver);

                if (dump)
                {
                    Console.WriteLine("Request message bytes:");
                    Console.WriteLine(ByteTool.Convert(request.ToBytes()));
                    Console.WriteLine("Response message bytes:");
                    Console.WriteLine(ByteTool.Convert(reply.ToBytes()));
                }

                if (reply is ReportMessage)
                {
                    if (reply.Pdu().Variables.Count == 0)
                    {
                        Console.WriteLine("wrong report message received");
                        return;
                    }

                    var id = reply.Pdu().Variables[0].Id;
                    if (id != Messenger.NotInTimeWindow)
                    {
                        var error = id.GetErrorMessage();
                        Console.WriteLine(error);
                        return;
                    }

                    // according to RFC 3414, send a second request to sync time.
                    request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(user), vList, priv, Messenger.MaxMessageSize, reply);
                    reply = request.GetResponse(timeout, receiver);
                }
                else if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                {
                    throw ErrorException.Create(
                        "error in response",
                        receiver.Address,
                        reply);
                }

                foreach (Variable v in reply.Pdu().Variables)
                {
                    Console.WriteLine(v);
                }
            }
            catch (SnmpException ex)
            {
                Console.WriteLine(ex);
            }
            catch (SocketException ex)
            {
                Console.WriteLine(ex);
            }
        }

        private static IAuthenticationProvider GetAuthenticationProviderByName(string authentication, string phrase)
        {
            if (authentication.ToUpperInvariant() == "MD5")
            {
                return new MD5AuthenticationProvider(new OctetString(phrase));
            }

            if (authentication.ToUpperInvariant() == "SHA")
            {
                return new SHA1AuthenticationProvider(new OctetString(phrase));
            }

            throw new ArgumentException("unknown name", "authentication");
        }

    }
}