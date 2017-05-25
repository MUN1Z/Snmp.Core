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

namespace SnmpGetWalk
{
    class Program
    {
        static void Main(string[] args)
        {
            string community = "public";
            bool showVersion = false;
            VersionCode version = VersionCode.V1;
            int timeout = 5000;
            Levels level = Levels.Reportable;
            string user = string.Empty;
            string authentication = string.Empty;
            string authPhrase = string.Empty;
            string privacy = string.Empty;
            string privPhrase = string.Empty;
            bool dump = false;

            int maxRepetitions = 10;
            WalkMode mode = WalkMode.WithinSubtree;

            IPAddress ip;
            bool parsed = IPAddress.TryParse(args[0], out ip);
            if (!parsed)
            {

                if (ip == null)
                {
                    Console.WriteLine("invalid host or wrong IP address found: " + args[0]);
                    return;
                }
            }

            try
            {

                Oid test = new Oid("1.3.6.1.2.1"); // extra.Count == 1 ? new Oid("1.3.6.1.2.1") : new Oid(extra[1]);
                IList<Variable> result = new List<Variable>();
                IPEndPoint receiver = new IPEndPoint(ip, 161);
                if (version == VersionCode.V1)
                {
                    Messenger.Walk(version, receiver, new OctetString(community), test, result, timeout, mode);
                }
                else if (version == VersionCode.V2)
                {
                    Messenger.BulkWalk(version, receiver, new OctetString(community), test, result, timeout, maxRepetitions, mode, null, null);
                }
                else
                {
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

                    Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetBulkRequestPdu);
                    ReportMessage report = discovery.GetResponse(timeout, receiver);
                    Messenger.BulkWalk(version, receiver, new OctetString(user), test, result, timeout, maxRepetitions, mode, priv, report);
                }

                foreach (Variable variable in result)
                {
                    Console.WriteLine(variable);
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