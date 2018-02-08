// typical usage
// snmpget -c=public -v=1 localhost 1.3.6.1.2.1.1.1.0
// snmpget -v=3 -l=authPriv -a=MD5 -A=authentication -x=DES -X=privacy -u=user localhost 1.3.6.1.2.1.1.1.0
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Snmp.Standard;
using Snmp.Standard.Messaging;

namespace SnmpGet
{
    class Program
    {
        static void Main(string[] args)
        {
            string community = "Huawei01!";
            VersionCode version = VersionCode.V2;
            int timeout = 5000;
            
            try
            {
                List<String> extra = new List<String>();
                extra.Add("1.3.6.1.2.1.1.1.0");
                extra.Add("1.3.6.1.2.1.1.2.0");
                extra.Add("1.3.6.1.2.1.1.3.0");
                extra.Add("1.3.6.1.2.1.1.4.0");
                extra.Add("1.3.6.1.2.1.1.5.0");
                extra.Add("1.3.6.1.2.1.1.6.0");

                List <Variable> vList = new List<Variable>();
                for (int i = 0; i < extra.Count; i++)
                {
                    Variable test = new Variable(new Oid(extra[i]));
                    vList.Add(test);
                }

                IPEndPoint receiver = new IPEndPoint(IPAddress.Parse("10.60.13.7"), 161);
                if (version != VersionCode.V3)
                {
                    foreach (Variable variable in Messenger.Get(version, receiver, new OctetString(community), vList, timeout))
                    {
                        Console.WriteLine(variable);
                    }

                   Console.ReadKey();
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
    }
}