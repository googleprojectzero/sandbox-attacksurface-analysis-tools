//  Copyright 2015 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

using SandboxAnalysisUtils;
using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace CheckNetworkAccess
{
    class Program
    {
        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckNetworkAccess [options] address port");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static IPEndPoint ParseEndpoint(string address, string port)
        {            
            return new IPEndPoint(IPAddress.Parse(address), int.Parse(port));
        }

        static void ConnectTest(int pid, IPEndPoint ep)
        {
            using (var imp = NtToken.Impersonate(pid, SecurityImpersonationLevel.Impersonation))
            {
                TcpClient client = new TcpClient();
                client.Connect(ep);
                client.Close();

                Console.WriteLine("** Opened Connection **");
            }
        }

        static void ListenTest(int pid, IPEndPoint ep)
        {
            using (var imp = NtToken.Impersonate(pid, SecurityImpersonationLevel.Impersonation))
            {
                TcpListener listener = new TcpListener(ep);

                listener.Start();

                Console.WriteLine("Make a connection to {0}", ep);

                listener.AcceptTcpClient();

                Console.WriteLine("** Accepted Connection **");
            }
        }

        static void Main(string[] args)
        {
            int pid = Process.GetCurrentProcess().Id;
            bool show_help = false;
            bool test_listen = false;

            try
            {
                OptionSet opts = new OptionSet() {                        
                            { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },  
                            { "l", "Test binding/listening on a socket", v => test_listen = v != null },
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                        };

                List<string> eps = opts.Parse(args);

                if (show_help || (eps.Count != 2))
                {
                    ShowHelp(opts);
                }
                else
                {
                    if (test_listen)
                    {
                        ListenTest(pid, ParseEndpoint(eps[0], eps[1]));
                    }
                    else
                    {
                        ConnectTest(pid, ParseEndpoint(eps[0], eps[1]));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
