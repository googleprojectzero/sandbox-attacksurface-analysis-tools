//  Copyright 2015, 2017 Google Inc. All Rights Reserved.
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

using Microsoft.Win32.SafeHandles;
using NDesk.Options;
using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace CheckServiceAccess
{
    class Program
    {
        class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [DllImport("Advapi32.dll", SetLastError = true)]
            static extern bool CloseServiceHandle(IntPtr hSCObject);

            public SafeServiceHandle() : base(true)
            {
            }

            protected override bool ReleaseHandle()
            {
                return CloseServiceHandle(handle);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SERVICE_TRIGGER_INFO
        {
            public int cTriggers;
            public IntPtr pTriggers;
            public IntPtr pReserved;
        }

        enum ServiceTriggerType
        {
            DeviceInterfaceArrival = 1,
            IPAddressAvailability = 2,
            DomainJoin = 3,
            FirewallPortEvent = 4,
            GroupPolicy = 5,
            NetworkEndpoint = 6,
            CustomSystemStateChange = 7,
            Custom = 20,
            Aggregate = 30,
        }

        enum ServiceTriggerDataType
        {
            Binary = 1,
            String = 2,
            Level = 3,
            KeywordAny = 4,
            KeywordAll = 5,
        }

        enum ServiceTriggerAction
        {
            Start = 1,
            Stop = 2
        }

        static Guid NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID = new Guid("4f27f2de-14e2-430b-a549-7cd48cbc8245");
        static Guid NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID = new Guid("cc4ba62a-162e-4648-847a-b6bdf993e335");
        static Guid DOMAIN_JOIN_GUID = new Guid("1ce20aba-9851-4421-9430-1ddeb766e809");
        static Guid DOMAIN_LEAVE_GUID = new Guid("ddaf516e-58c2-4866-9574-c3b615d42ea1");
        static Guid FIREWALL_PORT_OPEN_GUID = new Guid("b7569e07-8421-4ee0-ad10-86915afdad09");
        static Guid FIREWALL_PORT_CLOSE_GUID = new Guid("a144ed38-8e12-4de4-9d96-e64740b1a524");
        static Guid MACHINE_POLICY_PRESENT_GUID = new Guid("659FCAE6-5BDB-4DA9-B1FF-CA2A178D46E0");
        static Guid USER_POLICY_PRESENT_GUID = new Guid("54FB46C8-F089-464C-B1FD-59D1B62C3B50");
        static Guid RPC_INTERFACE_EVENT_GUID = new Guid("bc90d167-9470-4139-a9ba-be0bbbf5b74d");
        static Guid NAMED_PIPE_EVENT_GUID = new Guid("1f81d131-3fac-4537-9e0c-7e7b0c2f4b55");
        static Guid CUSTOM_SYSTEM_STATE_CHANGE_EVENT_GUID = new Guid("2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9");


        [StructLayout(LayoutKind.Sequential)]
        struct SERVICE_TRIGGER
        {
            public ServiceTriggerType dwTriggerType;
            public ServiceTriggerAction dwAction;
            public IntPtr pTriggerSubtype;
            public int cDataItems;
            public IntPtr pDataItems;

            public Guid GetSubType()
            {
                if (pTriggerSubtype != IntPtr.Zero)
                {
                    return Marshal.PtrToStructure<Guid>(pTriggerSubtype);
                }
                return Guid.Empty;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SERVICE_TRIGGER_SPECIFIC_DATA_ITEM
        {
            public ServiceTriggerDataType dwDataType;
            public int cbData;
            public IntPtr pData;
        }

        const int SERVICE_CONFIG_TRIGGER_INFO = 8;

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeServiceHandle OpenSCManager(string lpMachineName, string lpDatabaseName, ServiceControlManagerAccessRights dwDesiredAccess);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeServiceHandle OpenService(
              SafeServiceHandle hSCManager,
              string lpServiceName,
              ServiceAccessRights dwDesiredAccess
            );

        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(SafeServiceHandle hService, 
            SecurityInformation dwSecurityInformation, 
            [Out] byte[] lpSecurityDescriptor, 
            int cbBufSize, 
            out int pcbBytesNeeded);

        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceConfig2(
          SafeServiceHandle hService,
          int dwInfoLevel,
          SafeBuffer lpBuffer,
          int cbBufSize,
          out int pcbBytesNeeded
        );

        [Flags]
        enum ServiceControlManagerAccessRights : uint
        {
            CreateService = 0x0002,
            Connect = 0x0001,
            EnumerateService= 0x0004,
            Lock = 0x0008,
            ModifyBootConfig = 0x0020,
            QueryLockStatus = 0x0010,
            All = CreateService | Connect | EnumerateService 
                | Lock | ModifyBootConfig | QueryLockStatus | ReadControl 
                | Delete | WriteDac | WriteOwner,
            GenericRead = GenericAccessRights.GenericRead,
            GenericWrite = GenericAccessRights.GenericWrite,
            GenericExecute = GenericAccessRights.GenericExecute,
            GenericAll = GenericAccessRights.GenericAll,
            Delete = GenericAccessRights.Delete,
            ReadControl = GenericAccessRights.ReadControl,
            WriteDac = GenericAccessRights.WriteDac,
            WriteOwner = GenericAccessRights.WriteOwner,
            Synchronize = GenericAccessRights.Synchronize,
            MaximumAllowed = GenericAccessRights.MaximumAllowed,
            AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
        }

        [Flags]
        enum ServiceAccessRights : uint
        {
            ChangeConfig   = 0x0002,
            EnumerateDependents  = 0x0008,
            Interrogate  = 0x0080,	
            PauseContinue  = 0x0040,
            QueryConfig = 0x0001,	
            QueryStatus  = 0x0004,	
            Start  = 0x0010,
            Stop  = 0x0020,
            UserDefinedControl = 0x0100,
            All = ChangeConfig | EnumerateDependents | Interrogate | PauseContinue 
                | QueryStatus | QueryConfig | Start | Stop | UserDefinedControl | ReadControl
                | Delete | WriteDac | WriteOwner,
            GenericRead = GenericAccessRights.GenericRead,
            GenericWrite = GenericAccessRights.GenericWrite,
            GenericExecute = GenericAccessRights.GenericExecute,
            GenericAll = GenericAccessRights.GenericAll,
            Delete = GenericAccessRights.Delete,
            ReadControl = GenericAccessRights.ReadControl,
            WriteDac = GenericAccessRights.WriteDac,
            WriteOwner = GenericAccessRights.WriteOwner,
            Synchronize = GenericAccessRights.Synchronize,
            MaximumAllowed = GenericAccessRights.MaximumAllowed,
            AccessSystemSecurity = GenericAccessRights.AccessSystemSecurity
        }

        static GenericMapping GetSCMGenericMapping()
        {
            GenericMapping mapping = new GenericMapping();
            mapping.GenericRead = (uint)(ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.EnumerateService | ServiceControlManagerAccessRights.QueryLockStatus);
            mapping.GenericWrite = (uint)(ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.CreateService | ServiceControlManagerAccessRights.ModifyBootConfig);
            mapping.GenericExecute = (uint)(ServiceControlManagerAccessRights.ReadControl | ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.Lock);
            mapping.GenericAll = (uint)ServiceControlManagerAccessRights.All;
            return mapping;
        }

        static GenericMapping GetServiceGenericMapping()
        {
            GenericMapping mapping = new GenericMapping();
            mapping.GenericRead = (uint)(ServiceAccessRights.ReadControl | ServiceAccessRights.QueryConfig | ServiceAccessRights.QueryStatus | ServiceAccessRights.Interrogate | ServiceAccessRights.EnumerateDependents);
            mapping.GenericWrite = (uint)(ServiceAccessRights.ReadControl | ServiceAccessRights.ChangeConfig);
            mapping.GenericExecute = (uint)(ServiceAccessRights.ReadControl | ServiceAccessRights.Start | ServiceAccessRights.Stop | ServiceAccessRights.PauseContinue | ServiceAccessRights.UserDefinedControl);
            mapping.GenericAll = (uint)ServiceAccessRights.All;
            return mapping;
        }

        static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage: CheckServiceAccess [options] [service1..serviceN]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }

        static uint GetGrantedAccess(SecurityDescriptor sd, NtToken token, uint specific_rights, GenericMapping generic_mapping)
        {
            uint granted_access = 0;
            specific_rights = generic_mapping.MapMask(specific_rights);

            if (specific_rights != 0)
            {
                granted_access = NtSecurity.GetAllowedAccess(sd, token, (GenericAccessRights)(specific_rights), generic_mapping);
            }
            else
            {
                granted_access = NtSecurity.GetMaximumAccess(sd, token, generic_mapping);
            }

            if (granted_access != 0)
            {
                // As we can get all the rights for the key get maximum
                if (specific_rights != 0)
                {
                    granted_access = NtSecurity.GetMaximumAccess(sd, token, generic_mapping);
                }
            }

            return granted_access;
        }

        static SecurityDescriptor GetServiceSecurityDescriptor(SafeServiceHandle handle)
        {
            int required = 0;
            byte[] sd = new byte[8192];
            if (!QueryServiceObjectSecurity(handle, SecurityInformation.AllBasic, sd, sd.Length, out required))
            {
                throw new Win32Exception();
            }

            return new SecurityDescriptor(sd);
        }

        static uint ParseRight(string name, Type enumtype)
        {
            return (uint)Enum.Parse(enumtype, name, true);
        }

        static bool HasWriteAccess(uint granted_access)
        {
            GenericMapping generic_mapping = GetServiceGenericMapping();
            if ((granted_access & (uint)(SectionAccessRights.WriteDac | SectionAccessRights.WriteOwner)) != 0)
            {
                return true;
            }

            granted_access &= 0xFFFF;
            return (granted_access & generic_mapping.GenericWrite) != 0;
        }

        static void ReadArray<T>(IntPtr ptr, int count, out T[] ret) where T : struct
        {
            ret = new T[count];
            using (SafeHGlobalBuffer buffer = new SafeHGlobalBuffer(ptr, count * Marshal.SizeOf(typeof(T)), false))
            {
                buffer.ReadArray(0, ret, 0, count);
            }
        }

        static void DumpCustomData(SERVICE_TRIGGER trigger)
        {
            SERVICE_TRIGGER_SPECIFIC_DATA_ITEM[] data_items;
            ReadArray(trigger.pDataItems, trigger.cDataItems, out data_items);
            for (int i = 0; i < data_items.Length; ++i)
            {
                var data_item = data_items[i];
                Console.WriteLine("Data Item: {0} - Type: {1} - Size: {2}", i, data_item.dwDataType, data_item.cbData);
                if (data_item.pData != IntPtr.Zero && data_item.cbData > 0)
                {
                    switch (data_item.dwDataType)
                    {
                        case ServiceTriggerDataType.Level:
                            if (data_item.cbData == 1)
                            {
                                Console.WriteLine("Data: 0x{0:X02}", Marshal.ReadByte(data_item.pData));
                            }
                            break;
                        case ServiceTriggerDataType.KeywordAny:
                        case ServiceTriggerDataType.KeywordAll:
                            if (data_item.cbData == 8)
                            {
                                Console.WriteLine("Data: 0x{0:X016}", Marshal.ReadInt64(data_item.pData));
                            }
                            break;
                        case ServiceTriggerDataType.String:
                            if ((data_item.cbData & 1) == 0)
                            {
                                string[] ss = Marshal.PtrToStringUni(data_item.pData, data_item.cbData / 2).TrimEnd('\0').Split('\0');
                                if (ss.Length == 1)
                                {
                                    Console.WriteLine("Data: {0}", ss[0]);
                                }
                                else
                                {
                                    for (int j = 0; j < ss.Length; ++j)
                                    {
                                        Console.WriteLine("Data[{0}]: {1}", j, ss[j]);
                                    }
                                }
                            }
                            break;
                        case ServiceTriggerDataType.Binary:
                        default:
                            {
                                byte[] data = new byte[data_item.cbData];
                                Marshal.Copy(data_item.pData, data, 0, data.Length);
                                Console.WriteLine("Data: [{0}]", String.Join(",", data.Select(b => String.Format("0x{0:X02}", b))));
                            }
                            break;
                    }
                }
            }
        }

        static void DumpTriggers(SafeServiceHandle service)
        {
            using (var buf = new SafeStructureInOutBuffer<SERVICE_TRIGGER_INFO>(8192, false))
            {
                int required = 0;
                if (!QueryServiceConfig2(service, SERVICE_CONFIG_TRIGGER_INFO, buf, 8192, out required))
                {
                    return;
                }

                SERVICE_TRIGGER_INFO trigger_info = buf.Result;
                if (trigger_info.cTriggers == 0)
                {
                    return;
                }

                SERVICE_TRIGGER[] trigger_arr;
                using (SafeHGlobalBuffer triggers = new SafeHGlobalBuffer(trigger_info.pTriggers, trigger_info.cTriggers * Marshal.SizeOf(typeof(SERVICE_TRIGGER)), false))
                {
                    trigger_arr = new SERVICE_TRIGGER[trigger_info.cTriggers];
                    triggers.ReadArray(0, trigger_arr, 0, trigger_arr.Length);
                }
                for(int i = 0; i < trigger_arr.Length; ++i)
                {
                    SERVICE_TRIGGER trigger = trigger_arr[i];
                    Console.WriteLine("Trigger: {0} - Type: {1} - Action: {2}", i, trigger.dwTriggerType, trigger.dwAction);
                    switch (trigger.dwTriggerType)
                    {
                        case ServiceTriggerType.Custom:
                            Console.WriteLine("Subtype: [ETW UUID] {0:B}", trigger.GetSubType());
                            break;
                        case ServiceTriggerType.DeviceInterfaceArrival:
                            Console.WriteLine("Subtype: [Interface Class GUID] {0:B}", trigger.GetSubType());
                            break;
                        case ServiceTriggerType.GroupPolicy:
                            {
                                Guid sub_type = trigger.GetSubType();
                                if (sub_type == MACHINE_POLICY_PRESENT_GUID)
                                {
                                    Console.WriteLine("Subtype: [Machine Policy Present]");
                                }
                                else if (sub_type == USER_POLICY_PRESENT_GUID)
                                {
                                    Console.WriteLine("Subtype: [User Policy Present]");
                                }
                                else
                                {
                                    Console.WriteLine("Subtype: [Unknown Group Policy] {0:B}", sub_type);
                                }
                            }
                            break;
                        case ServiceTriggerType.NetworkEndpoint:
                            {
                                Guid sub_type = trigger.GetSubType();
                                if (sub_type == RPC_INTERFACE_EVENT_GUID)
                                {
                                    Console.WriteLine("Subtype: [RPC Interface]");
                                }
                                else if (sub_type == NAMED_PIPE_EVENT_GUID)
                                {
                                    Console.WriteLine("Subtype: [Named Pipe]");
                                }
                                else
                                {
                                    Console.WriteLine("Subtype: [Unknown Network Endpoint] {0:B}", sub_type);
                                }
                            }
                            break;
                        case ServiceTriggerType.DomainJoin:
                            {
                                Guid sub_type = trigger.GetSubType();
                                if (sub_type == DOMAIN_JOIN_GUID)
                                {
                                    Console.WriteLine("Subtype: [Domain Join]");
                                }
                                else if (sub_type == DOMAIN_LEAVE_GUID)
                                {
                                    Console.WriteLine("Subtype: [Domain Leave]");
                                }
                                else
                                {
                                    Console.WriteLine("Subtype: [Unknown Domain Join] {0:B}", sub_type);
                                }
                            }
                            break;
                        case ServiceTriggerType.IPAddressAvailability:
                            {
                                Guid sub_type = trigger.GetSubType();
                                if (sub_type == NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID)
                                {
                                    Console.WriteLine("Subtype: [First IP Address Available]");
                                }
                                else if (sub_type == NETWORK_MANAGER_LAST_IP_ADDRESS_REMOVAL_GUID)
                                {
                                    Console.WriteLine("Subtype: [Last IP Address Available]");
                                }
                                else
                                {
                                    Console.WriteLine("Subtype: [Unknown IP Address Availability] {0:B}", sub_type);
                                }
                            }
                            break;
                    }

                    if (trigger.pDataItems != IntPtr.Zero && trigger.cDataItems > 0)
                    {
                        DumpCustomData(trigger);
                    }
                }
            }
        }

        static void DumpService(SafeServiceHandle scm, string name, NtToken token, uint service_rights, bool show_write_only, bool print_sddl, bool dump_triggers)
        {
            using (SafeServiceHandle service = OpenService(scm, name, ServiceAccessRights.QueryConfig | ServiceAccessRights.ReadControl))
            {
                if (!service.IsInvalid)
                {
                    GenericMapping generic_mapping = GetServiceGenericMapping();
                    SecurityDescriptor sd = GetServiceSecurityDescriptor(service);
                    uint granted_access = GetGrantedAccess(sd, token, service_rights, generic_mapping);

                    if (granted_access != 0 && !show_write_only || HasWriteAccess(granted_access))
                    {
                        Console.WriteLine("{0} Granted Access: {1}", name, (ServiceAccessRights)granted_access);
                        if (print_sddl)
                        {
                            Console.WriteLine("{0} SDDL: {1}", name, sd.ToSddl());
                        }
                        if (dump_triggers)
                        {
                            DumpTriggers(service);
                        }
                    }
                }
                else
                {
                    throw new Win32Exception();
                }
            }
        }

        static bool Test(string s)
        {
            return s != null;
        }
        
        static void Main(string[] args)
        {
            bool show_help = false;

            int pid = Process.GetCurrentProcess().Id;
            bool show_write_only = false;
            bool print_sddl = false;
            bool dump_triggers = false;
            bool dump_scm = false;
            uint service_rights = 0;
            bool quiet = false;

            try
            {
                OptionSet opts = new OptionSet() {
                        { "sddl", "Print full SDDL security descriptors", v => print_sddl = v != null },
                        { "p|pid=", "Specify a PID of a process to impersonate when checking", v => pid = int.Parse(v.Trim()) },
                        { "w", "Show only write permissions granted", v => show_write_only = v != null },
                        { "k=", String.Format("Filter on a specific right [{0}]",
                            String.Join(",", Enum.GetNames(typeof(ServiceAccessRights)))),
                            v => service_rights |= ParseRight(v, typeof(ServiceAccessRights)) },
                        { "t", "Dump trigger information for services", v => dump_triggers = v != null },
                        { "scm", "Dump SCM security information", v => dump_scm = v != null },
                        { "q", "Don't print our errors", v => quiet = v != null },
                        { "h|help",  "show this message and exit", v => show_help = v != null },
                    };

                List<string> service_names = opts.Parse(args);

                if (show_help)
                {
                    ShowHelp(opts);
                }
                else
                {
                    if (service_names.Count == 0)
                    {
                        service_names.AddRange(ServiceController.GetServices().Select(s => s.ServiceName));
                    }

                    using (NtToken token = NtToken.OpenProcessToken(pid))
                    {
                        using (SafeServiceHandle scm = OpenSCManager(null, null, ServiceControlManagerAccessRights.Connect | ServiceControlManagerAccessRights.ReadControl))
                        {
                            if (dump_scm)
                            {
                                SecurityDescriptor sd = GetServiceSecurityDescriptor(scm);
                                Console.WriteLine("SCM Granted Access: {0}", (ServiceControlManagerAccessRights)GetGrantedAccess(sd, token, 0, GetSCMGenericMapping()));
                                if (print_sddl)
                                {
                                    Console.WriteLine("SCM SDDL: {0}", sd.ToSddl());
                                }
                            }

                            foreach (string name in service_names)
                            {
                                try
                                {
                                    DumpService(scm, name, token, service_rights, show_write_only, print_sddl, dump_triggers);
                                }
                                catch (Exception ex)
                                {
                                    if (!quiet)
                                    {
                                        Console.Error.WriteLine("Error querying service: {0} - {1}", name, ex.Message);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
        }
    }
}
