//  Copyright 2019 Google Inc. All Rights Reserved.
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

using NtApiDotNet.Ndr;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace NtObjectManager.Cmdlets.Rpc
{
    [DataContract]
    internal sealed class NdrStructureMemberNameData
    {
        [DataMember]
        public int Index { get; set; }
        [DataMember]
        public string Name { get; set; }

        public NdrStructureMemberNameData(NdrStructureMember member, int index)
        {
            Index = index;
            Name = member.Name;
        }
    }

    [DataContract]
    internal sealed class NdrStructureNameData
    {
        [DataMember]
        public int Index { get; set; }
        [DataMember]
        public string Name { get; set; }
        [DataMember]
        public List<NdrStructureMemberNameData> Members { get; set; }

        public NdrStructureNameData(NdrBaseStructureTypeReference type, int index)
        {
            Index = index;
            Name = type.Name;
            Members = type.Members.Select((m, i) => new NdrStructureMemberNameData(m, i)).ToList();
        }

        public void UpdateNames(NdrBaseStructureTypeReference type)
        {
            type.Name = Name;
            var members = type.Members.ToList();
            foreach (var member in Members)
            {
                if (members.Count > member.Index)
                {
                    members[member.Index].Name = member.Name;
                }
            }
        }
    }

    [DataContract]
    internal sealed class NdrProcedureParameterNameData
    {
        [DataMember]
        public int Index { get; set; }
        [DataMember]
        public string Name { get; set; }

        public NdrProcedureParameterNameData(NdrProcedureParameter parameter, int index)
        {
            Name = parameter.Name;
            Index = index;
        }
    }

    [DataContract]
    internal sealed class NdrProcedureNameData
    {
        [DataMember]
        public int Index { get; set; }
        [DataMember]
        public string Name { get; set; }
        [DataMember]
        public List<NdrProcedureParameterNameData> Parameters { get; set; }

        public NdrProcedureNameData(NdrProcedureDefinition procedure)
        {
            Index = procedure.ProcNum;
            Name = procedure.Name;
            Parameters = procedure.Params.Select((p, i) => new NdrProcedureParameterNameData(p, i)).ToList();
        }

        public void UpdateNames(NdrProcedureDefinition procedure)
        {
            if (Name != null)
            {
                procedure.Name = Name;
            }

            if (Parameters != null)
            {
                var ps = procedure.Params;
                foreach (var p in Parameters)
                {
                    if (ps.Count > p.Index)
                    {
                        ps[p.Index].Name = p.Name;
                    }
                }
            }
        }
    }

    [DataContract]
    internal sealed class RpcServerNameData
    {
        [DataMember]
        public Guid InterfaceId { get; set; }
        [DataMember]
        public int InterfaceMajorVersion { get; set; }
        [DataMember]
        public int InterfaceMinorVersion { get; set; }
        [DataMember]
        public List<NdrStructureNameData> Structures { get; set; }
        [DataMember]
        public List<NdrProcedureNameData> Procedures { get; set; }

        public RpcServerNameData(RpcServer server)
        {
            InterfaceId = server.InterfaceId;
            InterfaceMajorVersion = server.InterfaceVersion.Major;
            InterfaceMinorVersion = server.InterfaceVersion.Minor;
            Structures = server.ComplexTypes.OfType<NdrBaseStructureTypeReference>()
                .Select((s, i) => new NdrStructureNameData(s, i)).ToList();
            Procedures = server.Procedures.Select(p => new NdrProcedureNameData(p)).ToList();
        }

        public void UpdateNames(RpcServer server)
        {
            if (server.InterfaceId != InterfaceId ||
                server.InterfaceVersion.Major != InterfaceMajorVersion ||
                server.InterfaceVersion.Minor != InterfaceMinorVersion)
            {
                throw new ArgumentException("Name XML doesn't match the server identity");
            }

            if (Structures != null)
            {
                var structures = server.ComplexTypes.OfType<NdrBaseStructureTypeReference>().ToList();
                foreach (var s in Structures)
                {
                    if (structures.Count > s.Index)
                    {
                        s.UpdateNames(structures[s.Index]);
                    }
                }
            }

            if (Procedures != null)
            {
                var procedures = server.Procedures.ToList();
                foreach (var p in Procedures)
                {
                    if (procedures.Count > p.Index)
                    {
                        p.UpdateNames(procedures[p.Index]);
                    }
                }
            }
        }

        public string ToXml()
        {
            DataContractSerializer ser = new DataContractSerializer(typeof(RpcServerNameData));
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.OmitXmlDeclaration = true;
            settings.Indent = true;
            StringBuilder builder = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(builder, settings))
            {
                ser.WriteObject(writer, this);
            }
            return builder.ToString();
        }
    }
}
