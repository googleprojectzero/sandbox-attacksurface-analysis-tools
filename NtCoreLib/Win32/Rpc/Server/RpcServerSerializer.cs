//  Copyright 2024 Google LLC. All Rights Reserved.
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

using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Ndr64;
using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Serialization;
using System.Xml;

#nullable enable

namespace NtCoreLib.Win32.Rpc.Server;

internal static class RpcServerSerializer
{
    private class RpcDataContractResolver : DataContractResolver
    {
        public RpcDataContractResolver()
        {
        }

        public override Type? ResolveName(string typeName, string typeNamespace, Type declaredType, DataContractResolver knownTypeResolver)
        {
            return knownTypeResolver.ResolveName(typeName, typeNamespace, declaredType, knownTypeResolver);
        }

        public override bool TryResolveType(Type type, Type declaredType, DataContractResolver knownTypeResolver, out XmlDictionaryString? typeName, out XmlDictionaryString? typeNamespace)
        {
            if (knownTypeResolver.TryResolveType(type, declaredType, knownTypeResolver, out typeName, out typeNamespace))
            {
                return true;
            }
            System.Diagnostics.Trace.WriteLine(type.FullName);
            return false;
        }
    }

    private static bool FilterType(Type t)
    {
        return t.IsSerializable && !t.IsGenericTypeDefinition && t.DeclaringType == null && t.FullName.StartsWith("NtCoreLib.Ndr.");
    }

    private static IEnumerable<Type> GetKnownTypes()
    {
        var types = typeof(RpcServerSerializer).Assembly.GetTypes().Where(FilterType).ToList();
        types.Add(typeof(ReadOnlyCollection<NdrProcedureDefinition>));
        types.Add(typeof(ReadOnlyCollection<NdrProcedureParameter>));
        types.Add(typeof(ReadOnlyCollection<Ndr64ProcedureDefinition>));
        types.Add(typeof(ReadOnlyCollection<Ndr64ProcedureParameter>));
        types.Add(typeof(ReadOnlyCollection<RpcProtocolSequenceEndpoint>));
        types.Add(typeof(ReadOnlyCollection<MidlSyntaxInfo>));
        types.Add(typeof(ReadOnlyCollection<NdrExpression>));
        return types;
    }

    private static readonly Lazy<IEnumerable<Type>> _known_types = new(GetKnownTypes);

    private static DataContractSerializer CreateSerializer()
    {
        DataContractSerializerSettings settings = new();
        settings.KnownTypes = _known_types.Value;
        settings.DataContractResolver = new RpcDataContractResolver();
        settings.PreserveObjectReferences = true;
        return new(typeof(RpcServer), settings);
    }

    public static void Serialize(RpcServer server, Stream stm)
    {
        DataContractSerializer ser = CreateSerializer();
        MemoryStream mem_stm = new();
        using (GZipStream out_stm = new(mem_stm, CompressionMode.Compress))
        {
            ser.WriteObject(out_stm, server);
        }
        byte[] data = mem_stm.ToArray();
        BinaryWriter writer = new(stm);
        writer.Write(data.Length);
        writer.Write(data);
    }

    public static RpcServer Deserialize(Stream stm)
    {
        DataContractSerializer ser = new(typeof(RpcServer), _known_types.Value);
        BinaryReader reader = new(stm);
        byte[] data = reader.ReadAllBytes(reader.ReadInt32());
        using GZipStream in_stm = new(new MemoryStream(data), CompressionMode.Decompress);
        return (RpcServer)ser.ReadObject(in_stm);
    }
}
