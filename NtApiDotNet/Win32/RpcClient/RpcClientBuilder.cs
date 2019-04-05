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

using Microsoft.CSharp;
using NtApiDotNet.Ndr;
using System;
using System.CodeDom;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace NtApiDotNet.Win32.RpcClient
{
    /// <summary>
    /// Builder to create an RPC client from an RpcServer class.
    /// </summary>
    public sealed class RpcClientBuilder
    {
        #region Private Members
        private static readonly Dictionary<Tuple<RpcServer, RpcClientBuilderArguments>, Assembly> _compiled_clients
            = new Dictionary<Tuple<RpcServer, RpcClientBuilderArguments>, Assembly>();
        private readonly Dictionary<NdrBaseTypeReference, RpcTypeDescriptor> _type_descriptors;
        private readonly RpcServer _server;
        private readonly RpcClientBuilderArguments _args;
        private readonly HashSet<string> _proc_names;

        private bool HasFlag(RpcClientBuilderFlags flag)
        {
            return (_args.Flags & flag) == flag;
        }

        private static Type GetSystemHandleType(NdrSystemHandleTypeReference type)
        {
            switch (type.Resource)
            {
                case NdrSystemHandleResource.File:
                case NdrSystemHandleResource.Pipe:
                case NdrSystemHandleResource.Socket:
                    return typeof(NtFile);
                case NdrSystemHandleResource.Semaphore:
                    return typeof(NtSemaphore);
                case NdrSystemHandleResource.RegKey:
                    return typeof(NtKey);
                case NdrSystemHandleResource.Event:
                    return typeof(NtEvent);
                case NdrSystemHandleResource.Job:
                    return typeof(NtJob);
                case NdrSystemHandleResource.Mutex:
                    return typeof(NtMutant);
                case NdrSystemHandleResource.Process:
                    return typeof(NtProcess);
                case NdrSystemHandleResource.Section:
                    return typeof(NtSection);
                case NdrSystemHandleResource.Thread:
                    return typeof(NtThread);
                case NdrSystemHandleResource.Token:
                    return typeof(NtToken);
                default:
                    return typeof(NtObject);
            }
        }

        private static Type GetBuiltinType(NdrBaseTypeReference type)
        {
            if (type is NdrSimpleTypeReference)
            {
                switch (type.Format)
                {
                    case NdrFormatCharacter.FC_BYTE:
                    case NdrFormatCharacter.FC_USMALL:
                        return typeof(byte);
                    case NdrFormatCharacter.FC_SMALL:
                    case NdrFormatCharacter.FC_CHAR:
                        return typeof(sbyte);
                    case NdrFormatCharacter.FC_WCHAR:
                        return typeof(char);
                    case NdrFormatCharacter.FC_SHORT:
                        return typeof(short);
                    case NdrFormatCharacter.FC_USHORT:
                        return typeof(ushort);
                    case NdrFormatCharacter.FC_LONG:
                        return typeof(int);
                    case NdrFormatCharacter.FC_ULONG:
                        return typeof(uint);
                    case NdrFormatCharacter.FC_FLOAT:
                        return typeof(float);
                    case NdrFormatCharacter.FC_HYPER:
                        return typeof(long);
                    case NdrFormatCharacter.FC_DOUBLE:
                        return typeof(double);
                    case NdrFormatCharacter.FC_INT3264:
                        return typeof(IntPtr);
                    case NdrFormatCharacter.FC_UINT3264:
                        return typeof(UIntPtr);
                    case NdrFormatCharacter.FC_C_WSTRING:
                    case NdrFormatCharacter.FC_WSTRING:
                    case NdrFormatCharacter.FC_C_CSTRING:
                    case NdrFormatCharacter.FC_CSTRING:
                        return typeof(string);
                    case NdrFormatCharacter.FC_ENUM16:
                        return typeof(int);
                    case NdrFormatCharacter.FC_ENUM32:
                        return typeof(int);
                    case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                        return typeof(IntPtr);
                    case NdrFormatCharacter.FC_AUTO_HANDLE:
                    case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                    case NdrFormatCharacter.FC_BIND_CONTEXT:
                    case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                    case NdrFormatCharacter.FC_BIND_GENERIC:
                        return typeof(IntPtr);
                    case NdrFormatCharacter.FC_ERROR_STATUS_T:
                        return typeof(uint);
                }

            }
            else if (type is NdrKnownTypeReference known_type)
            {
                switch (known_type.KnownType)
                {
                    case NdrKnownTypes.GUID:
                        return typeof(Guid);
                    case NdrKnownTypes.BSTR:
                        return typeof(string);
                    case NdrKnownTypes.HSTRING:
                        return typeof(string);
                }
            }
            else if (type is NdrBaseStringTypeReference)
            {
                return typeof(string);
            }

            return null;
        }

        private RpcTypeDescriptor GetTypeDescriptorInternal(NdrBaseTypeReference type)
        {
            if (type is NdrSimpleTypeReference)
            {
                Type builtin_type = GetBuiltinType(type);
                if (builtin_type == null)
                {
                    return null;
                }

                switch (type.Format)
                {
                    case NdrFormatCharacter.FC_BYTE:
                    case NdrFormatCharacter.FC_USMALL:
                        return new RpcTypeDescriptor(builtin_type, "ReadByte", "Write", type);
                    case NdrFormatCharacter.FC_SMALL:
                    case NdrFormatCharacter.FC_CHAR:
                        return new RpcTypeDescriptor(builtin_type, "ReadSByte", "Write", type);
                    case NdrFormatCharacter.FC_WCHAR:
                        return new RpcTypeDescriptor(builtin_type, "ReadChar", "Write", type);
                    case NdrFormatCharacter.FC_SHORT:
                        return new RpcTypeDescriptor(builtin_type, "ReadInt16", "Write", type);
                    case NdrFormatCharacter.FC_USHORT:
                        return new RpcTypeDescriptor(builtin_type, "ReadUInt16", "Write", type);
                    case NdrFormatCharacter.FC_LONG:
                    case NdrFormatCharacter.FC_ENUM16:
                    case NdrFormatCharacter.FC_ENUM32:
                        return new RpcTypeDescriptor(builtin_type, "ReadInt32", "Write", type);
                    case NdrFormatCharacter.FC_ULONG:
                    case NdrFormatCharacter.FC_ERROR_STATUS_T:
                        return new RpcTypeDescriptor(builtin_type, "ReadUInt32", "Write", type);
                    case NdrFormatCharacter.FC_FLOAT:
                        return new RpcTypeDescriptor(builtin_type, "ReadFloat", "Write", type);
                    case NdrFormatCharacter.FC_HYPER:
                        return new RpcTypeDescriptor(builtin_type, "ReadInt64", "Write", type);
                    case NdrFormatCharacter.FC_DOUBLE:
                        return new RpcTypeDescriptor(builtin_type, "ReadDouble", "Write", type);
                    case NdrFormatCharacter.FC_INT3264:
                        return new RpcTypeDescriptor(builtin_type, "ReadIntPtr", "Write", type);
                    case NdrFormatCharacter.FC_UINT3264:
                        return new RpcTypeDescriptor(builtin_type, "ReadUIntPtr", "Write", type);
                    case NdrFormatCharacter.FC_C_WSTRING:
                        return new RpcTypeDescriptor(builtin_type, "ReadConformantString", "WriteConformantString", type);
                    case NdrFormatCharacter.FC_C_CSTRING:
                        return new RpcTypeDescriptor(builtin_type, "ReadAnsiConformantString", "WriteAnsiConformantString", type);
                    case NdrFormatCharacter.FC_CSTRING:
                    case NdrFormatCharacter.FC_WSTRING:
                        break;
                    case NdrFormatCharacter.FC_AUTO_HANDLE:
                    case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                    case NdrFormatCharacter.FC_BIND_CONTEXT:
                    case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                    case NdrFormatCharacter.FC_BIND_GENERIC:
                        break;
                }
            }
            else if (type is NdrKnownTypeReference known_type)
            {
                switch (known_type.KnownType)
                {
                    case NdrKnownTypes.GUID:
                        return new RpcTypeDescriptor(typeof(Guid), "ReadGuid", "Write", type);
                    case NdrKnownTypes.BSTR:
                        break;
                    case NdrKnownTypes.HSTRING:
                        break;
                }
            }
            else if (type is NdrBaseStringTypeReference)
            {
                if (type is NdrConformantStringTypeReference conformant_str)
                {
                    if (conformant_str.Format == NdrFormatCharacter.FC_C_CSTRING)
                    {
                        return new RpcTypeDescriptor(typeof(string), "ReadAnsiConformantString", "WriteAnsiConformantString", type);
                    }
                    return new RpcTypeDescriptor(typeof(string), "ReadConformantString", "WriteConformantString", type);
                }
            }
            else if (type is NdrSystemHandleTypeReference system_handle)
            {
                Type handle_type = GetSystemHandleType(system_handle);
                return new RpcTypeDescriptor(handle_type, $"ReadHandle<{handle_type.FullName}>", "Write", type);
            }
            else if (type is NdrSimpleArrayTypeReference simple_array)
            {
                RpcTypeDescriptor element_type = GetTypeDescriptor(simple_array.ElementType);
                if (element_type.BuiltinType == typeof(char))
                {
                    return new RpcTypeDescriptor(typeof(string), "ReadFixedString", "WriteFixedString", type, CodeGenUtils.GetPrimitive(simple_array.ElementCount));
                }
                else if (element_type.BuiltinType == typeof(byte))
                {
                    return new RpcTypeDescriptor(typeof(byte[]), "ReadBytes", "WriteFixedBytes", type, CodeGenUtils.GetPrimitive(simple_array.ElementCount));
                }
            }
            else if (type is NdrPointerTypeReference pointer)
            {
                var desc = GetTypeDescriptor(pointer.Type);
                if (desc != null)
                {
                    return new RpcTypeDescriptor(desc, true);
                }
            }

            return null;
        }

        // Should implement this for each type rather than this.
        private RpcTypeDescriptor GetTypeDescriptor(NdrBaseTypeReference type)
        {
            if (!_type_descriptors.ContainsKey(type))
            {
                _type_descriptors[type] = GetTypeDescriptorInternal(type);
            }
            return _type_descriptors[type];
        }

        private static FieldDirection GetDirection(NdrProcedureParameter p)
        {
            if (p.IsInOut)
            {
                return FieldDirection.Ref;
            }
            else if (p.IsOut)
            {
                return FieldDirection.Out;
            }
            return FieldDirection.In;
        }

        private const string MARSHAL_NAME = "m";
        private const string UNMARSHAL_NAME = "u";

        private void GenerateComplexTypes(CodeNamespace ns)
        {
            // First populate the type cache.
            foreach (var complex_type in _server.ComplexTypes)
            {
                if (complex_type is NdrBaseStructureTypeReference struct_type)
                {
                    _type_descriptors[complex_type] = new RpcTypeDescriptor(complex_type.Name, true,
                        $"ReadStruct<{CodeGenUtils.MakeIdentifier(complex_type.Name)}>", "Write", complex_type);
                }
            }

            // Now generate the compelx types.
            foreach (var complex_type in _server.ComplexTypes)
            {
                if (complex_type is NdrBaseStructureTypeReference struct_type)
                {
                    var s_type = ns.AddType(complex_type.Name);
                    s_type.IsStruct = true;
                    s_type.BaseTypes.Add(new CodeTypeReference(typeof(INdrStructure)));

                    var marshal_method = s_type.AddMarshalMethod(MARSHAL_NAME);
                    marshal_method.AddAlign(MARSHAL_NAME, struct_type.Alignment + 1);
                    var unmarshal_method = s_type.AddUnmarshalMethod(UNMARSHAL_NAME);
                    unmarshal_method.AddAlign(UNMARSHAL_NAME, struct_type.Alignment + 1);
                    bool deferred_members = false;

                    foreach (var member in struct_type.Members)
                    {
                        var f_type = GetTypeDescriptor(member.MemberType);
                        if (f_type != null)
                        {
                            s_type.AddField(f_type.CodeType, member.Name, MemberAttributes.Public);
                            if (f_type.Pointer)
                            {
                                deferred_members = true;
                                marshal_method.AddWriteReferent(MARSHAL_NAME, member.Name);
                                unmarshal_method.AddReadReferent(UNMARSHAL_NAME, member.Name);
                            }
                            else
                            {
                                if (!f_type.ValueType)
                                {
                                    marshal_method.AddNullCheck(MARSHAL_NAME, member.Name);
                                }
                                marshal_method.AddMarshalCall(f_type, MARSHAL_NAME, member.Name);
                                unmarshal_method.AddUnmarshalCall(f_type, UNMARSHAL_NAME, member.Name);
                            }
                        }
                        else
                        {
                            s_type.Comments.Add(new CodeCommentStatement($"Unsupported type for {member.MemberType} {member.Name}"));
                        }
                    }

                    if (deferred_members)
                    {
                        foreach (var member in struct_type.Members)
                        {
                            var f_type = GetTypeDescriptor(member.MemberType);
                            if (f_type != null && f_type.Pointer)
                            {
                                marshal_method.AddMarshalCall(f_type, MARSHAL_NAME, member.Name);
                                unmarshal_method.AddDeferredUnmarshalCall(f_type, UNMARSHAL_NAME, member.Name);
                            }
                        }
                    }

                    marshal_method.AddAlign(MARSHAL_NAME, struct_type.Alignment + 1);
                    unmarshal_method.AddAlign(UNMARSHAL_NAME, struct_type.Alignment + 1);
                }
                else
                {
                    ns.Comments.Add(new CodeCommentStatement($"Unsupported type {complex_type.GetType()} {complex_type.Name}"));
                }
            }
        }

        private void GenerateClient(string name, CodeNamespace ns)
        {
            CodeTypeDeclaration type = ns.AddType(name);
            type.IsClass = true;
            type.TypeAttributes = TypeAttributes.Public | TypeAttributes.Sealed;
            type.BaseTypes.Add(typeof(RpcAlpcClient));

            CodeConstructor constructor = type.AddConstructor(MemberAttributes.Public | MemberAttributes.Final);
            constructor.BaseConstructorArgs.Add(CodeGenUtils.GetPrimitive(_server.InterfaceId.ToString()));
            constructor.BaseConstructorArgs.Add(CodeGenUtils.GetPrimitive(_server.InterfaceVersion.Major));
            constructor.BaseConstructorArgs.Add(CodeGenUtils.GetPrimitive(_server.InterfaceVersion.Minor));

            foreach (var proc in _server.Procedures)
            {
                string proc_name = proc.Name;
                if(!_proc_names.Add(proc_name))
                {
                    proc_name = $"{proc_name}_{proc.ProcNum}";
                    if (!_proc_names.Add(proc_name))
                    {
                        throw new ArgumentException($"Duplicate name {proc.Name}");
                    }
                }

                var method = type.AddMethod(proc_name, MemberAttributes.Public | MemberAttributes.Final);
                RpcTypeDescriptor return_type = GetTypeDescriptor(proc.ReturnValue.Type);
                if (return_type == null)
                {
                    method.ThrowNotImplemented("Return type unsupported.");
                    continue;
                }

                method.ReturnType = return_type.CodeType;

                method.CreateMarshalObject(MARSHAL_NAME);
                foreach (var p in proc.Params)
                {
                    if (p != proc.Handle)
                    {
                        RpcTypeDescriptor p_type = GetTypeDescriptor(p.Type);
                        if (p_type != null)
                        {
                            var p_obj = method.AddParam(p_type.CodeType, p.Name);
                            p_obj.Direction = p.GetDirection();
                            if (p.IsIn)
                            {
                                if (p_type.Pointer)
                                {
                                    method.AddWriteReferent(MARSHAL_NAME, p.Name);
                                }
                                else if (!p_type.ValueType)
                                {
                                    method.AddNullCheck(MARSHAL_NAME, p.Name);
                                }
                                method.AddMarshalCall(p_type, MARSHAL_NAME, p.Name);
                            }
                        }
                        else
                        {
                            method.ThrowNotImplemented($"Param {p.Name} unsupported type");
                            continue;
                        }
                    }
                }

                method.SendReceive(MARSHAL_NAME, UNMARSHAL_NAME, proc.ProcNum);

                foreach (var p in proc.Params.Where(x => x.IsOut))
                {
                    if (p != proc.Handle)
                    {
                        RpcTypeDescriptor p_type = GetTypeDescriptor(p.Type);
                        if (p_type != null)
                        {
                            if (p_type.Pointer)
                            {
                                method.AddReadReferent(UNMARSHAL_NAME, p.Name);
                                method.AddDeferredUnmarshalCall(p_type, UNMARSHAL_NAME, p.Name);
                            }
                            else
                            {
                                method.AddUnmarshalCall(p_type, UNMARSHAL_NAME, p.Name);
                            }
                        }
                    }
                }

                method.AddUnmarshalReturn(return_type, UNMARSHAL_NAME);
            }

            if (HasFlag(RpcClientBuilderFlags.GenerateValueConstructors))
            {
                foreach (var complex_type in _server.ComplexTypes)
                {
                    RpcTypeDescriptor p_type = GetTypeDescriptor(complex_type);
                    if (p_type != null)
                    {
                        type.AddConstructorMethod(complex_type.Name, p_type);
                    }
                }
            }
        }

        private static string GenerateSourceCode(CodeCompileUnit unit)
        {
            CodeDomProvider provider = new CSharpCodeProvider();
            StringBuilder builder = new StringBuilder();
            CodeGeneratorOptions options = new CodeGeneratorOptions
            {
                IndentString = "    ",
                BlankLinesBetweenMembers = false,
                VerbatimOrder = true,
                BracingStyle = "C"
            };
            TextWriter writer = new StringWriter(builder);
            provider.GenerateCodeFromCompileUnit(unit, writer, options);
            return builder.ToString();
        }

        private CodeCompileUnit Generate()
        {
            CodeCompileUnit unit = new CodeCompileUnit();
            string ns_name = _args.NamespaceName;
            if (string.IsNullOrWhiteSpace(ns_name))
            {
                ns_name = $"rpc_{_server.InterfaceId.ToString().Replace('-', '_')}_{_server.InterfaceVersion.Major}_{_server.InterfaceVersion.Minor}";
            }
            string name = _args.ClientName;
            if (string.IsNullOrWhiteSpace(name))
            {
                name = "Client";
            }

            CodeNamespace ns = unit.AddNamespace(ns_name);
            GenerateComplexTypes(ns);
            GenerateClient(name, ns);

            return unit;
        }

        private static Assembly Compile(CodeCompileUnit unit)
        {
            CompilerParameters compileParams = new CompilerParameters();
            TempFileCollection tempFiles = new TempFileCollection(Path.GetTempPath());

            compileParams.GenerateExecutable = false;
            compileParams.GenerateInMemory = true;
            compileParams.IncludeDebugInformation = true;
            compileParams.TempFiles = tempFiles;
            compileParams.ReferencedAssemblies.Add(typeof(RpcClientBuilder).Assembly.Location);
            CodeDomProvider provider = new CSharpCodeProvider();
            CompilerResults results = provider.CompileAssemblyFromDom(compileParams, unit);
            if (results.Errors.HasErrors)
            {
                foreach (CompilerError e in results.Errors)
                {
                    System.Diagnostics.Debug.WriteLine($"{e.Line} {e.Column} {e.ErrorText}");
                }
                throw new InvalidOperationException("Internal error compiling RPC source code");
            }
            return results.CompiledAssembly;
        }

        #endregion

        #region Constructors

        private RpcClientBuilder(RpcServer server, RpcClientBuilderArguments args)
        {
            _server = server;
            _type_descriptors = new Dictionary<NdrBaseTypeReference, RpcTypeDescriptor>();
            _args = args;
            _proc_names = new HashSet<string>();
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Build a C# source file for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="args">Additional builder arguments.</param>
        /// <returns>The C# source code file.</returns>
        public static string BuildSource(RpcServer server, RpcClientBuilderArguments args)
        {
            return GenerateSourceCode(new RpcClientBuilder(server, args).Generate());
        }

        /// <summary>
        /// Build a C# source file for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <returns>The C# source code file.</returns>
        public static string BuildSource(RpcServer server)
        {
            return BuildSource(server, new RpcClientBuilderArguments());
        }

        /// <summary>
        /// Compile an in-memory assembly for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="args">Additional builder arguments.</param>
        /// <param name="ignore_cache">True to ignore cached assemblies.</param>
        /// <returns>The compiled assembly.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static Assembly BuildAssembly(RpcServer server, RpcClientBuilderArguments args, bool ignore_cache)
        {
            if (ignore_cache)
            {
                return Compile(new RpcClientBuilder(server, args).Generate());
            }

            var key = Tuple.Create(server, args);
            if (!_compiled_clients.ContainsKey(key))
            {
                _compiled_clients[key] = Compile(new RpcClientBuilder(server, args).Generate());
            }
            return _compiled_clients[key];
        }

        /// <summary>
        /// Compile an in-memory assembly for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="args">Additional builder arguments.</param>
        /// <returns>The compiled assembly.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static Assembly BuildAssembly(RpcServer server, RpcClientBuilderArguments args)
        {
            return BuildAssembly(server, args, false);
        }

        /// <summary>
        /// Compile an in-memory assembly for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="ignore_cache">True to ignore cached assemblies.</param>
        /// <returns>The compiled assembly.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static Assembly BuildAssembly(RpcServer server, bool ignore_cache)
        {
            return BuildAssembly(server, new RpcClientBuilderArguments(), ignore_cache);
        }

        /// <summary>
        /// Compile an in-memory assembly for the RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <returns>The compiled assembly.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static Assembly BuildAssembly(RpcServer server)
        {
            return BuildAssembly(server, false);
        }

        /// <summary>
        /// Create an instance of an RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="ignore_cache">True to ignore cached assemblies.</param>
        /// <param name="args">Additional builder arguments.</param>
        /// <returns>The created RPC client.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static RpcAlpcClient CreateClient(RpcServer server, RpcClientBuilderArguments args, bool ignore_cache)
        {
            Type type = BuildAssembly(server, args, ignore_cache).GetTypes().Where(t => typeof(RpcAlpcClient).IsAssignableFrom(t)).First();
            return (RpcAlpcClient)Activator.CreateInstance(type);
        }

        /// <summary>
        /// Create an instance of an RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <param name="args">Additional builder arguments.</param>
        /// <returns>The created RPC client.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static RpcAlpcClient CreateClient(RpcServer server, RpcClientBuilderArguments args)
        {
            return CreateClient(server, args, false);
        }

        /// <summary>
        /// Create an instance of an RPC client.
        /// </summary>
        /// <param name="server">The RPC server to base the client on.</param>
        /// <returns>The created RPC client.</returns>
        /// <remarks>This method will cache the results of the compilation against the RpcServer.</remarks>
        public static RpcAlpcClient CreateClient(RpcServer server)
        {
            return CreateClient(server, new RpcClientBuilderArguments());
        }

        #endregion
    }
}
