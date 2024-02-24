//  Copyright 2018 Google Inc. All Rights Reserved.
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

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Ndr
{
    internal sealed class IdlNdrFormatterInternal : INdrFormatterInternal
    {
        #region Private Members
        private class NdrFormatterContextEntry<T>
        {
            /// <summary>
            /// List of attributes to apply to the entry.
            /// </summary>
            public HashSet<string> Attributes { get; }
            /// <summary>
            /// Type name.
            /// </summary>
            public string TypeName { get; set; }
            /// <summary>
            /// Additional comment text.
            /// </summary>
            public string Comment { get; set; }
            /// <summary>
            /// The name of the entry.
            /// </summary>
            public string Name { get; }
            /// <summary>
            /// The offset of the entry.
            /// </summary>
            public int Offset { get; }
            /// <summary>
            /// The entry.
            /// </summary>
            public T Entry { get; }

            public void AddAttributes(IEnumerable<string> attrs)
            {
                foreach (var attr in attrs)
                {
                    Attributes.Add(attr);
                }
            }

            public NdrFormatterContextEntry(string name, int offset, T entry)
            {
                Name = name;
                Offset = offset;
                TypeName = string.Empty;
                Attributes = new HashSet<string>();
                Comment = string.Empty;
                Entry = entry;
            }
        }

        private class NdrTypeDefEntry
        {
            public NdrBaseTypeReference BaseType { get; }
            public string TypeDef { get; }
            public string Name { get; }
            public NdrTypeDefEntry(NdrBaseTypeReference base_type, string type_def, string name)
            {
                BaseType = base_type;
                TypeDef = type_def;
                Name = name;
            }
        }

        private struct ContextHandleId
        {
            public int? Id;
            public bool Strict;

            public override bool Equals(object obj)
            {
                return obj is ContextHandleId id &&
                       Id == id.Id && Strict == id.Strict;
            }

            public override int GetHashCode()
            {
                return 2108858624 + Id.GetHashCode() + Strict.GetHashCode();
            }
        }

        private readonly Stack<string> _postfix = new Stack<string>();
        private readonly Dictionary<NdrBaseTypeReference, NdrTypeDefEntry> _typedefs = new Dictionary<NdrBaseTypeReference, NdrTypeDefEntry>();
        private readonly Dictionary<ContextHandleId, NdrTypeDefEntry> _context_handles = new Dictionary<ContextHandleId, NdrTypeDefEntry>();
        private readonly Dictionary<NdrUnionArms, NdrUnionTypeReference> _arms_to_union = new Dictionary<NdrUnionArms, NdrUnionTypeReference>();
        private readonly bool _remove_comments;
        private readonly bool _enable_typedefs;
        private readonly IDictionary<Guid, string> _iids_to_name;
        private readonly Func<string, string> _demangle_com_name;

        public bool ShowProcedureParameterAttributes => true;

        private static string SystemHandleToAttributeName(NdrSystemHandleTypeReference handle_type)
        {
            switch (handle_type.Resource)
            {
                case NdrSystemHandleResource.File:
                    return "sh_file";
                case NdrSystemHandleResource.Pipe:
                    return "sh_pipe";
                case NdrSystemHandleResource.Socket:
                    return "sh_socket";
                case NdrSystemHandleResource.Semaphore:
                    return "sh_semaphore";
                case NdrSystemHandleResource.RegKey:
                    return "sh_reg_key";
                case NdrSystemHandleResource.Event:
                    return "sh_event";
                case NdrSystemHandleResource.Job:
                    return "sh_job";
                case NdrSystemHandleResource.Mutex:
                    return "sh_mutant";
                case NdrSystemHandleResource.Process:
                    return "sh_process";
                case NdrSystemHandleResource.Section:
                    return "sh_section";
                case NdrSystemHandleResource.Thread:
                    return "sh_thread";
                case NdrSystemHandleResource.Token:
                    return "sh_token";
                case NdrSystemHandleResource.Composition:
                    return "sh_composition";
                default:
                    return "sh_unknown_handle";
            }
        }

        private static string FormatRange(int min, int max)
        {
            return $"range({min}, {max})";
        }

        private bool HasTypeDef(NdrBaseTypeReference type)
        {
            if (!_enable_typedefs)
                return false;
            if (_typedefs.ContainsKey(type))
                return true;
            NdrSupplementTypeReference supp_type = type as NdrSupplementTypeReference;
            if ((supp_type != null && supp_type.BaseType == NdrFormatCharacter.FC_BIND_CONTEXT)
                || type.Format == NdrFormatCharacter.FC_BIND_CONTEXT)
            {
                ContextHandleId index = new ContextHandleId() { Id = supp_type?.Argument2 };
                return _context_handles.ContainsKey(index);
            }
            return false;
        }

        private IEnumerable<string> GetAttributes(NdrBaseTypeReference type)
        {
            List<string> attributes = new List<string>();
            if (HasTypeDef(type))
                return attributes;

            if (type is NdrSupplementTypeReference supp_type)
            {
                switch (supp_type.BaseType)
                {
                    case NdrFormatCharacter.FC_RANGE:
                        attributes.Add(FormatRange(supp_type.Argument1, supp_type.Argument2));
                        break;
                    case NdrFormatCharacter.FC_BIND_CONTEXT:
                        attributes.Add("context_handle");
                        break;
                    case NdrFormatCharacter.FC_C_CSTRING:
                    case NdrFormatCharacter.FC_C_WSTRING:
                        attributes.Add("string");
                        attributes.Add(FormatRange(supp_type.Argument1, supp_type.Argument2));
                        break;
                }
            }
            else if (type is NdrSystemHandleTypeReference handle_type)
            {
                string base_attr = $"system_handle({SystemHandleToAttributeName(handle_type)}";
                if (handle_type.AccessMask != 0)
                {
                    base_attr += $", 0x{handle_type.AccessMask:X}";
                }
                attributes.Add(base_attr + ")");
            }
            else
            {
                switch (type.Format)
                {
                    case NdrFormatCharacter.FC_OP:
                    case NdrFormatCharacter.FC_UP:
                        attributes.Add("unique");
                        break;
                    case NdrFormatCharacter.FC_FP:
                        attributes.Add("ptr");
                        break;
                    case NdrFormatCharacter.FC_RANGE:
                        if (type is NdrRangeTypeReference range_type)
                        {
                            attributes.Add(FormatRange(range_type.MinValue, range_type.MaxValue));
                        }
                        break;
                    case NdrFormatCharacter.FC_CSTRING:
                    case NdrFormatCharacter.FC_C_CSTRING:
                    case NdrFormatCharacter.FC_WSTRING:
                    case NdrFormatCharacter.FC_C_WSTRING:
                        attributes.Add("string");
                        break;
                    case NdrFormatCharacter.FC_BIND_CONTEXT:
                        attributes.Add("context_handle");
                        break;
                }
            }

            if (!(type is NdrPointerTypeReference))
                return attributes;

            while (type is NdrPointerTypeReference pointer_type)
            {
                if (HasTypeDef(type))
                    return attributes;
                type = pointer_type.Type;
            }

            attributes.AddRange(GetAttributes(type));

            return attributes;
        }

        private IEnumerable<string> GetAttributes(NdrProcedureParameter parameter)
        {
            List<string> attributes = new List<string>();
            if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsIn))
            {
                attributes.Add("in");
            }
            if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsOut))
            {
                attributes.Add("out");
            }
            if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsReturn))
            {
                attributes.Add("retval");
            }
            attributes.AddRange(GetAttributes(parameter.Type));

            return attributes;
        }

        private string FormatParameterName(NdrProcedureParameter parameter, int index)
        {
            return string.IsNullOrWhiteSpace(parameter.Name) ? $"p{index}" : parameter.Name;
        }

        private NdrFormatterContextEntry<T> GetLinkedEntry<T>(NdrFormatterContextEntry<T> entry, List<NdrFormatterContextEntry<T>> entries,
            NdrCorrelationType corellation_type, int offset)
        {
            int calc_offset = 0;
            switch (corellation_type)
            {
                case NdrCorrelationType.FC_NORMAL_CONFORMANCE:
                    calc_offset = entry.Offset + offset;
                    break;
                case NdrCorrelationType.FC_TOP_LEVEL_CONFORMANCE:
                case NdrCorrelationType.FC_POINTER_CONFORMANCE:
                    calc_offset = offset;
                    break;
            }
            return entries.Where(e => e.Offset == calc_offset).FirstOrDefault();
        }

        private void ApplyCorrelation<T>(string name, NdrFormatterContextEntry<T> entry,
            List<NdrFormatterContextEntry<T>> entries, NdrCorrelationDescriptor descriptor)
        {
            if (descriptor is null || !descriptor.IsValid)
                return;

            if (descriptor.IsConstant)
            {
                entry.Attributes.Add($"{name}({descriptor.Offset})");
                return;
            }

            if (!descriptor.IsNormal && !descriptor.IsTopLevel && !descriptor.IsPointer)
                return;

            string expression;
            if (descriptor.Operator == NdrFormatCharacter.FC_EXPR)
            {
                if (!descriptor.Expression.IsValid)
                    return;
                expression = descriptor.Expression.ToString(this, 
                    ofs => GetLinkedEntry(entry, entries, descriptor.CorrelationType, ofs)?.Name);
            }
            else
            {
                var linked_entry = GetLinkedEntry(entry, entries, descriptor.CorrelationType, descriptor.Offset);
                if (linked_entry == null)
                    return;

                switch (descriptor.Operator)
                {
                    case NdrFormatCharacter.FC_ADD_1:
                        expression = $"{linked_entry.Name}+1";
                        break;
                    case NdrFormatCharacter.FC_SUB_1:
                        expression = $"{linked_entry.Name}-1";
                        break;
                    case NdrFormatCharacter.FC_MULT_2:
                        expression = $"{linked_entry.Name}*2";
                        break;
                    case NdrFormatCharacter.FC_DIV_2:
                        expression = $"{linked_entry.Name}/2";
                        break;
                    case NdrFormatCharacter.FC_DEREFERENCE:
                        expression = $"*{linked_entry.Name}";
                        break;
                    default:
                        expression = linked_entry.Name;
                        break;
                }

                if (!(descriptor.Range is null) && descriptor.Range.IsValid)
                {
                    linked_entry.Attributes.Add(FormatRange(descriptor.Range.MinValue, descriptor.Range.MaxValue));
                }
            }

            entry.Attributes.Add($"{name}({expression})");
        }

        private void GetParameter(NdrFormatterContextEntry<NdrProcedureParameter> entry,
            List<NdrFormatterContextEntry<NdrProcedureParameter>> entries)
        {
            _postfix.Clear();
            NdrBaseTypeReference type = entry.Entry.Type;
            string type_name = !entry.Entry.Attributes.HasFlagSet(NdrParamAttributes.IsSimpleRef)
                ? FormatType(type) : FormatPointer(FormatType(type));
            entry.TypeName = $"{type_name} {entry.Name}{GetPostFix()}";
            entry.AddAttributes(GetAttributes(entry.Entry));
            ApplyCorrelation("size_is", entry, entries, entry.Entry.Type.GetConformanceDescriptor());
            ApplyCorrelation("length_is", entry, entries, entry.Entry.Type.GetVarianceDescriptor());

            while (type is NdrPointerTypeReference pointer_type)
            {
                type = pointer_type.Type;
            }

            if (type is NdrUnionTypeReference union_type && union_type.NonEncapsulated)
            {
                ApplyCorrelation("switch_is", entry, entries, union_type.Correlation);
            }

            if (type is NdrInterfacePointerTypeReference interface_ptr && !interface_ptr.IsConstant)
            {
                ApplyCorrelation("iid_is", entry, entries, interface_ptr.IidIsDescriptor);
            }
        }

        private string FormatParameter(NdrFormatterContextEntry<NdrProcedureParameter> entry)
        {
            if (entry.Attributes.Count > 0)
            {
                return $"{FormatAttributes(entry.Attributes)} {entry.TypeName}";
            }
            return entry.TypeName;
        }

        private void PopulateMember(NdrFormatterContextEntry<NdrStructureMember> entry,
            List<NdrFormatterContextEntry<NdrStructureMember>> entries)
        {
            string type_name = FormatType(entry.Entry.MemberType);
            entry.TypeName = $"{type_name} {entry.Name}{GetPostFix()}";
            entry.AddAttributes(GetAttributes(entry.Entry.MemberType));
            ApplyCorrelation("size_is", entry, entries, entry.Entry.MemberType.GetConformanceDescriptor());
            ApplyCorrelation("length_is", entry, entries, entry.Entry.MemberType.GetVarianceDescriptor());
            if (entry.Entry.MemberType is NdrUnionTypeReference union_type && union_type.NonEncapsulated)
            {
                ApplyCorrelation("switch_is", entry, entries, union_type.Correlation);
            }

            if (entry.Entry.MemberType is NdrInterfacePointerTypeReference interface_ptr && !interface_ptr.IsConstant)
            {
                ApplyCorrelation("iid_is", entry, entries, interface_ptr.IidIsDescriptor);
            }
        }

        private void FormatNonEncapsulatedUnion(NdrStringBuilder builder, NdrUnionTypeReference type)
        {
            if (_arms_to_union.ContainsKey(type.Arms))
                return;
            builder.Append($"[switch_type({SimpleTypeToName(type.SwitchType)})] ");
            builder.Append($"union {type.Name}").AppendLine(" {");
            builder.PushIndent(' ', 4);

            foreach (NdrUnionArm arm in type.Arms.Arms)
            {
                builder.AppendLine($"[case({arm.CaseValue})]");
                var attrs = GetAttributes(arm.ArmType);
                if (attrs.Any())
                    builder.Append($"{FormatAttributes(attrs)} ");
                builder.AppendLine($"{FormatType(arm.ArmType)} {arm.Name};");
            }

            if (type.Arms.DefaultArm != null)
            {
                builder.AppendLine("[default]");
                if (type.Arms.DefaultArm.Format != NdrFormatCharacter.FC_ZERO)
                {
                    builder.AppendLine($"{SimpleTypeToName(type.Arms.DefaultArm.Format)} Default;");
                }
                else
                {
                    builder.AppendLine(";");
                }
            }

            builder.PopIndent();
            builder.AppendLine("};");
            _arms_to_union[type.Arms] = type;
        }

        private void FormatProcedure(NdrStringBuilder builder, NdrProcedureDefinition procedure, bool com_proc)
        {
            string return_value;

            if (procedure.ReturnValue == null)
            {
                return_value = "void";
            }
            else if (procedure.ReturnValue.Type.Format == NdrFormatCharacter.FC_LONG && com_proc)
            {
                return_value = "HRESULT";
            }
            else
            {
                return_value = FormatType(procedure.ReturnValue.Type);
            }

            List<NdrFormatterContextEntry<NdrProcedureParameter>> entries =
                new List<NdrFormatterContextEntry<NdrProcedureParameter>>(procedure.Params.Select((param, i) =>
                new NdrFormatterContextEntry<NdrProcedureParameter>(FormatParameterName(param, i), param.Offset, param)));
            foreach (var entry in entries)
            {
                GetParameter(entry, entries);
            }

            builder.AppendLine($"{return_value} {procedure.Name}({string.Join(", ", entries.Select(p => FormatParameter(p)))});");
        }

        private string GuidToInterfaceName(Guid guid)
        {
            return $"intf_{guid.ToString().Replace('-', '_')}";
        }

        private string AddTypeDef(NdrBaseTypeReference base_type, string typedef_name, string name)
        {
            if (name == string.Empty)
            {
                name = $"TYPEDEF_NAME_{_typedefs.Count}";
            }
            var type_def = new NdrTypeDefEntry(base_type, typedef_name, $"_{name}");
            _typedefs[base_type] = type_def;
            return type_def.Name;
        }

        private string GetTypeDefName(NdrBaseTypeReference base_type)
        {
            if (_typedefs.TryGetValue(base_type, out NdrTypeDefEntry type_def))
            {
                return type_def.Name;
            }

            NdrSupplementTypeReference supp_type = base_type as NdrSupplementTypeReference;
            if ((supp_type != null && supp_type.BaseType == NdrFormatCharacter.FC_BIND_CONTEXT)
                || base_type.Format == NdrFormatCharacter.FC_BIND_CONTEXT)
            {
                ContextHandleId index = new ContextHandleId() {
                    Id = supp_type?.Argument2,
                    Strict = false
                };
                if (_context_handles.ContainsKey(index))
                {
                    return _context_handles[index].Name;
                }

                string base_name;
                if (index.Id.HasValue)
                {
                    base_name = "_TYPE_STRICT_CONTEXT_HANDLE_";
                }
                else if (index.Strict)
                {
                    base_name = "_STRICT_CONTEXT_HANDLE_";
                }
                else
                {
                    base_name = "_CONTEXT_HANDLE_";
                }
                NdrTypeDefEntry entry = new NdrTypeDefEntry(base_type, "[context_handle] void*", $"{base_name}{_context_handles.Count}");
                _context_handles[index] = entry;
                return entry.Name;
            }

            if (base_type is NdrBaseArrayTypeReference array_type)
            {
                if (array_type.ElementType is NdrPointerTypeReference)
                {
                    var attributes = GetAttributes(array_type.ElementType);
                    string type_desc = FormatType(array_type.ElementType);
                    if (attributes.Any())
                    {
                        type_desc = $"{FormatAttributes(attributes)} {type_desc}";
                    }

                    return AddTypeDef(array_type.ElementType, type_desc, string.Empty);
                }
            }

            string typedef_name = base_type.FormatType(this);
            if (base_type is NdrBaseStructureTypeReference struct_type)
            {
                typedef_name = AddTypeDef(struct_type, typedef_name, struct_type.Name);
            }
            else if (base_type is NdrUnionTypeReference union_type)
            {
                if (_arms_to_union.ContainsKey(union_type.Arms))
                {
                    union_type = _arms_to_union[union_type.Arms];
                }
                typedef_name = AddTypeDef(union_type, typedef_name, union_type.Name);
            }

            if (base_type is NdrPipeTypeReference pipe_type)
            {
                string type_desc = FormatType(pipe_type.BaseType);
                type_desc = $"pipe {type_desc}";
                return AddTypeDef(pipe_type, type_desc, $"PIPE_NAME_{_typedefs.Count}");
            }

            return typedef_name;
        }

        private void FormatEncapsulatedUnion(NdrStringBuilder builder, NdrUnionTypeReference type)
        {
            string selector_name = !string.IsNullOrWhiteSpace(type.SelectorName) ? type.SelectorName : "Selector";
            builder.Append($"union {type.Name} switch ({SimpleTypeToName(type.SwitchType)} {selector_name}) {type.Name}_UNION").AppendLine(" {");
            builder.PushIndent(' ', 4);

            foreach (NdrUnionArm arm in type.Arms.Arms)
            {
                builder.AppendLine($"case {arm.CaseValue}:");
                var attrs = GetAttributes(arm.ArmType);
                if (attrs.Any())
                    builder.Append($"{FormatAttributes(attrs)} ");
                builder.AppendLine($"{FormatType(arm.ArmType)} {arm.Name};");
            }

            if (type.Arms.DefaultArm != null)
            {
                builder.AppendLine("default:");
                if (type.Arms.DefaultArm.Format != NdrFormatCharacter.FC_ZERO)
                {
                    builder.AppendLine($"{SimpleTypeToName(type.Arms.DefaultArm.Format)} Default;");
                }
            }

            builder.PopIndent();
            builder.AppendLine("};");
        }

        private string FormatType(NdrBaseTypeReference base_type)
        {
            if (_enable_typedefs)
            {
                return GetTypeDefName(base_type);
            }

            return base_type.FormatType(this);
        }

        private string GetPostFix()
        {
            string ret = string.Join(string.Empty, _postfix);
            _postfix.Clear();
            return ret;
        }

        private string FormatAttributes(IEnumerable<string> attributes)
        {
            return $"[{string.Join(", ", attributes)}]";
        }

        private void FormatRpcInterface(NdrStringBuilder builder, NdrRpcServerInterface rpc_server)
        {
            builder.AppendLine("[");
            builder.PushIndent(' ', 2);
            builder.AppendLine($"uuid({rpc_server.InterfaceId.ToString().ToUpper()}),");
            builder.AppendLine($"version({rpc_server.InterfaceVersion})");
            builder.PopIndent();
            builder.AppendLine("]");
            builder.AppendLine($"interface {GuidToInterfaceName(rpc_server.InterfaceId)} {{");
            builder.PushIndent(' ', 4);
            foreach (NdrProcedureDefinition proc in rpc_server.Procedures)
            {
                FormatProcedure(builder, proc, false);
            }
            builder.PopIndent();
            builder.AppendLine("}").AppendLine();
        }

        private void FormatStruct(NdrStringBuilder builder, NdrBaseStructureTypeReference type)
        {
            List<NdrFormatterContextEntry<NdrStructureMember>> entries =
                new List<NdrFormatterContextEntry<NdrStructureMember>>(
                    type.Members.Select(m =>
                    new NdrFormatterContextEntry<NdrStructureMember>(m.Name, m.Offset, m)));

            foreach (var entry in entries)
            {
                PopulateMember(entry, entries);
            }

            builder.AppendLine($"struct {type.Name} {{");
            builder.PushIndent(' ', 4);

            foreach (var entry in entries)
            {
                if (entry.Attributes.Count > 0)
                {
                    builder.Append(FormatAttributes(entry.Attributes)).Append(" ");
                }
                builder.Append(entry.TypeName).AppendLine(";");
            }

            builder.PopIndent();
            builder.AppendLine("};");
        }

        private void FormatUnion(NdrStringBuilder builder, NdrUnionTypeReference type)
        {
            if (type.NonEncapsulated)
                FormatNonEncapsulatedUnion(builder, type);
            else
                FormatEncapsulatedUnion(builder, type);
        }

        private void FormatComProxy(NdrStringBuilder builder, NdrComProxyDefinition type)
        {
            builder.AppendLine("[");
            builder.PushIndent(' ', 2);
            builder.AppendLine("object,");
            builder.AppendLine($"uuid({type.Iid.ToString().ToUpper()}),");
            builder.PopIndent();
            builder.AppendLine("]");

            string base_name = IidToName(type.BaseIid);
            if (string.IsNullOrEmpty(base_name))
            {
                string unknown_iid = $"Unknown IID {type.BaseIid}";
                base_name = $"{FormatComment(unknown_iid)}IUnknown";
            }

            builder.AppendLine($"interface {GetProxyName(type)} : {base_name} {{");
            builder.PushIndent(' ', 4);
            foreach (NdrProcedureDefinition proc in type.Procedures)
            {
                FormatProcedure(builder, proc, true);
            }
            builder.PopIndent();
            builder.AppendLine("}").AppendLine();
        }
        #endregion

        #region Constructors
        public IdlNdrFormatterInternal(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name, DefaultNdrFormatterFlags flags)
        {
            _iids_to_name = iids_to_names ?? new Dictionary<Guid, string>();
            _demangle_com_name = demangle_com_name ?? (s => s);
            _remove_comments = flags.HasFlagSet(DefaultNdrFormatterFlags.RemoveComments);
            _enable_typedefs = flags.HasFlagSet(DefaultNdrFormatterFlags.EnableTypeDefs);
        }
        #endregion

        #region Public Methods
        public string GetProxyName(NdrComProxyDefinition proxy)
        {
            if (string.IsNullOrWhiteSpace(proxy.Name))
                return IidToName(proxy.Iid) ?? GuidToInterfaceName(proxy.Iid);
            return _demangle_com_name(proxy.Name);
        }

        public string FormatPointer(string base_type)
        {
            return $"{base_type}*";
        }

        public string FormatComment(string comment, params object[] args)
        {
            if (_remove_comments)
            {
                return string.Empty;
            }

            return $"/* {(args.Length > 0 ? string.Format(comment, args) : comment)} */ ";
        }

        public string IidToName(Guid iid)
        {
            if (_iids_to_name.TryGetValue(iid, out string value))
            {
                return _demangle_com_name(value);
            }

            if (iid == NdrNativeUtils.IID_IUnknown)
            {
                return "IUnknown";
            }
            else if (iid == NdrNativeUtils.IID_IDispatch)
            {
                return "IDispatch";
            }
            else if (iid == NdrNativeUtils.IID_IInspectable)
            {
                return "IInspectable";
            }
            return string.Empty;
        }

        public string SimpleTypeToName(NdrFormatCharacter format)
        {
            switch (format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_USMALL:
                    return "byte";
                case NdrFormatCharacter.FC_SMALL:
                case NdrFormatCharacter.FC_CHAR:
                    return "byte";
                case NdrFormatCharacter.FC_WCHAR:
                    return "wchar_t";
                case NdrFormatCharacter.FC_SHORT:
                    return "short";
                case NdrFormatCharacter.FC_USHORT:
                    return "unsigned short";
                case NdrFormatCharacter.FC_LONG:
                    return "int";
                case NdrFormatCharacter.FC_ULONG:
                    return "unsigned int";
                case NdrFormatCharacter.FC_FLOAT:
                    return "float";
                case NdrFormatCharacter.FC_HYPER:
                    return "__int64";
                case NdrFormatCharacter.FC_DOUBLE:
                    return "double";
                case NdrFormatCharacter.FC_INT3264:
                case NdrFormatCharacter.FC_IGNORE:
                    return "__int3264";
                case NdrFormatCharacter.FC_UINT3264:
                    return "unsigned __int3264";
                case NdrFormatCharacter.FC_C_WSTRING:
                case NdrFormatCharacter.FC_WSTRING:
                    return "wchar_t";
                case NdrFormatCharacter.FC_C_CSTRING:
                case NdrFormatCharacter.FC_CSTRING:
                    return "char";
                case NdrFormatCharacter.FC_ENUM16:
                    return "short";
                case NdrFormatCharacter.FC_ENUM32:
                    return "int";
                case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                    return "HANDLE";
                case NdrFormatCharacter.FC_AUTO_HANDLE:
                case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                case NdrFormatCharacter.FC_BIND_CONTEXT:
                case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                case NdrFormatCharacter.FC_BIND_GENERIC:
                    return "handle_t";
                case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    return "unsigned int";
                default:
                    return $"{format}";
            }
        }

        public string FormatComment(string comment)
        {
            if (_remove_comments)
            {
                return string.Empty;
            }

            return $"/* {comment} */ ";
        }

        public string FormatComplexType(NdrComplexTypeReference complex_type)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            if (complex_type is NdrBaseStructureTypeReference struct_type)
            {
                FormatStruct(builder, struct_type);
            }
            else if (complex_type is NdrUnionTypeReference union_type)
            {
                FormatUnion(builder, union_type);
            }
            return builder.ToString();
        }

        public string FormatProcedure(NdrProcedureDefinition procedure)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            FormatProcedure(builder, procedure, false);
            return builder.ToString();
        }

        public string FormatComProxy(NdrComProxyDefinition com_proxy)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            FormatComProxy(builder, com_proxy);
            return builder.ToString();
        }

        public string FormatRpcServerInterface(NdrRpcServerInterface rpc_server)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            FormatRpcInterface(builder, rpc_server);
            return builder.ToString();
        }
        #endregion
    }
}