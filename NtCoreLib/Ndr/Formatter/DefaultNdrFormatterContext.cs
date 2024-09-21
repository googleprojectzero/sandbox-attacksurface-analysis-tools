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

using NtCoreLib.Ndr.Com;
using NtCoreLib.Ndr.Dce;
using NtCoreLib.Ndr.Rpc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

#nullable enable

namespace NtCoreLib.Ndr.Formatter;

internal class DefaultNdrFormatterContext : INdrFormatterContext
{
    #region Private Members
    private readonly IDictionary<Guid, string> _iids_to_name;
    private readonly Func<string, string> _demangle_com_name;
    private readonly bool _cpp_style;
    private readonly bool _remove_comments;

    public DefaultNdrFormatterContext(IDictionary<Guid, string>? iids_to_names, Func<string, string>? demangle_com_name, NdrFormatterFlags flags, bool cpp_style)
    {
        _iids_to_name = iids_to_names ?? new Dictionary<Guid, string>();
        _demangle_com_name = demangle_com_name ?? (s => s);
        _cpp_style = cpp_style;
        _remove_comments = flags.HasFlagSet(NdrFormatterFlags.RemoveComments);
    }

    private static string SimpleTypeToNameCpp(NdrFormatCharacter format)
    {
        return format switch
        {
            NdrFormatCharacter.FC_BYTE or NdrFormatCharacter.FC_USMALL => "uint8_t",
            NdrFormatCharacter.FC_SMALL or NdrFormatCharacter.FC_CHAR => "int8_t",
            NdrFormatCharacter.FC_WCHAR => "wchar_t",
            NdrFormatCharacter.FC_SHORT => "int16_t",
            NdrFormatCharacter.FC_USHORT => "uint16_t",
            NdrFormatCharacter.FC_LONG => "int32_t",
            NdrFormatCharacter.FC_ULONG => "uint32_t",
            NdrFormatCharacter.FC_FLOAT => "float",
            NdrFormatCharacter.FC_HYPER => "int64_t",
            NdrFormatCharacter.FC_DOUBLE => "double",
            NdrFormatCharacter.FC_INT3264 => "intptr_t",
            NdrFormatCharacter.FC_UINT3264 => "uintptr_t",
            NdrFormatCharacter.FC_C_WSTRING or NdrFormatCharacter.FC_WSTRING => "wchar_t",
            NdrFormatCharacter.FC_C_CSTRING or NdrFormatCharacter.FC_CSTRING => "char",
            NdrFormatCharacter.FC_ENUM16 => "/* ENUM16 */ uint16_t",
            NdrFormatCharacter.FC_ENUM32 => "/* ENUM32 */ uint32_t",
            NdrFormatCharacter.FC_SYSTEM_HANDLE => "HANDLE",
            NdrFormatCharacter.FC_AUTO_HANDLE or NdrFormatCharacter.FC_CALLBACK_HANDLE or NdrFormatCharacter.FC_BIND_CONTEXT or NdrFormatCharacter.FC_BIND_PRIMITIVE or NdrFormatCharacter.FC_BIND_GENERIC => "handle_t",
            NdrFormatCharacter.FC_ERROR_STATUS_T => "uint",
            NdrFormatCharacter.FC_IGNORE => "void*",
            _ => $"{format}",
        };
    }

    private static string SimpleTypeToNameCS(NdrFormatCharacter format)
    {
        return format switch
        {
            NdrFormatCharacter.FC_BYTE or NdrFormatCharacter.FC_USMALL => "byte",
            NdrFormatCharacter.FC_SMALL or NdrFormatCharacter.FC_CHAR => "sbyte",
            NdrFormatCharacter.FC_WCHAR => "wchar_t",
            NdrFormatCharacter.FC_SHORT => "short",
            NdrFormatCharacter.FC_USHORT => "ushort",
            NdrFormatCharacter.FC_LONG => "int",
            NdrFormatCharacter.FC_ULONG => "uint",
            NdrFormatCharacter.FC_FLOAT => "float",
            NdrFormatCharacter.FC_HYPER => "long",
            NdrFormatCharacter.FC_DOUBLE => "double",
            NdrFormatCharacter.FC_INT3264 or NdrFormatCharacter.FC_IGNORE => "IntPtr",
            NdrFormatCharacter.FC_UINT3264 => "UIntPtr",
            NdrFormatCharacter.FC_C_WSTRING or NdrFormatCharacter.FC_WSTRING => "wchar_t",
            NdrFormatCharacter.FC_C_CSTRING or NdrFormatCharacter.FC_CSTRING => "char",
            NdrFormatCharacter.FC_ENUM16 => "/* ENUM16 */ int",
            NdrFormatCharacter.FC_ENUM32 => "/* ENUM32 */ int",
            NdrFormatCharacter.FC_SYSTEM_HANDLE => "HANDLE",
            NdrFormatCharacter.FC_AUTO_HANDLE or NdrFormatCharacter.FC_CALLBACK_HANDLE or NdrFormatCharacter.FC_BIND_CONTEXT or NdrFormatCharacter.FC_BIND_PRIMITIVE or NdrFormatCharacter.FC_BIND_GENERIC => "handle_t",
            NdrFormatCharacter.FC_ERROR_STATUS_T => "uint",
            _ => $"{format}",
        };
    }

    private IEnumerable<string> GetAttributes(NdrProcedureDefinition procedure, NdrProcedureParameter parameter)
    {
        if (_cpp_style)
            return Array.Empty<string>();

        List<string> attributes = new();
        if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsIn))
        {
            attributes.Add("In");
        }
        if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsOut))
        {
            attributes.Add("Out");
        }
        if (parameter.Attributes.HasFlagSet(NdrParamAttributes.IsReturn))
        {
            attributes.Add("RetVal");
        }
        return attributes;
    }

    private string FormatParameter(NdrProcedureDefinition procedure, NdrProcedureParameter parameter)
    {
        IEnumerable<string> attributes = GetAttributes(procedure, parameter);

        string type_format = !parameter.Attributes.HasFlagSet(NdrParamAttributes.IsSimpleRef)
            ? FormatType(parameter.Type) : FormatPointer(FormatType(parameter.Type));

        if (attributes.Any())
        {
            return $"[{string.Join(", ", attributes)}] {type_format}";
        }
        else
        {
            return type_format;
        }
    }

    private string FormatParameterName(NdrProcedureParameter parameter, int index)
    {
        return string.IsNullOrWhiteSpace(parameter.Name) ? $"p{index}" : parameter.Name;
    }

    private void AddCorrelation(StringBuilder builder, string type, NdrCorrelationDescriptor descriptor)
    {
        if (descriptor != null && descriptor.IsValid)
        {
            builder.Append($"{type}:{descriptor}");
        }
    }
    #endregion

    public string IidToName(Guid iid)
    {
        if (_iids_to_name.TryGetValue(iid, out string value))
        {
            return _demangle_com_name(value);
        }
        return string.Empty;
    }

    public string GetProxyName(NdrComProxyInterface proxy)
    {
        if (string.IsNullOrWhiteSpace(proxy.Name))
            return IidToName(proxy.Iid) ?? $"intf_{proxy.Iid.ToString().Replace('-', '_')}";
        return _demangle_com_name(proxy.Name);
    }

    public string SimpleTypeToName(NdrFormatCharacter format)
    {
        return _cpp_style ? SimpleTypeToNameCpp(format) : SimpleTypeToNameCS(format);
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

    public string FormatLineComment(string comment, params object[] args)
    {
        if (_remove_comments)
        {
            return string.Empty;
        }

        return $"// {(args.Length > 0 ? string.Format(comment, args) : comment)}";
    }

    public string FormatType(NdrBaseTypeReference base_type)
    {
        return base_type.FormatTypeInternal(this);
    }

    public void FormatProcedure(NdrStringBuilder builder, NdrProcedureDefinition procedure)
    {
        string return_value;

        if (procedure.ReturnValue == null)
        {
            return_value = "void";
        }
        else if (procedure.ReturnValue.Type.Format == NdrFormatCharacter.FC_LONG)
        {
            return_value = "HRESULT";
        }
        else
        {
            return_value = FormatType(procedure.ReturnValue.Type);
        }

        if (_cpp_style)
        {
            string procedureParameters = string.Join(", ", procedure.Params.Select(
                    (p, i) => $"{FormatComment("Stack Offset: {0}", p.Offset)}{FormatParameter(procedure, p)}{FormatParameterName(p, i)}"));
            builder.AppendLine($"virtual {return_value} __stdcall {procedure.Name}({procedureParameters});");
        }
        else
        {
            builder.AppendLine($"{return_value} {procedure.Name}({string.Join(", ", procedure.Params.Select((p, i) => $"{FormatComment("Stack Offset: {0}", p.Offset)}{FormatParameter(procedure, p)} {FormatParameterName(p, i)}"))});");
        }
    }

    public string FormatArrayType(NdrBaseArrayTypeReference array_type)
    {
        StringBuilder builder = new();
        AddCorrelation(builder, "C", array_type.GetConformanceDescriptor());
        AddCorrelation(builder, "V", array_type.GetVarianceDescriptor());

        int element_count = array_type.ElementCount;
        string format = $"{FormatType(array_type.ElementType)}[{(element_count == 0 ? string.Empty : element_count.ToString())}]";
        if (builder.Length > 0)
        {
            return $"{FormatComment(builder.ToString())}{format}";
        }
        return format;
    }

    public string FormatAttributes(IEnumerable<string> attributes)
    {
        if (_cpp_style)
            return string.Empty;
        return $"[{string.Join(", ", attributes)}]";
    }

    public void FormatStruct(NdrStringBuilder builder, NdrBaseStructureTypeReference type)
    {
        builder.AppendLine(FormatLineComment("Memory Size: {0}", type.GetSize()));
        builder.Append(FormatType(type)).AppendLine(" {");
        builder.PushIndent(' ', 4);

        foreach (var member in type.Members)
        {
            builder.AppendLine($"{FormatComment($"Offset: {member.Offset}")}{FormatType(member.MemberType)} {member.Name};");
        }

        builder.PopIndent();
        builder.AppendLine("};");
    }

    public void FormatUnion(NdrStringBuilder builder, NdrUnionTypeReference type)
    {
        string selector_name = !string.IsNullOrWhiteSpace(type.SelectorName) ? type.SelectorName : "Selector";
        builder.AppendLine(FormatLineComment("Memory Size: {0}", type.GetSize()));
        builder.Append(FormatType(type)).AppendLine(" {");
        builder.PushIndent(' ', 4);

        if (!type.NonEncapsulated)
        {
            builder.AppendLine($"{SimpleTypeToName(type.SwitchType)} {selector_name};");
            builder.AppendLine("union { ");
            builder.PushIndent(' ', 8);
        }
        else
        {
            builder.AppendLine(FormatLineComment(type.Correlation.ToString()));
        }

        foreach (NdrUnionArm arm in type.Arms.Arms)
        {
            builder.AppendLine($"/* case: {arm.CaseValue} */");
            builder.AppendLine($"{FormatType(arm.ArmType)} {arm.Name};");
        }

        if (type.Arms.DefaultArm != null)
        {
            builder.AppendLine("/* default */");
            if (type.Arms.DefaultArm.Format != NdrFormatCharacter.FC_ZERO)
            {
                builder.AppendLine($"{SimpleTypeToName(type.Arms.DefaultArm.Format)} Default;");
            }
        }

        if (!type.NonEncapsulated)
        {
            builder.PopIndent();
            builder.AppendLine("};");
        }

        builder.PopIndent();
        builder.AppendLine("};");
    }

    public void FormatComProxy(NdrStringBuilder builder, NdrComProxyInterface type)
    {
        string base_name = IidToName(type.BaseIid);
        if (base_name == string.Empty)
        {
            string unknown_iid = $"Unknown IID {type.BaseIid}";
            base_name = $"{FormatComment(unknown_iid)}IUnknown";
        }

        if (_cpp_style)
        {
            builder.AppendLine(
                "class __declspec(uuid(\"{0}\")) {1} : public {2} {{\npublic:",
                type.Iid,
                GetProxyName(type),
                base_name
            );
        }
        else
        {
            builder.AppendLine("[Guid(\"{0}\")]", type.Iid);
            builder.AppendLine("interface {0} : {1} {{", GetProxyName(type), base_name);
        }
        builder.PushIndent(' ', 4);

        foreach (NdrProcedureDefinition proc in type.Procedures)
        {
            FormatProcedure(builder, proc);
        }
        builder.PopIndent();
        if (_cpp_style)
        {
            builder.AppendLine("};").AppendLine();
        }
        else
        {
            builder.AppendLine("}").AppendLine();
        }
    }

    public void FormatRpcInterface(NdrStringBuilder builder, RpcServerInterface rpc_server)
    {
        builder.AppendLine("[uuid(\"{0}\"), version({1})]", rpc_server.InterfaceId.Uuid, rpc_server.InterfaceId.Version);
        builder.AppendLine("interface intf_{0} {{", rpc_server.InterfaceId.Uuid.ToString().Replace('-', '_'));
        builder.PushIndent(' ', 4);
        foreach (NdrProcedureDefinition proc in rpc_server.GetDceProcs())
        {
            FormatProcedure(builder, proc);
        }
        builder.PopIndent();
        builder.AppendLine("}").AppendLine();
    }

    public string FormatTypeDefs()
    {
        return string.Empty;
    }
}
