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
    /// <summary>
    /// An interface which can be implemented to handle formatting parsed NDR data.
    /// </summary>
    public interface INdrFormatter
    {
        /// <summary>
        /// Format a complex type using the current formatter.
        /// </summary>
        /// <param name="complex_type">The complex type to format.</param>
        /// <returns>The formatted complex type.</returns>
        string FormatComplexType(NdrComplexTypeReference complex_type);

        /// <summary>
        /// Format a procedure using the current formatter.
        /// </summary>
        /// <param name="procedure">The procedure to format.</param>
        /// <returns>The formatted procedure.</returns>
        string FormatProcedure(NdrProcedureDefinition procedure);

        /// <summary>
        /// Format a COM proxy using the current formatter.
        /// </summary>
        /// <param name="com_proxy">The COM proxy to format.</param>
        /// <returns>The formatted COM proxy.</returns>
        string FormatComProxy(NdrComProxyDefinition com_proxy);

        /// <summary>
        /// Format an RPC server interface using the current formatter.
        /// </summary>
        /// <param name="rpc_server">The RPC server.</param>
        /// <returns>The formatted RPC server interface.</returns>
        string FormatRpcServerInterface(NdrRpcServerInterface rpc_server);
    }

    internal interface INdrFormatterInternal : INdrFormatter
    {
        string SimpleTypeToName(NdrFormatCharacter format);
        string FormatComment(string comment);
        string FormatComment(string comment, params object[] args);
        string FormatPointer(string base_type);
        string IidToName(Guid iid);
        string DemangleComName(string name);
        bool ShowProcedureParameterAttributes { get; }
    }

    /// <summary>
    /// An base class which describes a text formatter for NDR data.
    /// </summary>
    internal class NdrFormatter : INdrFormatterInternal
    {
        private readonly IDictionary<Guid, string> _iids_to_name;
        private readonly Func<string, string> _demangle_com_name;
        private DefaultNdrFormatterFlags _flags;

        bool INdrFormatterInternal.ShowProcedureParameterAttributes { get { return true; } }

        internal NdrFormatter(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name, DefaultNdrFormatterFlags flags)
        {
            _iids_to_name = iids_to_names;
            _demangle_com_name = demangle_com_name ?? (s => s);
            _flags = flags;
        }
        string INdrFormatterInternal.IidToName(Guid iid)
        {
            return IidToName(iid);
        }
        protected string IidToName(Guid iid)
        {
            if (_iids_to_name.ContainsKey(iid))
            {
                return _iids_to_name[iid];
            }
            return null;
        }

        string INdrFormatterInternal.DemangleComName(string name)
        {
            return _demangle_com_name(name);
        }

        string INdrFormatterInternal.SimpleTypeToName(NdrFormatCharacter format)
        {
            switch (format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_USMALL:
                    return "byte";
                case NdrFormatCharacter.FC_SMALL:
                case NdrFormatCharacter.FC_CHAR:
                    return "sbyte";
                case NdrFormatCharacter.FC_WCHAR:
                    return "wchar_t";
                case NdrFormatCharacter.FC_SHORT:
                    return "short";
                case NdrFormatCharacter.FC_USHORT:
                    return "ushort";
                case NdrFormatCharacter.FC_LONG:
                    return "int";
                case NdrFormatCharacter.FC_ULONG:
                    return "uint";
                case NdrFormatCharacter.FC_FLOAT:
                    return "float";
                case NdrFormatCharacter.FC_HYPER:
                    return "long";
                case NdrFormatCharacter.FC_DOUBLE:
                    return "double";
                case NdrFormatCharacter.FC_INT3264:
                    return "IntPtr";
                case NdrFormatCharacter.FC_UINT3264:
                    return "UIntPtr";
                case NdrFormatCharacter.FC_C_WSTRING:
                case NdrFormatCharacter.FC_WSTRING:
                    return "wchar_t";
                case NdrFormatCharacter.FC_C_CSTRING:
                case NdrFormatCharacter.FC_CSTRING:
                    return "char";
                case NdrFormatCharacter.FC_ENUM16:
                    return "/* ENUM16 */ int";
                case NdrFormatCharacter.FC_ENUM32:
                    return "/* ENUM32 */ int";
                case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                    return "HANDLE";
                case NdrFormatCharacter.FC_AUTO_HANDLE:
                case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                case NdrFormatCharacter.FC_BIND_CONTEXT:
                case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                case NdrFormatCharacter.FC_BIND_GENERIC:
                    return "handle_t";
                case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    return "uint";
            }

            return $"{format}";
        }

        string INdrFormatterInternal.FormatPointer(string base_type)
        {
            return $"{base_type}*";
        }

        string INdrFormatterInternal.FormatComment(string comment)
        {
            return FormatComment(comment);
        }
        string INdrFormatterInternal.FormatComment(string comment, params object[] args)
        {
            return FormatComment(string.Format(comment, args));
        }

        private string FormatComment(string comment)
        {
            if ((_flags & DefaultNdrFormatterFlags.RemoveComments) == DefaultNdrFormatterFlags.RemoveComments)
            {
                return string.Empty;
            }
            return $"/* {comment} */";
        }

        string INdrFormatter.FormatComplexType(NdrComplexTypeReference complex_type)
        {
            return complex_type.FormatComplexType(this);
        }

        string INdrFormatter.FormatProcedure(NdrProcedureDefinition procedure)
        {
            return procedure.FormatProcedure(this);
        }

        string INdrFormatter.FormatComProxy(NdrComProxyDefinition com_proxy)
        {
            return com_proxy.Format(this);
        }

        string INdrFormatter.FormatRpcServerInterface(NdrRpcServerInterface rpc_server)
        {
            return rpc_server.Format(this);
        }
    }


    /**
     * This formatter generates data that the CPP compiler can (hopefully) understand,
     * at least it will serve as a good skeleton to support spinning up new projects easily.
     * */
    internal class CppNdrFormatterInternal : NdrFormatter, INdrFormatterInternal
    {
        internal CppNdrFormatterInternal(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name, DefaultNdrFormatterFlags flags)
            : base(iids_to_names, demangle_com_name, flags)
        {

        }

        bool INdrFormatterInternal.ShowProcedureParameterAttributes { get { return false; } }

        string INdrFormatterInternal.SimpleTypeToName(NdrFormatCharacter format)
        {
            switch (format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_USMALL:
                    return "uint8_t";
                case NdrFormatCharacter.FC_SMALL:
                case NdrFormatCharacter.FC_CHAR:
                    return "int8_t";
                case NdrFormatCharacter.FC_WCHAR:
                    return "wchar_t";
                case NdrFormatCharacter.FC_SHORT:
                    return "int16_t";
                case NdrFormatCharacter.FC_USHORT:
                    return "uint16_t";
                case NdrFormatCharacter.FC_LONG:
                    return "int64_t";
                case NdrFormatCharacter.FC_ULONG:
                    return "uint64_t";
                case NdrFormatCharacter.FC_FLOAT:
                    return "float";
                case NdrFormatCharacter.FC_HYPER:
                    return "int64_t";
                case NdrFormatCharacter.FC_DOUBLE:
                    return "double";
                case NdrFormatCharacter.FC_INT3264:
                    return "intptr_t";
                case NdrFormatCharacter.FC_UINT3264:
                    return "uintptr_t";
                case NdrFormatCharacter.FC_C_WSTRING:
                case NdrFormatCharacter.FC_WSTRING:
                    return "wchar_t";
                case NdrFormatCharacter.FC_C_CSTRING:
                case NdrFormatCharacter.FC_CSTRING:
                    return "char";
                case NdrFormatCharacter.FC_ENUM16:
                    return "/* ENUM16 */ uint16_t";
                case NdrFormatCharacter.FC_ENUM32:
                    return "/* ENUM32 */ uint32_t";
                case NdrFormatCharacter.FC_SYSTEM_HANDLE:
                    return "HANDLE";
                case NdrFormatCharacter.FC_AUTO_HANDLE:
                case NdrFormatCharacter.FC_CALLBACK_HANDLE:
                case NdrFormatCharacter.FC_BIND_CONTEXT:
                case NdrFormatCharacter.FC_BIND_PRIMITIVE:
                case NdrFormatCharacter.FC_BIND_GENERIC:
                    return "handle_t";
                case NdrFormatCharacter.FC_ERROR_STATUS_T:
                    return "uint";
            }

            return $"{format}";
        }

        string INdrFormatter.FormatProcedure(NdrProcedureDefinition procedure)
        {
            return FormatProcedure(procedure);
        }
        private string FormatProcedure(NdrProcedureDefinition procedure)
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
                return_value = procedure.ReturnValue.Type.FormatType(this);
            }

            string procedureParameters = string.Join(", ", procedure.Params.Select(
                (p, i) => $"{(this as INdrFormatterInternal).FormatComment("Stack Offset: {0}", p.Offset)} {p.Format(this)} {p.FormatName(i)}"
            ));
            return $"virtual {return_value} __stdcall {procedure.Name}({procedureParameters});";
        }

        string INdrFormatter.FormatComProxy(NdrComProxyDefinition com_proxy)
        {
            NdrStringBuilder builder = new NdrStringBuilder();

            string base_name = this.IidToName(com_proxy.BaseIid);
            if (base_name == null)
            {
                string unknown_iid = $"Unknown IID {com_proxy.BaseIid}";
                string comment = (this as INdrFormatterInternal).FormatComment(unknown_iid);
                base_name = $"{comment} IUnknown";
            }

            builder.AppendLine(
                "class __declspec(uuid(\"{0}\")) {1} : public {2} {{\npublic:",
                com_proxy.Iid,
                (this as INdrFormatterInternal).DemangleComName(com_proxy.Name),
                base_name
            );

            builder.PushIndent(' ', 4);
            foreach (NdrProcedureDefinition proc in com_proxy.Procedures)
            {
                builder.AppendLine(this.FormatProcedure(proc));
            }
            builder.PopIndent();
            builder.AppendLine("};").AppendLine();
            return builder.ToString();
        }
    }

    /// <summary>
    /// Flags for the NDR formatter.
    /// </summary>
    [Flags]
    public enum DefaultNdrFormatterFlags
    {
        /// <summary>
        /// No flags. 
        /// </summary>
        None = 0,
        /// <summary>
        /// Don't emit comments.
        /// </summary>
        RemoveComments = 0x1,
    }

    /// <summary>
    /// Default NDR formatter constructor.
    /// </summary>
    public static class DefaultNdrFormatter
    {
        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="demangle_com_name">Function to demangle COM interface names during formatting.</param>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name, DefaultNdrFormatterFlags flags)
        {
            return new NdrFormatter(iids_to_names, demangle_com_name, flags);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="demangle_com_name">Function to demangle COM interface names during formatting.</param>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name)
        {
            return Create(iids_to_names, demangle_com_name, DefaultNdrFormatterFlags.None);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, DefaultNdrFormatterFlags flags)
        {
            return Create(iids_to_names, null, flags);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names)
        {
            return Create(iids_to_names, null);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(DefaultNdrFormatterFlags flags)
        {
            return Create(new Dictionary<Guid, string>(), flags);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create()
        {
            return Create(new Dictionary<Guid, string>());
        }
    }


    /// <summary>
    /// NDR formatter constructor for CPP style output.
    /// </summary>
    public static class CppNdrFormatter
    {
        /// <summary>
        /// Create the CPP formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="demangle_com_name">Function to demangle COM interface names during formatting.</param>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The CPP formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name, DefaultNdrFormatterFlags flags)
        {
            return new CppNdrFormatterInternal(iids_to_names, demangle_com_name, flags);
        }

        /// <summary>
        /// Create the CPP formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="demangle_com_name">Function to demangle COM interface names during formatting.</param>
        /// <returns>The CPPformatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, Func<string, string> demangle_com_name)
        {
            return Create(iids_to_names, demangle_com_name, DefaultNdrFormatterFlags.None);
        }

        /// <summary>
        /// Create the CPP formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The CPP formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names, DefaultNdrFormatterFlags flags)
        {
            return Create(iids_to_names, null, flags);
        }

        /// <summary>
        /// Create the CPP formatter.
        /// </summary>
        /// <param name="iids_to_names">Specify a dictionary of IIDs to names.</param>
        /// <returns>The CPP formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names)
        {
            return Create(iids_to_names, null);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <param name="flags">Formatter flags.</param>
        /// <returns>The CPP formatter.</returns>
        public static INdrFormatter Create(DefaultNdrFormatterFlags flags)
        {
            return Create(new Dictionary<Guid, string>(), flags);
        }

        /// <summary>
        /// Create the default formatter.
        /// </summary>
        /// <returns>The CPP formatter.</returns>
        public static INdrFormatter Create()
        {
            return Create(new Dictionary<Guid, string>());
        }
    }
}
