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
        /// <param name="procedure">The formatted procedure.</param>
        /// <returns>The formatted procedure.</returns>
        string FormatProcedure(NdrProcedureDefinition procedure);
    }

    /// <summary>
    /// An base class which describes a text formatter for NDR data.
    /// </summary>
    internal class NdrFormatter : INdrFormatter
    {
        private IDictionary<Guid, string> _iids_to_name;

        internal NdrFormatter(IDictionary<Guid, string> iids_to_names)
        {
            _iids_to_name = iids_to_names;
        }

        internal string IidToName(Guid iid)
        {
            if (_iids_to_name.ContainsKey(iid))
            {
                return _iids_to_name[iid];
            }
            return null;
        }

        internal string SimpleTypeToName(NdrFormatCharacter format)
        {
            switch (format)
            {
                case NdrFormatCharacter.FC_BYTE:
                case NdrFormatCharacter.FC_SMALL:
                    return "byte";
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
            }

            return String.Format("{0}", format);
        }

        internal string FormatPointer(string base_type)
        {
            return $"{base_type}*";
        }

        internal string FormatComment(string comment)
        {
            return $"/* {comment} */";
        }

        internal string FormatComment(string comment, params object[] args)
        {
            return FormatComment(string.Format(comment, args));
        }

        string INdrFormatter.FormatComplexType(NdrComplexTypeReference complex_type)
        {
            return complex_type.FormatComplexType(this);
        }

        string INdrFormatter.FormatProcedure(NdrProcedureDefinition procedure)
        {
            return procedure.FormatProcedure(this);
        }
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
        /// <returns>The default formatter.</returns>
        public static INdrFormatter Create(IDictionary<Guid, string> iids_to_names)
        {
            return new NdrFormatter(iids_to_names);
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
}
