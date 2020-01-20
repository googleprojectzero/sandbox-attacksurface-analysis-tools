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

// NOTE: This file is a modified version of COMProxyInstance.cs from OleViewDotNet
// https://github.com/tyranid/oleviewdotnet. It's been relicensed from GPLv3 by
// the original author James Forshaw to be used under the Apache License for this
// project.

using System;
using System.Collections.Generic;
using System.Linq;

namespace NtApiDotNet.Ndr
{
    /// <summary>
    /// Class to represent a single COM proxy definition.
    /// </summary>
    [Serializable]
    public class NdrComProxyDefinition
    {
        /// <summary>
        /// The name of the proxy interface.
        /// </summary>
        public string Name { get; }
        /// <summary>
        /// The IID of the proxy interface.
        /// </summary>
        public Guid Iid { get; }
        /// <summary>
        /// The base IID of the proxy interface.
        /// </summary>
        public Guid BaseIid { get; }
        /// <summary>
        /// The number of dispatch methods on the interface.
        /// </summary>
        public int DispatchCount { get; }
        /// <summary>
        /// List of parsed procedures for the interface.
        /// </summary>
        public IList<NdrProcedureDefinition> Procedures { get; }

        internal NdrComProxyDefinition(string name, Guid iid, Guid base_iid, int dispatch_count, IList<NdrProcedureDefinition> procedures)
        {
            Name = name;
            Iid = iid;
            BaseIid = base_iid == Guid.Empty ? NdrNativeUtils.IID_IUnknown : base_iid;
            DispatchCount = dispatch_count;
            Procedures = procedures;
        }

        /// <summary>
        /// Creates a proxy definition from a list of procedures.
        /// </summary>
        /// <param name="name">The name of the proxy interface.</param>
        /// <param name="iid">The IID of the proxy interface.</param>
        /// <param name="base_iid">The base IID of the proxy interface.</param>
        /// <param name="dispatch_count">The total dispatch count for the proxy interface.</param>
        /// <param name="procedures">The list of parsed procedures for the proxy interface.</param>
        /// <returns></returns>
        public static NdrComProxyDefinition FromProcedures(string name, Guid iid, Guid base_iid, int dispatch_count, IEnumerable<NdrProcedureDefinition> procedures)
        {
            return new NdrComProxyDefinition(name, iid, base_iid, dispatch_count, procedures.ToList().AsReadOnly());
        }

        internal string Format(INdrFormatterInternal context)
        {
            NdrStringBuilder builder = new NdrStringBuilder();
            builder.AppendLine("[Guid(\"{0}\")]", Iid);
            string base_name = context.IidToName(BaseIid);
            if (base_name == null)
            {
                string unknown_iid = $"Unknown IID {BaseIid}";
                base_name = $"{context.FormatComment(unknown_iid)} IUnknown";
            }

            builder.AppendLine("interface {0} : {1} {{", context.DemangleComName(Name), base_name);
            builder.PushIndent(' ', 4);
            foreach (NdrProcedureDefinition proc in Procedures)
            {
                builder.AppendLine(proc.FormatProcedure(context));
            }
            builder.PopIndent();
            builder.AppendLine("}").AppendLine();
            return builder.ToString();
        }
    }
}
