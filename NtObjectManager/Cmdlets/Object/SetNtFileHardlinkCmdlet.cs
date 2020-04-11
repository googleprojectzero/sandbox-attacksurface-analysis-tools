//  Copyright 2016 Google Inc. All Rights Reserved.
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

using NtApiDotNet;
using System.Management.Automation;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// <para type="synopsis">Creates a hardlink for a file.</para>
    /// <para type="description">This cmdlet creates a hard link to an existing file.
    /// The absolute path to the object in the NT object manager name space can be specified.
    /// To simplify calling it's also possible to specify the path in a Win32 format when using the -Win32Path parameter.</para>
    /// </summary>
    /// <example>
    ///   <code>Set-NtFileHardlink -Path \??\C:\ABC\XYZ.TXT -LinkPath \??\C:\TEMP\ABC.TXT</code>
    ///   <para>Create a hardlink for file \??\C:\ABC\XYZ.TXT as \??\C:\XYZ.</para>
    /// </example>
    /// <example>
    ///   <code>Set-NtFileHardlink -Path C:\ABC\XYZ.TXT -LinkPath C:\TEMP\ABC.TXT -Win32Path</code>
    ///   <para>Create a hardlink for file C:\ABC\XYZ.TXT as C:\TEMP\ABC.TXT.</para>
    /// </example>
    [Cmdlet(VerbsCommon.Set, "NtFileHardlink")]
    public class SetNtFileHardlinkCmdlet : GetNtFileCmdlet
    {
        /// <summary>
        /// <para type="description">Specify the path to the new link.</para>
        /// </summary>
        [Parameter(Mandatory = true, Position = 1)]
        public string LinkPath { get; set; }

        /// <summary>
        /// <para type="description">Specify a root object if TargetPath is relative.</para>
        /// </summary>
        [Parameter]
        public NtObject LinkRoot { get; set; }

        /// <summary>
        /// <para type="description">Specify to replace the target if it already exists.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter ReplaceIfExists { get; set; }

        /// <summary>
        /// Method to create an object from a set of object attributes.
        /// </summary>
        /// <param name="obj_attributes">The object attributes to create/open from.</param>
        /// <returns>The newly created object.</returns>
        protected override object CreateObject(ObjectAttributes obj_attributes)
        {
            using (NtFile file = (NtFile)base.CreateObject(obj_attributes))
            {
                if (LinkRoot == null && Win32Path)
                {
                    LinkPath = ResolveWin32Path(SessionState, LinkPath);
                }
                file.CreateHardlink(LinkPath, LinkRoot, ReplaceIfExists, true);
            }

            return null;
        }
    }
}
