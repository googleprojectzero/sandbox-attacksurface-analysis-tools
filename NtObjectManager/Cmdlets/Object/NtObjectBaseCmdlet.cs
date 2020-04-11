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
using NtObjectManager.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;

namespace NtObjectManager.Cmdlets.Object
{
    /// <summary>
    /// Base object cmdlet.
    /// </summary>
    public abstract class NtObjectBaseCmdlet : NtObjectBaseNoPathCmdlet
    {
        /// <summary>
        /// <para type="description">The NT object manager path to the object to use.</para>
        /// </summary>
        [Parameter(Position = 0)]
        public virtual string Path { get; set; }

        /// <summary>
        /// <para type="description">An existing open NT object to use when Path is relative.</para>
        /// </summary>
        [Parameter(ValueFromPipeline = true)]
        public NtObject Root { get; set; }

        /// <summary>
        /// <para type="description">Use a Win32 path for lookups. For NT objects this means relative to BNO, for files means a DOS style path.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter Win32Path { get; set; }

        /// <summary>
        /// <para type="description">Automatically close the Root object when this cmdlet finishes processing. Useful for pipelines.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CloseRoot { get; set; }

        /// <summary>
        /// <para type="description">Create any necessary NtDirectory objects to create the required object. Will return the created directories as well as the object in the output.
        /// The new object will be the first entry in the list. This doesn't work when opening an object or creating keys/files.</para>
        /// </summary>
        [Parameter]
        public SwitchParameter CreateDirectories { get; set; }
        
        /// <summary>
        /// Base constructor.
        /// </summary>
        protected NtObjectBaseCmdlet()
        {
        }

        /// <summary>
        /// Verify the parameters, should throw an exception if parameters are invalid.
        /// </summary>
        protected virtual void VerifyParameters()
        {
            string path = ResolvePath();
            if (path != null)
            {
                if (!path.StartsWith(@"\") && Root == null)
                {
                    throw new ArgumentException("Relative paths with no Root directory are not allowed.");
                }
            }

            if (Win32Path && Root != null)
            {
                throw new ArgumentException("Can't combine Win32Path and Root");
            }

            if (CreateDirectories)
            {
                if (!CanCreateDirectories())
                {
                    throw new ArgumentException("Can't specify CreateDirectories when opening an object.");
                }

                if (Root != null && !(Root is NtDirectory))
                {
                    throw new ArgumentException("Can't specify CreateDirectories when Root is not a directory.");
                }
            }
        }

        private static string RemoveDrive(string path)
        {
            int index = path.IndexOf(@":\");
            if (index < 0)
            {
                throw new ArgumentException("Invalid drive path");
            }
            return path.Substring(index + 2);
        }

        /// <summary>
        /// Get the Win32 path for a specified path.
        /// </summary>
        /// <param name="path">The path component.</param>
        /// <returns>The full NT path.</returns>
        protected virtual string GetWin32Path(string path)
        {
            return $@"{NtDirectory.GetBasedNamedObjects()}\{path}";
        }

        /// <summary>
        /// Virtual method to resolve the value of the Path variable.
        /// </summary>
        /// <returns>The object path.</returns>
        protected virtual string ResolvePath()
        {
            if (Path == null)
            {
                return null;
            }

            if (Win32Path)
            {
                if (Path.StartsWith(@"\"))
                {
                    throw new ArgumentException("Win32 paths can't start with a path separator");
                }

                return GetWin32Path(Path);
            }

            if (Path.StartsWith(@"\") || Root != null)
            {
                return Path;
            }

            var current_path = SessionState.Path.CurrentLocation;
            if (current_path.Drive is ObjectManagerPSDriveInfo drive)
            {
                string root_path = drive.DirectoryRoot.FullPath;
                if (root_path == @"\")
                {
                    root_path = string.Empty;
                }

                string relative_path = RemoveDrive(current_path.Path);
                if (relative_path.Length == 0)
                {
                    return $@"{root_path}\{Path}";
                }
                return $@"{root_path}\{relative_path}\{Path}";
            }
            else
            {
                throw new ArgumentException("Can't make a relative object path when not in a NtObject drive.");
            }
        }


        /// <summary>
        /// Determine if the cmdlet can create objects.
        /// </summary>
        /// <returns>True if objects can be created.</returns>
        protected abstract bool CanCreateDirectories();

        private IEnumerable<NtObject> CreateDirectoriesAndObject()
        {
            DisposableList<NtObject> objects = new DisposableList<NtObject>();
            string[] path_parts = ResolvePath().Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            StringBuilder builder = new StringBuilder();
            bool finished = false;
            if (Root == null)
            {
                builder.Append(@"\");
            }

            try
            {
                for (int i = 0; i < path_parts.Length - 1; ++i)
                {
                    builder.Append(path_parts[i]);
                    NtDirectory dir = null;
                    try
                    {
                        dir = NtDirectory.Create(builder.ToString(), Root, DirectoryAccessRights.MaximumAllowed);
                    }
                    catch (NtException)
                    {
                    }

                    if (dir != null)
                    {
                        objects.Add(dir);
                    }
                    builder.Append(@"\");
                }
                objects.Add((NtObject)CreateObject(ResolvePath(), AttributesFlags, Root, SecurityQualityOfService, SecurityDescriptor));
                finished = true;
            }
            finally
            {
                if (!finished)
                {
                    objects.Dispose();
                    objects.Clear();
                }
            }
            return objects.ToArray();
        }
        
        /// <summary>
        /// Overridden ProcessRecord method.
        /// </summary>
        protected override void ProcessRecord()
        {
            VerifyParameters();
            try
            {
                WriteObject(CreateObject(ResolvePath(), AttributesFlags, Root, SecurityQualityOfService, SecurityDescriptor), true);
            }
            catch (NtException ex)
            {
                if (ex.Status != NtStatus.STATUS_OBJECT_PATH_NOT_FOUND || !CreateDirectories)
                {
                    throw;
                }

                WriteObject(CreateDirectoriesAndObject().Reverse(), true);
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        /// <summary>
        /// Dispose object.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (CloseRoot && Root != null)
                {
                    NtObject obj = Root;
                    Root = null;
                    obj.Close();
                }
                disposedValue = true;
            }
        }

        #endregion
    }
}
