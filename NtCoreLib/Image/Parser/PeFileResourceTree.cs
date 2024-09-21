//  Copyright 2023 Google LLC. All Rights Reserved.
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

#nullable enable

using NtCoreLib.Win32;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace NtCoreLib.Image.Parser;

internal sealed class PeFileResourceTree
{
    public PeFileResourceDirectory Root { get; }

    public PeFileResourceTree() : this(new PeFileResourceDirectory())
    {
    }

    public PeFileResourceTree(PeFileResourceDirectory root)
    {
        Root = root;
    }

    public IEnumerable<ImageResourceType> GetResourceTypes()
    {
        return Root.Directories.Select(d => new ImageResourceType(d.Name));
    }

    public NtResult<IEnumerable<ImageResource>> FindResources(ImageResourceType type, int? lcid, bool throw_on_error)
    {
        lcid ??= CultureInfo.CurrentCulture.LCID;
        var dir = Root.Directories
            .Where(d => d.Name.Equals(type.Name)).FirstOrDefault();
        if (dir == null)
        {
            return Win32Error.ERROR_RESOURCE_TYPE_NOT_FOUND.CreateResultFromDosError<IEnumerable<ImageResource>>(throw_on_error);
        }
        List<ImageResource> resources = new();
        foreach (var entry in dir.Directories)
        {
            var lang_entries = entry.DataEntries.Select(e => new ImageResource(entry.Name, type, e.Data, e.Name.Id ?? 0));
            if (!lang_entries.Any())
            {
                continue;
            }
            if (lang_entries.Any(e => e.Language == lcid))
            {
                resources.Add(lang_entries.First(e => e.Language == lcid));
            }
            else
            {
                resources.Add(lang_entries.First());
            }
        }
        return resources.AsReadOnly().CreateResult<IEnumerable<ImageResource>>();
    }

    public NtResult<byte[]> LoadResourceData(ResourceString name, ImageResourceType type, int? lcid, bool throw_on_error)
    {
        var types = FindResources(type, lcid, throw_on_error);
        if (!types.IsSuccess)
            return types.Cast<byte[]>();

        var res = types.Result.Where(e => e.Name.Equals(name));
        if (!res.Any())
            return Win32Error.ERROR_RESOURCE_NAME_NOT_FOUND.CreateResultFromDosError<byte[]>(throw_on_error);
        return res.First().ToArray().CreateResult();
    }
}

