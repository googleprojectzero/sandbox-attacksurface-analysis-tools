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


namespace NtCoreLib.Image.Parser;

internal sealed class PeFileResourceDataEntry
{
    public ResourceString Name { get; }
    public byte[] Data { get; }
    public int CodePage { get; }

    public PeFileResourceDataEntry(ResourceString name, byte[] data, int code_page)
    {
        Name = name;
        Data = data;
        CodePage = code_page;
    }

    public ImageResource ToResource(ImageResourceType type)
    {
        return new ImageResource(Name, type, Data);
    }
}

