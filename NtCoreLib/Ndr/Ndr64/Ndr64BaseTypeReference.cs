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

using System;

namespace NtCoreLib.Ndr.Ndr64;

/// <summary>
/// Base type reference for NDR64.
/// </summary>
[Serializable]
public abstract class Ndr64BaseTypeReference
{
    /// <summary>
    /// NDR64 type format character.
    /// </summary>
    public Ndr64FormatCharacter Format { get; }

    private static Ndr64BaseTypeReference ReadInternal(Ndr64ParseContext context, IntPtr ptr)
    {
        Ndr64BaseTypeReference type;
        Ndr64FormatCharacter format = context.ReadFormat(ptr);
        switch (format)
        {
            case Ndr64FormatCharacter.FC64_UINT8:
            case Ndr64FormatCharacter.FC64_INT8:
            case Ndr64FormatCharacter.FC64_UINT16:
            case Ndr64FormatCharacter.FC64_INT16:
            case Ndr64FormatCharacter.FC64_INT32:
            case Ndr64FormatCharacter.FC64_UINT32:
            case Ndr64FormatCharacter.FC64_INT64:
            case Ndr64FormatCharacter.FC64_UINT64:
            case Ndr64FormatCharacter.FC64_INT128:
            case Ndr64FormatCharacter.FC64_UINT128:
            case Ndr64FormatCharacter.FC64_FLOAT32:
            case Ndr64FormatCharacter.FC64_FLOAT64:
            case Ndr64FormatCharacter.FC64_FLOAT80:
            case Ndr64FormatCharacter.FC64_FLOAT128:
            case Ndr64FormatCharacter.FC64_CHAR:
            case Ndr64FormatCharacter.FC64_WCHAR:
            case Ndr64FormatCharacter.FC64_ERROR_STATUS_T:
                return new Ndr64SimpleTypeReference(format);
            case Ndr64FormatCharacter.FC64_UP:
            case Ndr64FormatCharacter.FC64_RP:
            case Ndr64FormatCharacter.FC64_OP:
            case Ndr64FormatCharacter.FC64_FP:
                type = new Ndr64PointerTypeReference(format, context, ptr);
                break;
            case Ndr64FormatCharacter.FC64_SYSTEM_HANDLE:
                type = new Ndr64SystemHandleTypeReference(context, ptr);
                break;
            case Ndr64FormatCharacter.FC64_AUTO_HANDLE:
            case Ndr64FormatCharacter.FC64_BIND_CONTEXT:
            case Ndr64FormatCharacter.FC64_BIND_GENERIC:
            case Ndr64FormatCharacter.FC64_BIND_PRIMITIVE:
            case Ndr64FormatCharacter.FC64_CALLBACK_HANDLE:
                type = new Ndr64HandleTypeReference(format);
                break;
            case Ndr64FormatCharacter.FC64_SUPPLEMENT:
                type = new Ndr64SupplementTypeReference(context, ptr);
                break;
            case Ndr64FormatCharacter.FC64_FIX_ARRAY:
                type = new Ndr64FixedArrayTypeReference(context, ptr);
                break;
            default:
                type = new Ndr64UnknownTypeReference(format);
                break;
        }

        return type;
    }

    internal static Ndr64BaseTypeReference Read(Ndr64ParseContext context, IntPtr ptr)
    {
        if (context.Cache.Cache.TryGetValue(ptr, out Ndr64BaseTypeReference type))
            return type;

        // Add a pending reference type, this is used only if the current type refers to itself (or indirectly).
        Ndr64IndirectTypeReference ref_type = new();
        context.Cache.Cache.Add(ptr, ref_type);

        Ndr64BaseTypeReference ret = ReadInternal(context, ptr);
        ref_type.FixupType(ret);
        // Replace type cache entry with real value.
        context.Cache.Cache[ptr] = ret;
        return ret;
    }

    private protected Ndr64BaseTypeReference(Ndr64FormatCharacter format)
    {
        Format = format;
    }

    /// <summary>
    /// Overridden ToString method.
    /// </summary>
    /// <returns>The object as a string.</returns>
    public override string ToString() => $"{Format} - {GetType().Name}";

    /// <summary>
    /// Get the size of the type (if known).
    /// </summary>
    /// <returns>The size of the type.</returns>
    public virtual int GetSize()
    {
        return Format switch
        {
            Ndr64FormatCharacter.FC64_UINT8 or Ndr64FormatCharacter.FC64_INT8 => 1,
            Ndr64FormatCharacter.FC64_UINT16 or Ndr64FormatCharacter.FC64_INT16 => 2,
            Ndr64FormatCharacter.FC64_INT32 or Ndr64FormatCharacter.FC64_UINT32 => 4,
            Ndr64FormatCharacter.FC64_INT64 or Ndr64FormatCharacter.FC64_UINT64 => 8,
            Ndr64FormatCharacter.FC64_INT128 or Ndr64FormatCharacter.FC64_UINT128 => 16,
            Ndr64FormatCharacter.FC64_FLOAT32 => 4,
            Ndr64FormatCharacter.FC64_FLOAT64 => 8,
            Ndr64FormatCharacter.FC64_FLOAT80 or Ndr64FormatCharacter.FC64_FLOAT128 => 16,
            Ndr64FormatCharacter.FC64_CHAR => 1,
            Ndr64FormatCharacter.FC64_WCHAR => 2,
            Ndr64FormatCharacter.FC64_ERROR_STATUS_T => 4,
            _ => 8,
        };
    }

    private bool _late_bound_types_fixed;

    private protected virtual void OnFixupLateBoundTypes()
    {
        // Do nothing in the base.
    }

    internal static Ndr64BaseTypeReference GetIndirectType(Ndr64BaseTypeReference base_type)
    {
        if (base_type is Ndr64IndirectTypeReference type)
        {
            return type.RefType;
        }
        return base_type;
    }

    internal void FixupLateBoundTypes()
    {
        if (!_late_bound_types_fixed)
        {
            _late_bound_types_fixed = true;
            OnFixupLateBoundTypes();
        }
    }
}
