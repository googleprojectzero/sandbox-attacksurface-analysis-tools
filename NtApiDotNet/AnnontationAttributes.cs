using System;

namespace NtApiDotNet
{
    public enum SupportedVersion
    {
        Windows7,
        Windows8,
        Windows81,
        Windows10,
        Windows10_TH2,
        Windows10_RS1,
    }

    /// <summary>
    /// Attribute to indicate the required version for a function.
    /// Applied if the function needs a version greater than 7.
    /// </summary>
    public sealed class SupportedVersionAttribute : Attribute
    {
        public SupportedVersion Version { get; private set; }
        public SupportedVersionAttribute(SupportedVersion version)
        {
            Version = version;
        }
    }

    /// <summary>
    /// Attribute used for managed structures to indicate the start of data.
    /// This is used in situations where the data immediately trail 
    /// </summary>
    [AttributeUsage(AttributeTargets.Struct | AttributeTargets.Class)]
    public sealed class DataStartAttribute : Attribute
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="field_name">The field name which indicates the first address of data.</param>
        public DataStartAttribute(string field_name)
        {
            FieldName = field_name;
        }

        /// <summary>
        /// The field name which indicates the first address of data.
        /// </summary>
        public string FieldName { get; set; }
    }

}
