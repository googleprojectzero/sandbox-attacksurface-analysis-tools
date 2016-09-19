using System;

namespace HandleUtils
{
    [Flags]
    public enum AccessRights : uint
    {
        None = 0x0,
		SectionMapRead = 0x4,
		SectionMapWrite = 0x2,
	}

    [Flags]
    public enum DuplicateHandleOptions : uint
    {
        None = 0,
		DuplicateSameAccess = 0x2,
	}

    [Flags]
    public enum StandardAccessRights : uint
    {
        Delete = 0x00010000,
		ReadControl = 0x00020000,
		WriteDac = 0x00040000,
		WriteOwner = 0x00080000,
		Synchronize = 0x00100000,
	}

    [Flags]
    public enum GenericAccessRights : uint
    {
        GenericRead = 0x80000000U,
		GenericWrite = 0x40000000U,
		GenericExecute = 0x20000000U,
		GenericAll = 0x10000000U,
	}

    [Flags]
    public enum DirectoryAccessRights : uint
    {
        Query = 0x0001,
		Traverse = 0x0002,
		CreateObject = 0x0004,
		CreateSubdirectory = 0x0008
	}

    [Flags]
    public enum EventAccessRights : uint
    {
        QueryState = 0x0001,
		ModifyState = 0x0002,
	}

    [Flags]
    public enum SectionAccessRights : uint
    {
        Query = 0x0001,
		MapWrite = 0x0002,
		MapRead = 0x0004,
		MapExecute = 0x0008,
		ExtendSize = 0x0010,
		MapExecuteExplicit = 0x0020
	}

    [Flags]
    public enum FileAccessRights : uint
    {
        ReadData = 0x0001,
		WriteData = 0x0002,
		AppendData = 0x0004,
		ReadEa = 0x0008,
		WriteEa = 0x0010,
		Execute = 0x0020,
		DeleteChild = 0x0040,
		ReadAttributes = 0x0080,
		WriteAttributes = 0x0100,
	}

    [Flags]
    public enum FileDirectoryAccessRights : uint
    {
        ListDirectory = 0x0001,
		AddFile = 0x0002,
		AddSubDirectory = 0x0004,
		ReadEa = 0x0008,
		WriteEa = 0x0010,
		Traverse = 0x0020,
		DeleteChild = 0x0040,
		ReadAttributes = 0x0080,
		WriteAttributes = 0x0100,
	}


    [Flags]
    public enum KeyAccessRights : uint
    {
        QueryValue = 0x0001,
		SetValue = 0x0002,
		CreateSubKey = 0x0004,
		EnumerateSubKeys = 0x0008,
		Notify = 0x0010,
		CreateLink = 0x0020,
	}

    [Flags]
    public enum MutantAccessRights : uint
    {
        QueryState = 0x0001,
	}

    [Flags]
    public enum SemaphoreAccessRights : uint
    {
        QueryState = 0x0001,
		ModifyState = 0x0002,
	}

    [Flags]
    public enum JobObjectAccessRights : uint
    {
        AssignProcess = 0x0001,
		SetAttributes = 0x0002,
		Query = 0x0004,
		Terminate = 0x0008,
		SetSecurityAttributes = 0x0010
	}

    [Flags]
    public enum ProcessAccessRights : uint
    {
        CreateProcess = 0x0080,
		CreateThread = 0x0002,
		DupHandle = 0x0040,
		QueryInformation = 0x0400,
		QueryLimitedInformation = 0x1000,
		SetInformation = 0x0200,
		SetQuota = 0x0100,
		SuspendResume = 0x0800,
		Terminate = 0x0001,
		VmOperation = 0x0008,
		VmRead = 0x0010,
		VmWrite = 0x0020,
	}

    public enum ThreadAccessRights : uint
    {
        DirectImpersonation = 0x0200,
		GetContext = 0x0008,
		Impersonate = 0x0100,
		QueryInformation = 0x0040,
		QueryLimitedInformation = 0x0800,
		SetContext = 0x0010,
		SetInformation = 0x0020,
		SetLimitedInformation = 0x0400,
		SetToken = 0x0080,
		SuspendResume = 0x0002,
		Terminate = 0x0001,
	}

    public enum TokenAccessRights : uint
    {
        AssignPrimary = 0x0001,
		Duplicate = 0x0002,
		Impersonate = 0x0004,
		Query = 0x0008,
		QuerySource = 0x0010,
		AdjustPrivileges = 0x0020,
		AdjustGroups = 0x0040,
		AdjustDefault = 0x0080,
		AdjustSessionId = 0x0100,
	}

    [Flags]
    public enum SymbolicLinkAccessRights : uint
    {
        Query = 0x0001,
	}

    [Flags]
    public enum FileOpenOptions : uint
    {
        DIRECTORY_FILE = 0x00000001,
		WRITE_THROUGH = 0x00000002,
		SEQUENTIAL_ONLY = 0x00000004,
		NO_INTERMEDIATE_BUFFERING = 0x00000008,
		SYNCHRONOUS_IO_ALERT = 0x00000010,
		SYNCHRONOUS_IO_NONALERT = 0x00000020,
		NON_DIRECTORY_FILE = 0x00000040,
		CREATE_TREE_CONNECTION = 0x00000080,
		COMPLETE_IF_OPLOCKED = 0x00000100,
		NO_EA_KNOWLEDGE = 0x00000200,
		OPEN_REMOTE_INSTANCE = 0x00000400,
		RANDOM_ACCESS = 0x00000800,
		DELETE_ON_CLOSE = 0x00001000,
		OPEN_BY_FILE_ID = 0x00002000,
		OPEN_FOR_BACKUP_INTENT = 0x00004000,
		NO_COMPRESSION = 0x00008000,
		OPEN_REQUIRING_OPLOCK = 0x00010000,
		RESERVE_OPFILTER = 0x00100000,
		OPEN_REPARSE_POINT = 0x00200000,
		OPEN_NO_RECALL = 0x00400000,
		OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
	}

    [Flags]
    public enum FileShareMode : uint
    {
        Read = 0x00000001,
		Write = 0x00000002,
		Delete = 0x00000004,
		All = Read | Write | Delete
    }

    public enum FileCreateDisposition : uint
    {
        Supersede = 0x00000000,
		Open = 0x00000001,
		Create = 0x00000002,
		OpenIf = 0x00000003,
		Overwrite = 0x00000004,
		OverwriteIf = 0x00000005
	}

    public enum TokenSecurityLevel : uint
    {
        Anonymous = 0,
		Identification = 1,
		Impersonate = 2,
		Delegate = 3,
	}
}
