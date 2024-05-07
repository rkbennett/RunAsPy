import ctypes
import ctypes.wintypes

UOI_NAME = 2
ERROR_LOGON_TYPE_NOT_GRANTED = 1385
LOGON32_LOGON_INTERACTIVE = ctypes.wintypes.DWORD(2)
LOGON32_LOGON_NETWORK  = ctypes.wintypes.DWORD(3)
LOGON32_LOGON_BATCH = ctypes.wintypes.DWORD(4)
LOGON32_LOGON_SERVICE = ctypes.wintypes.DWORD(5)
LOGON32_LOGON_NETWORK_CLEARTEXT = ctypes.wintypes.DWORD(8)
LOGON32_LOGON_NEW_CREDENTIALS = ctypes.wintypes.DWORD(9)
LOGON_WITH_PROFILE = ctypes.c_uint32(1)
DUPLICATE_SAME_ACCESS = ctypes.c_uint(0x2)
LOGON32_PROVIDER_DEFAULT = ctypes.wintypes.DWORD(0)
LOGON32_PROVIDER_WINNT50 = ctypes.wintypes.DWORD(3)
Startf_UseStdHandles = 0x00000100
BUFFER_SIZE_PIPE = 1048576
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
CREATE_SUSPENDED = 0x00000004
ERROR_MORE_DATA = 234
CREATE_UNICODE_ENVIRONMENT = 0x00000400
PSID = ctypes.c_void_p

privileges = [
    "SeAssignPrimaryTokenPrivilege",   "SeAuditPrivilege",                "SeBackupPrivilege",                         "SeChangeNotifyPrivilege", 
    "SeCreateGlobalPrivilege",         "SeCreatePagefilePrivilege",       "SeCreatePermanentPrivilege",                "SeCreateSymbolicLinkPrivilege", 
    "SeCreateTokenPrivilege",          "SeDebugPrivilege",                "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", 
    "SeImpersonatePrivilege",          "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",                  "SeIncreaseWorkingSetPrivilege", 
    "SeLoadDriverPrivilege",           "SeLockMemoryPrivilege",           "SeMachineAccountPrivilege",                 "SeManageVolumePrivilege", 
    "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege",              "SeRemoteShutdownPrivilege",                 "SeRestorePrivilege", 
    "SeSecurityPrivilege",             "SeShutdownPrivilege",             "SeSyncAgentPrivilege",                      "SeSystemEnvironmentPrivilege", 
    "SeSystemProfilePrivilege",        "SeSystemtimePrivilege",           "SeTakeOwnershipPrivilege",                  "SeTcbPrivilege", 
    "SeTimeZonePrivilege",             "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege",                         "SeUnsolicitedInputPrivilege"
]

kernel32 = ctypes.WinDLL("kernel32.dll")
user32 = ctypes.WinDLL("User32.dll")
ws2_32 = ctypes.WinDLL("ws2_32.dll")
advapi32 = ctypes.WinDLL("Advapi32.dll")
userenv = ctypes.WinDLL("Userenv.dll")

connect = ws2_32.connect
closesocket = ws2_32.closesocket
WSASocket = ws2_32.WSASocketA
WSAStartup = ws2_32.WSAStartup
ReadFile = kernel32.ReadFile
CloseHandle = kernel32.CloseHandle
CreatePipe = kernel32.CreatePipe
CreateProcessW = kernel32.CreateProcessW
DuplicateHandle = kernel32.DuplicateHandle
SetNamedPipeHandleState = kernel32.SetNamedPipeHandleState
WaitForSingleObject = kernel32.WaitForSingleObject
GetCurrentProcessId = kernel32.GetCurrentProcessId
ProcessIdToSessionId = kernel32.ProcessIdToSessionId
GetTokenInformation = advapi32.GetTokenInformation
GetCurrentThread = kernel32.GetCurrentThread
GetCurrentProcess = kernel32.GetCurrentProcess
ResumeThread = kernel32.ResumeThread
LogonUser = advapi32.LogonUserA
GetSecurityDescriptorDacl = advapi32.GetSecurityDescriptorDacl
LookupAccountName = advapi32.LookupAccountNameA
GetAclInformation = advapi32.GetAclInformation
InitializeSecurityDescriptor = advapi32.InitializeSecurityDescriptor
GetLengthSid = advapi32.GetLengthSid
InitializeAcl = advapi32.InitializeAcl
GetAce = advapi32.GetAce
AddAce = advapi32.AddAce
CopySid = advapi32.CopySid
SetThreadToken = advapi32.SetThreadToken
RevertToSelf = advapi32.RevertToSelf
AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
LookupPrivilegeName = advapi32.LookupPrivilegeNameA
SetSecurityInfo = advapi32.SetSecurityInfo
CreateProcessWithLogonW = advapi32.CreateProcessWithLogonW
ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser
AllocateAndInitializeSid = advapi32.AllocateAndInitializeSid
OpenProcessToken = advapi32.OpenProcessToken
GetSidSubAuthorityCount = advapi32.GetSidSubAuthorityCount
GetSidSubAuthority = advapi32.GetSidSubAuthority
OpenThreadToken = advapi32.OpenThreadToken
DuplicateToken = advapi32.DuplicateToken
DuplicateTokenEx = advapi32.DuplicateTokenEx
AddAccessAllowedAce = advapi32.AddAccessAllowedAce
SetSecurityDescriptorDacl = advapi32.SetSecurityDescriptorDacl
SetTokenInformation = advapi32.SetTokenInformation
LookupPrivilegeValue = advapi32.LookupPrivilegeValueA
CreateProcessWithTokenW =advapi32.CreateProcessWithTokenW
CreateProcessAsUser = advapi32.CreateProcessAsUserA
GetProcessWindowStation = user32.GetProcessWindowStation
GetUserObjectInformation = user32.GetUserObjectInformationA
OpenWindowStation = user32.OpenWindowStationA
SetProcessWindowStation = user32.SetProcessWindowStation
OpenDesktop = user32.OpenDesktopA
GetUserObjectSecurity = user32.GetUserObjectSecurity
SetUserObjectSecurity = user32.SetUserObjectSecurity
GetUserProfileDirectory = userenv.GetUserProfileDirectoryA
LoadUserProfile = userenv.LoadUserProfileA
CreateEnvironmentBlock = userenv.CreateEnvironmentBlock
UnloadUserProfile = userenv.UnloadUserProfile
DestroyEnvironmentBlock = userenv.DestroyEnvironmentBlock

OpenThreadToken.restype = ctypes.c_bool

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

class TOKEN_MANDATORY_LABEL(ctypes.Structure):
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
        ('lpReserved',       ctypes.wintypes.LPWSTR),
        ('lpDesktop',        ctypes.wintypes.LPWSTR),
        ('lpTitle',          ctypes.wintypes.LPWSTR),
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

LPSTARTUPINFOW = ctypes.POINTER(STARTUPINFO)

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("process",    ctypes.wintypes.HANDLE),
        ("thread",     ctypes.wintypes.HANDLE),
        ("processId",  ctypes.wintypes.DWORD),
        ("threadId",   ctypes.wintypes.DWORD)
    ]

LPPROCESS_INFORMATION = ctypes.POINTER(PROCESS_INFORMATION)

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

class PROFILEINFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('dwFlags', ctypes.wintypes.DWORD),
        ('lpUserName', ctypes.wintypes.LPSTR),
        ('lpProfilePath', ctypes.wintypes.LPSTR),
        ('lpDefaultPath', ctypes.wintypes.LPSTR),
        ('lpServerName', ctypes.wintypes.LPSTR),
        ('lpPolicyPath', ctypes.wintypes.LPSTR),
        ('hProfile', ctypes.c_void_p)
    ]


class SECURITY_IMPERSONATION_LEVEL(object):
    SecurityAnonymous = ctypes.c_int(0)
    SecurityIdentification = ctypes.c_int(1)
    SecurityImpersonation = ctypes.c_int(2)
    SecurityDelegation = ctypes.c_int(3)


class AddressFamily(object):
    XAppleTalk = ctypes.c_int(16)
    Atm = ctypes.c_int(22)
    Banyan = ctypes.c_int(21)
    Ccitt = ctypes.c_int(10)
    Chaos = ctypes.c_int(5)
    Cluster = ctypes.c_int(24)
    ControllerAreaNetwork = ctypes.c_int(65537)
    DataKit = ctypes.c_int(9)
    DataLink = ctypes.c_int(13)
    DecNet = ctypes.c_int(12)
    Ecma = ctypes.c_int(8)
    FireFox = ctypes.c_int(19)
    HyperChannel = ctypes.c_int(15)
    Ieee12844 = ctypes.c_int(25)
    ImpLink = ctypes.c_int(3)
    InterNetwork = ctypes.c_int(2)
    InterNetworkV6 = ctypes.c_int(23)
    Ipx = ctypes.c_int(6)
    Irda = ctypes.c_int(26)
    Iso = ctypes.c_int(7)
    Lat = ctypes.c_int(1)
    Max = ctypes.c_int(2)
    NetBios = ctypes.c_int(17)
    NetworkDesigners = ctypes.c_int(28)
    NS = ctypes.c_int(6)
    Osi = ctypes.c_int(7)
    Packet = ctypes.c_int(65536)
    Pup = ctypes.c_int(4)
    Sna = ctypes.c_int(11)
    Unix = ctypes.c_int(1)
    Unknown = ctypes.c_int(-1)
    Unspecified = ctypes.c_int()
    VoiceView = ctypes.c_int(1)


class ProtocolType(object):
    Ggp = ctypes.c_int(3)
    Icmp = ctypes.c_int(1)
    IcmpV6 = ctypes.c_int(58)
    Idp = ctypes.c_int(22)
    Igmp = ctypes.c_int(2)
    IP = ctypes.c_int(0)
    IPSecAuthenticationHeader = ctypes.c_int(51)
    IPSecEncapsulatingSecurityPayload = ctypes.c_int(50)
    IPv4 = ctypes.c_int(4)
    IPv6 = ctypes.c_int(41)
    IPv6DestinationOptions = ctypes.c_int(60)
    IPv6FragmentHeader = ctypes.c_int(44)
    IPv6HopByHopOptions = ctypes.c_int(0)
    IPv6NoNextHeader = ctypes.c_int(59)
    IPv6RoutingHeader = ctypes.c_int(43)
    Ipx = ctypes.c_int(1000)
    ND = ctypes.c_int(77)
    Pup = ctypes.c_int(12)
    Raw = ctypes.c_int(255)
    Spx = ctypes.c_int(1256)
    SpxII = ctypes.c_int(1257)
    Tcp = ctypes.c_int(6)
    Udp = ctypes.c_int(17)
    Unknown = ctypes.c_int(-1)
    Unspecified = ctypes.c_int(0)


class SocketType(object):
    Dgram = ctypes.c_int(2)
    Raw = ctypes.c_int(3)
    Rdm = ctypes.c_int(4)
    Seqpacket = ctypes.c_int(5)
    Stream = ctypes.c_int(1)
    Unknown = ctypes.c_int(-1)


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
    OWNER_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000001)
    GROUP_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000002)
    DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000004)
    SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x00000008)
    UNPROTECTED_SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x10000000)
    UNPROTECTED_DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x20000000)
    PROTECTED_SACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x40000000)
    PROTECTED_DACL_SECURITY_INFORMATION = ctypes.wintypes.DWORD(0x80000000)

class SID_NAME_USE(object):
    SidTypeUser = ctypes.c_int(1)
    SidTypeGroup = ctypes.c_int(2)
    SidTypeDomain = ctypes.c_int(3)
    SidTypeAlias = ctypes.c_int(4)
    SidTypeWellKnownGroup = ctypes.c_int(5)
    SidTypeDeletedAccount = ctypes.c_int(6)
    SidTypeInvalid = ctypes.c_int(7)
    SidTypeUnknown = ctypes.c_int(8)
    SidTypeComputer = ctypes.c_int(9)
    SidTypeLabel = ctypes.c_int(10)


class TOKEN_ELEVATION(ctypes.Structure):
    _fields_ = [
        ('TokenIsElevated', ctypes.c_uint32)
    ]


class TOKEN_ELEVATION_TYPE(ctypes.Structure):
    _fields_ = [
        ('TokenElevationType', ctypes.c_uint32)
    ]


class ACL_INFORMATION_CLASS(object):
    AclRevisionInformation = ctypes.wintypes.DWORD(1)
    AclSizeInformation = ctypes.wintypes.DWORD(2)


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


class WSADATA(ctypes.Structure):
    _fields_ = [
        ('wVersion', ctypes.c_short),
        ('wHighVersion', ctypes.c_short),
        ('iMaxSockets', ctypes.c_short),
        ('iMaxUdpDg', ctypes.c_short),
        ('lpVendorInfo', ctypes.c_void_p),
        ('szDescription', ctypes.POINTER(ctypes.c_char * 257)),
        ('szSystemStatus', ctypes.POINTER(ctypes.c_char * 129))
    ]


class ACCESS_MASK(object):
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    STANDARD_RIGHTS_REQUIRED = 0x000F0000
    STANDARD_RIGHTS_READ = READ_CONTROL
    STANDARD_RIGHTS_WRITE = READ_CONTROL
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL
    STANDARD_RIGHTS_ALL = 0x001F0000
    SPECIFIC_RIGHTS_ALL = 0x0000FFFF
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    GENERIC_ACCESS = (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)
    WINSTA_ENUMDESKTOPS = 0x00000001
    WINSTA_READATTRIBUTES = 0x00000002
    WINSTA_ACCESSCLIPBOARD = 0x00000004
    WINSTA_CREATEDESKTOP = 0x00000008
    WINSTA_WRITEATTRIBUTES = 0x00000010
    WINSTA_ACCESSGLOBALATOMS = 0x00000020
    WINSTA_EXITWINDOWS = 0x00000040
    WINSTA_ENUMERATE = 0x00000100
    WINSTA_READSCREEN = 0x00000200
    WINSTA_ALL =  (
        WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS | WINSTA_CREATEDESKTOP    | WINSTA_ENUMDESKTOPS      | 
        WINSTA_ENUMERATE        | WINSTA_EXITWINDOWS       | WINSTA_READATTRIBUTES   | WINSTA_READSCREEN        | 
        WINSTA_WRITEATTRIBUTES  | DELETE                   | READ_CONTROL            | WRITE_DAC                | 
        WRITE_OWNER
    )
    DESKTOP_READOBJECTS = 0x00000001
    DESKTOP_CREATEWINDOW = 0x00000002
    DESKTOP_CREATEMENU = 0x00000004
    DESKTOP_HOOKCONTROL = 0x00000008
    DESKTOP_JOURNALRECORD = 0x00000010
    DESKTOP_JOURNALPLAYBACK = 0x00000020
    DESKTOP_ENUMERATE = 0x00000040
    DESKTOP_WRITEOBJECTS = 0x00000080
    DESKTOP_SWITCHDESKTOP = 0x00000100
    DESKTOP_ALL = (
        DESKTOP_READOBJECTS   | DESKTOP_CREATEWINDOW     | DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL  | 
        DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK  | DESKTOP_ENUMERATE  | DESKTOP_WRITEOBJECTS |
        DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED
    )


class ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ('AceType', ctypes.c_byte),
        ('AceFlags', ctypes.c_byte),
        ('AceSize', ctypes.c_ushort),
    ]


class TOKEN_PRIVILEGES_2(ctypes.Structure):
    _fields_ = [
        ('PrivilegeCount', ctypes.c_uint32),
        ('Luid', LUID),
        ('Attributes', ctypes.wintypes.DWORD)
    ]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [
        ('Header', ACE_HEADER),
        ('Mask', ctypes.wintypes.DWORD),
        ('SidStart', ctypes.wintypes.DWORD)
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ('sin_family', ctypes.c_short),
        ('sin_port', ctypes.c_short),
        ('sin_addr', ctypes.c_ulong),
        ('sin_zero', (ctypes.c_char * 8))
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


CreateProcessWithLogonW.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
    LPSTARTUPINFOW,
    LPPROCESS_INFORMATION
]

LogonUser.argtypes = [
    ctypes.wintypes.LPCSTR,
    ctypes.wintypes.LPCSTR,
    ctypes.wintypes.LPCSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.HANDLE)
]

GetUserProfileDirectory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPSTR,
    ctypes.wintypes.LPDWORD
]

CreateProcessW.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_bool,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO),
    ctypes.POINTER(PROCESS_INFORMATION)
]

GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_byte)
GetSidSubAuthority.restype = ctypes.POINTER(ctypes.wintypes.DWORD)
