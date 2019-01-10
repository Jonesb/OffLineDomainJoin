$source = @'
using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
namespace Nubile
{
    public class Kernel32
    {
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern int GetLastError();
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern void CloseHandle(IntPtr existingTokenHandle);
    }
    
    public class Netapi32
    {

         [DllImport("netapi32.dll", EntryPoint = "NetProvisionComputerAccount", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
            public static extern int NetProvisionComputerAccount(
            string lpDomain,
            string lpMachineName,
            string lpMachineAccountOU,
            string lpDcName,
            int dwOptions,
            IntPtr pProvisionBinData,
            IntPtr pdwProvisionBinDataSize,
            [MarshalAs(UnmanagedType.LPWStr)]
            out string pProvisionTextData);
        
    }

    public class AdvApi32
    {
        [DllImport("advapi32.DLL", SetLastError = true)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
        [DllImport("advapi32.dll", SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);
        public enum LogonTypes
        {
          
            LOGON32_LOGON_INTERACTIVE = 2,
            LOGON32_LOGON_NETWORK = 3,
            LOGON32_LOGON_BATCH = 4,
            LOGON32_LOGON_SERVICE = 5,
            LOGON32_LOGON_UNLOCK = 7,
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,
            LOGON32_LOGON_NEW_CREDENTIALS = 9,
        }
        public enum LogonProvider
        {
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }
        public enum SecurityImpersonationLevel : int
        {

            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }
        [DllImport("advapi32.DLL")]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken); //handle to token for logged-on user
        [DllImport("advapi32.DLL")]
        public static extern bool RevertToSelf();
        [DllImport("kernel32.dll")]
        public extern static bool CloseHandle(IntPtr hToken);
    }
    public class DomainJoin
    {
        public static int GetDomainJoin(String username, String password,string Domain, string MachineName,string OU,string DC,out string DomainJoinBlob)
        {
            int Result = -1;
           
            IntPtr existingTokenHandle = IntPtr.Zero;
            IntPtr duplicateTokenHandle = IntPtr.Zero;
           
            String[] splitUserName = username.Split('\\');
            string domain = splitUserName[0];
            userdomain = splitUserName[1];
           
          
            try
            {
                                
                bool isOkay = AdvApi32.LogonUser(username, userdomain, password,
                    (int)AdvApi32.LogonTypes.LOGON32_LOGON_NEW_CREDENTIALS,
                    (int)AdvApi32.LogonProvider.LOGON32_PROVIDER_WINNT50,
                    out existingTokenHandle);
                
                if (!isOkay)
                {
                    int lastWin32Error = Marshal.GetLastWin32Error();
                    int lastError = Kernel32.GetLastError();
                    throw new Exception("LogonUser Failed: " + lastWin32Error + " - " + lastError);
                }

                isOkay = AdvApi32.DuplicateToken(existingTokenHandle,
                    (int)AdvApi32.SecurityImpersonationLevel.SecurityImpersonation,
                    out duplicateTokenHandle);

               
                if (!isOkay)
                {
                    int lastWin32Error = Marshal.GetLastWin32Error();
                    int lastError = Kernel32.GetLastError();
                    Kernel32.CloseHandle(existingTokenHandle);
                    throw new Exception("DuplicateToken Failed: " + lastWin32Error + " - " + lastError);
                }

               
                AdvApi32.ImpersonateLoggedOnUser(duplicateTokenHandle);
                
                String blob = String.Empty;
                             
                Console.WriteLine("Calling NetProvisionComputerAccount");    

                Result = Netapi32.NetProvisionComputerAccount(Domain,MachineName,OU,DC,2,IntPtr.Zero, IntPtr.Zero, out blob);

                DomainJoinBlob = blob;
               
                if(AdvApi32.RevertToSelf())
                {
                    Console.WriteLine("RevertToSelf Succeeded");
                }
                else
                {
                    Console.WriteLine("RevertToSelf Failed");
                }
                
            }
            finally
            {
                if (existingTokenHandle != IntPtr.Zero)
                {
                    Kernel32.CloseHandle(existingTokenHandle);
                }
                if (duplicateTokenHandle != IntPtr.Zero)
                {
                    Kernel32.CloseHandle(duplicateTokenHandle);
                }
            }

            return Result;
        }
        static void Main(string[] args)
        {
            Console.WriteLine("MAIN CALLED");
            Console.ReadLine();
        }
    }
}
'@

#how to call
$result = Add-Type -TypeDefinition $Source -Language CSharp

$DomainJoinBlob = ""
$Result = [Nubile.DomainJoin]::GetDomainJoin("UserDomain\UserName", "Password","DOMAIN","MachineName","OU=ExampleOU,DC=domain ,DC=internal","DomainController",[ref] $DomainJoinBlob)

Write-host "Returned Value- " $Result
Write-host "Blob - " $DomainJoinBlob

