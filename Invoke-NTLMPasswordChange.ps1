function Invoke-NTLMPasswordChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$true)][String]$Account,
        [Parameter(Mandatory=$true)][String]$NEW_NTLM,
        [switch]$ChangePassword,
        [switch]$SetPassword,
        [String]$OLD_NTLM
    )

    $objUser = New-Object System.Security.Principal.NTAccount($Account)
    $objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    
    $EnableVerbose = $PSBoundParameters.ContainsKey('Verbose') 


$src = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;

namespace CPH
{
	public class CPH
	{
		[DllImport("samlib.dll")]
		static extern int SamConnect(ref UNICODE_STRING serverName, out IntPtr ServerHandle, int DesiredAccess, bool reserved);

		[DllImport("samlib.dll")]
		static extern int SamConnect(IntPtr server, out IntPtr ServerHandle, int DesiredAccess, bool reserved);

		[DllImport("samlib.dll")]
		static extern int SamCloseHandle(IntPtr SamHandle);

		[DllImport("samlib.dll")]
		static extern int SamOpenDomain(IntPtr ServerHandle, int DesiredAccess, byte[] DomainId, out IntPtr DomainHandle);
		
		[DllImport("samlib.dll")]
		static extern int SamOpenUser(IntPtr DomainHandle, int DesiredAccess, int UserId, out IntPtr UserHandle);
		
		[DllImport("samlib.dll")]
        static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLM, byte[] oldLM, byte[] newLM, bool isNewNTLM, byte[] oldNTLM, byte[] newNTLM);
		
		[DllImport("samlib.dll")]
		static extern int SamSetInformationUser(IntPtr UserHandle, int UserInformationClass, ref SAMPR_USER_INTERNAL1_INFORMATION Buffer);

		struct SAMPR_USER_INTERNAL1_INFORMATION
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public byte[] EncryptedNtOwfPassword;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public byte[] EncryptedLmOwfPassword;
			public byte NtPasswordPresent;
			public byte LmPasswordPresent;
			public byte PasswordExpired;
		}

		const int MAXIMUM_ALLOWED = 0x02000000;
		const int UserInternal1Information = 18;

		[StructLayout(LayoutKind.Sequential)]
		struct UNICODE_STRING : IDisposable
		{
			public ushort Length;
			public ushort MaximumLength;
			private IntPtr buffer;

			[SecurityPermission(SecurityAction.LinkDemand)]
			public void Initialize(string s)
			{
				Length = (ushort)(s.Length * 2);
				MaximumLength = (ushort)(Length + 2);
				buffer = Marshal.StringToHGlobalUni(s);
			}

			public void Dispose()
			{
				if (buffer != IntPtr.Zero)
					Marshal.FreeHGlobal(buffer);
				buffer = IntPtr.Zero;
			}
			public override string ToString()
			{
				if (Length == 0)
					return String.Empty;
				return Marshal.PtrToStringUni(buffer, Length / 2);
			}
		}

		static int GetRID(SecurityIdentifier sid)
		{
			string sidstring = sid.Value;
			int pos = sidstring.LastIndexOf('-');
			string rid = sidstring.Substring(pos + 1);
			return int.Parse(rid);
		}
		
		public static int ChangePassword(string server, SecurityIdentifier account, byte[] OldNTLM, byte[] NewNTLM, bool verbose)
		{
			IntPtr SamHandle = IntPtr.Zero;
			IntPtr DomainHandle = IntPtr.Zero;
			IntPtr UserHandle = IntPtr.Zero;
			int Status = 0;
			UNICODE_STRING ustr_server = new UNICODE_STRING();
			try
			{
				if (String.IsNullOrEmpty(server))
				{
					Status = SamConnect(IntPtr.Zero, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				else
				{
					ustr_server.Initialize(server);
					Status = SamConnect(ref ustr_server, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamrConnect failed {0}", Status.ToString("x"));
					return Status;
				}
                if (verbose) Console.WriteLine("SamConnect OK");				
                
				byte[] sid = new byte[SecurityIdentifier.MaxBinaryLength];
				account.AccountDomainSid.GetBinaryForm(sid, 0);
				Status = SamOpenDomain(SamHandle, MAXIMUM_ALLOWED, sid, out DomainHandle);
				if (Status != 0)
				{
					Console.WriteLine("SamrOpenDomain failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamrOpenDomain OK");
				int rid = GetRID(account);
				if (verbose) Console.WriteLine("rid is " + rid);
				Status = SamOpenUser(DomainHandle , MAXIMUM_ALLOWED , rid , out UserHandle);
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamrOpenUser failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamOpenUser OK");
                byte[] oldLm = new byte[16];
                byte[] newLm = new byte[16];
				Status = SamiChangePasswordUser(UserHandle, false, oldLm, newLm, true, OldNTLM, NewNTLM);
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamiChangePasswordUser failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamiChangePasswordUser OK");
			}
			finally
			{
				if (UserHandle != IntPtr.Zero)
					SamCloseHandle(UserHandle);
				if (DomainHandle != IntPtr.Zero)
					SamCloseHandle(DomainHandle);
				if (SamHandle != IntPtr.Zero)
					SamCloseHandle(SamHandle);
				ustr_server.Dispose();
			}
			if (verbose) Console.WriteLine("OK");
			return 0;
		}
		
		[SecurityPermission(SecurityAction.Demand)]
		public static int SetPassword(string server, SecurityIdentifier account, byte[] lm, byte[] ntlm, bool verbose)
		{
			IntPtr SamHandle = IntPtr.Zero;
			IntPtr DomainHandle = IntPtr.Zero;
			IntPtr UserHandle = IntPtr.Zero;
			int Status = 0;
			UNICODE_STRING ustr_server = new UNICODE_STRING();
			try
			{
				if (String.IsNullOrEmpty(server))
				{
					Status = SamConnect(IntPtr.Zero, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				else
				{
					ustr_server.Initialize(server);
					Status = SamConnect(ref ustr_server, out SamHandle, MAXIMUM_ALLOWED, false);
				}
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamrConnect failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamConnect OK");
				byte[] sid = new byte[SecurityIdentifier.MaxBinaryLength];
				account.AccountDomainSid.GetBinaryForm(sid, 0);
				Status = SamOpenDomain(SamHandle, MAXIMUM_ALLOWED, sid, out DomainHandle);
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamrOpenDomain failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamrOpenDomain OK");
				int rid = GetRID(account);
				if (verbose) Console.WriteLine("rid is " + rid);
				Status = SamOpenUser(DomainHandle , MAXIMUM_ALLOWED , rid , out UserHandle);
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamrOpenUser failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamOpenUser OK");
				SAMPR_USER_INTERNAL1_INFORMATION information = new SAMPR_USER_INTERNAL1_INFORMATION();
				information.EncryptedLmOwfPassword = lm;
				information.LmPasswordPresent = (byte) (lm == null ? 0 : 1);
				information.EncryptedNtOwfPassword = ntlm;
				information.NtPasswordPresent = (byte)(ntlm == null ? 0 : 1);
				information.PasswordExpired = 0;
				Status = SamSetInformationUser(UserHandle, UserInternal1Information, ref information);
				if (Status != 0)
				{
					if (verbose) Console.WriteLine("SamSetInformationUser failed {0}", Status.ToString("x"));
					return Status;
				}
				if (verbose) Console.WriteLine("SamSetInformationUser OK");
			}
			finally
			{
				if (UserHandle != IntPtr.Zero)
					SamCloseHandle(UserHandle);
				if (DomainHandle != IntPtr.Zero)
					SamCloseHandle(DomainHandle);
				if (SamHandle != IntPtr.Zero)
					SamCloseHandle(SamHandle);
				ustr_server.Dispose();
			}
			if (verbose) Console.WriteLine("OK");
			return 0;
		}
	}
}

"@
    Add-Type -TypeDefinition $src


    if($ChangePassword)
    {   
        $o_ntlm = [byte[]](0..15 | ForEach-Object { [Convert]::ToByte($OLD_NTLM.Substring($_*2,2),16)})
        $n_ntlm = [byte[]](0..15 | ForEach-Object { [Convert]::ToByte($NEW_NTLM.Substring($_*2,2),16)})
        [CPH.CPH]::ChangePassword($Server, $objSID, $o_ntlm, $n_ntlm, $EnableVerbose)
    }
    if($SetPassword)
    {
        $n_ntlm = [byte[]](0..15 | ForEach-Object { [Convert]::ToByte($NEW_NTLM.Substring($_*2,2),16)})
	    [CPH.CPH]::SetPassword($Server, $objSID, $n_ntlm, $n_ntlm, $EnableVerbose)
    }
}
