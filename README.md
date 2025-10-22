# NTLM Password Changer

A PowerShell utility that changes Windows account passwords through the native **Samlib.dll** API, the same low-level library used by Windows itself for SAM and NTLM account management.

This project demonstrates how local or domain password changes can occur at the NTLM level using `SamiChangePasswordUser` without triggering all of the typical password-change events.


## Features
- Directly interfaces with **samlib.dll** to perform password changes.
- Demonstrates **native NTLM API calls** instead of using built-in tools like `net.exe` or `Set-LocalUser`.
- Bypasses standard management layers to show how Windows internally processes password changes.
- Ideal for **security researchers** and **Red Teame Operators**.


## About `samlib.dll`
`samlib.dll` is a core Windows library that exposes **Security Account Manager (SAM)** functions through the **Local Security Authority (LSA)** interface.  
It includes APIs such as:
- `SamConnect`
- `SamOpenUser`
- `SamOpenDomain`
- `SamiChangePasswordUser`
- `SamSetInformationUser`
- `SamCloseHandle`

These APIs operate at a lower level than PowerShell cmdlets or NetAPI calls, interacting directly with the **NTLM authentication layer** and SAM database.



## Usage

### Prerequisites
- Administrator privileges

### Example
```powershell

.\Invoke-NTLMPasswordChange.ps1

# Change local user password to P@ssw0rd

Invoke-NTLMPasswordChange -SetPassword -Server . -Account test -NEW_NTLM E19CCF75EE54E06B06A5907AF13CEF42 -Verbose
Invoke-NTLMPasswordChange -ChangePassword -Server . -Account test -OLD_NTLM 32ED87BDB5FDC5E9CBA88547376818D4 -NEW_NTLM E19CCF75EE54E06B06A5907AF13CEF42 -Verbose
```



## Use cases

### Red‑team scenario
An attacker who cannot use Pass‑the‑Hash or Kerberos theft could temporarily overwrite a target account’s NTLM hash, use that credential for interactive access (for example RDP), then restore a previously known NTLM hash to reduce obvious traces. This demonstrates a detection blind spot: hash‑level changes may not always trigger the same high‑level audit events defenders expect.




## Auditing and Detection
When passwords are changed through standard interfaces (like Control Panel or ADUC), Windows typically logs:
- **4723** — An attempt was made to change an account's password.
- **4724** — An attempt was made to reset an account's password.
- **4738** — A user account was changed.

However, when using `SamiChangePasswordUser` (as in this tool), you may observe **different or missing event IDs**, depending on:
- Whether the change occurs locally or against a domain controller.
- The process context (user-mode vs. service).
- Audit policy configurations.





