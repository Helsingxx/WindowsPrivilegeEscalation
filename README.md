These are few scripts showcasing my training in privilege escalation methods used in windows penetration testing.

<hr

The UACBypass script uses the DelegateExecute technique. It runs fodhelper.exe, modifies a registry that tweaks it to pop a shell instead of continuing its normal execution.

The lsassDumper script looks up the lsass process then dumps it into hard disk through the MiniDumpWriteDump function. This lsass dump can then be used to find the NTLM hashes, these hashes are then used in a password cracker to find the sessions' passwords.

The stealprocesstoken script takes use of the SeDebugPrivilege permissions of the current process to steal another processe's token, then it creates a new process using this same token.
