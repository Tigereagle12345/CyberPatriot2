#Requires -RunAsAdministrator

function LocalSecPol {
    # Audit Policy
    # Audit all successes and failures on system
    auditpol /set /category:* /success:enable /failure:enable

    # Password Policy
    net accounts /MAXPWAGE:42 /MINPWLEN:14 /MINPWAGE:1 /UNIQUEPW:24
    # Set Minimum Password Length Audit to 14
    Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "MinimumPasswordLengthAudit" -value "14"
    # Enable Relax Minimum Password Length Limits
    Set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "RelaxMinimumPasswordLengthLimits" -value "1"

    # Account Lockout Policy
    secedit /configure /db c:\windows\security\local.sdb /cfg "$PSScriptRoot\lockout.inf" /areas SECURITYPOLICY
}