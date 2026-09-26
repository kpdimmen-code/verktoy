<#
.SYNOPSIS
  Fullstendig oppsett av Conditional Access i EIN tenant, interaktivt:
    0. Spør deg VED OPPSTART om dette skal vere ein dry run eller faktisk endring.
    1. Oppretter Named Locations (Z-0 til Z-4 + valfri Z-5-info) - finst
       ei location med same namn frå før, vert han IKKJE rørt/overskrive,
       berre gjenbrukt (id).
    2. Oppretter/gjenbruker standardgruppene CA-policyane refererer til som
       unntak - finst gruppa frå før, vert eksisterande Object ID brukt.
    3. Spør deg interaktivt om Object ID/UPN for break-glass-kontoane -
       vert lagt DIREKTE i excludeUsers på alle relevante policyar, i
       tillegg til å bli lagt til break-glass-gruppa ($BreakGlassGroupName,
       medvite nøytralt namn).
    4. Oppretter CA-policyane, ALLTID i "enabledForReportingButNotEnforced"
       (report-only). VIKTIG: Om ein policy med namn som startar med same
       CA-nummer (t.d. "CA-001", "CA-008-A") alt finst, vert OPPRETTINGA
       AV DEN POLICYEN HOPPA OVER - ingen duplikat, ingen overskriving av
       ein policy nokon alt har tilpassa.
    5. Skriv ut ein samla rapport til slutt (skjerm + CSV-fil).

.VIKTIG - KVAR DETTE KAN KØYRAST
  Krev interaktiv nettlesarpålogging - køyr LOKALT på ei maskin med
  nettlesar, ikkje som eit ubetjent Nerdio Azure Runbook.
  Standard er authorization code + PKCE: skriptet opnar nettlesaren og tek
  imot svaret på http://localhost:<tilfeldig port>. Denne flyten vert IKKJE
  blokkert av CA-010 (device code flow), og fungerer for GDAP-partnarbrukarar
  som ikkje kan leggjast i kunden sine unntaksgrupper.
  -UseDeviceCode gir gamal device code-pålogging (t.d. maskin utan
  nettlesar) - vert blokkert når CA-010 er slått PÅ.

.GDAP
  Køyr med kunden sin tenant-ID og logg inn med partnarkontoen. GDAP-
  relasjonen må gi: Conditional Access Administrator, Privileged Role
  Administrator, Groups Administrator og Directory Readers.

.FØREHANDSKRAV
  - Ingen PowerShell-modular krevst (rein REST via Invoke-RestMethod).
  - Brukaren som loggar inn må ha Global Administrator, eller kombinasjonen
    Privileged Role Administrator + Conditional Access Administrator +
    Groups Administrator + User Administrator. Privileged Role Administrator
    (eller GA) krevst for å opprette role-assignable unntaksgrupper.

.PARAMETER TenantId
  Tenant-ID eller domenenamn.

.PARAMETER WhatIf
  Valfri. Om denne vert gitt eksplisitt, vert IKKJE det interaktive
  modusvalet vist - skriptet køyrer rett i dry run. Utelat parameteren for
  å bli spurt interaktivt ved oppstart (anbefalt).

.PARAMETER UseDeviceCode
  Valfri. Bruk device code-pålogging i staden for nettlesar + PKCE.

.EXAMPLE
  .\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde1.onmicrosoft.com"
  # -> vert spurt om dry run eller faktisk endring

.EXAMPLE
  .\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde1.onmicrosoft.com" -WhatIf
  # -> tvinger dry run utan å spørje
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [switch]$WhatIf,

    [switch]$UseDeviceCode
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) { "ERROR" { "Red" }; "WARN" { "Yellow" }; "OK" { "Green" }; "STEP" { "Cyan" }; default { "White" } }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# ===========================================================================
# 0. Interaktivt modusval (om -WhatIf ikkje alt vart gitt eksplisitt på kommandolinja)
# ===========================================================================
if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " Vel køyremodus" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " 1) Dry run  - berre vis kva som VILLE blitt gjort, ingen endringar"
    Write-Host " 2) Faktisk endring - opprettar grupper/locations/policyar i Entra ID"
    Write-Host ""

    do {
        $modeChoice = Read-Host "Val (1 eller 2)"
    } while ($modeChoice -notin @("1", "2"))

    $WhatIf = ($modeChoice -eq "1")
}

if ($WhatIf) {
    Write-Log "`nKøyremodus: DRY RUN - ingen endringar vert gjort i Entra ID.`n" "WARN"
} else {
    Write-Log "`nKøyremodus: FAKTISK ENDRING - dette vil opprette objekt i Entra ID.`n" "WARN"
    $confirm = Read-Host "Skriv 'JA' for å stadfeste at du vil fortsette"
    if ($confirm -ne "JA") { Write-Log "Avbrote av brukar." "ERROR"; exit 1 }
}

# ===========================================================================
# 1. Interaktiv pålogging - nettlesar + PKCE (standard) eller device code, ingen modular
# ===========================================================================
$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"   # Microsoft Graph Command Line Tools (offisiell public client)
$Scope    = "https://graph.microsoft.com/Group.ReadWrite.All https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess https://graph.microsoft.com/Policy.Read.All https://graph.microsoft.com/Application.Read.All https://graph.microsoft.com/User.Read.All https://graph.microsoft.com/RoleManagement.ReadWrite.Directory offline_access openid profile"
$TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-RandomBase64Url([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ConvertTo-Base64Url $bytes
}

function Get-TokenWithBrowser {
    # Authorization code + PKCE (RFC 7636). Graph CLI-appen har http://localhost registrert som
    # redirect; Entra ignorerer portnummeret for localhost, så vi kan bruke ein tilfeldig ledig port.
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start(); $port = $tcp.LocalEndpoint.Port; $tcp.Stop()
    $redirectUri = "http://localhost:$port/"

    $codeVerifier = Get-RandomBase64Url 32
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $codeChallenge = ConvertTo-Base64Url ($sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))) } finally { $sha256.Dispose() }
    $state = Get-RandomBase64Url 16

    $query = @{
        client_id             = $ClientId
        response_type         = "code"
        redirect_uri          = $redirectUri
        response_mode         = "query"
        scope                 = $Scope
        state                 = $state
        code_challenge        = $codeChallenge
        code_challenge_method = "S256"
        prompt                = "select_account"   # la brukaren velje konto - viktig for GDAP/partnarkontoar
    }
    $queryString = ($query.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString($_.Value))" }) -join "&"
    $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$queryString"

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirectUri)
    $listener.Start()
    try {
        Write-Log "Opnar nettlesaren for pålogging (tenant: $TenantId)..." "WARN"
        Write-Host "Opnar ikkje nettlesaren seg, kopier denne adressa inn manuelt:`n$authUrl`n" -ForegroundColor DarkGray
        Start-Process $authUrl

        $ctxTask = $listener.GetContextAsync()
        if (-not $ctxTask.Wait([TimeSpan]::FromMinutes(5))) { throw "Tidsavbrot: ingen pålogging fullført innan 5 minutt." }
        $ctx = $ctxTask.Result
        $qs  = $ctx.Request.QueryString

        $ok = (-not $qs["error"]) -and ($qs["state"] -eq $state) -and $qs["code"]
        $html = if ($ok) { "<h3>Pålogging fullført.</h3><p>Du kan lukke denne fana og gå tilbake til PowerShell.</p>" }
                else     { "<h3>Pålogging feila.</h3><p>Sjå PowerShell-vindauget for detaljar.</p>" }
        $buf = [System.Text.Encoding]::UTF8.GetBytes("<html><head><meta charset='utf-8'></head><body style='font-family:sans-serif'>$html</body></html>")
        $ctx.Response.ContentType = "text/html; charset=utf-8"
        $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
        $ctx.Response.Close()

        if ($qs["error"]) { throw "Pålogging feila: $($qs['error']) - $($qs['error_description'])" }
        if ($qs["state"] -ne $state) { throw "Ugyldig state i svaret - pålogginga vart avbroten (mogleg CSRF)." }
        if (-not $qs["code"]) { throw "Fekk ingen autorisasjonskode i svaret." }
    } finally {
        $listener.Stop(); $listener.Close()
    }

    Invoke-RestMethod -Method POST -Uri $TokenUri -ContentType "application/x-www-form-urlencoded" `
        -Body @{ grant_type = "authorization_code"; client_id = $ClientId; code = $qs["code"]; redirect_uri = $redirectUri; code_verifier = $codeVerifier; scope = $Scope }
}

function Get-TokenWithDeviceCode {
    $deviceCodeResp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ client_id = $ClientId; scope = $Scope }

    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host $deviceCodeResp.message -ForegroundColor Cyan
    Write-Host "=====================================================`n" -ForegroundColor Cyan
    Write-Log "Ventar på godkjenning i nettlesaren..." "WARN"
    Write-Log "Device code vert blokkert når CA-010 er slått PÅ. Bruk nettlesarpålogging (utan -UseDeviceCode) om dette feilar." "WARN"

    $interval  = [int]$deviceCodeResp.interval
    $expiresAt = (Get-Date).AddSeconds([int]$deviceCodeResp.expires_in)

    while ((Get-Date) -lt $expiresAt) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method POST -Uri $TokenUri `
                -ContentType "application/x-www-form-urlencoded" `
                -Body @{ grant_type = "urn:ietf:params:oauth:grant-type:device_code"; client_id = $ClientId; device_code = $deviceCodeResp.device_code }
        } catch {
            $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($err.error -eq "authorization_pending") { continue }
            elseif ($err.error -eq "authorization_declined") { throw "Pålogginga vart avvist." }
            elseif ($err.error -eq "expired_token") { throw "Koden utløp. Køyr skriptet på nytt." }
            else { throw "Uventa feil under pålogging: $($_.Exception.Message)`n$($_.ErrorDetails.Message)" }
        }
    }
    throw "Fekk ikkje access token innan tidsavbrot."
}

$tokenResp = if ($UseDeviceCode) { Get-TokenWithDeviceCode } else { Get-TokenWithBrowser }
$accessToken  = $tokenResp.access_token
$refreshToken = $tokenResp.refresh_token
if (-not $accessToken) { throw "Fekk ikkje access token." }

$headers = @{ Authorization = "Bearer $accessToken"; "Content-Type" = "application/json" }
Write-Log "Innlogga OK mot tenant $TenantId." "OK"

function Update-AccessToken {
    Write-Log "  Access-token er utløpt - fornyer med refresh_token..." "WARN"
    $tokenResp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{ grant_type = "refresh_token"; client_id = $ClientId; refresh_token = $script:refreshToken; scope = $Scope }
    $script:accessToken  = $tokenResp.access_token
    if ($tokenResp.refresh_token) { $script:refreshToken = $tokenResp.refresh_token }   # behald gammalt token om svaret ikkje har nytt
    $script:headers      = @{ Authorization = "Bearer $($script:accessToken)"; "Content-Type" = "application/json" }
}

function Invoke-Graph {
    param([string]$Method, [string]$Uri, [string]$Body = $null, [switch]$IsRetry)
    try {
        if ($Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body }
        else { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 401 -and -not $IsRetry -and $script:refreshToken) {
            Update-AccessToken
            return Invoke-Graph -Method $Method -Uri $Uri -Body $Body -IsRetry
        }
        $detail = $_.ErrorDetails.Message
        throw "Graph-kall feila ($Method $Uri): $($_.Exception.Message)`n$detail"
    }
}

# Samla rapport - éi rad per objekt, uansett type
$Report = New-Object System.Collections.Generic.List[object]

# ===========================================================================
# 2. NAMED LOCATIONS - skip om namn alt finst (ikkje overskriv)
# ===========================================================================
Write-Log "`n=== STEG 1: Named Locations ===" "STEP"

$NamedLocations = @(
    @{ displayName = "NL-Zone-Perm-Block";  countriesAndRegions = @("RU","BY","IR","KP","CU","SY","MM") },
    @{ displayName = "NL-Zone-Home-NordEU"; countriesAndRegions = @(
            "NO","SE","DK","FI","IS","AT","BE","BG","HR","CY","CZ","EE","FR","DE","GR","HU","IE","IT",
            "LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","GB","CH","LI"
        )
    },
    @{ displayName = "NL-Zone-Americas"; countriesAndRegions = @("US","CA","MX","BR","AR","CL","CO","PE","EC","BO","PY","UY","GT","CR","PA","JM","DO","TT","VE") },
    @{ displayName = "NL-Zone-APAC";     countriesAndRegions = @("AU","NZ","JP","KR","TW","SG","IN","MY","TH","PH","ID","VN","LK","BD","HK","MO") }, # Kina med vilje utelate
    @{ displayName = "NL-Zone-MEA";      countriesAndRegions = @("AE","SA","QA","KW","BH","OM","IL","JO","TR","EG","MA","TN","DZ","ZA","KE","GH","RW","TZ","NG","LB","IQ") },
    @{ displayName = "NL-Zone-Other-Z5-Informational"; countriesAndRegions = @("CN","PK","AF","KZ","UZ","TM","KG","TJ") }
)

$locationMap = @{}

foreach ($loc in $NamedLocations) {
    $displayName = $loc.displayName
    $existing = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?`$filter=displayName eq '$displayName'"

    if ($existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Log "  $displayName -> $id (finst frå før - HOPPAR OVER, ikkje rørt)" "OK"
        $locationMap[$displayName] = $id
        $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Skipped-AlreadyExists"; Id = $id })
    } else {
        if ($WhatIf) {
            Write-Log "  [DRY RUN] Ville oppretta $displayName" "WARN"
            $locationMap[$displayName] = "<ville-blitt-oppretta>"
            $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "DryRun-WouldCreate"; Id = $null })
        } else {
            $body = @{
                "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
                displayName                       = $displayName
                countryLookupMethod               = "clientIpAddress"
                includeUnknownCountriesAndRegions = $false
                countriesAndRegions               = $loc.countriesAndRegions
            } | ConvertTo-Json -Depth 10
            $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Body $body
            Write-Log "  $displayName -> $($new.id) (oppretta)" "OK"
            $locationMap[$displayName] = $new.id
            $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Created"; Id = $new.id })
        }
    }
}

# ===========================================================================
# 3. GRUPPER - skip om namn alt finst
# ===========================================================================
Write-Log "`n=== STEG 2: Grupper ===" "STEP"

# Break-glass-gruppa har medvite eit nøytralt namn/beskriving: gruppenamn er lesbare for alle
# brukarar i tenanten, og eit namn som "BreakGlass" peikar ut kva kontoar som omgår CA.
# Endre gjerne namnet, men hald det nøytralt. Dokumenter kva gruppa er for UTANFOR tenanten.
$BreakGlassGroupName = "SG-Platform-Ops-01"

# Key = intern referanse i skriptet, Name = displayName i Entra.
# Alle unntaksgrupper vert oppretta som role-assignable (isAssignableToRole): då kan berre Global
# Administrator / Privileged Role Administrator endre medlemskap - ikkje Groups Admin, User Admin
# eller gruppeeigarar. Utan dette kan desse rollene leggje seg sjølv til og omgå CA-policyane.
$StandardGroups = @(
    @{ Key = "BreakGlass";        Name = $BreakGlassGroupName;              Description = "Plattformgruppe - endringar krev godkjenning fra IT-sikkerheit" }
    @{ Key = "ServiceAccounts";   Name = "CA-Exclusion-ServiceAccounts";   Description = "Godkjende tenestekontoar, ekskludert fra CA-001" }
    @{ Key = "EksternePartnarar"; Name = "CA-Exclusion-EksternePartnarar"; Description = "Eksterne partnarar med legitimt behov, ekskludert fra CA-005" }
    @{ Key = "DeviceCodeFlow";    Name = "CA-Exclusion-DeviceCodeFlow";    Description = "Godkjende behov for device code flow (t.d. Teams Rooms-ressurskontoar), ekskludert fra CA-010 - revider jamleg" }
    @{ Key = "AllowAmericas";     Name = "CA-Allow-Americas";              Description = "Midlertidig unntak - reise Z-2 (Amerika), maks 45 dagar" }
    @{ Key = "AllowAPAC";         Name = "CA-Allow-APAC";                  Description = "Midlertidig unntak - reise Z-3 (APAC), maks 45 dagar" }
    @{ Key = "AllowMEA";          Name = "CA-Allow-MEA";                   Description = "Midlertidig unntak - reise Z-4 (Midt-Austen/Afrika), maks 45 dagar" }
    @{ Key = "AllowOther";        Name = "CA-Allow-Other";                 Description = "Unntak Z-5 (fangst-alt) - krev CISO/CTO-godkjenning, maks 14 dagar" }
)

$groupMap = @{}

foreach ($g in $StandardGroups) {
    $existing = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($g.Name)'&`$select=id,displayName,isAssignableToRole"

    if ($existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Log "  $($g.Name) -> $id (finst frå før - gjenbrukt, ikkje rørt)" "OK"
        if (-not $existing.value[0].isAssignableToRole) {
            Write-Log "  $($g.Name) er IKKJE role-assignable - Groups Admin/User Admin/eigarar kan endre medlemskap og omgå CA. Kan ikkje endrast i etterkant: opprett ny gruppe og flytt medlemmane." "WARN"
        }
        $groupMap[$g.Key] = $id
        $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "Skipped-AlreadyExists"; Id = $id })
    } else {
        if ($WhatIf) {
            Write-Log "  [DRY RUN] Ville oppretta $($g.Name) (role-assignable)" "WARN"
            $groupMap[$g.Key] = "<ville-blitt-oppretta>"
            $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "DryRun-WouldCreate"; Id = $null })
        } else {
            $mailNickname = ($g.Name -replace '[^a-zA-Z0-9]', '')
            $body = @{ displayName = $g.Name; description = $g.Description; mailEnabled = $false; mailNickname = $mailNickname; securityEnabled = $true; isAssignableToRole = $true } | ConvertTo-Json
            $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Body $body
            Write-Log "  $($g.Name) -> $($new.id) (oppretta, role-assignable)" "OK"
            $groupMap[$g.Key] = $new.id
            $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "Created"; Id = $new.id })
        }
    }
}

# ===========================================================================
# 4. BREAK-GLASS-KONTOAR
# ===========================================================================
Write-Log "`n=== STEG 3: Break-glass-kontoar ===" "STEP"
Write-Host "Skriv inn UPN ELLER Object ID (GUID) for kvar" -ForegroundColor Cyan
Write-Host "break-glass-konto som ALLTID skal ekskluderast fra CA-policyane." -ForegroundColor Cyan
Write-Host "Trykk Enter utan tekst når du er ferdig.`n" -ForegroundColor Cyan

$breakGlassUserIds = New-Object System.Collections.Generic.List[string]
$guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

while ($true) {
    $inputVal = Read-Host "Break-glass UPN/Object ID"
    if ([string]::IsNullOrWhiteSpace($inputVal)) { break }
    try {
        $user = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$inputVal`?`$select=id,displayName,userPrincipalName"
        Write-Log "  Funne: $($user.displayName) <$($user.userPrincipalName)> - id: $($user.id)" "OK"
        if (-not $breakGlassUserIds.Contains($user.id)) { $breakGlassUserIds.Add($user.id) }
        $Report.Add([PSCustomObject]@{ Type = "BreakGlassUser"; Name = $user.userPrincipalName; Action = "Registered"; Id = $user.id })
    } catch {
        Write-Log "  Fann ikkje brukar '$inputVal' i tenanten - hoppar over. ($($_.Exception.Message))" "ERROR"
    }
}

if ($breakGlassUserIds.Count -eq 0) {
    Write-Log "INGEN break-glass-kontoar registrert. Policyane vert oppretta UTAN direkte brukar-unntak (berre gruppe-unntak)." "WARN"
} else {
    Write-Log "Registrerte break-glass-kontoar: $($breakGlassUserIds -join ', ')" "OK"
    if (-not $WhatIf -and $groupMap["BreakGlass"] -notlike "<*>") {
        foreach ($uid in $breakGlassUserIds) {
            $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$uid" } | ConvertTo-Json
            try {
                Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($groupMap['BreakGlass'])/members/`$ref" -Body $memberBody | Out-Null
                Write-Log "  Lagt til $uid i $BreakGlassGroupName" "OK"
            } catch {
                Write-Log "  Klarte ikkje å leggje $uid til gruppa (kanskje alt medlem): $($_.Exception.Message)" "WARN"
            }
        }
    }
}

$breakGlassArray = @($breakGlassUserIds)

# ===========================================================================
# 5. CA-POLICYAR - HOPP OVER om policy med same CA-nummer-prefiks alt finst
# ===========================================================================
Write-Log "`n=== STEG 4: Conditional Access-policyar (report-only) ===" "STEP"

# CA-002 rollegrunnlag (kjelde: learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference, henta 2026-09-24)
# A) Alle innebygde roller Microsoft merkar som PRIVILEGED
$PrivilegedRoleIds = @(
    "62e90394-69f5-4237-9190-012177145e10"   # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"   # Privileged Authentication Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d"   # Security Administrator
    "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f"   # Security Operator
    "5d6b6bb7-de71-4623-b4af-96380a352509"   # Security Reader
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"   # Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f"   # Authentication Administrator
    "25a516ed-2fa0-40ea-a2d0-12923a21473a"   # Authentication Extensibility Administrator
    "0b00bede-4072-4d22-b441-e7df02a1ef63"   # Authentication Extensibility Password Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"   # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7"   # Cloud Application Administrator
    "cf1c38e5-3621-4004-a7cb-879624dced7c"   # Application Developer
    "db506228-d27e-4b7d-95e5-295956d6615f"   # Agent ID Administrator
    "d2562ede-74db-457e-a7b6-544e236ebb61"   # AI Administrator
    "1fe13547-53f6-408d-ac04-7f8eed167b38"   # AI Reader
    "ecb2c6bf-0ab6-418e-bd87-7986f8d63bbe"   # Attribute Provisioning Administrator
    "422218e4-db15-4ef9-bbe0-8afb41546d79"   # Attribute Provisioning Reader
    "aaf43236-0c0d-4d5f-883a-6955382ac081"   # B2C IEF Keyset Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2"   # Cloud Device Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301"   # Directory Writers
    "8329153b-31d0-4727-b945-745eb3bc5f31"   # Domain Name Administrator
    "58f930cc-fcf4-4152-852c-1d7dbf502139"   # Entra SOC Identity Responder
    "be2f45a1-457d-42af-a067-6ec1fa63bc45"   # External Identity Provider Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451"   # Global Reader
    "729827e3-9c14-49f7-bb1b-9608f156bbb8"   # Helpdesk Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"   # Hybrid Identity Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e"   # Identity Governance Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5"   # Intune Administrator
    "59d46f88-662b-457b-bceb-5c3809e5908f"   # Lifecycle Workflows Administrator
    "4ba39ca4-527c-499a-b93d-d9b492c50246"   # Partner Tier1 Support (deprecated)
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"   # Partner Tier2 Support (deprecated)
    "966707d0-3269-4727-9be2-8c3a10f19b9d"   # Password Administrator
    "1981f584-96e9-4a6f-95b0-f522373f8fae"   # Tenant Governance Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1"   # User Administrator
)
# B) Ikkje merka PRIVILEGED, men dokumenterte eskaleringsvegar
$ElevationRoleIds = @(
    "29232cdf-9323-42fd-ade2-1d097af3e4de"   # Exchange Administrator - mailbox-/transportregel-tilgang, M365-grupper
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"   # SharePoint Administrator - tilgang til alle sites/OneDrive, M365-grupper
    "fdd7a751-b60b-444a-984c-02652fe8fa1c"   # Groups Administrator - medlemskap i grupper som styrer app-/ressurstilgang
    "0526716b-113d-4c15-b2c8-68e3c22b9f80"   # Authentication Policy Administrator - kan svekkje MFA-/autentiseringsmetodar
    "69091246-20e8-4a56-aa4d-066075b2a7a8"   # Teams Administrator - M365-grupper og Teams-policyar
    "ac434307-12b9-4fa1-a708-88bf58caabc1"   # Global Secure Access Administrator - trafikkruting og nettverkssignal til CA
)
# MEDVITE UTELATE: Directory Synchronization Accounts (d29b2b05-...) - Entra Connect-kontoen skal ikkje ha phishing-resistant MFA-krav.

$RoleIds = @($PrivilegedRoleIds + $ElevationRoleIds)

# C) Slå opp PRIVILEGED-roller dynamisk (fangar opp nye roller Microsoft legg til etter at lista over vart laga)
try {
    $dynPriv = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$filter=isPrivileged eq true and isBuiltIn eq true&`$select=templateId,displayName").value
    $newRoles = $dynPriv | Where-Object { $_.templateId -and $_.templateId -notin $RoleIds -and $_.templateId -ne "d29b2b05-8046-44ba-8758-1e26182fcf32" }
    foreach ($r in $newRoles) { Write-Log "  Ny PRIVILEGED-rolle funnen via Graph: $($r.displayName) ($($r.templateId))" "WARN" }
    $RoleIds = @($RoleIds + @($newRoles.templateId)) | Where-Object { $_ } | Select-Object -Unique
} catch {
    Write-Log "  Klarte ikkje hente privilegerte roller dynamisk - bruker statisk liste. ($($_.Exception.Message))" "WARN"
}
Write-Log "  CA-002 dekkjer $($RoleIds.Count) roller." "OK"
$PhishingResistantMfaId = "00000000-0000-0000-0000-000000000004"   # dokumentert builtin-id - brukt som fallback
try {
    $authStrengths = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies?`$filter=policyType eq 'builtIn'").value
    $psr = $authStrengths | Where-Object { $_.displayName -eq "Phishing-resistant MFA" } | Select-Object -First 1
    if ($psr) {
        $PhishingResistantMfaId = $psr.id
        Write-Log "  Bruker authenticationStrength '$($psr.displayName)' (id: $PhishingResistantMfaId)" "OK"
    } else {
        Write-Log "  Fann ikkje 'Phishing-resistant MFA' i authenticationStrength-policies - bruker hardkoda fallback-id $PhishingResistantMfaId" "WARN"
    }
} catch {
    Write-Log "  Klarte ikkje slå opp authenticationStrength dynamisk - bruker hardkoda fallback-id $PhishingResistantMfaId. ($($_.Exception.Message))" "WARN"
}

$bg  = $groupMap["BreakGlass"];        $svc = $groupMap["ServiceAccounts"]
$ext = $groupMap["EksternePartnarar"]; $dcf = $groupMap["DeviceCodeFlow"]
$aAm = $groupMap["AllowAmericas"];     $aAp = $groupMap["AllowAPAC"]
$aMe = $groupMap["AllowMEA"];          $aOt = $groupMap["AllowOther"]
$lPB = $locationMap["NL-Zone-Perm-Block"];         $lHo = $locationMap["NL-Zone-Home-NordEU"]
$lAm = $locationMap["NL-Zone-Americas"];           $lAp = $locationMap["NL-Zone-APAC"]
$lMe = $locationMap["NL-Zone-MEA"]

$Policies = @(
    @{ Prefix = "CA-001"; displayName = "CA-001 - Krev MFA - alle brukarar"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $svc) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("mfa") } },

    @{ Prefix = "CA-002"; displayName = "CA-002 - Sterk MFA - privilegerte roller"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @(); excludeUsers = $breakGlassArray; includeRoles = $RoleIds; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @(); authenticationStrength = @{ id = $PhishingResistantMfaId } } },

    @{ Prefix = "CA-003"; displayName = "CA-003 - Bloker eldre autentisering (Legacy Auth)"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("exchangeActiveSync","other") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-004"; displayName = "CA-004 - Appbeskyttelse - iOS og Android"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("Office365") }
                       platforms = @{ includePlatforms = @("iOS","android") }; clientAppTypes = @("all") }
       # "approvedApplication" er pensjonert av Microsoft (30.06.2026) og kan ikkje brukast i nye/endra policyar.
       grantControls = @{ operator = "OR"; builtInControls = @("compliantApplication") } },

    @{ Prefix = "CA-005"; displayName = "CA-005 - Krev kompatibel einheit - Windows/macOS"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $ext) }
                       applications = @{ includeApplications = @("All") }
                       platforms = @{ includePlatforms = @("windows","macOS") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("compliantDevice","domainJoinedDevice") } },

    @{ Prefix = "CA-006"; displayName = "CA-006 - Administrasjonsportalar - MFA og kompatibel einheit"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("MicrosoftAdminPortals","797f4846-ba00-4fd7-ba43-dac1f8f63013","00000002-0000-0ff1-ce00-000000000000") }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "AND"; builtInControls = @("mfa","compliantDevice") }
       # Merk: "Persistent Browser Session" kan berre brukast på policyar som gjeld
       # "Alle skyappar" (Graph API gir 400 InvalidConditionsForPersistentBrowserSessionMode
       # elles). Sidan CA-006 berre gjeld admin-portalane, kan vi difor IKKJE setje
       # persistentBrowser her - berre signInFrequency. Ønskjer de "aldri persistent
       # nettlesarøkt" generelt, må det leggjast i ein eigen policy som gjeld ALLE appar.
       sessionControls = @{ signInFrequency = @{ value = 4; type = "hours"; isEnabled = $true } } },

    @{ Prefix = "CA-007"; displayName = "CA-007 - Krev MFA ved enhetsregistrering"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeUserActions = @("urn:user:registerdevice") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("mfa") } },

    @{ Prefix = "CA-008-A"; displayName = "CA-008-A - Permanent blokk - Hoyrisikostatar (Z-0)"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @() }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lPB) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-B"; displayName = "CA-008-B - Bloker Amerika - Z-2"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aAm) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lAm) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-C"; displayName = "CA-008-C - Bloker Asia-Stillehavsregionen - Z-3"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aAp) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lAp) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-D"; displayName = "CA-008-D - Bloker Midt-Austen og Afrika - Z-4"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aMe) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lMe) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-E"; displayName = "CA-008-E - Bloker ovrig verd - Fangst-alt Z-5"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aOt) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @("All"); excludeLocations = @($lPB, $lHo, $lAm, $lAp, $lMe) }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-009"; displayName = "CA-009 - Sesjonskontroll - uadministrerte einheiter"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }
                       devices = @{ deviceFilter = @{ mode = "include"; rule = '(device.isCompliant -eq False) -and (device.trustType -ne "ServerAD")' } }
                       clientAppTypes = @("all") }
       grantControls = $null
       sessionControls = @{ signInFrequency = @{ value = 8; type = "hours"; isEnabled = $true }; persistentBrowser = @{ mode = "never"; isEnabled = $true } } },

    # Device code phishing: angriparen startar flyten og lurer brukaren til å taste koden på den ekte
    # microsoft.com/devicelogin-sida. Blokkerer flyten for alle, unntatt godkjende kontoar i $dcf.
    # Device Registration Service (01cb2876-...) MÅ ekskluderast, elles vert einheitsregistrering via
    # device code (t.d. Teams Rooms) blokkert - Microsoft handhevar dette sidan sept. 2024.
    @{ Prefix = "CA-010"; displayName = "CA-010 - Bloker device code flow (phishing)"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $dcf) }
                       applications = @{ includeApplications = @("All"); excludeApplications = @("01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9") }
                       authenticationFlows = @{ transferMethods = "deviceCodeFlow" }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    # Authentication transfer: overfører innlogga tilstand mellom einheiter (t.d. QR-kode i Outlook desktop
    # -> mobil). Kan misbrukast til å flytte ei økt til ei uadministrert einheit utan ny autentisering.
    # Brukarane må då logge inn på vanleg måte på mobilen i staden.
    @{ Prefix = "CA-011"; displayName = "CA-011 - Bloker authentication transfer"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }
                       authenticationFlows = @{ transferMethods = "authenticationTransfer" }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } }
)

Write-Log "CA-008-A ekskluderer break-glass-kontoane dine (viss registrert), sjølv om kravdokumentet opphavleg tilrår FULL blokkering utan unntak for Z-0. Vurder å fjerne manuelt i Entra-portalen om de vil følgje den strengaste tilrådinga." "WARN"

# Hent ALLE eksisterande CA-policyar éin gong (billigare enn eitt kall per policy)
$allExistingPolicies = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=id,displayName").value

foreach ($p in $Policies) {
    $prefix      = $p.Prefix
    $displayName = $p.displayName

    $match = $allExistingPolicies | Where-Object { $_.displayName -like "$prefix*" } | Select-Object -First 1

    if ($match) {
        Write-Log "  $prefix : HOPPAR OVER - finst alt som '$($match.displayName)' (id: $($match.id))" "WARN"
        $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "Skipped-Duplicate"; Id = $match.id; ExistingName = $match.displayName })
        continue
    }

    if ($WhatIf) {
        Write-Log "  $prefix : [DRY RUN] Ville oppretta '$displayName'" "WARN"
        $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "DryRun-WouldCreate"; Id = $null; ExistingName = $null })
        continue
    }

    # Select-Object på ein hashtable gir Keys/Values/Count, ikkje oppføringane - klon og fjern Prefix i staden
    $bodyObj = $p.Clone(); $bodyObj.Remove("Prefix")
    $body = $bodyObj | ConvertTo-Json -Depth 12
    $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body $body
    Write-Log "  $prefix : Oppretta '$displayName' (id: $($new.id))" "OK"
    $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "Created"; Id = $new.id; ExistingName = $null })
}

# ===========================================================================
# 6. SAMLA RAPPORT
# ===========================================================================
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host " RAPPORT" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

$Report | Format-Table -AutoSize -Property Type, Name, Action, Id, ExistingName

$created = ($Report | Where-Object { $_.Action -eq "Created" }).Count
$skipped = ($Report | Where-Object { $_.Action -like "Skipped*" }).Count
$dryRun  = ($Report | Where-Object { $_.Action -like "DryRun*" }).Count

Write-Host "`nOppsummering: $created oppretta, $skipped hoppa over (fanst frå før), $dryRun i dry-run-plan.`n" -ForegroundColor Cyan

$reportPath = ".\CA-Setup-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Report | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Log "Full rapport lagra til: $reportPath" "OK"

if ($WhatIf) {
    Write-Log "Dette var ein DRY RUN. Ingenting vart faktisk oppretta/endra. Køyr på nytt og vel modus 2 for å publisere." "WARN"
} else {
    Write-Log "Ferdig. Alle nye policyar er publisert i report-only. Overvak sign-in-loggen før de vurderer 'enabled'." "OK"
}
