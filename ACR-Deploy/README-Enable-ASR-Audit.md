# Enable-ASR-Audit.ps1

## ⚠️ DISCLAIMER

- **Test i eit ikkje-produksjonsmiljø/test-tenant fyrst.** Dette scriptet **skriv faktisk til tenanten din** (oppretter og kan tildele ein Intune-policy) – ikkje kjør det ukritisk mot ein produksjonstenant.
- **Les gjennom koden sjølv** og forstå kva han gjer før du køyrer han.
- Standard-oppførsel er trygg: utan `-AssignToGroupId` eller `-AssignToAllDevices` blir policyen oppretta, men IKKJE tildelt nokon einingar.
- `-AssignToAllDevices` bør berre brukast etter at du har testa på ei pilotgruppe fyrst via `-AssignToGroupId`.
- Verifiser gjerne GUID-lista mot [Microsoft sin offisielle ASR-referanse](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) – Microsoft kan leggje til nye reglar over tid.
- Brukast på eige ansvar. Ingen garanti er gitt, korkje uttrykt eller underforstått.
- Fann du ein feil? Meld frå via issues på [kpdimmen-code/verktoy](https://github.com/kpdimmen-code/verktoy).

## Kva gjer scriptet?

Oppretter ein `windows10EndpointProtectionConfiguration`-profil i Intune med alle 16 standard ASR-reglar sett til Audit-modus, via Microsoft Graph. Brukar den verifiserte CSP-baserte streng-eigenskapen `defenderAttackSurfaceReductionRules` (format: `GUID1=verdi|GUID2=verdi|...`), i staden for individuelt namngitte eigenskapar som berre dekkjer eit subsett av reglane og har eit mindre verifisert skjema.

Kan òg **tildele** policyen til ei gruppe eller alle einingar – utan tildeling gjeld han ingen einingar, sjølv om han er oppretta korrekt.

## Krav

**PowerShell-modular:**
```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement -Scope CurrentUser
```

**Graph-rettar (scopes):** `DeviceManagementConfiguration.ReadWrite.All`

## Parametrar

| Parameter | Type | Standard | Skildring |
|---|---|---|---|
| `-PolicyName` | string | "ASR - Audit All Rules (Baseline)" | Namn på Intune-policyen |
| `-Description` | string | (standardtekst) | Skildring av policyen |
| `-AssignToGroupId` | string | "" | Object ID til ei Entra-gruppe policyen skal tildelast |
| `-AssignToAllDevices` | switch | (av) | Tildel til alle einingar – bruk med varsemd |

## Bruk

```powershell
# Opprett policyen, men tildel han ikkje (trygt standardval)
.\Enable-ASR-Audit.ps1

# Opprett og tildel til ei pilotgruppe
.\Enable-ASR-Audit.ps1 -AssignToGroupId "11111111-2222-3333-4444-555555555555"

# Opprett og tildel til alle einingar (berre etter pilot-testing)
.\Enable-ASR-Audit.ps1 -AssignToAllDevices
```

## Output

Stadfesting av at policyen er oppretta (med Id), status på tildelinga (eller varsel om at ingen tildeling vart gjort), samt tips om oppfølging via `Get-ASRStatus.ps1 -Mode Remote` eller Defender-portalens rapportar.

## Kjend avgrensing

- **Tamper Protection er IKKJE del av denne profilen.** Konfigurer det separat under security.microsoft.com > Settings > Endpoints > Advanced features, eller via ein eigen Antivirus-tryggingspolicy i Intune.
- Scriptet oppdaterer ikkje ein eksisterande policy – kvar køyring lagar ein ny. Slett/oppdater manuelt i Intune-portalen om du treng å endre ein alt oppretta policy.

## Endringslogg

- **Ingen Endring**

