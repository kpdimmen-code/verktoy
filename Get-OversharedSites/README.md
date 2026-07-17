# Get-OversharedSites.ps1

Kartlegg SharePoint-nettstadar med for vide delingsinnstillingar – tenkt som eit steg før Copilot-utrulling, sidan Copilot søkjer på tvers av alt brukaren har tilgang til.

## Føresetnader

- PowerShell 5.1 eller 7+
- Modul: `Microsoft.Online.SharePoint.PowerShell`
- SharePoint-administratorrolle (eller Global Administrator)

```powershell
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

## Bruk

```powershell
.\Get-OversharedSites.ps1 -TenantAdminUrl "https://contoso-admin.sharepoint.com" -OutFile "rapport.csv"
```

## Parametrar

| Parameter | Påkravd | Skildring |
|---|---|---|
| `-TenantAdminUrl` | Ja | URL til SharePoint-administrasjonssida |
| `-IncludeOneDrive` | Nei | Tek med OneDrive for Business-nettstadar |
| `-OutFile` | Nei | Filsti for CSV-output, standard: konsoll |

## Kva han gjer

Hentar `SharingCapability` for kvar nettstad og rangerer risiko: `Disabled` (0) → `ExistingExternalUserSharingOnly` (1) → `ExternalUserSharingOnly` (2) → `ExternalUserAndGuestSharing` (3). Skriv ut nettstadar med score 2 eller høgare, sortert med mest opne øvst.

## Kjende avgrensingar

- Viser delingsnivå på nettstad-nivå, ikkje enkeltfiler eller -mapper med avvikande innstillingar.
- `Get-SPOSite -Limit All` kan ta fleire minutt i tenantar med mange tusen nettstadar.
- Fangar ikkje opp anonyme delingslenker som alt er oppretta – berre kva som er *tillate*. For det treng du ein separat gjennomgang med `Get-SPOSite -Detailed` eller søkeindeksen.
