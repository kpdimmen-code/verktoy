# Setup-ConditionalAccess-Full

Interaktivt PowerShell-script som byggjer ein komplett Conditional Access-baseline i Microsoft Entra ID: geo-soner (named locations), unntaksgrupper, break-glass-handtering og eit sett med CA-policyar – alt oppretta i **report-only**, aldri handheva automatisk.

Bakgrunn: å setje opp dette manuelt i portalen tek fort ein arbeidsdag med mykje repeterande klikking. Dette scriptet gjer det same jobbеn på nokre minutt, idempotent, og utan å røre noko som alt finst.

## Kva scriptet gjer

1. **Named Locations** – oppretter geo-soner (Z-0 til Z-4, sjå sonemodell under). Finst ei location med same namn frå før, blir ho hoppa over – ingen overskriving.
2. **Unntaksgrupper** – oppretter (eller gjenbrukar) standardgruppene CA-policyane refererer til: break-glass, tenestekontoar, eksterne partnarar, og mellombelse reise-unntak per sone.
3. **Break-glass-kontoar** – spør deg interaktivt om UPN/Object ID for kvar break-glass-konto. Desse blir lagt direkte i `excludeUsers` på relevante policyar, i tillegg til unntaksgruppa.
4. **CA-policyar** – oppretter 13 policyar (MFA, phishing-resistent MFA for privilegerte roller, blokk av legacy auth, appbeskyttelse, kompatibel eining, admin-portalar, geo-blokkering per sone, sesjonskontroll for uforvalta einingar). Finst det alt ein policy med same CA-nummer-prefiks, blir oppretting av **den** policyen hoppa over.
5. **Rapport** – skriv ut ei samla oversikt på skjerm og lagrar full rapport som CSV.

Alle CA-policyar blir oppretta i `enabledForReportingButNotEnforced` (report-only). Scriptet kan **ikkje** setje ein policy til `enabled` – det må gjerast manuelt, etter at de har sett gjennom sign-in-loggen.

## Sonemodell

| Sone | Innhald | Handtering |
|---|---|---|
| Z-0 | Høgrisikostatar (permanent blokkert) | Ingen unntaksgruppe – berre break-glass |
| Z-1 | Heimesone (Norden/EU/EØS m.fl.) | Ope – dette er normaltilstanden |
| Z-2 | Amerika | Blokkert, mellombels unntak via `CA-Allow-Americas` |
| Z-3 | Asia-Stillehavsregionen | Blokkert, mellombels unntak via `CA-Allow-APAC` |
| Z-4 | Midtausten og Afrika | Blokkert, mellombels unntak via `CA-Allow-MEA` |
| Z-5 | Alt anna (fangst-alt) | Definert som «alle lokasjonar minus Z-0 til Z-4» – treng inga eiga named location |

> **Viktig – dette er ein mal, ikkje ein fasit.** Landlistene (ISO 3166-1 alpha-2-kodar) i scriptet er eit fornuftig standardoppsett for dei fleste nordiske verksemder, men di verksemd kan ha forretningsaktivitet, kundar eller tilsette utanfor det som er føresett her. **Gå gjennom kvar sone og juster landkodane før produksjonssetjing** – spesielt heimesona (Z-1) og eventuelle land med sanksjons-/eksportkontrollomsyn.

## Unntakshandtering – anbefalt vidarebygging

Scriptet oppretter unntaksgruppene (`CA-Allow-Americas`, `CA-Allow-APAC`, osv.), men fyller dei ikkje med medlemmer. For å få reell governance på unntaka, kombiner dette med **tilgangspakker i Entra ID Governance (entitlement management)**: éin pakke per sone, med utløp etter t.d. 4 veker. Den tilsette ber sjølv om tilgang ved jobbreise/ferie, leiar godkjenner, og unntaket lukkar seg automatisk når det ikkje lenger trengst – i staden for å bli ståande i årevis fordi ingen hugsar å rydde.

## Krav

- **Tilgang:** Global Administrator, eller kombinasjonen Conditional Access Administrator + Groups Administrator + User Administrator
- **Lisens:** Entra ID P1 som minimum (P2 for risikobaserte policyar/entitlement management om de byggjer vidare på unntakshandteringa)
- **PowerShell:** Ingen eksterne modular – rein REST via `Invoke-RestMethod`. Krev PowerShell 5.1+ eller PowerShell 7+.
- **Pålogging:** Interaktiv device code-flyt (du må godkjenne i nettlesar). Køyr **lokalt** – fungerer ikkje ubetjent i eit Azure Runbook eller anna automatisert miljø.

## Bruk

```powershell
# Interaktivt val av dry run eller faktisk endring (anbefalt)
.\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde.onmicrosoft.com"

# Tving dry run utan å bli spurt
.\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde.onmicrosoft.com" -WhatIf
```

Ved faktisk endring må du stadfeste med å skrive `JA` før scriptet gjer noko i Entra ID.

## Tryggleik og idempotens

- Ingen policy, gruppe eller named location blir overskriven om han alt finst – scriptet matchar på namn/CA-nummer-prefiks og hoppar over.
- Alle CA-policyar blir oppretta i report-only. Ingen blir handheva automatisk.
- Merk: `CA-008-A` (permanent blokk av Z-0) ekskluderer break-glass-kontoane dine viss registrert – kravdokumentet dette er bygd på tilrår opphavleg full blokkering utan unntak for Z-0. Vurder å fjerne unntaket manuelt i Entra-portalen om de vil følgje den strengaste tilrådinga.
- Legg break-glass-kontoar til **før** de aktiverer nokon av policyane – ver sikker på at de faktisk testar innlogging på break-glass-kontoane etterpå.

## Ansvarsfråskriving

Dette scriptet er delt som eit utgangspunkt, ikkje ein ferdig levert leveranse. Gå gjennom kvar policy og landliste, test grundig i report-only, og tilpass til di eiga risikovurdering før noko blir sett til `enabled`. Bruk på eige ansvar.
