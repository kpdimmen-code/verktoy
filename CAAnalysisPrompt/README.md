# Export-CAAnalysisPrompt

Reint lese-script som kartlegg heile Conditional Access-oppsettet i ein Entra ID-tenant og pakkar det om til ein ferdig-formatert prompt du limer rett inn i ein LLM for statusanalyse. Ingenting blir endra i tenanten – dette er kartleggingssteget, ikkje byggjesteget.

Naturleg makker til [`Setup-ConditionalAccess-Full`](../CA-Policy-baseline/): analyser først med dette scriptet, bygg/juster baselinen, og køyr analysen på nytt etterpå for å verifisere at hola faktisk vart tetta.

## Kva scriptet gjer

1. Hentar alle CA-policyar, named locations, Security Defaults-status og Authentication Methods-policy via Microsoft Graph.
2. Slår opp lesbare namn for roller og appar der det er mogleg (kjende Microsoft-roller er hardkoda, resten blir slått opp live) – slik at prompten viser «Global Administrator» i staden for ein rå GUID.
3. Bygg ein strukturert markdown-rapport: éin seksjon per policy med brukarar/grupper/roller, appar, platformer, lokasjonar, einingsfilter, grant- og sesjonskontrollar.
4. Pakkar heile rapporten inn i ein ferdig analyseoppgåve til ein LLM – modenheitsvurdering, kritiske manglar, prioriterte forbetringsforslag, konsistenssjekk og vurdering mot kjende baseline-/Zero Trust-anbefalingar.
5. Lagrar prompten som `.md`-fil og kopierer han til utklippstavla, klar til å limast rett inn.

## Krav

- **Tilgang:** Kun lesetilgang – Global Reader, Security Reader, eller Conditional Access Administrator/Global Administrator (som òg har leserettar). Scriptet ber berre om `Policy.Read.All`, `Directory.Read.All` og `Application.Read.All`, og gjer ingen skriveoperasjonar.
- **PowerShell:** Ingen eksterne modular – rein REST via `Invoke-RestMethod`. PowerShell 5.1+ eller 7+.
- **Pålogging:** Interaktiv device code-flyt. Køyr lokalt.

## Bruk

```powershell
.\Export-CAAnalysisPrompt.ps1 -TenantId "kunde.onmicrosoft.com"

# Eige filnamn/plassering
.\Export-CAAnalysisPrompt.ps1 -TenantId "kunde.onmicrosoft.com" -OutputPath "C:\Audit\ca-prompt.md"
```

Prompten blir automatisk kopiert til utklippstavla i tillegg til lagra som fil.

## Viktig om kvar du limer prompten

Output frå dette scriptet er ei fullstendig skildring av CA-forsvaret i tenanten – kven som har unntak, kva som er blokkert, kva som *ikkje* er dekt. Det er sensitiv informasjon.

**Lim han berre inn i ein LLM du har databehandlaravtale med og stoler på** – til dømes Microsoft 365 Copilot med enterprise data protection, eller tilsvarande verksemdsavtale. Aldri i ein vilkårleg gratis chatbot.

## Ansvarsfråskriving

Scriptet er reint lesande og gjer ingen endringar, men resultatet – og analysen du får tilbake frå LLM-en – bør handsamast som eit utgangspunkt for vurdering, ikkje ein automatisk fasit. Bruk på eige ansvar.
