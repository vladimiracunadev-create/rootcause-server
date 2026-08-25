$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:ROOTCAUSE_API_TOKEN)) {
    throw "ROOTCAUSE_API_TOKEN is required."
}

& rootcause-agent.exe @args
