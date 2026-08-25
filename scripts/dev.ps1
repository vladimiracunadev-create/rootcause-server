$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:ROOTCAUSE_API_TOKEN)) {
    throw "ROOTCAUSE_API_TOKEN is required. Generate one with: cargo run -p rootcause-server -- token"
}

cargo run -p rootcause-server -- serve @args
