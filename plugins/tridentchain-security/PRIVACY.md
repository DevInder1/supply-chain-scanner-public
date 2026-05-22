# TridentChain Security — Privacy Policy

**Effective date:** 2026-05-20  
**Applies to:** Claude plugin, `tridentchain-mcp` MCP server, and `tridentchain-security` CLI.

## Summary

TridentChain Security is **local-first**. Scans run on your machine. We do not operate a hosted scanning service that receives your source code.

## Data collection

| Data | Collected by us? | Notes |
|------|------------------|-------|
| Your source code | **No** (not sent to TridentChain) | Stays on your device; scanner reads local files |
| Dependency names/versions | **Locally only** | Used to query public advisory APIs |
| API keys you configure | **No** | Stored in your environment / `.env`, not in the plugin |
| Scan reports | **Locally only** | Written to paths you choose (e.g. `.tridentchain-out/`) |

## Network usage

The scanner may contact **public security feeds** (e.g. OSV, NVD) to fetch vulnerability metadata. Requests include package identifiers and versions, not your full repository contents.

Optional sources (GHSA, Sonatype) use **your** tokens if you set them via environment variables.

## Storage

- Reports and cache: local disk (default SQLite cache under scanner config).
- No TridentChain cloud account or central telemetry is required.

## Third-party sharing

We do not sell or share your project data with third parties. Public advisory APIs receive standard package/version queries as part of normal vulnerability lookup.

## Retention

You control retention by deleting output directories and the local vulnerability cache database.

## Contact

- Issues: https://github.com/DevInder1/supply-chain-scanner-public/issues  
- Repository: https://github.com/DevInder1/supply-chain-scanner-public

## Changes

We may update this policy in the repository. Continued use after changes constitutes acceptance of the updated policy.
