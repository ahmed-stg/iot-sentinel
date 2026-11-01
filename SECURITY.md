# Security policy

## Supported versions

Only the latest tagged release receives fixes.

## Reporting a vulnerability

This tool generates risk reports and firewall rulesets; a bug in it can
therefore weaken a network. If you find a vulnerability in `iotsentinel`
(for example a generated ruleset that allows more than the MUD file asks,
or an SBOM that silently drops components), email **a.kaouadji@esi-sba.dz**
with:

- the command line you ran,
- the generated output,
- why you believe it is wrong.

Please do not open a public issue for an exploitable flaw. I aim to
acknowledge reports within 7 days and will credit reporters in the
changelog unless they prefer otherwise.

## What this tool is not

`iotsentinel` reports "known CVE in a matching version" and generates
least-privilege rulesets. It does not prove exploitability, it does not
manage a live gateway, and it is not a substitute for a professional audit.
See the *Known limitations* section of the README before deploying anything
it produces.
