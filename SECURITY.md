# Security policy

This is a read-only educational/reference audit implementation. Use only against environments you own or have explicit permission to assess.

- Never share access tokens, client secrets, or real user exports.
- Enable public-client device-code auth only on the intended interactive app registration.
- Restrict permissions to the delegated Graph reads necessary for the approved scope.
- Keep real reports out of public source control and treat them as sensitive evidence.
- Check and approve retention and distribution before exporting real data.
- Handle reported security issues privately rather than publishing live tenant details.
- No automated remediation is performed. Findings require human confirmation.
