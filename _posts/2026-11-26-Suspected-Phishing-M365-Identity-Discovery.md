---
title: "From a Suspected Phishing Email to a Microsoft 365 Identity Discovery"
date: 2026-11-26 18:30:00 +0000
categories: [Blue Team Notebook, Investigations]
tags: [microsoft-365, entra-id, phishing-investigation, sharepoint, b2b, smart-lockout, password-spraying, shared-mailbox]
description: "A first-person, anonymised investigation: suspected phishing, precautionary account protection, external guest access, a licensed generic mailbox, and wider authentication probing."
image:
  path: /assets/Thumbnails/phish-identity-thumb.png
  alt: "Cartoon eyeball investigating a suspicious email and shielding a shared mailbox from failed sign-in attempts"
---

> **Anonymised field notes.** This is an educational account of my investigative process, not a breach report. Names, domains, IP addresses, project details, tenant IDs, identifying timestamps and customer-specific counts have been omitted or generalised. A failed sign-in is not proof of account compromise.
{: .prompt-info }

## The email that started it

A user reported several unexpected invitations to documents in another organisation's SharePoint environment. The messages looked like familiar Microsoft 365 sharing notifications, but opening the links led to a Microsoft-branded **account locked** message rather than the documents.

My initial working possibilities were phishing, a genuine but unsafe cloud-hosted document, a home-account authentication problem, or a legitimate external-sharing invitation with broken guest access. I did not want to decide which one it was from the email's appearance alone.

## First response: contain the possible exposure

Because credentials might have been entered into an unexpected authentication flow, precautionary account protection was appropriate. The reporting user's **password was reset, MFA registration was required again, and existing sessions were revoked**. These actions reduced potential exposure while the link and sign-in evidence were examined. They did **not** mean that phishing or compromise had been proven.

I inspected the copied hyperlink rather than trusting the visible button. Its host and path were consistent with a genuine `*.sharepoint.com` sharing link, without an obvious lookalike domain. That was useful evidence, but a genuine Microsoft-hosted link is not automatically safe: malicious content can also be hosted on legitimate services.

The user could authenticate normally to their own Microsoft 365 portal. The failure appeared specifically when accessing the external resource. That moved my attention from a general home-account lockout to the external sharing relationship.

## Following the guest-access clue

The invitations had been addressed to a **generic mailbox**, while the reporting user opened the messages through **Exchange mailbox delegation**. This matters because being allowed to read a mailbox does not mean being granted access to documents shared with the mailbox's identity.

Microsoft Entra B2B external sharing may involve a guest identity in the resource owner's tenant. I checked the reporting user's sign-in records and found failures including `AADSTS500571`, which points to a **disabled guest account in the resource tenant**. This was a much better fit for the SharePoint access problem than a general lockout of the user's home account.

I could not inspect or repair the external organisation's guest object. The appropriate next step was to have the resource owner verify the guest identity and, if needed, reissue the invitation to the individual's own account.

> **Finding, not proof of safety:** The link structure and guest error supported a legitimate external-sharing issue. They did not independently authenticate the sender or establish that the hosted documents were harmless.
{: .prompt-warning }

## The second account nobody was signing into

Investigating the invitation recipient led to a separate discovery. The generic mailbox was **used like a shared mailbox**, with staff opening it through delegation, but it was configured as a **licensed user mailbox** with its own Microsoft Entra sign-in identity. It had **no MFA configured**.

That configuration is not necessarily wrong for every organisation. In this case, though, nobody needed to sign in directly as that identity. A predictable generic address with an enabled sign-in path was unnecessary exposure.

So I checked its authentication history.

## What the sign-in logs revealed

The generic identity had repeated failed sign-ins from geographically dispersed networks, targeting applications such as **Azure Portal, Azure CLI and Microsoft Entra PowerShell**. That is not normal usage for a correspondence mailbox. Some request characteristics were consistent with scripted authentication.

| Error | What I took from it |
|:--|:--|
| `AADSTS50126` | Invalid credentials; not a successful sign-in. |
| `AADSTS50053` | Authentication blocked by lockout or malicious-source protections; the individual event details matter. |

At first, the admin centre showed the account as **enabled**, while a log entry said **locked**. Those states are compatible. Entra Smart Lockout can block authentication without an administrator disabling the user object. A `50053` result alone does not prove an attacker knew the correct password.

I then checked successful **interactive and non-interactive** sign-ins for the generic identity across the available month-long period. **None were found.** The evidence supported repeated unsuccessful credential probing, not a confirmed compromise.

### Was anyone else being targeted?

I widened the review to other accounts in the tenant. Several showed similar failed attempts against administrative applications from changing international IP addresses. Some identities had repeated activity, while others had isolated probes. No successful sign-in from the exact suspicious source IPs was found in the reviewed extract.

I deliberately separated these from ordinary authentication noise:

| Error or pattern | More appropriate interpretation |
|:--|:--|
| `AADSTS70044` followed by expected MFA-backed access | Often session expiry or reauthentication. |
| `AADSTS50105` | Application assignment or access restriction. |
| `AADSTS500571` | Disabled guest in the resource tenant. |
| A local `50126` followed immediately by a successful sign-in | May be a mistyped password rather than an attack. |

This was a **sample**, not a complete tenant-wide historical assessment. I recommended reviewing longer-range successful and non-interactive sign-ins, risk detections, MFA methods and Conditional Access, particularly for the most frequently targeted and privileged identities. I would not label every failure malicious, or reset every password solely because a failed event appeared.

## MFA or a proper shared mailbox?

The mailbox configuration presented a choice:

1. **Keep the user mailbox:** enforce MFA and appropriate Conditional Access, and retain direct sign-in only if it serves a real operational need.
2. **Convert to a shared mailbox:** preserve delegated access through staff identities and **block direct sign-in** for the underlying mailbox account.

Because staff only used delegated access, **conversion was the better fit**. It removed the need for an interactive identity instead of merely adding another authentication challenge to it. Conversion alone does **not** block sign-in; that is a separate hardening control to verify.

> Don't just protect access that isn't needed. Remove the access path.
{: .prompt-tip }

### A conversion snag worth remembering

The mailbox licence was removed before conversion, after which the admin interface reported a resource-not-found error and Exchange PowerShell could not resolve the mailbox normally. Reassigning the licence restored visibility, and the conversion could proceed.

For a cloud-only mailbox, the conversion command was:

```powershell
Set-Mailbox -Identity "generic@example.invalid" -Type Shared
```

An immediate read-back still showed the old recipient type, but a later check in PowerShell and the Exchange admin centre confirmed `SharedMailbox`. Exchange Online state changes can take time to become visible, so I avoided repeatedly issuing the conversion once the new state appeared.

### Don't overlook online archiving

A further check revealed an **active online archive at its configured quota**. The primary mailbox was within the normal unlicensed shared-mailbox limit, but that did not settle the archive entitlement.

```powershell
Get-MailboxStatistics -Identity "generic@example.invalid" -Archive | Format-List TotalItemSize,ItemCount
```

I kept conversion and licence removal as separate decisions. Shared-mailbox archiving and higher capacities can require **Exchange Online Plan 2** or **Exchange Online Plan 1 plus Exchange Online Archiving**. Removing the licence without reviewing archive requirements would risk turning a security improvement into a retention or availability problem.

Microsoft's guidance: [Convert a user mailbox to a shared mailbox](https://learn.microsoft.com/en-us/microsoft-365/admin/email/convert-user-mailbox-to-shared-mailbox) and [About shared mailboxes](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes).

## Where the investigation finished

| Area | Evidence-based outcome |
|:--|:--|
| Suspected phishing | Not confirmed. The SharePoint URL looked structurally legitimate, and sign-in evidence supported a disabled external guest identity. |
| Reporting user's account | Password reset, MFA re-registration required, sessions revoked; normal home-tenant sign-in worked. |
| Generic mailbox | Found to be a licensed, MFA-less user identity with repeated failed authentication. No successful sign-ins found in the reviewed month. Successfully converted to a shared mailbox. |
| Wider tenant | Similar failed credential probing affected additional identities; no successful sign-in from the suspicious source IPs in the reviewed extract. |
| Follow-up | Verify direct sign-in is blocked and delegation still works; review archive licensing; ask the external resource owner to repair guest access; expand MFA and sign-in reviews. |

I have deliberately not marked the external guest problem, licence removal or every follow-up control as completed where the evidence only established a recommendation or outstanding check.

## Lessons I took away

1. **Contain first, classify second.** A precautionary password reset is sensible when exposure is plausible, but it is not evidence of a breach.
2. **Follow the actual identity path.** The invited address and the user authenticating to SharePoint may be different.
3. **Audit generic mailboxes.** A mailbox that looks shared to staff may still be a sign-in-capable licensed user account.
4. **Read the failure reason, not just the status.** `50053`, `50126`, guest errors and session expiry tell different stories.
5. **Look sideways.** Once I saw repeated probing against one identity, checking the wider tenant revealed related activity.
6. **Don't confuse unsuccessful attacks with successful access.** State what the logs establish and what remains unknown.
7. **Protect the operational details.** Delegation, archive licensing, holds and mailbox quotas all matter when changing identity configuration.

## Practical follow-up checklist

- [ ] Validate the link destination and authentication domain without opening untrusted content.
- [ ] Confirm the invited identity and the account actually authenticating.
- [ ] Review detailed Entra failures, successful interactive sign-ins and non-interactive sign-ins.
- [ ] Distinguish credential failures from session, app-assignment and guest-access errors.
- [ ] Check MFA and Conditional Access for generic and privileged accounts.
- [ ] Block direct sign-in for mailbox identities that do not need it.
- [ ] Verify delegate access after mailbox conversion.
- [ ] Check archive capacity, retention requirements and licence entitlements before licence removal.

## Final thought

I started by asking **"Is this a phishing email?"** and ended up finding an external guest-access problem, an unnecessarily sign-in-capable mailbox and a broader pattern of unsuccessful authentication attempts. There was no confirmed breach to announce. The value was in following the evidence, correcting an avoidable exposure and identifying what deserved further review.

---

*Independent Blue Team Notebook field notes. This is educational content, not an official assessment, incident declaration or statement on behalf of any customer or employer.*

## References

- [Microsoft Learn: Convert a user mailbox to a shared mailbox](https://learn.microsoft.com/en-us/microsoft-365/admin/email/convert-user-mailbox-to-shared-mailbox)
- [Microsoft Learn: About shared mailboxes in Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes)
- [Microsoft Learn: Remediate and unblock users in Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock)
