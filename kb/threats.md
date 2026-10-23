# What can be dangerous on a phone

Read this file when the owner asks what a finding means. Use it to explain,
never to change a finding or its severity. The report and `kb/findings.yaml`
always win.

## 1. Mercenary spyware

- Examples: Pegasus (NSO Group), Predator (Intellexa), Graphite (Paragon),
  Hermit (RCS Lab).
- Governments buy it and use it against journalists, activists, lawyers and
  politicians. It often needs no click from the victim.
- How it shows: MVT indicator matches (`mvt-ioc-match`): process names,
  domains in SMS or browser history, crash logs, odd files.
- It is rare. One match needs expert review; it is not a final answer.
- Who helps: Amnesty Tech Security Lab, Access Now Helpline, Citizen Lab.

## 2. Stalkerware

- Commercial spy apps that someone with access to the phone installs:
  a partner, ex-partner or family member.
- They read messages, track location, record calls, and often hide their icon.
- How it shows on Android: `stalkerware` match, an app installed by hand with
  accessibility, notification access or device administrator rights, a
  system-like name (`looks-like-system`).
- iPhone: stalkerware usually works through the iCloud account, not an app.
  Check the account sessions in the report's next steps.
- **Safety rule: do not remove it and do not confront anyone before a safety
  plan.** Removing it can alert the abuser and increase the danger.
- Who helps: stopstalkerware.org lists support services by country.

## 3. Monitoring apps (watchware)

- Parental control, employee monitoring, remote support. Legal, but often
  misused against a partner.
- How it shows: `watchware`, `device-admin`, `ios-mdm-profile`.
- The question is always: does the owner know and agree?

## 4. Banking trojans and other malware

- Apps that steal bank logins and one-time codes. They often come as a fake
  "update", a parcel-tracking link in an SMS, or a fake app.
- How it shows: app installed by hand (`sideloaded-app`,
  `unknown-origin-app`) plus `accessibility-service` or
  `notification-listener`.

## 5. Fake and modified apps

- Copies of WhatsApp, Telegram or Signal ("GB WhatsApp", "WhatsApp Plus") or
  of banking apps. They look the same and send your data elsewhere.
- How it shows: `impersonation`, `signer-mismatch`, `sideloaded-store-app`,
  `apk-signature-invalid`.
- Why the signature matters: anyone can reuse an app's name, but only the
  developer has the signing key. An app from Google Play is always the real
  one for that name. A copy from outside the store may not be.

## 6. Device management and profiles

- Android device owner / device administrator, iPhone MDM and configuration
  profiles. They give an organisation control over the phone.
- Normal on a work or school phone. On a personal phone, very suspicious.
- A trusted root certificate (`ios-root-certificate`) or an unknown VPN
  (`always-on-vpn`, `ios-vpn-profile`) lets someone read the traffic.

## 7. Outdated system

- No security updates means known holes stay open (`outdated-os`).
- Not a sign of infection. It makes infection easier.

## 8. What the phone check does not see

- Online accounts: someone can read mail, cloud backups, photos or chats from
  another device. Linked devices in WhatsApp, Signal and Telegram, and the
  sessions in the Google or Apple account, must be checked by hand. The
  report's next steps list where.
- A clean result is not proof. Say "no signs found by these checks".

## Words to use

- Say "sign", "trace", "needs review". Do not say "infected" or "hacked"
  unless a specialist confirms it.
- Say "no signs found by these checks", never "your phone is clean".
