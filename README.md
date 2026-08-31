# Park Test

Monthly two-person fitness test scorecard. A single static page backed by Neon
Postgres over the Neon Data API. No server to run, no build step.

## Files

| File | What it is |
|---|---|
| `index.html` | The whole app. React and all styles are inlined, so it works offline once loaded. Never needs editing. |
| `config.js` | Your Neon address. The only file you edit. Survives future versions of `index.html`. |
| `schema.sql` | Run once in Neon. Contains one line you must edit. |
| `icon-180.png`, `icon.svg`, `manifest.webmanifest` | Home Screen icon and full-screen launch. |

## Setting it up

**1. Neon.** Create a *new* project rather than reusing an existing one. Open
**Data API** in the sidebar, pick the branch, enable it. Copy the URL it gives
you, ending in `/rest/v1`. Check the anonymous role name on that page; the SQL
assumes `anonymous`.

**2. Set your passphrase.** In `schema.sql`, find the line marked
`>>> CHANGE THIS PASSPHRASE <<<` and replace `change-this-passphrase`. Three or
four unrelated words. Then paste the whole file into the Neon SQL editor and run
it.

**3. Set the address.** In `config.js`, paste your Data API URL between the
quotes on the last line. Nothing else needs editing, now or later.

**4. GitHub Pages.** Push all the files to a repo, then Settings → Pages →
deploy from branch, root.

**5. Open it.** The page asks for the passphrase once per device and remembers
it. Send your friend the page address and the passphrase by different routes.

**6. Home Screen.** Safari → share icon → Add to Home Screen.

## How the security works

The two data tables have row-level security on with no policies, and no grants
to the anonymous role, so they cannot be read or written over the API at all.
Access goes through five `security definer` functions, each of which takes the
passphrase as its first argument and checks it against a bcrypt hash before
doing anything. Ten wrong attempts locks everything for fifteen minutes.

That means the Data API address is safe to commit to a public repo. The
passphrase is the credential, and it never appears in the page or the repo.

**Change the passphrase** any time in Setup. It changes for both of you, and the
other phone will ask for the new one next time it syncs.

## What lives where

- **In Neon, behind the passphrase:** names, the exercise list, every filed test,
  and one photo per month.
- **On your phone only:** your morning stiffness minutes, and your copy of the
  passphrase. Neither is ever sent.

## Things worth knowing

- Offline is handled. The last known state is cached on the device, anything
  entered without signal is held and marked "unsent", and **Send now** in Setup
  pushes it when you're back on data.
- **Photos.** One joint shot per month, optional. It is resized to 1600px on the
  long edge in the browser before it goes anywhere, roughly 400KB, which is sharp
  on screen and fine printed at 6x4. That is about 5MB a year against a 0.5GB
  project limit. Photos load only when you open that month.
- **Export JSON** in Setup takes a full backup of scores and settings. It does
  not include photos. Worth doing a couple of times a year.
- **Lock this phone** in Setup forgets the passphrase on that device.
- If you lose the passphrase, reset it by running the `insert into parktest_auth`
  line again as an `update` in the Neon SQL editor. The data is untouched.

## Updating later

Replace `index.html` with the new one and leave `config.js` alone. If the change
also needs SQL, it will be additive, so your scores, photos and passphrase are
untouched. GitHub Pages and the Home Screen shortcut both cache hard: if the old
version persists, close the shortcut fully and reopen, or load the URL with
`?v=2` on the end.

Not medical advice. The measures are worth taking to a clinician as a series,
not read one month at a time.
