# PentestAI — Expo Playbook

> Read tonight. Glance at **Section 13** at the booth.
> Anything marked `[TODO: ...]` needs you to confirm it before you say it out loud.

---

## 1. Project Snapshot

**Name:** PentestAI — *AI Powered Penetration Testing Platform for Automated Vulnerability Detection*

**Tagline:** **Find it. Prove it. Fix it. Confirm it's gone.**

**One sentence:** PentestAI scans your GitHub code for security holes, double-checks the serious ones in a locked-down sandbox, writes a fix that it re-tests before opening a pull request, and confirms on the next scan that the hole is really closed.

**Team** — Dept. of CSE, K.S. School of Engineering and Management (KSSEM), 2026–27
Guide: **Mrs. Bindu K.P**, Assistant Professor

| Member | USN | Role at the booth |
| --- | --- | --- |
| Gagana R | 1KG23CS034 | `[TODO: confirm role — e.g. hook + opening pitch]` |
| Kushal K R | 1KG23CS056 | `[TODO: confirm role — e.g. live demo driver]` |
| M G Sahana | 1KG23CS061 | `[TODO: confirm role — e.g. poster walkthrough + backup demo]` |
| M Harshit Pramod | 1KG23CS062 | `[TODO: confirm role — e.g. technical Q&A]` |

**Tech stack, in plain words**

| Part | What we used | In one line |
| --- | --- | --- |
| Website | React 19 + TanStack Start, Tailwind | The dashboard you see in the browser |
| Database + login | Supabase (Postgres) with GitHub sign-in | Stores users, scans and findings; each user only sees their own rows (Row Level Security) |
| Scanning brain | Google Gemini (`gemini-2.5-flash`) | An AI model that reads code and reports security problems |
| Secret finder | Regular-expression rules | Exact pattern matching for leaked keys and passwords — no AI guessing |
| Sandbox | Docker Compose (Caddy, Fastify API, Redis queue, worker) | Separate, locked-down containers where untrusted code is analysed |
| Verification | CodeQL + Semgrep | Industry static-analysis tools that trace how data flows through code |
| Fix writer | Qwen3-Coder via OpenRouter | A code-specialised AI model that writes the patch |
| Email | nodemailer (SMTP) | Weekly digest emails |
| Tests | Vitest — **206 tests passing** | Automated checks for the security-critical logic |

---

## 2. The Problem

**Who has it:** student developers, startups and small teams who ship code every day but **have no security engineer**.

**How painful:**
- Manual penetration testing is **slow, expensive and needs specialists** — most small teams simply skip it.
- Automated scanners exist, but they **dump long lists of "possible" issues**. Developers can't tell real threats from false alarms, so they start ignoring the tool.
- Even when a fix is suggested, **nobody checks that the fix actually worked** — the same bug can quietly come back later.

**What happens today without us:** code goes live with an SQL injection or a leaked API key, and the team finds out when someone else does.

**Relatable examples / statistics** (quote only after you verify the source):
- Leaked secrets on GitHub: `[TODO: confirm — GitGuardian "State of Secrets Sprawl" report, number of secrets found in public GitHub commits, and year]`
- Cost of a breach: `[TODO: confirm — IBM "Cost of a Data Breach" report, global average cost, and year]`
- Injection is a long-standing top web risk: `[TODO: confirm — OWASP Top 10 (2021) lists Injection as A03]`
- Safe, non-statistic example you can always use: *"Someone pastes an AWS key into a config file, pushes to GitHub, and the bill arrives before they notice."*

---

## 3. Our Solution (What It Does)

**For a non-technical visitor:**
> "Think of it as a security guard for your code. It reads your project, finds the weak spots, double-checks the serious ones so it isn't crying wolf, writes the repair, and then comes back later to make sure the repair actually worked."

**Core features — what it does → why it matters**

| Feature | What it does | Why it matters |
| --- | --- | --- |
| **AI repository scan** | Gemini reads the most security-relevant files and reports each issue with severity, CWE, CVSS, file and line | Developers get a clear, ranked list instead of raw tool noise |
| **Secret detection** | Pattern rules catch AWS / GitHub / Google / OpenAI / Stripe / Slack keys, private keys, JWTs and real values in `.env` files | Leaked keys are caught **every time**, even if the AI misses them; any secret drags the score down |
| **Sandbox verification** | Every **high and critical** finding is re-checked with CodeQL/Semgrep in a container with **no internet** and a read-only file system | Cuts false alarms; results are backed by evidence, not just AI opinion |
| **Verified AI fix → Pull Request** | Qwen3-Coder writes a patch; the patch is **re-scanned twice** and must remove the bug without adding a new medium/high/critical one; only then is a PR opened | A human always approves; we don't ship fixes that didn't pass our own re-test |
| **Vulnerability lifecycle tracking** | Each finding keeps one history across scans: resolved when it disappears, **reopened as a regression** if it comes back | Proves the fix really closed the hole — and catches it if someone breaks it again |
| **Dashboard + reports** | Security score, severity counts, per-finding timeline, live sandbox console, JSON/PDF reports | Easy to understand and to hand to a teacher, manager or client |
| **Weekly auto-scan + email** | Opt-in per repo; rescans weekly and emails one digest per user | Security keeps running without anyone remembering to click |
| **Security Assistant** | Chat that answers questions using **your own scan data** | Ask "what should I fix first?" in plain English |

**How it works — 5 steps**
1. **Connect** — sign in with GitHub and pick a repository.
2. **Scan** — AI + secret rules find issues and give a security score.
3. **Verify** — serious findings are re-checked inside an isolated sandbox → *confirmed* or *not exploitable*.
4. **Fix** — click *Fix with AI*; a re-tested patch arrives as a GitHub pull request.
5. **Confirm** — merge it, scan again → the finding is marked **resolved** on its timeline.

---

## 4. Why Choose Ours (Selling Points)

**Top 5 strengths, ranked**
1. **Closes the loop.** Scan → verify → fix → re-scan → confirmed resolved. Most tools stop at "here's a list".
2. **Fixes are tested before you see them.** A patch must pass **two** independent re-scans (up to 3 attempts) or **no PR is opened at all**.
3. **Evidence over opinion.** High/critical findings are double-checked by CodeQL/Semgrep, and the result must match the expected weakness type — an SQL-injection finding can't be "confirmed" by an unrelated XSS hit.
4. **Safe by design.** Untrusted code runs in containers with no network, read-only disk, memory/process limits and a hard timeout; GitHub tokens are encrypted (AES-256-GCM) and never written to disk or the command line.
5. **Human stays in control.** Every change is a pull request a developer reviews and merges — nothing is pushed silently.

**Us vs. alternatives** (keep this fair — judges respect it)

| | Manual pentest | Rule-based scanner alone (e.g. Semgrep / SonarQube) | PentestAI |
| --- | --- | --- | --- |
| Cost / speed | Expensive, days–weeks | Cheap, fast | Cheap, minutes `[TODO: confirm typical scan time]` |
| Needs a security expert | Yes | To triage results | No — results are ranked and explained |
| Filters false positives | Yes (human) | No | Partly — second-tool verification on high/critical |
| Suggests a fix | Report only | Some do | Yes — as a **re-tested** pull request |
| Confirms the fix worked later | Only if re-hired | Re-run manually | **Automatic** on next scan, with regression detection |

> If asked about big commercial tools (GitHub Advanced Security, Snyk): **"They're excellent and some also suggest AI fixes. Our focus is the full loop — re-testing the fix before the PR and tracking that it stays fixed — in a self-hostable package a small team or college can run."** Don't claim they lack a feature unless you've checked.

**Practical / affordable / scalable**
- Built from open tools (CodeQL, Semgrep, Docker, Postgres) + pay-per-use AI APIs.
- Self-hostable on a single machine with Docker — that's how we run it.
- Job queue (Redis) separates the website from the heavy work, so more workers can be added later.

---

## 5. Impact

**Who benefits**
- **Students & beginners** — learn secure coding from real findings on their own code.
- **Startups / small teams** — security checks without hiring a security engineer.
- **Colleges** — scan project repos before submission or deployment.
- **Open-source maintainers** — catch leaked keys and injection bugs before release.

**Short-term:** fewer vulnerable projects going live; leaked keys caught before they're abused.
**Long-term:** security becomes part of everyday development (DevSecOps) instead of a once-a-year audit.

**Where it could be deployed:** college labs and hackathons, startup CI/workflows, internal company Git servers, freelance agencies auditing client code.

**Growth potential** (present as *potential*, not plans already executed): hosted SaaS with free tier for students, paid team tier; on-premise version for companies that can't send code outside.

---

## 6. Pitch Scripts

### 15-second hook (passersby)
> "Ever pushed code to GitHub and wondered if it's hackable? Our project finds the security holes, proves which ones are real, and writes a tested fix as a pull request. Want to see it catch one live?"

### 30-second elevator pitch
> "Small teams ship code daily but can't afford a security expert. Existing scanners give long lists of maybes. **PentestAI** scans a GitHub repo with AI, double-checks the serious findings in an isolated sandbox using CodeQL, then writes a fix that it re-tests twice before opening a pull request. After you merge and scan again, it confirms the vulnerability is gone — and reopens it if it ever comes back."

### 2-minute full pitch
> **Hook:** "What if your code had a security guard that not only found problems but fixed them — and checked its own work?"
>
> **Problem:** "Penetration testing is slow and expensive. Automated scanners are cheap, but they flood you with false alarms, and nobody verifies that a fix actually worked."
>
> **Solution:** "PentestAI connects to GitHub. Google Gemini scans the most security-relevant files, and exact pattern rules catch leaked keys. Every high and critical finding is re-checked inside a Docker sandbox with no internet, using CodeQL — so we show evidence, not just an AI's opinion."
>
> **Demo moment:** "Here's a demo repo with an SQL injection on line 9 — a high-severity bug. *(show)* The sandbox confirmed it. I click Fix with AI… the patch was re-scanned twice before this pull request was opened. I merge it, scan again — and the finding is now **resolved** on its timeline."
>
> **Impact:** "That's the whole loop — find, prove, fix, confirm — for teams that don't have a security engineer."
>
> **Close:** *(see closing line below)*

### 5-minute deep-dive (judges)
1. **(0:00–0:30) Problem** — as above, plus *why* false positives kill adoption.
2. **(0:30–1:30) Architecture** — point at the poster diagram:
   - App (TanStack Start + Supabase) and Sandbox (Docker Compose) are **two separate halves** that talk only through **HMAC-signed** messages.
   - The app never runs untrusted code; the sandbox never holds a database password.
3. **(1:30–2:30) Scan + verify** —
   - Picks up to **18 files / 250 KB**, ranked by security relevance (`.env`, auth, db, upload, config first).
   - Gemini returns severity, CWE, CVSS; output is validated because **AI output is untrusted input**.
   - High/critical → runner container: `--network none`, read-only root, 3 GB / 512 process limits, hard timeout. CodeQL taint analysis, Semgrep fallback; result must match the expected CWE.
4. **(2:30–3:45) Fix + gate (live demo)** —
   - Baseline scanned twice (AI varies between runs), Qwen3-Coder patches, patch re-scanned **twice**, up to **3** attempts, compared finding-by-finding.
   - Only a passing patch becomes a PR. Merge → rescan → resolved.
5. **(3:45–4:30) Lifecycle** —
   - One row per finding for its whole life.
   - Resolved after **2 consecutive misses**, or on the **first miss if its AI-fix PR was merged**.
   - Reopened as a **regression** if it returns. Every change shows on a timeline.
6. **(4:30–5:00) Honesty + future** — "Verification today is a second independent static analysis, not live exploitation. Next we'd add dynamic exploit tests in the sandbox and dependency scanning." → closing line.

### Closing line (end every pitch with this)
> **"Other tools tell you what might be wrong. PentestAI proves it, fixes it, and makes sure it stays fixed."**

---

## 7. Demo Plan

**Setup:** demo repo **`Harshithpramod/pentest-demo2`** — a tiny Express API with an **SQL injection in `src/routes/users.js` (line 9)**. Backup repo **`Harshithpramod/pentest-demo`** already has the full story completed (PR #1 merged, finding resolved, later secured with auth → score **95**, status secure).

| # | Show | Say | Time |
| --- | --- | --- | --- |
| 1 | Dashboard, repo list | "We've signed in with GitHub — here's a repo we deliberately made vulnerable." | 15 s |
| 2 | Click **Scan**, live progress | "It picks the most security-relevant files and sends them to the AI, plus exact rules for leaked keys." | `[TODO: time a real scan]` |
| 3 | Finding: **High — SQL Injection**, file + line | "Line 9 pastes user input straight into a database query. An attacker could read every user." | 20 s |
| 4 | Verification badge + live **sandbox console** | "This was re-checked in a container with **no internet** using CodeQL — it's **confirmed**, not just the AI's guess." | `[TODO: time CodeQL verify]` |
| 5 | Click **Fix with AI**, console shows attempts | "A code model writes the fix, then we re-scan it **twice**. If it fails, no PR is opened." | `[TODO: time a fix job]` |
| 6 | Open the **PR on GitHub**, show the diff | "It switched to a **parameterised query** — the input can no longer change the SQL." | 30 s |
| 7 | **Merge** → back to app → **Scan again** | — | scan time |
| 8 | ⭐ **Finding shows Resolved** + timeline | "Merged, rescanned — **gone**. And if anyone reintroduces it, it reopens as a regression." | 20 s |

**⭐ Wow moment:** step 8 — the timeline showing *detected → confirmed → fix PR → merged → resolved*. **Pause, let them look, then say the closing line.**

**Fill dead time** during scans with the architecture poster (steps 2, 4, 5 take the longest).

**If a new, smaller finding appears after the rescan** (this happened in rehearsal — a medium *missing access control*, CWE-284):
> "That's actually correct — this demo endpoint has no login check at all. With the louder SQL bug gone, the scanner reports the next real issue. In our other repo we added authentication and it went to **secure, score 95**." → switch to `pentest-demo`.

**Backup plan, in order**
1. **`pentest-demo` repo** — already-completed run: show the merged PR #1, the resolved finding and its timeline.
2. **`/demo` page** — a full simulated product tour built into the app; **no sign-in, no internet to GitHub needed**.
3. **Screenshots** from the report/poster (dashboard, confirmed finding, sandbox console + timeline, assistant). `[TODO: put them in one folder on the laptop + phone]`
4. **Screen recording** of a full successful run. `[TODO: record tonight]`
5. **Offline explanation** with the poster's architecture and sequence diagrams.

---

## 8. Booth Strategy

**Opening lines**
- "Want to see an AI find and fix a hack in under [TODO] minutes?"
- "Do you have code on GitHub? This checks if it's hackable."
- "We made a website with a security hole on purpose — want to watch it get fixed?"

**Read the visitor and adjust**

| Visitor | Signs | Lead with | Go deep on |
| --- | --- | --- | --- |
| **Judge** | Clipboard, asks "what's novel?" | 2-min pitch → live demo | Fix gate, lifecycle, honest limits, what each member built |
| **Student** | Curious, casual | 15-s hook → show the SQL bug | "Here's what SQL injection looks like and how the fix works" |
| **Industry person** | Asks about scale, CI, cost | Selling points 1, 2, 4 | Sandbox isolation, token security, self-hosting |
| **Investor / startup-minded** | Asks "who pays?" | Problem + impact | Target users, SaaS/on-prem potential, cost per scan |

**Body language & tone**
- Stand **beside** the screen, not in front of it; face the visitor, not the laptop.
- Smile, slow down, short sentences. Pause after the wow moment.
- One person speaks at a time; others nod and stay ready.
- If you don't know: say so calmly (see Section 9).

**What to display**
- **A3 poster** (top centre).
- **Laptop** with the live app; second screen/tablet with backup screenshots or `/demo` if possible.
- **QR code** to the GitHub repo or demo repo. `[TODO: decide — public repo link? make one tonight]`
- Optional handout: one-page Quick Card (Section 13). `[TODO: print?]`

**Speaking roles** — see table in Section 1. Suggested split: **Hook/pitch**, **Demo driver**, **Q&A (technical)**, **Backup + poster walkthrough**. Rotate if someone's voice gets tired.

---

## 9. Q&A Prep

### Technical
**1. How does it find vulnerabilities?**
> "Google Gemini reads up to 18 of the most security-relevant files and reports each issue with severity, CWE and CVSS. Separately, exact pattern rules look for leaked keys, so those are caught even if the AI misses them."

**2. What does "verified" mean? Do you actually hack the code?**
> "Honestly — no live attack. Verification is a **second, independent analysis** with CodeQL or Semgrep inside an isolated container, and it must agree on the same weakness type. It's evidence the bug is real, not a live exploit. Dynamic exploitation is our top future step."

**3. Why only verify high and critical?**
> "Each verification spins up a container and runs CodeQL, which takes minutes. We spend that cost where the risk is highest."

**4. How do you know the AI fix doesn't break things?**
> "The fix must pass two re-scans showing the bug is gone and nothing new appeared. But it's **re-scanned, not compiled or tested** — that's why it comes as a pull request a human reviews. Adding automatic test runs is on our roadmap."

**5. How is it safe to run strangers' code?**
> "We never execute it. Analysis runs in a container with no network, read-only disk, memory and process limits and a hard timeout. The GitHub token is removed before the code is mounted."

**6. Where are GitHub tokens stored?**
> "Encrypted with AES-256-GCM in the database. When cloning, a git credential helper passes the token, so it never appears in the command line or `.git/config`."

**7. Why this stack?**
> "Supabase gives us Postgres, GitHub login and row-level security out of the box. Docker gives isolation. CodeQL is the industry standard for taint analysis. Gemini Flash is fast and cheap for scanning; Qwen3-Coder is specialised for writing code."

**8. Does it scale?**
> "The website and the heavy work are separated by a Redis job queue, so more workers can be added. Today we run one worker on a single machine — horizontal scaling is designed for but not load-tested." `[TODO: don't quote throughput numbers — we haven't measured them]`

### Business
**9. What does it cost to run?**
> "Infrastructure is open-source; the main cost is AI API calls per scan and per fix." `[TODO: confirm approximate cost per scan/fix from your Gemini + OpenRouter usage pages]`

**10. Who would pay for this?**
> "Startups and small teams without a security engineer, and colleges. A free student tier plus a paid team tier, or an on-premise version for companies that can't send code out."

**11. Isn't GitHub / Snyk already doing this?**
> "They're strong tools, and some suggest AI fixes too. Our focus is the full loop — re-testing the fix before the PR and confirming it stays fixed — and it's self-hostable for small teams and colleges."

### Impact
**12. Real-world value?**
> "Catching one leaked key or one injection bug before release can prevent a breach. For students, it teaches secure coding on their own code."

### Challenges (great stories — judges love these)
**13. What went wrong and how did you fix it?**
- *Sandbox always said "not exploitable".* Semgrep tried to download rules but the container has no internet → we **bundled offline rules**.
- *Fix gate was fooled.* Early version just **counted** CWEs; a real patch removed one auth bug and added a different one with the same CWE → same count, looked fine. Now we compare **finding by finding**.
- *Same fix, flaky result.* AI scans vary between runs → we scan the original **twice** and require the patch to pass **twice**.
- *Race condition (TOCTOU).* Double-clicking *Fix* could start two fix jobs → we made the claim **atomic** in the database.
- *Lost results.* The sandbox could finish before the app saved the job id → the **app now generates the id first**.

### Tough / skeptical
**14. "It's called PentestAI but you don't actually exploit anything."**
> "Fair point. Today it's verified static analysis plus verified fixes — the 'pentest' part is the verification and isolation design. The sandbox is built so dynamic exploit tests can plug in next."

**15. "AI is non-deterministic. Can the same code give different results?"**
> "Yes, and we designed for it: a finding needs **two consecutive** misses before we call it resolved, and fixes must pass **two** re-scans. The one exception is a merged AI-fix PR, which resolves on the first clean scan."

**16. "Why did a new vulnerability appear after the fix?" / "Why not 100?"**
> "After the SQL bug was fixed, the scanner reported the next real issue — the endpoint had no login check. We added authentication and it went secure at 95. The score is the AI's judgment and it rarely gives a perfect 100; we don't fake it."

**17. "Does my code get sent to Google?"**
> "The selected files are sent to the Gemini API for analysis, yes. For sensitive code, the architecture allows swapping in a self-hosted model — that's future work."

**18. "It only reads 18 files — what about big repos?"**
> "True — it samples the most security-relevant files by path. It's a strong first pass, not full coverage. Covering the whole repo with CodeQL during scanning is a clear next step."

**19. "What did each of you build?"** `[TODO: each member prepare a 2-line answer about their own part]`

### When you don't know
> "Good question — I don't want to guess. What I can tell you is ___ [nearest true fact]. We'll note it as future work."

Never invent a number. **"We haven't measured that yet"** is a respectable answer.

---

## 10. Limitations and Future Scope

| Limitation (honest) | How to say it positively |
| --- | --- |
| Verification is a second static analysis, not live exploitation | "Evidence-based confirmation today; the isolated sandbox is ready for dynamic tests next." |
| Scan reads up to 18 files / 250 KB | "Focused on the most security-relevant files for speed and cost." |
| Severity and security score are the AI's judgment; results can vary run to run | "We design around it — double scans, two-miss rule, two re-scans for fixes." |
| AI fixes are re-scanned, not compiled or tested | "That's why every fix is a pull request a human approves." |
| Secret detection is pattern-based (no ML); no dependency/library scanning yet | "Deterministic and reliable for known key formats; dependency scanning is on the roadmap." |
| A job lost mid-run (worker restart) isn't retried automatically | "Single-machine prototype; a durable queue is the production upgrade." |
| Runs locally on Docker Desktop, not deployed publicly | "Self-hostable by design." |

**Next 3 improvements**
1. **Dynamic exploit testing** in the sandbox (actually run safe attack payloads against the app).
2. **Run tests/build on AI fixes** before opening the PR.
3. **Dependency scanning** + full-repo CodeQL during scans.

**Long-term vision:** a self-hostable "security teammate" that every repo has from day one — scanning on every push, fixing with proof, and keeping a lifelong history of every vulnerability.

---

## 11. Key Numbers & Facts Cheat Sheet

| Fact | Value |
| --- | --- |
| Files read per scan | up to **18 files**, **250 KB** total |
| Severity levels | **4** — critical, high, medium, low |
| Verified in sandbox | **high + critical** only |
| Scan AI model | Google **gemini-2.5-flash** |
| Fix AI model | **Qwen3-Coder** via OpenRouter |
| Fix attempts | up to **3** (configurable, max 5) |
| Re-scans a fix must pass | **2** (original also scanned **2×** for a baseline) |
| Fix gate rule | original finding gone **and** no new medium/high/critical |
| Resolve rule | **2 consecutive** missed scans, or **1** if its AI-fix PR was merged |
| Regression | a fixed finding seen again is **reopened** |
| Sandbox runner limits | **no network**, read-only root, **3 GB** RAM, **512** processes, hard timeout |
| Secret patterns | **12** named key formats + a `.env` rule |
| Secrets & score | any secret caps the score at **30 or lower** (15 with 4+ secrets) |
| Token storage | **AES-256-GCM** encrypted |
| Sandbox ↔ app messages | **HMAC-SHA256** signed, constant-time check |
| Weekly scan default | every **168 hours** (7 days), opt-in per repo |
| Live console cap | **300** lines per job, secrets redacted |
| Automated tests | **206 passing** (9 test files) |
| Demo result | High SQLi → AI PR #1 merged → rescan → **resolved**; then auth added → **Secure, score 95** |
| Typical scan / verify / fix time | `[TODO: time each one tonight]` |
| Cost per scan / fix | `[TODO: check API usage dashboards]` |

**Jargon in one line each**
- **SQL injection** — user input sneaks into a database query and changes what it does.
- **CWE** — a standard ID number for a type of weakness (e.g. CWE-89 = SQL injection).
- **CVSS** — a 0–10 score for how severe a vulnerability is.
- **Static analysis / taint analysis** — reading code (without running it) to trace whether untrusted input reaches a dangerous spot.
- **Sandbox** — a sealed container where untrusted code can't touch anything else.
- **Pull request (PR)** — a proposed code change a developer reviews before merging.
- **Regression** — a bug that was fixed and came back.
- **LLM** — a large language model, the AI that reads and writes code.

---

## 12. Last-Minute Checklist

### Tonight
- [ ] **Full rehearsal run** end-to-end on a fresh vulnerable repo; time scan / verify / fix.
- [ ] **Reset the demo repo.** `pentest-demo2` is single-use — once the PR is merged, the bug is gone. Either make a fresh copy (e.g. `pentest-demo3`) from the original vulnerable commit, or keep one unused repo per demo slot. `[TODO: decide how many live demos you'll run tomorrow]`
- [ ] Check API credit/quota: **Gemini key** and **OpenRouter key** have balance.
- [ ] Check GitHub sign-in still works in the browser you'll use; GitHub token connected.
- [ ] Docker Desktop starts cleanly; sandbox stack and app both come up. `[TODO: write the exact start commands on a sticky note]`
- [ ] Record a **screen video** of a full successful run (backup).
- [ ] Save screenshots to the laptop **and** a phone.
- [ ] Open `/demo` once to confirm the offline backup works.
- [ ] Print the **A3 poster** (add batch number + group photo first). `[TODO: confirm print shop / borderless print]`
- [ ] Each member rehearses the 30-s and 2-min pitch out loud once; assign roles.
- [ ] Charge laptop, phone, power bank.

### Tomorrow morning
- [ ] Arrive early; test **venue Wi-Fi** — scans need internet (GitHub, Gemini, OpenRouter). Have a **phone hotspot** ready.
- [ ] Start Docker Desktop → sandbox → app; sign in; open dashboard, `pentest-demo`, and `/demo` in separate tabs.
- [ ] Disable sleep / screen lock and notifications on the laptop.
- [ ] One dry run of steps 1–3 of the demo.
- [ ] Put up poster and QR code.

### Carry
Laptop + charger · extension board · phone + hotspot · power bank · HDMI adapter (if a monitor is provided) · printed poster · printed Quick Card · college ID cards · project report copy · pen + sticky notes · water.

---

## 13. One-Page Quick Card

**PentestAI — Find it. Prove it. Fix it. Confirm it's gone.**

**3 selling points**
1. **Closes the loop** — scan → verify → fix PR → rescan → resolved (and regressions reopen).
2. **Fixes are re-tested twice** before a PR exists — or no PR is opened.
3. **Evidence over opinion** — high/critical findings re-checked by CodeQL in a no-internet sandbox.

**3 impact lines**
- Security checks for teams with **no security engineer**.
- Leaked keys and injection bugs caught **before release**.
- Teaches students secure coding **on their own code**.

**"Why should we choose this?"**
> "Because it doesn't stop at a list of maybes. It proves which issues are real, delivers a fix that already passed its own re-test, and confirms after you merge that the vulnerability is actually gone."

**Key numbers:** 18 files/scan · 4 severities · 2 re-scans per fix · 3 attempts · resolve after 2 misses (1 if PR merged) · 206 tests · demo: High SQLi → resolved → Secure 95.

**If stuck:** "Good question — we haven't measured that yet; here's what we do know…"

**Closing line:**
> **"Other tools tell you what might be wrong. PentestAI proves it, fixes it, and makes sure it stays fixed."**
