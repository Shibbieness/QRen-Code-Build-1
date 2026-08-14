# Attribution

Short version: **keep the credit line where a user can find it.** If you're
big and commercially licensed, put it somewhere people actually see.

The canonical credit line is:

```
Built on QRen Coder — © Shibbieness / M MAOU LLC
```

## If you're using the free (AGPL-3.0) license

This is an **additional term under AGPL-3.0 §7(b)**, which expressly permits
a license to require "preservation of specified reasonable legal notices or
author attributions."

You must preserve the credit line in at least one of the places a user would
reasonably look:

- an About box, credits screen, or `--version` / `--about` output;
- an `/about`, `/credits`, or equivalent page for a network service;
- the README, docs, or a `NOTICE`/`THIRD-PARTY` file shipped with the work;
- the source file headers, if you're redistributing source.

That's the whole obligation. You do **not** owe a splash screen, a
watermark, a mention in your marketing, or a link on your homepage. Removing
or obscuring the notice is the only thing that breaks it.

This term is intentionally small so it stays GPL-compatible and doesn't make
QRen Coder awkward to depend on.

## If you're commercially licensed

A commercial license waives AGPL's copyleft (share-alike) obligation. In
exchange, the credit obligation gets larger and more visible — the trade the
maintainer is asking for is: *you don't have to open your source, but you do
have to say whose foundation you built on.*

Intended shape (placeholder figures, see caveat below): for a commercially
licensed product generating over **USD $1,000,000/year gross revenue**, the
credit must appear somewhere the public encounters it — product credits, an
end-of-reel or closing-credits equivalent, a "powered by" line in the
footer, the app store listing, or the documentation landing page. Roughly
the way a film credits its vendors or a brand credits a licensed
technology — visible, but not the headline.

Below that threshold, the free-tier requirement above is all that applies.

Exact wording, placement, threshold, and duration are settled in the
commercial agreement itself, not here. See `LICENSE-COMMERCIAL.md`.

## Why it's split this way

This split is deliberate and worth understanding before changing it.

AGPL §7 allows a licensor to add supplemental terms, but only from a
short enumerated list. Attribution/notice preservation (§7(b)) is on that
list. A **revenue-triggered marketing-credit requirement is not.** Bolting
one onto the free license would push QRen Coder out of GPL compatibility
and into "badgeware" — the category of licenses (SugarCRM's old Exhibit B,
Socialtext, and similar) that drew sustained criticism, were treated with
suspicion by the OSI, and made those projects meaningfully harder for others
to adopt.

Putting the larger credit obligation in the **commercial** license avoids all
of that, because a commercial license is a private contract: the maintainer
can require essentially any reasonable term there, and the party agreeing to
it is a paying company that negotiated it, not a student who cloned a repo.

The result is what was actually wanted — small projects and individuals just
keep a notice; large money-making products give real visible credit — without
compromising the open-source side.

## Not legal advice

None of this has been reviewed by an attorney. §7(b) additional terms and
revenue-triggered contract obligations are both areas where homemade wording
causes real problems. Have a lawyer review this and
`LICENSE-COMMERCIAL.md` before enforcing either against anyone.

---

## Authorship inside this repository

Distinct from everything above, which is about how *downstream users* credit
this project. This section is about how commits here are attributed.

**Author of record is Shibbieness.** The work is his, directed by him, and
owned by M MAOU LLC.

**AI co-authorship is credited by name, in the commit body:**

```
Built by Claude. Direction and ownership: Shibbieness · M MAOU LLC.
```

A plain sentence — not a `Co-Authored-By:` trailer, and no email address.

**No vendor addresses. No links to chat sessions.** Both were present across
this history and have been removed; `tools/leakguard.py --history` now checks
for them, and a `commit-msg` hook refuses them before they land.

### Why

The model provider is a service that is paid for. It is not an employer, a
partner, or a contributor. A `Co-Authored-By:` trailer carrying a company's
address is a machine-readable assertion that the company contributed — git
and GitHub both treat it that way — and no agreement supports that assertion.
Attribution is not consideration, and a paid subscription does not purchase a
byline on the subscriber's work.

The credit to the assistant stays, because that part is true. What goes is
the company address attached to it, which was never a statement about who
wrote anything.
