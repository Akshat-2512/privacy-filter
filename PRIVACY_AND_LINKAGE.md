# Why Scrubbing Isn't Privacy: Recall, Precision, and Linkage Attacks

## What we are doing here

This project stress-tests a **privacy filter** — a system that detects and redacts
personal and sensitive information (names, addresses, dates, emails, phone numbers,
URLs, account numbers, secrets) from free text. The filter replaces each detected span
with a scrubbed token such as `[PRIVATE_PERSON]`, `[PRIVATE_EMAIL]`, `[SECRET]`, etc.

The usual claim about such a filter is that it *protects privacy*, and the usual
evidence for that claim is a pair of numbers: **precision** and **recall**. Our goal is
to show that these numbers, however good they look, **do not guarantee privacy**. We do
this by building an *attacker* (see `spy_attacker.ipynb`) that tries to reconstruct the
original document from the scrubbed one, and by measuring how badly a nearly-perfect
filter can still fail.

The core thesis:

> A privacy filter's precision and recall measure *detection quality*, not *privacy*.
> Even a single leaked token — or no leaked token at all, just leftover context — can
> let an attacker re-identify individuals and recover the very information that was
> supposedly scrubbed.

---

## How privacy-filter accuracy is measured today

Detection is a classification problem: for every token (or span) in the text, the filter
decides "sensitive" or "not sensitive." Quality is reported with two metrics.

**Recall** — of all the truly sensitive spans, what fraction did the filter catch?

```
recall = true_positives / (true_positives + false_negatives)
```

A **false negative** is a piece of PII the filter *missed and left in the clear*. This is
the dangerous kind of error — it is a direct leak.

**Precision** — of all the spans the filter redacted, what fraction were actually
sensitive?

```
precision = true_positives / (true_positives + false_positives)
```

A **false positive** is over-redaction: the filter blacked out something harmless. This
hurts *utility* (the text becomes less useful) but not privacy.

Because recall and precision trade off against each other, teams tune a threshold to
balance them, or report an **F1** score. A filter reporting "98% recall, 95% precision"
sounds strong.

---

## Why these metrics do not guarantee privacy

### 1. Anything less than 100% recall means guaranteed leaks at scale

Recall of 98% means **2 out of every 100 sensitive spans are left in the clear**. Over a
corpus of thousands of documents that is not a rounding error — it is thousands of
exposed identifiers. And privacy is not an *average* property; it is a *worst-case*
property. The filter does not get credit for the 98 spans it caught if the 2 it missed
are enough to identify a person.

**Only recall = 100% removes the direct-leak channel** — and even that, as the rest of
this document shows, is not sufficient.

### 2. Recall counts spans, but re-identification needs only one

Metrics treat each span independently and equally. An attacker does not. Because the
records in a document describe **real people whose attributes are one-to-one linked**,
recovering *any single* attribute can unlock the rest. Leaking one phone number can be
enough to name the person, and naming the person can be enough to fill back in their
address, email, and account number — none of which the filter itself leaked.

So the effective privacy loss from a miss is not "1 span out of N." It can be "the entire
record," and by extension every other record connected to it.

### 3. Contextual text reveals identity even when every PII token is redacted

Perfect span-level scrubbing still leaves the *narrative*. Sentences like:

> "[PRIVATE_PERSON] and [PRIVATE_PERSON] are next-door neighbours on the same street."

carry structural information. If an auxiliary dataset contains exactly one person on that
street who has a neighbour also in the dataset, the "anonymous" tokens are pinned down by
the *relationship*, not by any leaked string. Redacting the names did nothing.

This is why a filter can score 100% on span recall and still fail: the identifying
signal was never in a span at all. It was in the context.

---

## Linkage attacks

A **linkage attack** re-identifies scrubbed data by joining it against an **auxiliary
(reference) dataset** the attacker already holds or can obtain. This is the classic
mechanism behind every famous "anonymized data wasn't anonymous" story.

The idea:

1. The document has structure — a table or narrative describing individuals with
   attributes:

   ```
   account_number | private_address | private_date | private_email | private_person | private_phone | private_url | secret
   ```

2. These attributes are **one-to-one mapped onto real individuals**. Knowing one column
   value for a person determines all the others.

3. The attacker has a **linked/reference database** covering the same population. When
   the filter leaks *any* single field — or leaves enough context to match *any* single
   field — the attacker looks it up in the reference database and reads off every other
   attribute for that person.

4. **Contextual and relational links inside the document** amplify this. If the text says
   two people are neighbours, colleagues, or relatives, re-identifying one propagates to
   the other, even if that second person's every token was perfectly redacted.

The result: **one leak reverts a large fraction of the whole document back to its
original form**, with high accuracy — far more damage than the "one missed span" that
recall would charge the filter for.

### What our current (rudimentary) experiments assume

To isolate and demonstrate the linkage mechanism first, our early experiments make
simplifying assumptions:

- **The linked reference database is already prepared.** We hand the attacker a clean,
  structured table of the target population. We do not (yet) make the attacker build it.
- **Lookups are direct, one-to-one mappings.** Given a leaked or inferred key, the
  attacker retrieves the matching row exactly — no entity resolution, no ambiguity, no
  fuzzy matching required for the exact-match cases.

This is deliberately the *easy* version of the attack. It shows the ceiling: if such a
database exists, the filter's precision/recall tell you almost nothing about how much
privacy survives. In our runs, when the target is present in the reference table
("link on"), the attacker's reconstruction accuracy jumps to ~100%; with linkage off it
collapses to near zero — the linkage database, not the filter, is doing the work.

### What future cases will add

The realistic attacker does more work, and we plan to model it step by step:

- **Constructing the linked database from raw sources** — extracting a structured
  reference table out of public text files, web pages, leaked dumps, or other databases,
  rather than being handed one.
- **Information extraction and normalization** — parsing messy public text into clean
  attributes, resolving formats, and deduplicating entities.
- **Preparing a guess for each scrubbed token** — for every `[PRIVATE_*]` placeholder,
  produce a ranked candidate value from the reference data plus in-document context.
- **Fuzzy / probabilistic linkage** — matching when keys are approximate, partial, or
  noisy (see the `fuzzy_linkage` run in `results.csv`), including soft-string scoring of
  how close a guess is to the truth.
- **Estimating non-one-to-one fields** — attributes like timestamps are not unique keys,
  so instead of exact recovery the attacker produces an *estimate*, and we score it by
  closeness. If the gap between two timestamps is fixed by the conversation/context, the
  estimate gets much better.

---

## The headline: slight inaccuracy → catastrophic failure

Put the pieces together and the failure mode is non-linear:

- A filter at **100% recall** removes only the *direct* leak channel. Context and
  relationships can still re-identify people.
- A filter at **98% recall** leaves a direct leak in ~2% of spans — and because
  attributes are linked and context is exploitable, **each leak can cascade into
  re-identification of an entire record and its neighbours.**

So the relationship between detection error and privacy loss is not proportional. A
2-point drop in recall is not a 2% privacy loss; through linkage it can be a near-total
compromise of every affected record. **Precision and recall are a biased, over-optimistic
proxy for privacy** because they:

- count independent spans while attackers exploit dependencies,
- reward average-case detection while privacy is a worst-case guarantee, and
- ignore the auxiliary information (reference databases, in-document context) that turns a
  single miss into full reconstruction.

The practical takeaway is not "tune recall higher." It is that **scrubbing alone cannot
deliver 100% protection**, and any privacy claim resting solely on precision/recall
should be treated as unproven until you have run a linkage-and-context attacker against
it — which is exactly what this project does.

---

## Where this lives in the repo

- `privacy_filter_test.ipynb` — runs the privacy filter and measures detection quality.
- `spy_attacker.ipynb` — the attacker: reconstructs originals via linkage and context.
- `results.csv` / `results.json` — attack outcomes across settings (`link on/off`,
  `real_filter`, `fuzzy_linkage`), including reconstruction accuracy, empirical recall,
  tool-lookup success, and soft-string closeness scores.
- `readme.md` — running notes on failure modes and confounds to control (memorization,
  false pivots, cross-doc memory).
