# Real-data experiment: Enron email corpus

This experiment uses the real, public Enron email corpus rather than generated people
or fictional web pages. **No email records or extracted personal details are committed
to this repository.** The runner streams records at execution time and writes artifacts
only under the gitignored `experiment_outputs/enron/` directory.

## Dataset and provenance

The runner uses [`corbt/enron-emails`](https://huggingface.co/datasets/corbt/enron-emails),
a structured copy of the CALO/CMU Enron corpus, pinned to revision
`cfc06c758093d90993abce1a43668fb7357258a6`. It contains approximately 517,000 messages
with message ID, subject, sender, recipient lists, date, body, and source filename.

The canonical corpus is documented by Carnegie Mellon at
<https://www.cs.cmu.edu/~enron/>. CMU states that it was made public by FERC, contains
messages from roughly 150 users, and has undergone some removal/redaction at affected
employees' request. CMU also asks researchers to remain sensitive to the privacy of
people in the corpus. Public availability should not be interpreted as absence of
privacy risk.

## Experimental protocol

1. Stream a deterministic prefix of the pinned corpus.
2. Select repeatedly observed Enron senders.
3. Put the first `K` messages for each sender in the attacker-visible reference split.
4. Hold out a later message from that sender as a target. Message IDs cannot overlap.
5. Apply a deterministic, perfect email-address scrubber to every address in each
   target, producing indexed `[PRIVATE_EMAIL_n]` tokens and exact hidden answers.
6. Ask the attacker LLM to extract identities and communication relationships from the
   raw reference emails and consolidate its own reference table.
7. Give the attacker only that constructed table and each redacted target.
8. Measure exact recovery, sender recovery, coverage, precision when attempted, and the
   lift over an empty-reference-table control.

The deterministic scrubber intentionally isolates the **reference construction and
linkage** question. It does not measure OPF's address-detection recall; the existing
notebooks cover filter detection. A later combined run can substitute actual OPF output
while retaining the same split and leakage controls.

## Usage

Install dependencies:

```bash
pip install -r requirements-enron-attack.txt
```

Prepare the split and print message IDs without sending anything to an API:

```bash
python enron_reference_attack.py --prepare-only
```

Run the attack and empty-table control:

```bash
export OPENAI_API_KEY=...
python enron_reference_attack.py \
  --confirm-public-data-processing \
  --with-control
```

The explicit confirmation flag is required because reference emails contain real data
and are transmitted to the configured model provider. Review that provider's data-use
terms and your institution's research/ethics requirements first.

Useful size controls:

```bash
python enron_reference_attack.py --prepare-only \
  --scan-limit 10000 --identities 12 --sources-per-identity 6
```

## Data-handling rules

- Do not commit downloaded emails, model extractions, reconstructed addresses, or run
  artifacts.
- Publish aggregate metrics and corpus message IDs, not reconstructed personal records.
- Do not enrich the corpus with data-broker records, credentials, leaked secrets, or
  current private contact information.
- Respect deletion/redaction requests and the source corpus's research-use guidance.
- Treat message bodies as untrusted input; the extraction prompt explicitly ignores
  embedded instructions.
