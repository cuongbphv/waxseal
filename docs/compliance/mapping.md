# Compliance mapping — what waxseal evidences, and what it does not

*[Tiếng Việt](mapping.vi.md)*

**Read this first.** waxseal is an integrity and evidence layer. It can produce technical
evidence that *supports* a record-keeping, traceability, or log-integrity obligation. It
does **not** make any organisation compliant with anything, and no row in the tables below
should be read as "this requirement is met". Whether an obligation is satisfied depends on
governance, scope, policy, controls, and legal interpretation that live entirely outside
this library, and is a determination for the deploying institution's compliance and legal
functions.

Nothing here is legal advice. This document names no institution, product, or person.

### How the tables are labelled

| Label | Meaning |
|---|---|
| **Direct** | waxseal produces evidence that speaks to this requirement's substance |
| **Partial** | waxseal covers part of it; the rest is organisational or out of scope |
| **Out of scope** | listed so nobody assumes it is covered — it is not |

Every clause quoted below was retrieved from the source named in
[§8 Sources and verification](#8-sources-and-verification) on 2026-08-23. Where a claim
could not be verified against a primary or official source, it is labelled
`[Unverified]` inline and should be checked before use.

---

## 1. What waxseal actually produces

Before mapping anything, this is the complete list of evidence primitives. Every "Direct"
below reduces to one of these.

| Primitive | Evidence it produces | Where |
|---|---|---|
| Hash chain over `EntryHeader` | a record existed at position *n*, in this order, unaltered since | `domain/chain.py` |
| Schema fingerprint | which field tuple a row was signed under; unknown → *unverifiable*, never *tampered* | `domain/fingerprint.py` |
| `DecisionRecord` | AI system id, model name/version/digest, outcome, rationale, policy version, confidence, human-oversight mode | `domain/decision.py` |
| `input_commitment` | the input the model saw, committed by hash after redaction, not stored | `sources/decisions.py` |
| Redact-before-hash | secrets never reach disk in cleartext | `adapters/redactors.py` |
| Merkle checkpoint + anchor | a root published to another trust domain before an edit could occur | `domain/anchoring.py` |
| Forward-secure seal | a suffix rewrite or truncation is detectable with an escrowed key | `domain/sealing.py` |
| Proof bundle | one decision, checkable offline, without disclosing the rest of the log | `domain/export.py` |
| `dropped_writes` | a **measured minimum** of writes that failed; `None` = not measured | `adapters/drops.py` |
| Audit report | the above, plus explicit *not checked* for anything not run | `domain/report.py` |

---

## 2. EU AI Act — Regulation (EU) 2024/1689

### Applicability first

Annex III point 5(b) makes high-risk "AI systems intended to be used to evaluate the
creditworthiness of natural persons or establish their credit score, **with the exception
of AI systems used for the purpose of detecting financial fraud**".

That exception matters and is easy to over-read in the deploying institution's favour or
against it. The AML/fraud-screening use case in the [PoC](../../examples/banking-poc/README.md)
sits in the excepted category on a plain reading, and credit scoring does not. Determining
which category a given system falls into is a legal question, not a technical one — the
tables below apply where the Act applies.

### Article 12 — Record-keeping

> **12(1)** "High-risk AI systems shall technically allow for the automatic recording of
> events (logs) over the lifetime of the system."
>
> **12(2)** "…logging capabilities shall enable the recording of events relevant for:
> (a) identifying situations that may result in the high-risk AI system presenting a risk
> within the meaning of Article 79(1) or in a substantial modification; (b) facilitating
> the post-market monitoring referred to in Article 72; and (c) monitoring the operation of
> high-risk AI systems referred to in Article 26(5)."

| Clause | Coverage | What waxseal provides | What is still needed |
|---|---|---|---|
| 12(1) automatic recording over the lifetime | **Partial** | an append-only chain that records each decision event with its own integrity evidence; nothing in the library deletes | *which* events get recorded is the integration's decision, not the library's; "over the lifetime" is a retention and rotation programme |
| 12(2)(a) events relevant to risk identification | **Partial** | outcome, rationale, confidence, policy version and model version are all in the record, so a shift is attributable to a version | the risk taxonomy and the detection of "substantial modification" are organisational |
| 12(2)(b) facilitating post-market monitoring (Art. 72) | **Direct** | `waxseal report --json` is a queryable, integrity-checked feed by decision type, oversight mode and model version | the monitoring plan itself |
| 12(2)(c) monitoring operation per Art. 26(5) | **Partial** | `human_oversight` is recorded per decision, with *not recorded* distinguished from *automated* | the oversight process being real |
| 12(3) minimum logging for Annex III point 1(a) | **Out of scope** | — | 12(3) is specific to biometric systems (period of use, reference database, matched input, verifying persons); the `DecisionRecord` field set is not built for it |

### Article 19 — Automatically generated logs (providers)

> "Providers of high-risk AI systems shall keep the logs referred to in Article 12(1),
> automatically generated by their high-risk AI systems, to the extent such logs are under
> their control. Without prejudice to applicable Union or national law, the logs shall be
> kept for a period appropriate to the intended purpose of the high-risk AI system, of at
> least six months, unless provided otherwise in the applicable Union or national law, in
> particular in Union law on the protection of personal data.
>
> Providers that are financial institutions subject to requirements regarding their
> internal governance, arrangements or processes under Union financial services law shall
> maintain the logs automatically generated by their high-risk AI systems as part of the
> documentation kept under the relevant financial services law."

| Aspect | Coverage | Note |
|---|---|---|
| Logs kept, unaltered, for the period | **Partial** | append-only by construction, so nothing is lost to the library's own behaviour; **waxseal does not enforce retention** and has no expiry mechanism |
| Integrity of the retained logs | **Direct** | this is the whole library. Art. 19 does not itself demand tamper-evidence, but a log that cannot be shown unaltered is weak evidence of anything |
| Financial-institution documentation route | **Out of scope** | which documentation regime absorbs the logs is a legal determination |

### Article 26(6) — Deployer log retention

> "Deployers of high-risk AI systems shall keep the logs automatically generated by that
> high-risk AI system to the extent such logs are under their control, for a period
> appropriate to the intended purpose of the high-risk AI system, of at least six months,
> unless provided otherwise in applicable Union or national law".

Same coverage as Art. 19. The operationally useful point is "**to the extent such logs are
under their control**": a deployer running the agent tier controls the decision log even
when the model is a third party's, so this is precisely the layer a deployer can own. The
[reference architecture](../architecture/banking-deployment.md#6-retention-dr-and-capacity)
covers chain rotation as the retention mechanism.

### Tension: append-only vs. erasure

Art. 19 subordinates retention to "Union law on the protection of personal data". An
append-only chain cannot delete a payload without breaking the evidence it exists to
provide. waxseal's answer is that **nothing personal should enter a payload**:
`subject_ref` and `reviewer_ref` are documented as pseudonymous references into systems
that can delete. This is a design constraint on the integration, and getting it wrong is
not recoverable after the fact.

---

## 3. NIST AI RMF 1.0 (AI 100-1)

Subcategory text below is quoted from the NIST AI RMF Playbook.

| Subcategory | Text | Coverage | What waxseal provides |
|---|---|---|---|
| GOVERN 1.4 | "The risk management process and its outcomes are established through transparent policies, procedures, and other controls…" | **Partial** | `policy_version` on every decision makes "which policy was in force for this decision" answerable after the fact |
| GOVERN 1.6 | mechanisms inventory AI systems | **Partial** | `system_id` and the report's inventory-by-fingerprint give a usage-derived inventory, not a governance register |
| GOVERN 4.2 | "Organizational teams document AI risks and potential impacts and communicate findings broadly" | **Partial** | `report --json` is a durable, integrity-checked artefact to communicate from |
| GOVERN 6.1 | third-party AI risk policies | **Partial** | model name/version/**digest** pins exactly which third-party artefact produced a decision |
| MEASURE 2.4 | "The functionality and behavior of the AI system and its components are monitored when in production" | **Direct** | the decision log *is* the production behaviour record; counts by decision type and outcome are in the report |
| MEASURE 2.8 | "Risks associated with transparency and accountability are examined and documented" | **Direct** | accountability requires a record that cannot be quietly revised; that is the library's function |
| MEASURE 2.9 | "The AI model is explained, validated, and documented, and AI system output is interpreted within its context" | **Partial** | `rationale` and `input_commitment` capture the per-decision context; explanation quality is the model's problem |
| MANAGE 4.1 | "Post-deployment AI system monitoring plans are implemented…" | **Partial** | supplies the monitoring substrate; the plan is organisational |
| MANAGE 4.3 | "Incidents and errors are communicated to relevant AI actors; tracking and recovery processes documented" | **Direct** | a decision under investigation can be extracted as a proof bundle and shown intact independently of the operator holding the log |

**NIST AI 600-1 (Generative AI Profile).** [Unverified] — the GenAI Profile's specific
action identifiers were not retrieved for this document. The traceability and provenance
actions in it are the relevant ones; check them directly before citing.

---

## 4. DORA — Regulation (EU) 2022/2554 and its RTS

The closest fit in the DORA family is not the Regulation itself but **Commission Delegated
Regulation (EU) 2024/1774, Article 12 (Logging)** — the RTS on ICT risk management tools,
methods, processes and policies.

| Requirement (RTS Art. 12) | Coverage | What waxseal provides |
|---|---|---|
| "measures to protect logging systems and log information against **tampering, deletion, and unauthorised access** at rest, in transit, and, where relevant, in use" | **Direct** for tampering and deletion | the chain detects alteration; anchoring detects a consistent whole-log rewrite; forward-secure seals detect truncation. **Not** access control or encryption — those are the deployment's, not the library's |
| "measures to **detect a failure of logging systems**" | **Partial** | `dropped_writes` measures exactly this failure mode, and reports `None` when it was not measured rather than implying zero. It is a measured minimum: a sidecar can itself be lost |
| retention periods set from business, security, and risk-assessment considerations | **Out of scope** | waxseal does not expire anything |
| "synchronisation of the clocks … upon a documented reliable reference time source" | **Out of scope** | **waxseal's `ts` is supplied by the caller** (`now_fn` is injectable, deliberately, so tests never sleep). It is a recorded assertion of time, not attested time. For attested time, anchor to an RFC 3161 TSA — the timestamp then comes from the TSA, not from the writing host |

DORA Art. 10(1)/(3) (detection of anomalous activity, monitoring of user activity) are
**Partial**: an integrity-verified decision log is a detection input, but waxseal raises no
alerts of its own beyond the verifier's exit codes.

---

## 5. Model risk management — SR 11-7 and successors

SR 11-7 / OCC Bulletin 2011-12, *Supervisory Guidance on Model Risk Management* (2011), is
the long-standing reference. **[Unverified]** the Federal Reserve issued **SR 26-2,
"Revised Guidance on Model Risk Management"**, and the OCC issued a corresponding 2026
bulletin; the listing was confirmed but the revised text was not retrieved, and whether it
supersedes SR 11-7 in whole or in part was not verified. Check which guidance applies
before relying on this section.

Against SR 11-7's themes:

| Theme | Coverage | What waxseal provides |
|---|---|---|
| Model inventory | **Partial** | `system_id` + model name/version/digest per decision yields a *usage-derived* inventory — what actually ran, as opposed to what the register says should have run. Reconciling the two is a genuinely useful control |
| Documentation sufficient for an independent party to understand what was done | **Partial** | per-decision provenance, not model development documentation |
| Effective challenge / independent validation | **Partial** | validation needs an unimpeachable record of what production actually decided; a log the model owner can revise cannot support challenge. Separation of duties in the [architecture](../architecture/banking-deployment.md#3-separation-of-duties) is the part that makes this real |
| Ongoing monitoring and outcomes analysis | **Partial** | supplies the outcome record; the analysis is the institution's |
| Change control over model versions | **Partial** | a version change is visible in the log the moment the first decision under it is written |

---

## 6. SOC 2 (AICPA Trust Services Criteria)

The AICPA criteria are not reproduced verbatim here (they are not openly published). The
identifiers below are used descriptively; **[Unverified]** against the official TSC text.

| Criterion | Area | Coverage |
|---|---|---|
| CC4.1–CC4.2 | monitoring activities | **Partial** — scheduled verification produces evidence that a control operated, with an exit code per run |
| CC7.2 | detection and monitoring of system events | **Partial** — the trail is monitored evidence; alerting is the deployment's |
| CC7.3–CC7.4 | evaluating and responding to security events | **Partial** — exit 1 is an incident signal with a specific sequence number and reason; exit 2 explicitly is not an incident |

The strongest SOC 2 argument for this layer is not any single criterion — it is that the
evidence a service auditor samples can be shown to be the evidence that was produced at the
time, rather than an export generated afterwards by the party being audited.

---

## 7. Vietnam — digital asset market pilot

**Resolution 05/2025/NQ-CP** (9 September 2025), piloting the digital asset market for
five years, at **Điều 15(2)(l)** requires service providers to:

> "Lưu trữ trên hệ thống máy chủ tại Việt Nam tối thiểu 10 năm về lịch sử giao dịch, thông
> tin về người khởi tạo, người thụ hưởng (tối thiểu tên, địa chỉ, địa chỉ ví), lịch sử địa
> chỉ thiết bị đăng nhập hoặc địa chỉ giao thức Internet…"
>
> *(Store on server systems in Vietnam, for a minimum of 10 years, transaction history and
> information on the originator and beneficiary (at minimum name, address, wallet address),
> and the history of login device addresses or IP addresses…)*

This wording was confirmed identically on a government portal and a commercial legal
database, but **not** against the official gazette text — treat the clause numbering as
verified-by-two-secondary-sources rather than primary.

| Aspect | Coverage | Note |
|---|---|---|
| 10-year retention on servers in Vietnam | **Out of scope** | a deployment and data-residency decision. waxseal's backends run wherever they are deployed and expire nothing |
| Integrity of what is retained | **Direct** | the Resolution requires storage, not tamper-evidence. Tamper-evident storage is a **stronger** posture than the text demands — present it that way, not as a requirement it imposes |
| Originator/beneficiary names and addresses | **Conflict** | the Resolution requires *identifying* data; waxseal requires payloads to be *pseudonymous* because a chain cannot delete. Resolve by keeping the identity store separate and referencing it by `subject_ref` — the chain then evidences the decision, and the identity store satisfies the retention duty |

**Decision 96/QĐ-BTC** (20 January 2026) publishes the new administrative procedures
(licensing, amendment, revocation) implementing Resolution 05/2025/NQ-CP. It concerns
licensing procedure, **not** audit-trail or logging requirements, and is listed here only
so it is not assumed to impose one.

`[Unverified]` Level-4 information-system security certification is reported as required by
Điều 8(7) of the Resolution; the clause number was not confirmed against a primary source.

---

## 8. Sources and verification

Retrieved 2026-08-23:

| Source | Used for | Status |
|---|---|---|
| [EU AI Act Art. 12](https://artificialintelligenceact.eu/article/12/), [Art. 19](https://artificialintelligenceact.eu/article/19/), [Art. 26](https://artificialintelligenceact.eu/article/26/), [Annex III](https://artificialintelligenceact.eu/annex/3/) | verbatim clause text | retrieved; **unofficial reproduction** of Reg. (EU) 2024/1689 — confirm against EUR-Lex before formal use |
| [NIST AI RMF Playbook — Govern](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Govern), [Measure](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Measure), [Manage](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Manage) | subcategory identifiers and text | retrieved from NIST |
| [Commission Delegated Reg. (EU) 2024/1774](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774) | RTS Art. 12 (Logging) | retrieved from EUR-Lex (official) |
| [DORA Art. 10](https://www.digital-operational-resilience-act.com/Article_10.html) | detection provisions | unofficial reproduction |
| [Fed SR letters 2026](https://www.federalreserve.gov/supervisionreg/srletters/2026.htm) | existence and title of SR 26-2 | listing confirmed; **text not retrieved** |
| [Resolution 05/2025/NQ-CP full text](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-quyet-so-5-2025-nq-cp-ve-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-119250909184045221.htm) and [luatvietnam](https://luatvietnam.vn/tai-chinh/nghi-quyet-05-2025-nq-cp-cua-chinh-phu-ve-viec-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-410830-d1.html) | Điều 15(2)(l) | two concurring secondary sources; not the gazette |
| [Decision 96/QĐ-BTC](https://luatvietnam.vn/hanh-chinh/quyet-dinh-96-qd-btc-2026-cong-bo-thu-tuc-hanh-chinh-moi-ve-thi-truong-tai-san-ma-hoa-424349-d1.html) | scope (administrative procedures only) | secondary source |
| ISO/IEC 42001 | — | **not retrieved** — the standard is not openly published. No clause identifiers are cited in this document, deliberately |
| AICPA Trust Services Criteria | CC identifiers | **not retrieved** — used descriptively only |

---

## 9. Honest gap analysis — what waxseal does **not** do

Stated plainly, because a mapping document is exactly where over-claiming happens.

| Not provided | Why it matters |
|---|---|
| **Governance** | no risk taxonomy, no approval workflow, no roles, no policy engine. A perfectly verified log of an ungoverned system evidences ungoverned decisions faithfully |
| **Access control** | the library never authenticates or authorises. Who may read the trail is entirely the deployment's problem |
| **Encryption at rest / in transit** | not provided (`RemoteBackend` uses whatever TLS the URL implies). Integrity ≠ confidentiality |
| **Retention enforcement** | nothing expires, nothing is deleted. Minimum-retention duties are helped; maximum-retention and erasure duties are made *harder* |
| **Data residency** | wherever the backend runs |
| **Model documentation, validation, bias testing, explainability** | entirely outside. The log records what a model decided, never whether it should have |
| **Trusted time** | `ts` is asserted by the caller, not attested. Anchor to an RFC 3161 TSA if attested time is needed |
| **Trail completeness** | integrity ≠ completeness. A decision never written leaves no gap. `dropped_writes` is a measured minimum, and `None` means not measured |
| **Tamper-proofing** | tamper-**evident** only. An attacker with write access can rewrite the trail; anchoring and forward-secure seals bound that, and only if they live under a different authority |
| **A compliance verdict** | no output of this library asserts that any obligation is met, and none should be quoted as if it did |

---

## 10. If you take one thing from this document

The claim worth making to a reviewer is narrow and defensible:

> *This decision was recorded at this position, under this model version and this policy
> version, with this human-oversight status, and can be shown to be unaltered since —
> independently of the party that holds the log, and without disclosing any other
> decision.*

Everything broader than that sentence is somebody else's control.
