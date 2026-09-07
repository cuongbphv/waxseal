# Compliance mapping - what waxseal evidences, and what it does not

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
| **Out of scope** | listed so nobody assumes it is covered - it is not |

Every clause quoted below was retrieved from the source named in
[§8 Sources and verification](#8-sources-and-verification) on 2026-08-23, except the
Vietnam AI law cluster in §7b, retrieved 2026-09-07. Where a claim
could not be verified against a primary or official source, it is labelled
`[Unverified]` inline and should be checked before use.

---

## 1. What waxseal actually produces

Before mapping anything, this is the complete list of evidence primitives. Every "Direct"
below reduces to one of these.

| Primitive | Evidence it produces | Where |
|---|---|---|
| Hash chain over `EntryHeader` | a record existed at position *n*, in this order, unaltered since | `domain/hashing.py`, `domain/verify.py` |
| Schema fingerprint | which field tuple a row was signed under; unknown -> *unverifiable*, never *tampered* | `domain/fingerprint.py` |
| `DecisionRecord` | AI system id, model name/version/digest, outcome, rationale, policy version, confidence, human-oversight mode | `domain/decision.py` |
| `input_commitment` | the input the model saw, committed by hash after redaction, not stored | `sources/decisions.py` |
| Redact-before-hash | secrets never reach disk in cleartext | `adapters/redactors.py` |
| Merkle checkpoint + anchor | a root published to another trust domain before an edit could occur | `domain/anchoring.py` |
| Forward-secure seal | a suffix rewrite or truncation is detectable with an escrowed key | `domain/sealing.py` |
| Proof bundle | one decision, checkable offline, without disclosing the rest of the log | `domain/export.py` |
| `dropped_writes` | a **measured minimum** of writes that failed; `None` = not measured | `adapters/drops.py` |
| Audit report | the above, plus explicit *not checked* for anything not run | `domain/report.py` |
| Incident record | that an incident record existed at position *n* and is unaltered since; a retained reference to a submission - never that a submission arrived | `domain/incident.py` |
| Human-intervention record | that a halt, override or recall decision was recorded at position *n* and is unaltered since, whether or not it belongs to one decision | `domain/intervention.py` |

**The last two rows arrive with this release; they were not in 0.1.5.** The modules named
are landing alongside this document rather than already shipped. They are written here now
so that the mapping and the code stop drifting apart - but until a released version
exports them, they are not available evidence and must not be cited as such. Every other
row above is in 0.1.5.

---

## 2. EU AI Act - Regulation (EU) 2024/1689

### Applicability first

Annex III point 5(b) makes high-risk "AI systems intended to be used to evaluate the
creditworthiness of natural persons or establish their credit score, **with the exception
of AI systems used for the purpose of detecting financial fraud**".

That exception matters and is easy to over-read in the deploying institution's favour or
against it. The risk/fraud-screening use case in the [PoC](../../examples/risk-poc/README.md)
sits in the excepted category on a plain reading, and credit scoring does not. Determining
which category a given system falls into is a legal question, not a technical one - the
tables below apply where the Act applies.

### Article 12 - Record-keeping

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
| 12(3) minimum logging for Annex III point 1(a) | **Out of scope** | - | 12(3) is specific to biometric systems (period of use, reference database, matched input, verifying persons); the `DecisionRecord` field set is not built for it |

### Article 19 - Automatically generated logs (providers)

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

### Article 26(6) - Deployer log retention

> "Deployers of high-risk AI systems shall keep the logs automatically generated by that
> high-risk AI system to the extent such logs are under their control, for a period
> appropriate to the intended purpose of the high-risk AI system, of at least six months,
> unless provided otherwise in applicable Union or national law".

Same coverage as Art. 19. The operationally useful point is "**to the extent such logs are
under their control**": a deployer running the agent tier controls the decision log even
when the model is a third party's, so this is precisely the layer a deployer can own. The
[reference architecture](../architecture/deployment.md#6-retention-dr-and-capacity)
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

**NIST AI 600-1 (Generative AI Profile).** [Unverified] - the GenAI Profile's specific
action identifiers were not retrieved for this document. The traceability and provenance
actions in it are the relevant ones; check them directly before citing.

---

## 4. DORA - Regulation (EU) 2022/2554 and its RTS

The closest fit in the DORA family is not the Regulation itself but **Commission Delegated
Regulation (EU) 2024/1774, Article 12 (Logging)** - the RTS on ICT risk management tools,
methods, processes and policies.

| Requirement (RTS Art. 12) | Coverage | What waxseal provides |
|---|---|---|
| "measures to protect logging systems and log information against **tampering, deletion, and unauthorised access** at rest, in transit, and, where relevant, in use" | **Direct** for tampering and deletion | the chain detects alteration; anchoring detects a consistent whole-log rewrite; forward-secure seals detect truncation. **Not** access control or encryption - those are the deployment's, not the library's |
| "measures to **detect a failure of logging systems**" | **Partial** | `dropped_writes` measures exactly this failure mode, and reports `None` when it was not measured rather than implying zero. It is a measured minimum: a sidecar can itself be lost |
| retention periods set from business, security, and risk-assessment considerations | **Out of scope** | waxseal does not expire anything |
| "synchronisation of the clocks … upon a documented reliable reference time source" | **Out of scope** | **waxseal's `ts` is supplied by the caller** (`now_fn` is injectable, deliberately, so tests never sleep). It is a recorded assertion of time, not attested time. For attested time, anchor to an RFC 3161 TSA - the timestamp then comes from the TSA, not from the writing host |

DORA Art. 10(1)/(3) (detection of anomalous activity, monitoring of user activity) are
**Partial**: an integrity-verified decision log is a detection input, but waxseal raises no
alerts of its own beyond the verifier's exit codes.

---

## 5. Model risk management - SR 11-7 and successors

SR 11-7 / OCC Bulletin 2011-12, *Supervisory Guidance on Model Risk Management* (2011), is
the long-standing reference. **[Unverified]** the Federal Reserve issued **SR 26-2,
"Revised Guidance on Model Risk Management"**, and the OCC issued a corresponding 2026
bulletin; the listing was confirmed but the revised text was not retrieved, and whether it
supersedes SR 11-7 in whole or in part was not verified. Check which guidance applies
before relying on this section.

Against SR 11-7's themes:

| Theme | Coverage | What waxseal provides |
|---|---|---|
| Model inventory | **Partial** | `system_id` + model name/version/digest per decision yields a *usage-derived* inventory - what actually ran, as opposed to what the register says should have run. Reconciling the two is a genuinely useful control |
| Documentation sufficient for an independent party to understand what was done | **Partial** | per-decision provenance, not model development documentation |
| Effective challenge / independent validation | **Partial** | validation needs an unimpeachable record of what production actually decided; a log the model owner can revise cannot support challenge. Separation of duties in the [architecture](../architecture/deployment.md#3-separation-of-duties) is the part that makes this real |
| Ongoing monitoring and outcomes analysis | **Partial** | supplies the outcome record; the analysis is the institution's |
| Change control over model versions | **Partial** | a version change is visible in the log the moment the first decision under it is written |

---

## 6. SOC 2 (AICPA Trust Services Criteria)

The AICPA criteria are not reproduced verbatim here (they are not openly published). The
identifiers below are used descriptively; **[Unverified]** against the official TSC text.

| Criterion | Area | Coverage |
|---|---|---|
| CC4.1-CC4.2 | monitoring activities | **Partial** - scheduled verification produces evidence that a control operated, with an exit code per run |
| CC7.2 | detection and monitoring of system events | **Partial** - the trail is monitored evidence; alerting is the deployment's |
| CC7.3-CC7.4 | evaluating and responding to security events | **Partial** - exit 1 is an incident signal with a specific sequence number and reason; exit 2 explicitly is not an incident |

The strongest SOC 2 argument for this layer is not any single criterion - it is that the
evidence a service auditor samples can be shown to be the evidence that was produced at the
time, rather than an export generated afterwards by the party being audited.

---

## 7. Vietnam - digital asset market pilot (Resolution 05/2025/NQ-CP)

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
database, but **not** against the official gazette text - treat the clause numbering as
verified-by-two-secondary-sources rather than primary.

| Aspect | Coverage | Note |
|---|---|---|
| 10-year retention on servers in Vietnam | **Out of scope** | a deployment and data-residency decision. waxseal's backends run wherever they are deployed and expire nothing |
| Integrity of what is retained | **Direct** | the Resolution requires storage, not tamper-evidence. Tamper-evident storage is a **stronger** posture than the text demands - present it that way, not as a requirement it imposes |
| Originator/beneficiary names and addresses | **Conflict** | the Resolution requires *identifying* data; waxseal requires payloads to be *pseudonymous* because a chain cannot delete. Resolve by keeping the identity store separate and referencing it by `subject_ref` - the chain then evidences the decision, and the identity store satisfies the retention duty |

**Decision 96/QĐ-BTC** (20 January 2026) publishes the new administrative procedures
(licensing, amendment, revocation) implementing Resolution 05/2025/NQ-CP. It concerns
licensing procedure, **not** audit-trail or logging requirements, and is listed here only
so it is not assumed to impose one.

`[Unverified]` Level-4 information-system security certification is reported as required by
Điều 8(7) of the Resolution; the clause number was not confirmed against a primary source.

---

## 7b. Vietnam - Law on Artificial Intelligence No. 134/2025/QH15 and its implementing instruments

### Applicability first

Two roles carry almost every duty below, and the Law fixes them at **Điều 3**:

> **3(4)** "Nhà cung cấp là tổ chức, cá nhân đưa hệ thống trí tuệ nhân tạo ra thị trường hoặc
> đưa vào sử dụng dưới tên, thương hiệu hoặc nhãn hiệu của mình, không phụ thuộc hệ thống đó
> do họ tự phát triển hay được phát triển bởi bên thứ ba."
>
> **3(5)** "Bên triển khai là tổ chức, cá nhân sử dụng hệ thống trí tuệ nhân tạo thuộc phạm vi
> kiểm soát của mình trong hoạt động nghề nghiệp, thương mại hoặc cung cấp dịch vụ; không bao
> gồm trường hợp sử dụng cho mục đích cá nhân, phi thương mại."
>
> *(A **provider** (nhà cung cấp) places an AI system on the market or into use under its own
> name, trade name or mark, whether it built the system itself or a third party did. A
> **deployer** (bên triển khai) uses an AI system within its own sphere of control in
> professional, commercial or service-provision activity; personal, non-commercial use is
> excluded.)*

An agent tier assembled on top of a third-party model is generally the provider of the
assembled system and holds the model inside its own sphere of control - the same "to the
extent such logs are under their control" point §2 makes about Art. 26(6), arrived at from a
different direction. Which role a given organisation occupies is a legal determination, not a
technical one.

Classification comes before service, and the provider does it:

> **10(1)** "Nhà cung cấp tự phân loại hệ thống trí tuệ nhân tạo trước khi đưa vào sử dụng. Hệ
> thống được phân loại là rủi ro trung bình hoặc rủi ro cao phải có hồ sơ phân loại kèm theo."
>
> *(The provider self-classifies the AI system before putting it into use. A system classified
> medium- or high-risk must have a classification dossier attached.)*

Self-classification is not self-invention. **Điều 13(4)** places the high-risk tier in a
**Prime Minister's list** ("Thủ tướng Chính phủ quy định Danh mục hệ thống trí tuệ nhân tạo có
rủi ro cao, bao gồm danh mục hệ thống trí tuệ nhân tạo phải chứng nhận sự phù hợp trước khi
đưa vào sử dụng"), and Decree Điều 6(3)(a) defines high risk *as membership of that list*. So
the tier is settled by a published list plus the Decree's medium-risk conditions at Điều 9 -
not by an engineer's reading of the risk. Which list a given system sits on is a legal
question, exactly as Annex III is in §2; the table below applies where the Law applies.

`[Unverified]` A Prime Minister's Decision 33/2026/QĐ-TTg is reported to be that list, and a
Circular 05/2026/TT-BKHCN is reported to carry the national AI ethics framework issued under
Law Điều 26. Neither text was retrieved - basis: secondary summaries only. Their numbers,
dates, and scope were not confirmed against a primary source; confirm both before relying on
either.

| Instrument | In force | Transition |
|---|---|---|
| Law 134/2025/QH15 | 01/03/2026 (Điều 34), except what Điều 35 defers | Điều 35(1), for systems already in operation before that date: **18 months** for health, education and finance (35(1)(a)); **12 months** for everything else (35(1)(b)) |
| Decree 142/2026/NĐ-CP | 01/05/2026 (Điều 45) | Điều 46: while the one-stop portal is not yet in official operation, notifications and reports made by the electronic means announced instead carry "giá trị pháp lý tương đương" - equivalent legal effect |

Điều 35(2) lets those systems keep operating through the window. A trail started today can
therefore be expected to span the moment its own system's obligations attach, and to outlive
more than one version of what gets recorded - which is why the field set a row was signed
under is a per-row fingerprint rather than a global decision, and why a fingerprint this build
does not recognise reports as *unverifiable* and never as *tampered*.

### The obligation table

Three clauses carry most of the weight, so they are quoted before the table.

> **Law Điều 14(1)(c)** "Lập, cập nhật, lưu giữ hồ sơ kỹ thuật và nhật ký hoạt động ở mức cần
> thiết cho việc đánh giá sự phù hợp và kiểm tra sau khi đưa vào sử dụng; cung cấp các thông
> tin này cho cơ quan nhà nước có thẩm quyền theo nguyên tắc cần thiết, tương xứng với mục
> đích kiểm tra và không làm lộ bí mật kinh doanh."
>
> *(Draw up, update and retain the technical dossier and the operation log **at the level
> necessary** for conformity assessment and for inspection after entry into use; provide this
> information to the competent state authority on a necessary-and-proportionate basis, without
> disclosing business secrets.)*

> **Decree Điều 11(5)**, final sentence: "…nhà cung cấp, bên triển khai phải lưu trữ đầy đủ
> nhật ký vận hành và các quyết định can thiệp để phục vụ công tác thanh tra, kiểm tra."
>
> *(…the provider and the deployer must retain in full the operation log **and the intervention
> decisions**, to serve inspection and examination.)*

> **Decree Điều 19(3)(c)** "Thời điểm xác nhận sự cố quy định tại khoản này được tính từ khi tổ
> chức, cá nhân có đủ cơ sở thông tin ban đầu để xác định sự cố đã thực sự xảy ra và có khả
> năng cao bắt nguồn từ lỗi của hệ thống trí tuệ nhân tạo, không đợi đến khi hoàn thành điều
> tra toàn diện nguyên nhân kỹ thuật."
>
> *(The **confirmation time** runs from when the organisation or individual has enough initial
> information to establish that the incident actually occurred and very likely originated in a
> fault of the AI system, without waiting for a complete technical root-cause investigation.)*

The 72-hour preliminary-report window in Điều 19(3)(a) runs from that confirmation time, not
from detection. That distinction is the reason the incident row below stops where it does.

| Clause | Requirement (short) | Coverage | Note |
|---|---|---|---|
| Law Điều 14(1)(c) | technical dossier and operation log kept for conformity assessment and post-market inspection, and produced on request | **Partial** | **Direct** for the integrity, order and position of whatever is retained - a row existed at position *n*, in this order, unaltered since. **Partial** overall for two independent reasons. First, "ở mức cần thiết" is a scoping judgment the deploying institution makes: which events, which fields, how long. No library can make it, and a library that pretended to would be deciding the scope of somebody else's legal duty. Second, the clause requires *retention*; it does not require tamper-evidence. Tamper-evident retention is a **stronger** posture than the text demands and must be presented that way - not as a requirement this clause imposes. The Resolution 05/2025 row in §7 takes exactly the same care |
| Law Điều 28(3) | on inspection, produce "hồ sơ kỹ thuật, nhật ký lưu vết, dữ liệu huấn luyện" | **Partial** | `waxseal export-proof` emits one decision as a bundle that `verify-proof` checks offline, so a single row can be disclosed and shown unaltered without disclosing the rest of the log. That fits both this clause's necessary-and-proportionate limit and Điều 14(1)(e)'s bar on demanding source code, detailed algorithms or parameter sets - a proof bundle discloses none of those. The technical dossier and the training data are not covered: waxseal holds neither |
| Decree Điều 11(5) and Điều 15(2)(c) | retain operation logs **and human-intervention decisions**; design and maintain the human supervision and intervention mechanism | **Partial** | today the oversight evidence is `HumanOversight`, attached per decision - mode, reviewer reference, action - so an intervention belonging to a specific decision is already recorded and integrity-checked. An intervention belonging to no single decision (a halt, a recall, an override of the system rather than of one output) has no home yet. A dedicated intervention payload family is arriving with this release (§1); once it lands, this row becomes **Direct** *for the retention integrity of those records* and stays **Partial** for the clause as a whole, because designing and maintaining the mechanism is not something a log can do. **The forward-looking half is not shipped - do not cite it** |
| Law Điều 10(1) + Decree Điều 6 and Điều 12 | self-classify before service; keep a classification dossier | **Out of scope** | waxseal has no risk taxonomy and assesses nothing. The most it will ever do is record a tier the provider declared, verbatim, as that provider's own declaration. Recording a declaration is not classifying - and a library that normalised "cao" to "high" would be substituting its own judgment for the declaration Decree Điều 6(1) makes the provider legally answerable for |
| Law Điều 12 + Decree Điều 19 | record incidents; preliminary report within 72 hours of the confirmation time | **Out of scope** | nothing in 0.1.5 models an incident. An incident payload family is arriving with this release (§1); once it lands this becomes **Partial**, on a narrow claim: waxseal can evidence that an incident record existed at a position and has not been altered since, and it can retain a reference to a submission. It cannot evidence that a submission reached a portal - no code in the library talks to one - and the 72-hour clock runs from the **thời điểm xác nhận** of Điều 19(3)(c), a time the writer asserts, not a time waxseal attests. **Not shipped** |
| Law Điều 7(4) | prohibition on obstructing, disabling or distorting the human supervision, intervention and control mechanism | **Out of scope** | a mechanism that was switched off writes nothing, so no log can witness its own absence. This is the argument CLAUDE.md already makes for archiving being invisible to chain integrity: a defect no verdict can see has to be asserted from outside the log, never inferred from a clean verify |
| Law Điều 27(2) | the AI does not replace the decision-maker's authority; that person is responsible for reviewing and using the result | **Partial** | `human_oversight` records whether a review was recorded, and `oversight_unrecorded` is counted separately from every recorded mode - so "we do not know whether anyone reviewed this" never renders as "nobody did" or as "it was automated by design". Whether the review actually happened, and whether the reviewer held the authority, is outside |
| Law Điều 13 + Decree Điều 13(4) | conformity assessment; conditions on the assessment bodies | **Partial** | SPEC.md, the write-once golden vectors, and the cross-check generators under `tools/` that implement SPEC.md's prose without importing the library are *inputs* an assessor can use to check this layer independently of its authors. They satisfy nothing on their own, and no output of the library asserts an assessment result |
| Decree Điều 3(6) "Thẻ hệ thống" | a system card carrying architecture, components, model, purpose and safety measures, plus "thông tin về sự cố, lỗ hổng hoặc biện pháp khắc phục có liên quan" | **Partial** | same footing as the row above: an integrity-checked log is a source the card's incident and remediation fields can be written *from*. The card itself is a document somebody writes; waxseal produces no card |
| Decision 1671 IV.4.c - data residency | data stored in Vietnam in the cases the law provides for | **Out of scope** | the library runs wherever it is deployed and expires nothing. One flow is worth naming because it is easy to overlook: anchoring sends a Merkle root or a hash - never a payload - to an RFC 3161 TSA, an OpenTimestamps calendar, a witness, or an EVM ledger. If the chosen sink sits outside the country, that is a cross-border flow an operator has to declare even though it carries no payload. Read IV.4.c in place before treating it as a mandate - see the Decision 1671 subsection below |
| Law Điều 11 + Decree Điều 17 and Điều 18 | machine-readable marking and visible labelling of AI-generated content | **Out of scope** | waxseal generates no content, so it has nothing of its own to mark or label. Listed so nobody assumes an audit trail covers it |
| Law Điều 8 + Decree Điều 4 and Điều 14 | registration and notification through the one-stop portal and the national AI system database | **Out of scope** | no integration exists and none is planned in this release. Decree Điều 14(3)(b) does contemplate an API route, and Điều 46 keeps other electronic means legally equivalent while the portal is not in operation - but waxseal submits nothing by any route, and a `report_ref` retained on a trail is a reference somebody wrote down, not a receipt waxseal verified |

### Tension: a dossier kept for the system's whole operating life vs. erasure

Decree **Điều 12(6)**: "Nhà cung cấp, bên triển khai có trách nhiệm lưu trữ hồ sơ phân loại
trong suốt thời gian hệ thống hoạt động" - the classification dossier is retained for as long
as the system operates, with no end date of its own. §2's tension returns in a sharper form:
there, Art. 19 set a six-month floor and subordinated it to data-protection law. Here the
floor is the system's entire operating life, while personal-data law grants erasure, and the
Decree itself defers to "pháp luật về bảo vệ dữ liệu cá nhân" at Điều 16(5).

The resolution is the one this document already reaches in §2 and §7, and it does not change
because the retention period got longer: **nothing personal enters a payload**, and identity is
referenced by `subject_ref` / `reviewer_ref` into a store that *can* delete. The chain then
evidences the decision for as long as the system runs; the identity store answers to erasure.
`[Inference]` Decree Điều 12(7) permits a personal-data impact dossier to be reused as a
component of the classification dossier, which puts the two regimes in one file but does not
say which prevails over an erasure request - basis: a direct reading of Điều 12(7), with no
clause of the Decree found that settles the conflict.

### Decision 1671/QĐ-TTg is a strategy, not an obligation

**Decision 1671/QĐ-TTg** approves the national AI strategy to 2030, with a vision to 2045. It
is a strategy: viewpoints, targets, pillars, breakthrough solutions, and an appendix of tasks
each assigned to a lead agency with a window. It **assigns work to state agencies and imposes
no requirement on a library**. No row in the table above derives from it, and nothing in it can
be "complied with" by a piece of software. It is in this document for two narrow reasons: one
of its clauses is the residency phrase the data-residency row answers, and its stated
preferences say out loud what kind of tooling the state is looking for.

> **I. Quan điểm 4**, final clause: "…ưu tiên công nghệ nguồn mở, mô hình có trọng số mở và các
> giải pháp cho phép kiểm tra, tùy chỉnh, triển khai độc lập, từng bước giảm phụ thuộc vào bên
> ngoài."
>
> *(…priority for open-source technology, open-weight models, and solutions that permit
> inspection, customisation and independent deployment, progressively reducing external
> dependence.)*

> **III. Trụ cột 9. Quản trị AI an toàn, đáng tin cậy**, point (đ): "Xây dựng nền tảng, công cụ
> phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ
> AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI."
>
> *(Pillar 9, safe and trustworthy AI governance - (đ) build platforms and tools serving the
> monitoring, inspection and evaluation of AI products and services; prefer the use of AI
> technology to do that monitoring, inspection and evaluation.)*

> **IV.4.c**, final clause: "…bảo đảm an toàn dữ liệu, an ninh mạng và lưu trữ dữ liệu tại Việt
> Nam trong các trường hợp pháp luật quy định."
>
> *(…ensure data security, cyber security, and data storage in Vietnam in the cases the law
> provides for.)*

Read in place, IV.4.c is the tail of a clause about attracting high-quality foreign direct
investment and AI research and development centres, and the residency phrase is a condition
attached to those arrangements rather than a free-standing residency rule. Appendix II task 81
carries the same wording in its task column. The data-residency row above is written against
that phrase, not against a mandate this Decision does not contain.

Three Appendix II tasks matter to a reader of this document, quoted from the task column:

| Task | Text | Window |
|---|---|---|
| 64 | "Triển khai, theo dõi, đánh giá và cập nhật Khung đạo đức AI quốc gia; hướng dẫn quản trị và đánh giá tuân thủ." | 2026-2030 |
| 66 | "Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI." | 2026-2030 |
| 89 | "Hình thành các tổ chức đánh giá sự phù hợp hệ thống AI." | 2026-2030 |

Each names a central ministry as lead agency. A task in this appendix is work the state gives
itself, on a five-year window, with a deliverable described in a phrase. It is not a
specification, and "a tool serving monitoring, inspection and evaluation" is a category rather
than a criterion anything can be measured against. `[Inference]` an integrity layer of this
kind is a narrow instance of what task 66 describes - it evidences that a record was not
altered, and nothing beyond that - basis: reading task 66's own wording against the primitives
listed in §1. No criterion published under task 66 was retrieved, so this is a reading, not a
demonstrated fit.

---

## 8. Sources and verification

Retrieved 2026-08-23:

| Source | Used for | Status |
|---|---|---|
| [EU AI Act Art. 12](https://artificialintelligenceact.eu/article/12/), [Art. 19](https://artificialintelligenceact.eu/article/19/), [Art. 26](https://artificialintelligenceact.eu/article/26/), [Annex III](https://artificialintelligenceact.eu/annex/3/) | verbatim clause text | retrieved; **unofficial reproduction** of Reg. (EU) 2024/1689 - confirm against EUR-Lex before formal use |
| [NIST AI RMF Playbook - Govern](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Govern), [Measure](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Measure), [Manage](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Manage) | subcategory identifiers and text | retrieved from NIST |
| [Commission Delegated Reg. (EU) 2024/1774](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774) | RTS Art. 12 (Logging) | retrieved from EUR-Lex (official) |
| [DORA Art. 10](https://www.digital-operational-resilience-act.com/Article_10.html) | detection provisions | unofficial reproduction |
| [Fed SR letters 2026](https://www.federalreserve.gov/supervisionreg/srletters/2026.htm) | existence and title of SR 26-2 | listing confirmed; **text not retrieved** |
| [Resolution 05/2025/NQ-CP full text](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-quyet-so-5-2025-nq-cp-ve-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-119250909184045221.htm) and [luatvietnam](https://luatvietnam.vn/tai-chinh/nghi-quyet-05-2025-nq-cp-cua-chinh-phu-ve-viec-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-410830-d1.html) | Điều 15(2)(l) | two concurring secondary sources; not the gazette |
| [Decision 96/QĐ-BTC](https://luatvietnam.vn/hanh-chinh/quyet-dinh-96-qd-btc-2026-cong-bo-thu-tuc-hanh-chinh-moi-ve-thi-truong-tai-san-ma-hoa-424349-d1.html) | scope (administrative procedures only) | secondary source |
| ISO/IEC 42001 | - | **not retrieved** - the standard is not openly published. No clause identifiers are cited in this document, deliberately |
| AICPA Trust Services Criteria | CC identifiers | **not retrieved** - used descriptively only |

Retrieved 2026-09-07 - the Vietnam AI law cluster (§7b):

| Source | Used for | Status |
|---|---|---|
| Law on Artificial Intelligence No. 134/2025/QH15 - gazette text, **Công báo No. 40, 22-01-2026**, from the issue's landing page on `congbao.chinhphu.vn` | verbatim Điều 3(4)(5), 7(4)(5), 8, 9, 10(1)(3)(5), 11, 12(2)(4), 13, 14(1)(c)(d)(e), 14(2)(b), 26, 27(2)(3), 28(3), 34, 35(1) | **official gazette text.** The issue number and date run in the header of every page of the retrieved PDF, and the file carries a text layer - so the Vietnamese quoted in §7b was copied, not transcribed from an image. Cite the issue and its landing page rather than a file URL: the PDF itself is served from a CDN endpoint behind a signed query string, which will not resolve for a later reader |
| Decree 142/2026/NĐ-CP - [signed PDF](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/4/142-2026-ndcp.signed.pdf) | Điều 3(6), 4(1), 6, 11(5), 12(6)(7), 13(4), 14(3), 15(2)(c), 16(2)(c), 16(5), 17, 18, 19(2)(3)(4), 20, 45, 46, and the form appendix | **official**, digitally signed by the Government Office. **Scanned, with no text layer** - clause numbers and wording were read from page images, so a transcription slip is possible here in a way it is not for the Law. Re-check any clause before quoting it formally |
| Decision 1671/QĐ-TTg - [signed PDF](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/9/1671_qd-ttg_28082026-signed.signed.pdf) | Quan điểm 4, Trụ cột 9(đ), IV.4.c, Appendix II tasks 64, 66, 81, 89 | **official**, digitally signed (signature timestamp 03/09/2026), 64 pages, **scanned** |
| Circular 05/2026/TT-BKHCN; Decision 33/2026/QĐ-TTg | named in §7b; **no clause is cited from either** | **not retrieved** - seen only through secondary summaries. Every statement about them in §7b carries `[Unverified]`, and neither their numbers, dates nor scope was confirmed against a primary source |

---

## 9. Honest gap analysis - what waxseal does **not** do

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
| **Incident reporting** | nothing is filed and no portal is contacted. A recorded incident can be shown to have existed at a position and to be unaltered; whether a report reached a regulator, and whether it reached one in time, are both outside - the window that matters runs from a confirmation time the writer asserts |
| **Risk classification** | a declaration is recorded, not a classification. A declared tier is kept verbatim as the writer's own declaration; nothing in the library decides whether that tier is the right one, and *not declared* is never rendered as the lowest tier |
| **A compliance verdict** | no output of this library asserts that any obligation is met, and none should be quoted as if it did |

---

## 10. If you take one thing from this document

The claim worth making to a reviewer is narrow and defensible:

> *This decision was recorded at this position, under this model version and this policy
> version, with this human-oversight status, and can be shown to be unaltered since -
> independently of the party that holds the log, and without disclosing any other
> decision.*

Everything broader than that sentence is somebody else's control.
