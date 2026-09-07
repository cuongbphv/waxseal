# Decision 1671/QĐ-TTg (28/08/2026) - Vietnam's national AI strategy, and where waxseal actually touches it

*[Tiếng Việt](qd-1671-2026-ai-strategy.vi.md)*

**This is a research report, not a compliance mapping.** The labelled mapping tables live in
[docs/compliance/mapping.md](../compliance/mapping.md); this document explains *why* those
rows are placed as they are for Vietnam's AI legal cluster, and records the verification
level of every source behind them.

waxseal is an integrity and evidence layer. It can produce technical evidence that
*supports* a log-retention, traceability, or post-market inspection obligation. It does
**not** make any organisation compliant with anything, and no row below should be read as
"this obligation is met". Nothing here is legal advice, and this document names no
institution, product, or person.

All sources retrieved **2026-09-07**. Per-source verification level is in
[§7](#7-sources-and-verification).

---

## 1. Executive summary

**Decision 1671/QĐ-TTg of 28 August 2026** of the Prime Minister approves the *National
strategy on artificial intelligence to 2030, with a vision to 2045*. The document runs 28
pages of body text plus Appendix I (32 indicators) and Appendix II (97 tasks and measures).
Under Điều 3 (Article 3) it takes effect on the day of signature and replaces Decision
127/QĐ-TTg of 26 January 2021.

**A strategy imposes no technical obligation on a library.** Decision 1671 speaks in
*quan điểm* (guiding views), objectives, pillars, measures, and assignments to state
agencies. It prescribes no log format, no integrity mechanism, and no duty on any particular
piece of software. Appendix II's columns are "lead agency / co-ordinating agency /
product-result / timeframe" - that is the work of the administrative machine, not a technical
requirement on a vendor. Reading Decision 1671 as a checklist to be "met" is reading the
wrong kind of document.

**The binding obligations live elsewhere.** The requirements for an *operating log*, an
*audit trail*, *incident recording*, *human-intervention decisions*, and *self-classification
of risk* sit in the **Law on Artificial Intelligence No. 134/2025/QH15** and in **Decree
142/2026/NĐ-CP**. Those are the two texts an integrity layer can say something true about.
Decision 1671 is the surrounding policy context, plus two indirect contact points worth
naming:

- **Quan điểm 4** prioritises "open-source technology… solutions that permit inspection,
  customisation and independent deployment" - which describes the shape of an MIT-licensed,
  stdlib-only library whose verifier runs offline.
- **Pillar 9(đ) and Appendix II task 66** put the building of "platforms and tools serving
  the supervision, inspection and evaluation of AI products and services" into the national
  2026-2030 programme. waxseal is *one* tool in the very narrow sense of that sentence: it
  demonstrates that a record has not been altered. It does not evaluate an AI product.

**The practical conclusion.** In waxseal 0.1.5 the integrity mechanism already supports one
narrow, defensible sentence about *logs* (see [§4](#4-coverage-matrix)). The three real gaps
are (i) no field recording the risk tier *as declared by the provider*, (ii) no *incident*
record and no *human-intervention* record independent of one specific AI decision, and
(iii) no corresponding report block. All three are *evidence to be recorded*, not mechanism
to be changed ([§5](#5-gaps-and-proposed-extensions)).

One thing this document does not do: it does not say waxseal is tamper-proof. waxseal is
tamper-evident, and the boundary of the stronger claim is set out in
[threat model §1](../security/threat-model.md#1-tamper-evident-is-not-tamper-proof).

---

## 2. The structure of Decision 1671

### 2.1 Six guiding views (Section I)

| # | Core content | Relevance to waxseal |
|---|---|---|
| 1 | Shift from "putting AI into products" to "AI as core capability"; "institutions and AI governance as the breakthrough" | context |
| 2 | Unified leadership and management; "perfecting institutions and safe, trustworthy, human-centred AI governance"; balancing innovation against "safety, security, ethics, accountability" | the exact problem an evidence layer addresses: accountability needs a record that cannot be quietly revised |
| 3 | AI workforce as the decisive foundation | none |
| 4 | Shared infrastructure, data, models and platforms; **"prioritise open-source technology, open-weight models and solutions that permit inspection, customisation and independent deployment, progressively reducing external dependence"** | a direct fit on positioning: MIT, no runtime dependencies, `verify` runs offline, no outbound service call unless an operator enables anchoring |
| 5 | Vietnamese AI enterprises as the main force; "Make in Viet Nam" products | see the note on "Make in Viet Nam" in [§5.4](#54-further-out-and-deliberately-not-built) |
| 6 | International co-operation tied to strategic self-reliance; "not dependent on a single market, a single platform, a single model, a single technology source or a single supply chain" | the same reasoning behind waxseal naming no default anchor |

Quan điểm 4, the relevant clause verbatim:

> "…ưu tiên công nghệ nguồn mở, mô hình có trọng số mở và các giải pháp cho phép kiểm tra,
> tùy chỉnh, triển khai độc lập, từng bước giảm phụ thuộc vào bên ngoài."
>
> *(…prioritise open-source technology, open-weight models and solutions that permit
> inspection, customisation and independent deployment, progressively reducing external
> dependence.)*

### 2.2 Objectives (Section II)

**Overall 2030 objective**: make Vietnam "one of the centres with capability in AI research,
development, application and value co-creation in ASEAN and Asia", with AI "becoming a core
capability, deeply and comprehensively integrated into national governance and public
service delivery".

**2045 vision**: Vietnam "among the 10 leading countries in Asia in AI research,
development, mastery and national AI transformation", with AI "becoming the principal
operating substrate of the State, the economy and society" (Appendix I, indicator 32).

Three 2030 indicators create the volume of *AI-assisted administrative decisions* an evidence
layer can say something about:

| Indicator (Appendix I) | Content | Lead monitoring agency |
|---|---|---|
| 7 | "60% quyết định chỉ đạo, điều hành của cơ quan nhà nước được hỗ trợ bởi dữ liệu và AI" *(60% of state agencies' direction and administration decisions supported by data and AI)* | Ministry of Science and Technology |
| 14 | "100% dịch vụ công trực tuyến được tích hợp, hỗ trợ bởi AI" *(100% of online public services integrated with and supported by AI)* | Ministry of Science and Technology |
| 15 | "100% hồ sơ TTHC được hỗ trợ xử lý bằng AI" *(100% of administrative-procedure files processed with AI support)* | Ministry of Justice |

Every such decision poses precisely the question a decision record is designed to answer:
who decided, on which model version, who reviewed it, under which policy.

### 2.3 Nine strategic pillars (Section III)

1. AI workforce and AI skills for all · 2. Data and AI models · 3. AI infrastructure ·
4. AI research, development and technology mastery · 5. AI in national governance · 6. AI
for sectors and industries · 7. AI for small and medium enterprises, household businesses
and co-operatives · 8. The AI ecosystem · **9. Safe, trustworthy AI governance**.

Pillar 9 is the only pillar an integrity layer falls inside, and only at point đ:

> "đ) Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm,
> dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm,
> dịch vụ AI."
>
> *(đ) Build platforms and tools serving the supervision, inspection and evaluation of AI
> products and services. Prioritise using AI technology to supervise, inspect and evaluate
> AI products and services.)*

### 2.4 Six breakthrough measure groups (Section IV)

1. Perfecting institutions, policy and law · 2. National co-ordination and implementation
responsibility · 3. Resource mobilisation and funding · 4. International co-operation and
standards development · 5. Communication, awareness and a culture of responsible AI use ·
6. Measurement, monitoring and evaluation.

Four points inside them are contact points:

- **IV.1(g)** - "Xây dựng cơ chế, chính sách kiểm soát luồng dữ liệu trong hoạt động AI
  xuyên biên giới, kiểm soát xuất khẩu công nghệ AI nhạy cảm…" *(Build mechanisms and
  policies to control cross-border data flows in AI activity, and control the export of
  sensitive AI technology…)*. See [§6](#6-on-shore-deployment): an anchor or witness located
  outside the territory is *an outbound data flow*, hash-only though it is.
- **IV.2(d)** - the **"6 rõ"** principle: "rõ người, rõ việc, rõ thời gian, rõ trách nhiệm,
  rõ sản phẩm, rõ thẩm quyền" *(clear person, clear task, clear time, clear responsibility,
  clear deliverable, clear authority)*. This is an administrative-assignment principle, not
  a data schema - but it is a useful cross-check against the fields of a decision record
  ([§4.2](#42-the-6-rõ-frame-against-a-decision-record)).
- **IV.4(c)** - at the end of the point: "…bảo đảm an toàn dữ liệu, an ninh mạng và lưu trữ
  dữ liệu tại Việt Nam trong các trường hợp pháp luật quy định." *(…ensure data safety,
  cyber-security, and storage of data in Vietnam in the cases prescribed by law.)* **Read in
  place** (pages 21-22), this is the tail of a clause about *attracting high-quality foreign
  direct investment and large technology groups to build AI research and development centres
  in Vietnam*, and the residency phrase is **a condition attached to those arrangements**,
  not a free-standing data-residency rule. Appendix II task 81 carries the same wording in
  its task column, in the same FDI context. This document is written against *that phrase*,
  not against a mandate the Decision does not contain.
- **IV.4(h), (i), (l)** - harmonising national standards and technical regulations with
  international AI standards, and "Hình thành các tổ chức đánh giá sự phù hợp hệ thống AI"
  *(establish AI system conformity-assessment bodies)*.

### 2.5 The Appendix II tasks that touch this library

Quoted from the columns "Nhiệm vụ, giải pháp" (task/measure), "Cơ quan chủ trì" (lead
agency), "Sản phẩm/Kết quả" (product/result) and "Thời gian thực hiện" (timeframe). These
thirteen are the whole set an integrity layer is relevant to; the remaining 84 are not.

| No. | Task (verbatim Vietnamese, abridged where "…") | Lead agency | Product / result | Timeframe |
|---|---|---|---|---|
| **34** | "Xây dựng, triển khai Nền tảng AI hỗ trợ công vụ quốc gia theo hướng AI-First, AI-Native, ưu tiên các nhóm bài toán: trợ lý AI công vụ; AI hỗ trợ cung cấp dịch vụ công; AI hỗ trợ xây dựng, rà soát, hoàn thiện thể chế; AI phục vụ lãnh đạo, chỉ đạo, điều hành." *(Build and deploy a national public-service AI platform, AI-First and AI-Native, prioritising: a public-service AI assistant; AI support for public service delivery; AI support for drafting and reviewing institutions; AI serving leadership and administration.)* | Ministry of Science and Technology | "Cuối năm 2026 có phiên bản đầu tiên của nền tảng AI hỗ trợ công vụ quốc gia. Hoàn thiện mở rộng, tích hợp và vận hành trong các năm tiếp theo." *(A first version by end-2026; extension, integration and operation in following years.)* | 2026 - 2030 |
| **63** | "Hỗ trợ cộng đồng AI mở, mã nguồn mở, mô hình mở, công cụ và bộ dữ liệu mở có kiểm soát." *(Support the open AI community: open source, open models, open tools and controlled open datasets.)* | Ministry of Science and Technology; Ministry of Public Security | "Cộng đồng AI mở, mã nguồn mở, mô hình mở và bộ dữ liệu mở có kiểm soát được hỗ trợ và phát triển." | 2026 - 2030 |
| **64** | "Triển khai, theo dõi, đánh giá và cập nhật Khung đạo đức AI quốc gia; hướng dẫn quản trị và đánh giá tuân thủ." *(Deploy, monitor, evaluate and update the National AI Ethics Framework; issue governance and compliance-evaluation guidance.)* | Ministry of Science and Technology | "2026: Khung đạo đức AI quốc gia và cơ chế giám sát đạo đức AI được ban hành; triển khai, theo dõi, đánh giá và cập nhật… trong các năm tiếp theo." *(2026: the framework and an AI-ethics supervision mechanism issued; deployment, monitoring, evaluation and updating in following years.)* | 2026 - 2030 |
| **65** | "Nghiên cứu, phát triển công nghệ bảo mật cho hệ thống AI; phát hiện, ngăn chặn, giám sát và ứng phó với các mối đe dọa." *(Research and develop security technology for AI systems; detect, prevent, monitor and respond to threats.)* | Ministry of Public Security | "Công nghệ bảo mật cho hệ thống AI; phát hiện, ngăn chặn, giám sát và ứng phó với các mối đe dọa được nghiên cứu, phát triển." | 2026 - 2030 |
| **66** | "Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI." *(Build platforms and tools for supervising, inspecting and evaluating AI products and services; prioritise using AI technology to do so.)* | Ministry of Science and Technology | "Nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI" | 2026 - 2030 |
| **73** | "Xây dựng cơ chế, chính sách kiểm soát luồng dữ liệu trong hoạt động AI xuyên biên giới, kiểm soát xuất khẩu công nghệ AI nhạy cảm, triển khai các biện pháp pháp lý, kỹ thuật phù hợp và hợp tác quốc tế để bảo đảm an toàn thông tin, an ninh không gian mạng, dữ liệu cá nhân và thông tin chiến lược của quốc gia." *(Build mechanisms and policies to control cross-border AI data flows and the export of sensitive AI technology; apply suitable legal and technical measures and international co-operation to protect information security, cyberspace security, personal data and the nation's strategic information.)* | Ministry of Public Security | "Văn bản quy định hoặc hướng dẫn." *(A regulation or a guidance document.)* | 2026 |
| **86** | "Rà soát, cập nhật bảo đảm các tiêu chuẩn quốc gia, quy chuẩn kỹ thuật quốc gia theo hướng hài hòa, phù hợp với tiêu chuẩn quốc tế về AI." *(Review and update national standards and technical regulations towards harmonisation with international AI standards.)* | Ministry of Science and Technology | "Tiêu chuẩn quốc gia, quy chuẩn kỹ thuật về AI được rà soát và cập nhật." | 2026 - 2030 |
| **87** | "Xây dựng tiêu chuẩn, quy chuẩn kỹ thuật ngành, tiêu chí kỹ thuật áp dụng cho sản phẩm, dịch vụ ứng dụng AI trong các ngành, lĩnh vực." *(Develop sectoral standards, technical regulations and technical criteria for AI-applying products and services.)* | Line ministries | "Các tiêu chuẩn, quy chuẩn, tiêu chí kỹ thuật." | 2026 - 2030 |
| **88** | "Tham gia hoạt động tiêu chuẩn hóa AI khu vực và toàn cầu." *(Participate in regional and global AI standardisation.)* | Ministry of Science and Technology | "Tiêu chuẩn, quy chuẩn kỹ thuật AI được xây dựng, hài hòa và áp dụng phù hợp với tiêu chuẩn khu vực và quốc tế." | 2026 - 2030 |
| **89** | "Hình thành các tổ chức đánh giá sự phù hợp hệ thống AI." *(Establish AI system conformity-assessment bodies.)* | Ministry of Science and Technology | "Số lượng tổ chức đánh giá sự phù hợp hệ thống AI." *(A count of such bodies.)* | 2026 - 2030 |
| **94** | "Xây dựng, ban hành và định kỳ rà soát, cập nhật các chỉ tiêu đánh giá mức độ chuyển đổi AI của bộ, ngành, địa phương và quốc gia phù hợp với Chiến lược, điều kiện thực tiễn và thông lệ quốc tế" *(Develop, issue and periodically review indicators measuring the AI transformation of ministries, sectors, localities and the nation.)* | Ministry of Science and Technology | "Nghiên cứu, xây dựng chỉ tiêu đánh giá mức độ chuyển đổi AI của bộ, ngành, địa phương và quốc gia." | 2026 |
| **95** | "Đánh giá chuyển đổi AI quốc gia và công bố công khai kết quả đánh giá định kỳ hằng năm, làm căn cứ theo dõi, đôn đốc, điều chỉnh Chiến lược…" *(Assess national AI transformation and publish the annual assessment results as the basis for monitoring, prompting and adjusting the Strategy…)* | Ministry of Science and Technology | "Kết quả đánh giá định kỳ hằng năm." | 2026 - 2030 |
| **96** | "Xây dựng, triển khai các giải pháp công nghệ để theo dõi, thống kê, đo lường, giám sát, đánh giá được các mục tiêu, kết quả thực hiện nhiệm vụ của Chiến lược trên môi trường số, bảo đảm tự động tối đa, kịp thời, công khai, minh bạch." *(Build and deploy technology solutions to track, count, measure, monitor and evaluate the Strategy's objectives and results in the digital environment, maximally automated, timely, public and transparent.)* | Ministry of Science and Technology | "Các giải pháp công nghệ để theo dõi, thống kê, đo lường, giám sát, đánh giá." | 2027 - 2028 |

Read as clusters: 64-66 is the safe-AI-governance cluster (Pillar 9), 86-89 is the standards
and conformity-assessment cluster, and 94-96 is the automated-measurement cluster. Those
three are respectively why `SPEC.md` plus frozen golden vectors,
`export-proof`/`verify-proof`, and `report --json` exist at all - but no task among them
*requires* a log-integrity mechanism, and this document does not claim otherwise.

---

## 3. The legal tree

### 3.1 Five instruments, in order of legal force

```
Law on Artificial Intelligence 134/2025/QH15   (National Assembly, passed 10/12/2025)
  │   root obligations: operating log, audit trail, self-classification, incidents
  ├── Decree 142/2026/NĐ-CP                     (Government, signed 30/04/2026)
  │     detail: classification dossier, conformity assessment, the 72-hour clock, forms
  ├── Circular 05/2026/TT-BKHCN                 (MoST - National AI Ethics Framework, Law Điều 26)
  └── Decision 33/2026/QĐ-TTg                   (PM - list of high-risk AI systems, Law Điều 13(4))

Decision 1671/QĐ-TTg                            (PM, signed 28/08/2026)
      a strategy: views, objectives, pillars, measures, assignments
      NOT part of the obligation chain above - it is the programme of action around it
```

### 3.2 Effective dates and transition

| Date | Event | Basis |
|---|---|---|
| 10/12/2025 | The 15th National Assembly, 10th session, passes Law 134/2025/QH15 | closing line of the Law |
| 22/01/2026 | The Law appears in Công báo (official gazette) No. 40 | the gazette text |
| **01/03/2026** | Law 134 takes effect, except the matters in Điều 35 | Law Điều 34 |
| 10/03/2026 | Circular 05/2026/TT-BKHCN takes effect | `[Unverified - chỉ từ nguồn thứ cấp, chưa đối chiếu bản gốc Thông tư / secondary sources only, original not obtained]` |
| 30/04/2026 | Decree 142/2026/NĐ-CP is signed | header of the Decree's forms appendix |
| **01/05/2026** | Decree 142 takes effect | Decree Điều 45 |
| 15/08/2026 | Decision 33/2026/QĐ-TTg (high-risk list) takes effect | `[Unverified - chỉ từ nguồn thứ cấp, chưa tải được bản gốc / secondary sources only, original not obtained]` |
| **28/08/2026** | Decision 1671/QĐ-TTg is signed, effective on signature, replacing Decision 127/QĐ-TTg of 26/01/2021 | Decision 1671 Điều 3(1), 3(2) |

**The transition windows, in the statute's own words, not converted to dates.** Điều 35(1)
sets two periods running **from the Law's effective date**: **18 months** for AI systems in
health, education and finance, and **12 months** for everything else. Both apply only to
**systems already put into operation before the Law took effect**, and neither is attached to
the high-risk list - Điều 35(1) does not mention the list at all. This document deliberately
**prints no converted calendar date**: the Law itself prints none, and a date a reader added
up and then presented as a milestone of the text is exactly the class of error this whole
document is avoiding. Điều 35(2) lets those systems keep operating through the window, unless
the regulator determines the system risks serious harm.

The transitional provision verbatim:

> "1. Đối với các hệ thống trí tuệ nhân tạo đã được đưa vào hoạt động trước ngày Luật này
> có hiệu lực thi hành, nhà cung cấp và bên triển khai có trách nhiệm thực hiện các nghĩa
> vụ tuân thủ theo quy định của Luật này trong thời hạn sau đây: a) 18 tháng kể từ ngày
> Luật này có hiệu lực thi hành đối với hệ thống trí tuệ nhân tạo trong lĩnh vực y tế, giáo
> dục và tài chính; b) 12 tháng kể từ ngày Luật này có hiệu lực thi hành đối với các hệ
> thống trí tuệ nhân tạo không thuộc trường hợp quy định tại điểm a khoản này."
>
> *(1. For AI systems already put into operation before this Law takes effect, providers and
> deployers are responsible for performing the compliance obligations under this Law within
> the following periods: (a) 18 months from the effective date, for AI systems in health,
> education and finance; (b) 12 months from the effective date, for AI systems not falling
> under point (a).)*
>
> - Law 134/2025/QH15, Điều 35(1)

There is a second transitional provision worth quoting, because it calls for exactly the kind
of evidence waxseal produces. Where a system must be reclassified as high-risk, Decree Điều
11(5) allows up to 12 months and attaches a condition:

> "Trong thời hạn chuyển tiếp, hệ thống được phép tiếp tục hoạt động nhưng nhà cung cấp, bên
> triển khai phải thiết lập và duy trì cơ chế giám sát thực chất của con người. Người thực
> hiện giám sát phải được bảo đảm đủ thông tin, thẩm quyền để đánh giá độc lập, can thiệp
> hoặc bác bỏ kết quả của hệ thống; đồng thời, nhà cung cấp, bên triển khai phải lưu trữ đầy
> đủ nhật ký vận hành và các quyết định can thiệp để phục vụ công tác thanh tra, kiểm tra."
>
> *(During the transition the system may continue to operate, but the provider and deployer
> must establish and maintain a substantive human oversight mechanism. The person exercising
> oversight must be assured sufficient information and authority to independently assess,
> intervene in, or reject the system's output; at the same time, the provider and deployer
> must retain in full the operating log and the intervention decisions, to serve inspection
> and examination.)*
>
> - Decree 142/2026/NĐ-CP, Điều 11(5)

### 3.3 Which of the five were read in the original, and which were not

| Instrument | Original read? |
|---|---|
| Decision 1671/QĐ-TTg | **Yes** - the digitally signed PDF from the Government Office, all 64 pages (body + Appendix I + Appendix II) |
| Law 134/2025/QH15 | **Yes** - the Công báo No. 40 of 22/01/2026, with a text layer; Điều 7, 8, 9, 10, 11, 12, 13, 14, 15, 26, 27, 28, 33, 34, 35 read directly |
| Decree 142/2026/NĐ-CP | **Yes** - the digitally signed PDF; Điều 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 43, 44, 45, 46 and forms AI01a, AI01b, AI02, AI08a read directly |
| Circular 05/2026/TT-BKHCN | **No** - secondary sources only; every statement about the Circular's content in this document carries an `[Unverified]` tag |
| Decision 33/2026/QĐ-TTg | **No** - secondary sources only; every statement about the high-risk list carries an `[Unverified]` tag |

The consequence of the last two rows: this document reaches **no** conclusion about whether
any particular system falls inside the high-risk list, and cites **no** article or clause
number from Circular 05/2026. `[Unverified]` the groups reported to appear in Decision
33/2026 (education; ethnic and religious affairs; health; banking, including automated
transaction processing and credit decisions; legal proceedings, biometrics; transport) - that
list comes from secondary sources, has not been checked against the original, and its clause
numbering is deliberately not reproduced here because it could not be confirmed.

---

## 4. Coverage matrix

The labels are the three this repository already uses in
[mapping.md](../compliance/mapping.md): **Direct** (waxseal produces evidence that speaks to
the requirement's substance), **Partial** (it covers part of it; the rest is organisational
or out of scope), **Out of scope** (listed so nobody assumes it is covered - it is not).

No row says an obligation is met. The "what waxseal 0.1.5 does today" column names module
paths so a reader can check the claim by reading the code rather than by trusting this table.

**The authoritative labelled table is [mapping.md §7b](../compliance/mapping.md#7b-vietnam--law-on-artificial-intelligence-no-1342025qh15-and-its-implementing-instruments)**,
with its twelve obligation rows and its "Applicability first" section fixing the provider and
deployer roles at Law Điều 3(4) and 3(5). The table below does **not** replace it and does not
label anything differently from it; it adds the three things a mapping document has no room
for: a module path per row, the Decree clauses Decision 1671 leads into, and a "gap" column
pointing at [§5](#5-gaps-and-proposed-extensions). Where the two tables differ, mapping.md is
the correct one.

### 4.1 The table

| Requirement (article / clause) | What waxseal 0.1.5 does today | Label | Gap |
|---|---|---|---|
| Establish, update and retain the **technical dossier and operating log** "**ở mức cần thiết**" - at the level necessary - for conformity assessment and post-market inspection (Law Điều 14(1)(c)) | hash chain over `EntryHeader` (`domain/header.py`, `domain/hashing.py`); schema fingerprint (`domain/fingerprint.py`); `verify`/`report`/`export-proof` (`domain/verify.py`, `domain/report.py`, `domain/export.py`); append-only; three-valued verdict (`domain/verdict.py`) | **Partial** - *direct* only for the **integrity, order and position** of whatever was retained | two independent reasons the row as a whole is Partial: (i) "at the level necessary" is a scoping judgment the deploying institution has to make - which events, which fields, how long. No library can make it, and a library that pretended to would be deciding the scope of somebody else's legal duty; (ii) the clause requires *retention*, **not** tamper-evidence - tamper-evident retention is a **stronger** posture than the text demands and must be presented that way, not as a requirement this clause imposes. waxseal also enforces no retention period and expires nothing |
| Provide the "technical dossier, **audit trail**, training data" on inspection (Law Điều 28(3)) | `export-proof` extracts one decision as a bundle checkable offline without disclosing the other decisions (`domain/export.py`, `verify_proof_bundle`) | **Partial** | the bundle fits both this clause's necessary-and-proportionate limit and Điều 14(1)(e)'s bar on demanding source code, detailed algorithms or parameter sets - a proof bundle discloses none of those. But the *technical dossier* and the *training data* are not covered: waxseal holds neither; and the scope, extent and manner of disclosure is the institution's legal determination |
| Retain in full the **operating log and the intervention decisions** during a reclassification transition (Decree Điều 11(5)); design and maintain a human oversight and intervention mechanism (Law Điều 14(1)(d); Decree Điều 15(2)(c), 15(5)(c)) | `HumanOversight.mode` / `reviewer_ref` / `action`, attached **per AI decision** (`domain/decision.py`); `report` counts `oversight_unrecorded` separately (`domain/report.py`) | **Partial** | there is no *standalone* intervention record - an emergency halt, a recall, a suspension of the system that belongs to no single AI decision has nowhere to go -> **E2b** ([§5.2](#52-e2---incident-and-human-intervention-payload-families)) |
| **Record** a serious incident promptly (Law Điều 12(2)(b); Decree Điều 19(2)(a)) and file a preliminary report within **72 hours** / **5 working days** of the **incident-confirmation time** (Decree Điều 19(3)(a)(b)(c)) | none | **Out of scope** | -> **E2a**. Note the scope: waxseal could only ever show that *an incident record existed at position n, bearing timestamps asserted by the writer, and is unaltered since*. It does **not** show that a report reached the one-stop portal, and must never be printed as if it did |
| Maintain and retain the **system log**, data and incident-related information for verification, assessment and remediation (Decree Điều 19(4)) | the hash chain, `verify --anchors`, and the forward-secure seal (`domain/sealing.py`) make post-incident editing of the log detectable | **Partial** | this is the *log-retention* clause, distinct from the *incident recording and reporting* duty in the row above (Out of scope). "Maintain and retain" is the institution's retention programme; waxseal deletes nothing and stores nothing on anyone's behalf |
| **Self-classify** the system before putting it into use, bearing legal responsibility for the accuracy and truthfulness of the result (Law Điều 10(1); Decree Điều 6(1)); retain the classification dossier for the system's whole operating life (Decree Điều 12(6)) | none; `mapping.md` §9 states plainly "no risk taxonomy" | **Out of scope** | -> **E1**: record the risk tier *the provider declared*, verbatim, with a pointer to the classification dossier. waxseal does not classify and does not adjudicate anyone's classification |
| Evidence for the high-risk exclusion criterion - "an authorised person is able to independently review, intervene in, refuse or change the system's decision **before that decision takes effect**" (Decree Điều 8(2)(b)) | `human_oversight` records the presence or absence of review per decision, with `"unrecorded"` as a distinct value rather than the absence of one | **Partial** | waxseal shows that the *record of review* is unaltered. It does not show that the review happened, nor that it happened *before* the decision took effect - chain order is **write** order, not **action** order |
| The prohibition on "obstructing, disabling or **distorting** human oversight, intervention and control mechanisms" (Law Điều 7(4)) | detects edits, deletions, insertions and reordering of oversight *records* (`domain/verify.py`) - but that is the record, not the mechanism | **Out of scope** | a mechanism that was switched off writes nothing, so no log can witness its own absence. This is the argument CLAUDE.md already makes for archiving being invisible to chain integrity: a defect no verdict can see has to be asserted from outside the log, never inferred from a clean verify |
| The prohibition on "concealing information subject to mandatory disclosure, transparency or accountability; erasing or distorting mandatory information, labels and warnings" (Law Điều 7(5)) | for what has reached the trail: editing or deleting a row makes `verify` return `broken` with a sequence number and a reason | **Out of scope** | the clause is about mandatory information, labels and warnings *in AI activity* - none of which waxseal generates, renders or distributes. That it detects alteration of a row already on the trail is a fact about the trail, not coverage of this clause |
| "AI systems do not replace the authority and decision responsibility of the decision-maker… The decision-maker is responsible for reviewing and using the system's output" (Law Điều 27(2); Decree Điều 20(6)) | `human_oversight` plus a separately counted `oversight_unrecorded`; `ModelRef.digest = None` means "unpinned", a weaker claim recorded as the weaker claim it is | **Partial** | `oversight_unrecorded` is counted separately from every recorded mode, so "we do not know whether anyone reviewed this" never renders as "nobody did" or as "it was automated by design". Whether the review actually happened, and whether the reviewer held the authority, are both outside an integrity layer |
| "Thẻ hệ thống" - the system card, carrying "thông tin về sự cố, lỗ hổng hoặc biện pháp khắc phục có liên quan" *(information on related incidents, vulnerabilities or remediation measures)* (Decree Điều 3(6)) | an integrity-checked log is a *source* the card's incident and remediation fields can be written from | **Partial** | the card itself is a document somebody writes; waxseal produces no card |
| The impact-assessment report for state agencies, including the "mechanism assuring human oversight and intervention" (Law Điều 27(3); Decree Điều 20(3)(d), form AI02 §II.5) | `report --json` (`domain/report.py`) is a source of figures for the "oversight mechanism" and "degree of automation" items (form AI02 §II.4) | **Partial** | the impact-assessment report is the agency's document, not a library output |
| Conformity assessment; conformity-assessment bodies (Law Điều 13; Decree Điều 13; Decision 1671 task 89) | `SPEC.md`, write-once golden vectors, independent vector-generation scripts in `tools/`, `verify-proof` offline | **Partial** - an input for an assessor | the assessor, the criteria and the conclusion are all outside |
| "Retain information and documents serving inspection and supervision" (Decree Điều 16(2)(c)) | append-only by construction; `verify` reports and never repairs | **Partial** | no retention enforcement, no expiry mechanism |
| Trustworthy time for the 72-hour mark (Decree Điều 19(3)) | `ts` is a **caller-asserted** value, not attested time; `--tsa-url` allows anchoring to any RFC 3161 TSA, `--tsa-ca-file` is the operator's choice, and waxseal names no default trust anchor (`adapters/rfc3161.py`, `adapters/rfc3161_verify.py`) | **Partial** | `[Unverified]` whether a licensed Vietnamese timestamping provider exposes a usable RFC 3161 endpoint - a question to check before designing, not something this document asserts |
| The phrase "storage of data in Vietnam in the cases prescribed by law" (Decision 1671 IV.4(c); Appendix II task 81) | the library's data lives wherever the library runs; no outbound service is required | **Out of scope** for the library | read the phrase in place before treating it as a mandate: it is the tail of the clause on attracting FDI and foreign AI R&D centres, and a condition attached to those arrangements ([§2.4](#24-six-breakthrough-measure-groups-section-iv)). Addressed at the deployment layer ([§6](#6-on-shore-deployment)); the only outbound flow is a hash to an anchor or witness, and it must be declared |
| Control of cross-border AI data flows (Decision 1671 IV.1(g); Appendix II task 73) | every trail-reading command runs offline; only `anchor` and `--witness` open an outbound connection | **Out of scope** for the library - but an *architectural fact that must be declared*, see [§6.3](#63-exactly-one-class-of-outbound-traffic) | |
| Registration of an AI system in the **national AI system database** (Law Điều 8(2); Decision 1671 Điều 2.3(c)) | none | **Out of scope** | see [§5.4](#54-further-out-and-deliberately-not-built) |
| Notification and reporting via the **one-stop AI portal**, including "sending information automatically through an application programming interface" (Law Điều 10(3), 12(4); Decree Điều 14(3)(b), 19(8)) | none | **Out of scope** | see [§5.4](#54-further-out-and-deliberately-not-built) |
| Labelling and technical marking of AI-generated content (Law Điều 11; Decree Điều 17, 18) | none | **Out of scope** | waxseal generates no content |
| Vietnamese-language documentation and interface | every file under `docs/**` has a `.vi.md` twin; the portal defaults to Vietnamese | adequate for the purpose | the CLI and the verdict words (`ok`/`broken`/`unverifiable`) are **deliberately untranslated**: they are controlled vocabulary that exit codes and documentation both depend on |

### 4.2 The "6 rõ" frame against a decision record

`[Inference]` This cross-reference is this document's own construction, not a legal
requirement about schemas. The 6 rõ principle in Decision 1671 IV.2(d) is a principle for
assigning administrative responsibility; no instrument says it must map onto data fields. But
it is a useful way to check whether a decision record leaves anything blank:

| "rõ" (clear …) | Corresponding field | Note |
|---|---|---|
| clear person | `human_oversight.reviewer_ref`, `subject_ref` | pseudonymous, and required to be - the chain cannot delete |
| clear task | `decision_type`, `outcome` | open strings; an unfamiliar value is kept verbatim and is never an error |
| clear time | `ts` (caller-asserted) plus an upper bound from an anchor receipt | two different kinds of time, never to be conflated |
| clear responsibility | `human_oversight.mode` / `action`, and (E2b) the intervention record | `"unrecorded"` is a value, not the absence of one |
| clear deliverable | `payload_hash`, `input_commitment`, `model.digest` | `digest = None` means "unpinned", not "matched" |
| clear authority | `policy_version`, and (E1) the declared `risk_tier` | the tier is *the provider's declaration*, never waxseal's conclusion |

---

## 5. Gaps and proposed extensions

The three extensions below are described by *the evidence they would produce*, not as code.
None of them changes the chain mechanism: `hash_version` is the fingerprint of the header
field tuple, and the payload is referenced only by `payload_hash` - adding a payload family
does not touch the chain, which is exactly why the envelope is shaped that way.

### 5.1 E1 - the **declared** risk tier, not an **adjudicated** one

**Evidence it would produce:** for each AI decision, an unalterable record of *the risk tier
the provider had declared at the moment that decision was written*, plus a pseudonymous
pointer to the corresponding risk-classification dossier (an identifier and a version, not a
path carrying a person's name).

**Why "declared":** Law Điều 10(1) and Decree Điều 6(1) place the classification - and legal
responsibility for its accuracy and truthfulness - on the provider. If waxseal normalised
tier values, mapping "cao" onto `high`, waxseal would have placed itself in the position of
adjudicating the provider's classification. The value is recorded verbatim: `"cao"`,
`"high"`, `"tier-2"` are all accepted and all distinct.

**The third value:** where no tier was declared, the record carries "not declared", and that
value **never** renders as `"low"`. That is precisely the error `dropped_writes: None` exists
to avoid: an unmeasured state forced into a measured one. In a report, an undeclared tier is
counted separately and added to no tier.

**What it would not produce:** no evidence that the declared tier is *correct*, that the
classification dossier *exists*, or that it was notified to anyone.

### 5.2 E2 - incident and human-intervention payload families

**E2a - the incident record.** Evidence it would produce: that an incident record exists at
position `n` in the chain, bearing writer-asserted timestamps, and is unaltered since. The
fields follow Decree 142's **form AI01a** closely, so the record is reusable when the report
has to be filled in: system identifier (AI-ID), risk level, time of detection, **time of
confirmation of the causal link**, kind of consequence, operating status, preliminary
assessment of cause.

One detail read from the original and worth recording: the 72-hour clock does **not** run
from detection.

> "c) Thời điểm xác nhận sự cố quy định tại khoản này được tính từ khi tổ chức, cá nhân có
> đủ cơ sở thông tin ban đầu để xác định sự cố đã thực sự xảy ra và có khả năng cao bắt
> nguồn từ lỗi của hệ thống trí tuệ nhân tạo, không đợi đến khi hoàn thành điều tra toàn
> diện nguyên nhân kỹ thuật. Việc nộp báo cáo sơ bộ trong thời hạn quy định không bị coi là
> sự thừa nhận lỗi kỹ thuật hoặc trách nhiệm pháp lý của tổ chức, cá nhân báo cáo."
>
> *(c) The incident-confirmation time under this clause is counted from when the organisation
> or individual has sufficient initial information to determine that the incident actually
> occurred and is highly likely to originate from a fault of the AI system, without waiting
> for a complete investigation of the technical cause. Filing the preliminary report within
> the prescribed period is not treated as an admission of technical fault or legal liability
> by the reporting party.)*
>
> - Decree 142/2026/NĐ-CP, Điều 19(3)(c)

So the record has to carry *both* marks - detection and confirmation - and if the confirmation
mark is absent, a reading of the 72-hour window is **unmeasured**, with a reason naming the
missing mark. Silently substituting the detection time would be inventing a measurement, and
it can be wrong in both directions.

**What E2a would not produce, and must never be printed as if it did:** evidence that a
report was filed; evidence that a deadline was missed. The absence of a submission record on
this trail is not "not filed" - Decree Điều 46(1) allows filing by another electronic means
of "equivalent legal validity" while the portal is not yet officially in operation, and a
trail that sees nothing cannot see that either.

**E2b - the human-intervention record.** Evidence it would produce: that an intervention
decision - an emergency halt, an override, a suspension - is retained intact, *without*
having to belong to one specific AI decision, because in practice many interventions belong
to none. This is exactly the data **form AI08a §V** asks for outright: §V.6 "Người/bộ phận
có thẩm quyền giám sát, can thiệp và **số lần can thiệp**" *(the person or unit authorised to
supervise and intervene, and the number of interventions)*; §V.9 "**Số lần kích hoạt cơ chế
dừng khẩn cấp**, tình huống kích hoạt và kết quả xử lý" *(the number of emergency-stop
activations, the triggering situations and the outcomes)*.

And one more item on the same form is the clearest reason a log-integrity layer exists in this
context at all:

> "10. Việc lưu giữ nhật ký hệ thống, thời gian lưu giữ và biện pháp bảo đảm tính toàn vẹn
> của nhật ký: …"
>
> *(10. The retention of the system log, the retention period, and the measures assuring the
> integrity of the log: …)*
>
> - Decree 142/2026/NĐ-CP, Appendix, form AI08a §V.10

No instrument in this cluster *prescribes* a log-integrity mechanism. But the form asks
outright what the "measures assuring the integrity of the log" are - meaning the regulator
treats it as a line to be filled in, and an institution needs some answer for it.

**What E2b would not produce:** evidence that the oversight mechanism was *not disabled* (Law
Điều 7(4)). A mechanism that is switched off writes nothing, and an empty chain still
verifies `ok`. That boundary has to be stated every time, not treated as a technicality.

### 5.3 E3 - the corresponding report block

**Evidence it would produce:** an inventory extractable from `report --json` - a count of
incident records by severity, a count of intervention records by action label, and the
distribution of declared tiers with "not declared" as its own line.

Two rules govern how such a block renders:

1. **No records is not "nothing happened."** A trail with zero incident records must print
   *"0 incident records on this trail - a count of RECORDED incidents, not evidence that none
   occurred"*. This is `dropped_writes` again: chain integrity is not trail completeness.
2. **Not scanned is not "scanned, found zero."** The incident and intervention sections must
   always render, even when empty. A section that vanishes from a report cannot distinguish
   "none" from "not scanned", and that is precisely the three-into-two collapse this whole
   codebase exists to prevent.

The report is an inventory, not a verdict dimension: such a block would **not** change
`report`'s exit code, and would not evaluate the 72-hour window - the report has no clock.

### 5.4 Further out, and deliberately not built

The three items below sit inside the obligation cluster but outside an integrity layer. They
are listed so nobody assumes they are present.

- **Registering a system in the national AI system database** (Law Điều 8(2); Decision 1671
  Điều 2.3(c) assigns the Ministry of Public Security to "build and operate the national
  database on artificial intelligence"). Registration is an administrative act with an
  agency. An evidence layer can show that *a record saying registration happened* is
  unaltered, but it cannot show that registration happened - and selling the first as the
  second is the exact error this whole document is trying to avoid.
- **Filing notifications and reports through the one-stop AI portal**, including the
  automated API route (Decree Điều 14(3)(b), 19(8)). An integrity library does not file
  paperwork on anyone's behalf: doing so would turn it into an integration client against an
  agency, pulling an institution's operational duty and legal liability inside an
  MIT-licensed library with no service commitment. `[Unverified]` a public specification for
  that programming interface - none was found, so even if it were wanted there is nothing yet
  to build against. The right place for this is a pointer field: a submission identifier or
  receipt, written to the trail as a writer-asserted fact.
- **Labelling and technical marking of AI-generated content** (Law Điều 11; Decree Điều 17,
  18). waxseal does not generate, render or distribute content; it only ever sees the hash of
  an already-redacted payload. Labelling is a duty on whoever produces the content and
  whoever releases it to the public, not on wherever the evidence is stored.

---

## 6. On-shore deployment

### 6.1 The four trust domains and a territorial location for each

[Reference architecture §1](../architecture/deployment.md#1-topology) sets out four separate
administrative domains, and the load-bearing property is not four boxes on a diagram but
**four different administrative authorities**. The table below adds one column the
architecture document does not have: where the domain can sit territorially.

| Domain | Holds | Can it sit on-shore? | Note |
|---|---|---|---|
| **Application** (the AI system) | the model, the redactor, the payloads | **Yes, entirely** | the redactor runs before any hash, so cleartext never leaves this domain |
| **Chain** (chain server, append-only store) | the trail and its ordering | **Yes, entirely** | JSONL / SQLite / Postgres / S3 as the backend; no outbound service is required |
| **Anchor** (the third authority) | published roots, timestamped elsewhere | **Yes, but this is the hard one** | an on-shore anchor still has to sit under a **different administrative authority** from the chain - see [§6.2](#62-same-territory-does-not-mean-same-authority) |
| **Verifier** (second line / internal audit) | the seal key A₀, the verify job, the reports | **Yes, entirely** | A₀ never sits on a writing host; the pin file never sits where the writer can touch it |

### 6.2 Same territory does not mean same authority

Three deployment options, every component running inside the country:

1. **All within one organisation, four internal authorities.** Chain server and verifier in
   different namespaces or clusters with separated RBAC; the anchor is an internal system
   owned by a different unit. Cheapest, but the anchor domain is the weakest: if whoever
   writes the trail can also reach where the roots are kept, the "consistent whole-log
   rewrite" scenario stops being detectable.
2. **The anchor is a domestic counterparty.** Roots are published to a different
   organisation - an agency, a counterparty, a conformity-assessment body of the kind
   Decision 1671 task 89 anticipates. The authorities are genuinely different and no data
   leaves the territory.
3. **Fully air-gapped, no anchor.** Chain integrity, ordering, detection of
   edit/delete/insert/reorder and the forward-secure seal all still work. What is lost is the
   upper time bound: with no anchor, nothing says a root existed before a given moment, and
   every timestamp is the writer's assertion. That is a trade-off to be written into the
   design, not an operational detail.

### 6.3 Exactly one class of outbound traffic

If, and only if, an operator enables one of the anchor domains, waxseal opens an outbound
connection. Naming what that flow contains matters, because this is the point of contact with
**IV.1(g)** - Appendix II task 73, led by the Ministry of Public Security, product "a
regulation or a guidance document", timeframe 2026 - and with the phrase at IV.4(c), which
[§2.4](#24-six-breakthrough-measure-groups-section-iv) puts back into its FDI context rather
than treating as a free-standing residency rule:

**What goes out:** a Merkle root, or a hash. Concretely - a checkpoint root to an RFC 3161
TSA (`--tsa-url`); a digest to an OpenTimestamps calendar (`--ots-calendar`); a checkpoint to
a witness (`--witness`); a checkpoint to an EVM ledger (`--evm-rpc`). The four anchor domains
record independently of each other.

**What does not go out:** the payload. No decision content, no `rationale`, no original
`input_commitment`, no personal data, no names. A hash does not invert back into a payload.

**But it is still a cross-border flow if the receiving endpoint sits outside the
territory**, and an operator has to declare it as one. Three things to know when declaring
it:

- A hash emitted on a schedule is still **metadata**: it reveals that a trail exists, that it
  is growing, and at what times it grows. That is not content, but it is not nothing either.
- waxseal **names no default trust anchor** and has no default TSA, calendar, witness or
  ledger. Choosing one would decide whom an operator trusts without saying so on any line of
  output. The direct consequence: no outbound flow happens unless the operator configures it,
  and the receiving endpoint is always the operator's choice - including the choice to put it
  inside the country.
- Without `--tsa-ca-file`, RFC 3161 receipts are checked structurally only, and the run
  **says so out loud** rather than passing over it in silence.

### 6.4 What must not be co-located

These three constraints matter more than any packaging choice (container, Helm, systemd,
direct install). They come from
[architecture §3](../architecture/deployment.md#3-separation-of-duties) and
[threat model §5](../security/threat-model.md#5-an-attacker-who-can-write):

- **witness ↔ chain**: a witness installed from the same release, under the same authority as
  the chain server, proves nothing.
- **pin file ↔ writer**: if the writer can reach the pin state, pinning detects nothing.
- **A₀ ↔ a writing host**: a forward-secure seal key sitting on the host that writes the trail
  makes truncation undetectable again.

Every deployment form is only a way of making those three constraints the default instead of
something to remember.

---

## 7. Sources and verification

Retrieved **2026-09-07**.

| Source | Used for | Status |
|---|---|---|
| Decision 1671/QĐ-TTg of 28/08/2026 - [signed PDF](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/9/1671_qd-ttg_28082026-signed.signed.pdf) | all of §2: the six views, the 2030/2045 objectives, the nine pillars, the six measure groups, Appendix I indicators 7/14/15/32, Appendix II tasks 34, 63-66, 73, 81, 86-89, 94-96, Điều 2, Điều 3 | **official**, digitally signed by the Government Office (signature timestamp 03/09/2026), 64 pages, **scanned with no text layer** - content read from page images. The URL was checked: HTTP 200, `application/pdf`, `content-length` 25131696, a byte-exact match for the copy that was downloaded and read |
| Law on Artificial Intelligence No. 134/2025/QH15 - gazette text, **Công báo No. 40, 22-01-2026**, from that issue's landing page on `congbao.chinhphu.vn` | Điều 7(4), 7(5), 8, 9, 10(1), 10(3), 11, 12(2)(b), 12(4), 13, 14(1)(c)(d)(e), 14(2)(b), 26, 27(2), 27(3), 28(3), 34, 35(1) | **official gazette text, with a text layer** - the Vietnamese quoted here was copied rather than transcribed from an image, so it is character-accurate. **No file URL is given, deliberately**: the PDF is served from a CDN endpoint behind a signed query string that will not resolve for a later reader, so the citation is to the issue and its landing page rather than to a file |
| Decree 142/2026/NĐ-CP of 30/04/2026 - [signed PDF](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/4/142-2026-ndcp.signed.pdf) | Điều 6(1), 8(1)(a), 8(2)(b), 11(5), 12(6), 14(3)(b), 15(2)(c), 15(5)(b)(c), 16(2)(c), 19(1)-(4), 19(8), 20(3)(d), 20(6), 45, 46(1); forms appendix: AI01a, AI01b, AI02, AI08a | **official**, digitally signed; the pages listed in [§3.3](#33-which-of-the-five-were-read-in-the-original-and-which-were-not) read directly. **Scanned, with no text layer** - clause numbers and wording were read from page images, so a transcription slip is a real possibility here in a way it is not for the Law. The URL was checked: HTTP 200, `application/pdf`, `content-length` 3661910, a byte-exact match for the copy that was downloaded and read |
| Circular 05/2026/TT-BKHCN - National AI Ethics Framework (Law Điều 26) | effective date, existence of the instrument | **original not obtained** - secondary sources only (a commercial legal portal and news coverage). No article or clause number from the Circular is cited in this document, deliberately |
| Decision 33/2026/QĐ-TTg - list of high-risk AI systems (Law Điều 13(4); Decree Điều 7) | effective date, the sector groups | **original not obtained** - secondary sources only. The group list in [§3.3](#33-which-of-the-five-were-read-in-the-original-and-which-were-not) carries an `[Unverified]` tag; no clause number is cited |
| Decision 127/QĐ-TTg of 26/01/2021 | mentioned only because Decision 1671 Điều 3(2) replaces it | **not retrieved** - none of its content is used |
| `waxseal` at the current working-branch commit | the "what waxseal 0.1.5 does today" column in [§4](#4-coverage-matrix) | **read directly from the source tree in this repository**; every module path in the table can be checked by opening the file |

Two notes on source quality, stated plainly because this is where over-claiming is easiest:

1. Decision 1671 and Decree 142 are **scans with no text layer**. Their content was read from
   page images. For the longer verbatim quotations, errors at the level of diacritics and the
   occasional character are a real possibility; check the relevant page of the original before
   any formal use.
2. Law 134 is a gazette text with a text layer, so the quotations from the Law here are
   character-accurate.

---

## 8. What this document does **not** claim

| Not claimed | Why it has to be said |
|---|---|
| **That any obligation has been met** | no row in [§4](#4-coverage-matrix) is a compliance verdict. "Direct" means *the evidence speaks to the requirement's substance*, not *the requirement is discharged* |
| **That waxseal makes anyone compliant with anything** | compliance depends on governance, scope, policy, controls and legal interpretation - all outside the library, and a determination for the deploying institution's compliance and legal functions |
| **That Decision 1671 imposes any technical requirement** | it is a strategy. Presenting it as a requirements list would manufacture an obligation that does not exist, and then a promise to meet it |
| **That any particular system is or is not in the high-risk list** | the original of Decision 33/2026 was not read, and even if it had been, classification is the provider's responsibility under Law Điều 10(1) and Decree Điều 6(1), not a research document's |
| **That Circular 05/2026's content is as described here** | `[Unverified]` - not checked against the original. No article or clause number from the Circular is cited |
| **That waxseal shows an incident report was filed** | it shows that a *record* exists at a position and is unaltered. Filing is an act with an agency, and it happens off the trail |
| **That a deadline was missed** | timestamps on the trail are the writer's assertions, and the 72-hour window is a parameter the operator types. No waxseal output asserts that an obligation was breached |
| **That no record means nothing happened** | chain integrity is not trail completeness. A decision, an incident, or an intervention that was never written leaves no gap to detect |
| **That the human oversight mechanism was not disabled** | Law Điều 7(4) prohibits disabling the mechanism; waxseal only detects distortion of the *record*. A mechanism that is switched off writes nothing, and an empty chain still verifies `ok` |
| **That time on the trail is attested time** | `ts` is caller-asserted. Attested time comes only from an anchor, and only as an *upper bound* - "this root existed before time t" |
| **That waxseal prevents alteration** | waxseal is **tamper-evident, not tamper-proof**. An attacker with write access can rewrite the trail; anchoring and forward-secure seals bound that, and only if they live under a different authority. See [threat model §1](../security/threat-model.md#1-tamper-evident-is-not-tamper-proof) |
| **That waxseal qualifies as "Make in Viet Nam"** | `[Unverified]` - the recognition criteria and procedure were not checked. Decision 1671 Quan điểm 5 and Appendix II tasks 60 and 71 concern prioritising "Make in Viet Nam" products in public procurement; whether a project qualifies is an administrative conclusion, not a technical fact |
| **That a licensed Vietnamese TSA with a usable RFC 3161 endpoint exists** | `[Unverified]` - a question to check when designing an on-shore deployment, not something this document knows |
| **That this is legal advice** | it is not. This document names no institution, product or person, and it does not substitute for reading the originals |

### If you take one thing from this document

The sentence worth putting in front of a reviewer is narrow, and defensible precisely because
it is narrow:

> *This record - an AI decision, an incident, a human intervention - was written at this
> position in the chain, under this model version and this policy version, with this
> human-oversight status, bearing a timestamp asserted by the writer, and can be shown to be
> unaltered since - independently of the party that holds the log, and without disclosing any
> other record.*

Everything broader than that sentence - whether the system was classified correctly, whether
the report was filed, whether the review was real, whether the obligation was met - is
somebody else's control, and this document does not claim to cover it.
