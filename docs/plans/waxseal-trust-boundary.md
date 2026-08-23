# waxseal — Nâng cấp "trust boundary": attested time, Byzantine defense, threat model

## Context

Người dùng đặt 6 câu hỏi về giới hạn tin cậy của waxseal và yêu cầu một kế hoạch nâng cấp
đầy đủ để thư viện áp dụng được cho mọi ngành (đặc biệt banking, blockchain, AI agent).
Khảo sát hiện trạng (0.1.2 + Unreleased) cho thấy phần lớn nền tảng đã có:
checkpoint/anchoring (RFC 6962/9162), FssAgg `fs-hmac-agg-sha256-v1`, `.drops` completeness,
proof bundle, auditor report, decision log, compliance mapping. Các lỗ hổng còn lại:

| Câu hỏi | Hiện trạng | Việc cần làm |
|---|---|---|
| 1. Tamper-evident → "proof"? | Anchoring có, nhưng chỉ File/HTTP sink | Tamper-proof tuyệt đối là bất khả trong phần mềm thuần; thu hẹp bằng anchor đa trust-domain (RFC 3161, OpenTimestamps) + THREATMODEL.md chứng minh giới hạn |
| 2. Integrity ≠ completeness | Đã model đúng (`.drops`, `None ≠ 0`, gaps) | Chỉ cần tài liệu hoá trong THREATMODEL.md; không thêm code |
| 3. RFC 3161 attested time | `ts` là asserted; RFC 3161 chỉ nằm trong docs | `Rfc3161AnchorSink` + DER tối thiểu stdlib (quyết định của user) |
| 4. Byzantine chain server | REMOTE.md tuyên bố "trusted writer"; client chỉ check shape | TOFU pinned-head + witness cross-check (quyết định của user); chứng minh split-view là bất khả nếu không có kênh ngoài |
| 5. Attacker có quyền ghi | FssAgg có, nhưng SPEC §11 ghi rõ residual risk: replay `.sealagg` cũ + truncate | Bind aggregate vào checkpoint được anchor → anchor ngoài bắt được replay |
| 6. Không khẳng định nghĩa vụ | Report chưa có scope statement | Thêm dòng scope cố định vào report (md + json) |

Quyết định đã chốt với user:
- Đầu ra: kế hoạch nâng cấp đầy đủ (phân tích + code).
- RFC 3161: DER encoder/parser tối thiểu bằng stdlib; token lưu opaque; verify chữ ký đầy đủ uỷ quyền cho `openssl ts`/verifier inject.
- Blockchain: OpenTimestamps sink built-in + docs hướng dẫn sink cho chain khác.
- Byzantine: TOFU pinned-head **và** witness cross-check.

## Ràng buộc bất biến (CLAUDE.md)

- Zero runtime dependencies; domain/ thuần, không I/O, không import ports/adapters.
- SPEC.md append-only; golden vectors write-once; fingerprint registry append-only.
- Unknown/unparseable → unverifiable, không bao giờ "tampered"; `None ≠ 0`; fail-open phải được dán nhãn.
- Public API frozen — mở rộng phải sửa `tests/architecture/test_invariants.py` cùng commit kèm rationale.
- TDD bắt buộc, coverage ≥ 90%.
- Exit codes: 0 intact / 1 broken / 2 unverifiable-present / 3 path missing.

## Thứ tự triển khai

Mỗi phần là một chuỗi commit TDD độc lập, theo thứ tự: **P1 Scope statement** (nhỏ nhất,
chạm plumbing report mà các phần sau mở rộng) → **P2 TOFU pin** → **P3 FssAgg-anchor
binding** → **P4 Witness** → **P5 RFC 3161** → **P6 OpenTimestamps** → **P7 THREATMODEL.md
+ docs** (viết cuối để mô tả đúng những gì đã có).

---

## P1 — Scope statement (câu 6)

`src/waxseal/domain/report.py`:
- `SCOPE_STATEMENT: Final` — văn bản cố định: output chỉ attest tính toàn vẹn hash-chain và
  các phép đo completeness của entries ĐÃ GHI; không attest nghĩa vụ đã được đáp ứng, nội
  dung payload là đúng sự thật, hay sự kiện chưa ghi là không xảy ra.
- `SCOPE_ID: Final = "waxseal-scope-v1"` — handle máy-đọc-được; đổi văn bản = id mới
  (kỷ luật append-only).
- `to_json()`: field top-level `"scope": {"id", "statement"}`. `to_markdown()`: section
  `## Scope` cuối cùng (sau Sidecar checks, không đẩy verdict xuống).
- CLI `verify`: một dòng trailing `scope: ...` trên mọi verdict path (0/1/2) qua một helper
  duy nhất; exit codes không đổi. `tail/inspect/head/checkpoint` KHÔNG thêm (in data,
  không in verdict).

## P2 — TOFU pinned-head verification (câu 4a)

Pin = một `Checkpoint` do chính verifier tính và lưu ở trust domain của verifier
(tương tự `known_hosts` của SSH). Pin check = `verify_checkpoint(fetched_hashes, pin)`
với vocabulary lỗi riêng — không đụng bộ reason `anchor_*` đã đóng băng.

**File mới `src/waxseal/domain/pinning.py`** (thuần, qua `TestDomainPurity`):
- `PinState(target, chain_id, checkpoint, pinned_ts)`, `PIN_STATE_VERSION = 1`.
- `check_pin(entry_hashes, pin) -> str | None` — map reason:
  `anchor_beyond_head → "pin_beyond_head"` (rollback/truncation),
  `anchor_entry_hash_mismatch`/`anchor_root_mismatch → "pin_mismatch"` (viết lại lịch sử),
  `malformed_checkpoint → "malformed_pin"`.
- `render_pin_state`/`parse_pin_state` — JSON versioned; `PinVersionUnknown` là type RIÊNG
  với `PinMalformed`: version tương lai → unverifiable-by-name (beads rule), không phải break.

**File mới `src/waxseal/adapters/pinstore.py`**: `FilePinStore.load() -> PinState | None`
(None = chưa có file, first use), `save()` qua `atomic_write_bytes(..., 0o600)`
(atomic.py vẫn là chủ duy nhất của `os.replace`).

**CLI `waxseal verify <path|url> --pin <statefile>`** (path tường minh, không default):

| Trạng thái | Hành vi | Exit |
|---|---|---|
| Chưa có pin file | TOFU: verify xong, nếu 0/2 thì ghi pin; in nhãn `PIN INITIALIZED (trust-on-first-use)...` — không bao giờ im lặng | theo chain |
| Pin khớp | in `pin ok (seq N)`; **auto-advance** pin chỉ khi verdict tổng 0/2 VÀ anchors (nếu yêu cầu) pass | theo chain |
| `pin_mismatch` / `pin_beyond_head` | lịch sử đã-xác-minh bị viết lại / trail ngắn hơn đã-xác-minh | **1** |
| Pin file hỏng | `malformed_pin` — KHÔNG re-pin, không tự sửa (chống re-pin attack: kẻ ghi đè pin file không được âm thầm hạ cấp về TOFU) | **1** |
| Pin version lạ (`v > 1`) | `pin_version_unknown — NOT evidence of tampering`; không check, không update | **2** |
| `target`/`chain_id` không khớp | từ chối check lẫn update — quyết định của operator | **1** |

Ghi chú "CLI never writes to the log": pin file là state của VERIFIER, không phải log hay
sidecar của log — ghi vào SPEC §13 + docstring cli.py (tiền lệ: `anchor` đã ghi `.anchors`).
`AuditReport` thêm `pin: CheckSummary | None = None` (AuditReport không nằm trong `__all__`
frozen → không cần sửa test_invariants).

## P3 — FssAgg-in-anchor binding (câu 5)

**Phát hiện thiết kế quyết định hình dạng**: KHÔNG được anchor giá trị `mu` thô — SPEC §11
cấm persist `mu_i` trung gian vì kẻ truncate có thể copy `mu_{t'}` từ record append-only và
viết lại `.sealagg` để pass `verify_aggregate` trên trail đã cắt. Vậy anchor một
**commitment**, không phải giá trị:

```
AGG_COMMIT_FRAME_PREFIX = b"waxseal-aggcommit-v1\n"
agg_commit = hex(sha256(PREFIX || u64be(2) || lp(str(epoch)) || lp(agg)))
```

Verifier giữ `initial_key` replay fold (máy móc `verify_aggregate` sẵn có) và so commitment;
kẻ đọc anchor stream không thu được gì fold tiếp được.

**Chọn Option A — frame checkpoint v2** (thay vì nhét JSON keys vào record `.anchors`):
sink ký-bytes (TSA RFC 3161, OTS, git) witness đúng `sha256(checkpoint_frame)`, nên binding
phải nằm TRONG frame; JSON side-channel sẽ hở đúng với lớp sink quan trọng nhất.
- `CHECKPOINT_FRAME_PREFIX_V2 = b"waxseal-checkpoint-v2\n"`; `Checkpoint` thêm
  `agg_commit: str | None = None`, `agg_epoch: int | None = None` (additive, default None →
  `checkpoint_frame` trả ĐÚNG bytes v1 như cũ — golden vectors bất biến).
- Cả hai agg field khác None → frame v2: prefix v2 + u64be(5) + 5 trường lp.
- `sealing.py` thêm `aggregate_commit(epoch, agg) -> str` và
  `verify_anchored_aggregate(attestations, initial_key, *, agg_start, anchored_epoch,
  anchored_commit) -> str | None` — fail closed; reasons: `malformed_anchored_aggregate`,
  `anchored_aggregate_epoch_mismatch` (chính là ca replay-sealagg-cũ + truncate),
  `anchored_aggregate_mismatch`.
- `log.py::anchor()`: nếu attestor có `read_aggregate()` → build checkpoint kèm commit.
  Method mới `verify_anchored_aggregates(*, initial_key) -> AttestResult`.
- `FileAnchorSink`: record `"v": 2` khi có agg fields (giữ nguyên shape v1 cho checkpoint
  thường); `records()` version-aware — `"v"` lạ → đánh dấu unverifiable, exit 2, không crash.
  `HTTPAnchorSink` thêm keys vào POST body khi có (REMOTE.md: receiver MUST ignore unknown keys).
- CLI: `verify --anchors` trên record v2 check bộ ba v1 và in
  `agg binding present but NOT checked (no seal key available to the CLI)` — non-check có nhãn.
  Verify anchored-aggregate là API-level (CLI `--seal-key-file` là follow-up riêng, không argv).
- Public API: `Checkpoint/checkpoint_for/checkpoint_frame` đã export, mở rộng additive →
  KHÔNG đổi `__all__`; không export `aggregate_commit` (giữ posture của frozen-set).
- Vectors: THÊM (không sửa) vectors frame v2 + known-answers `aggregate_commit`.

## P4 — Witness cross-check (câu 4b)

**Port mới `src/waxseal/ports/witness.py`**: `WitnessReader` Protocol —
`name: str`, `fetch() -> Sequence[Checkpoint]` (oldest first; raise khi unreachable —
caller ghi "unreachable", không bao giờ là pass). Publish không cần port mới: witness LÀ
một `AnchorSink` ở chiều ghi.

**REMOTE.md §8 mới (append-only)** — witness read-back:
`GET <anchor-url>` → `200 {"checkpoints": [{seq, entry_hash, root, ...ignore extra}]}`,
`404` = chưa thấy gì (không phải lỗi). Auth Bearer như cũ. Normative: witness chỉ có giá trị
khi là trust domain KHÁC chain server (mirror wording §7).

**Adapter `src/waxseal/adapters/witness.py`**: `HTTPWitness` = AnchorSink + WitnessReader
(anchor delegate logic HTTPAnchorSink; fetch GET, 404 → [], parse fail → RemoteError).

**Domain `src/waxseal/domain/witnessing.py`** (thuần):
`WitnessVerdict(name, status: "consistent"|"inconsistent"|"unreachable", checked, reason,
broken_seq)`; `check_witnessed(entry_hashes, checkpoints, *, name)` — chạy
`verify_checkpoint` cho từng checkpoint witnessed (với full local hashes, đây chính là mệnh
đề `verify_consistency` chứng minh, không cần sinh proof để tự verify).
`unreachable` quyết định ở tầng CLI/adapter, không ở domain.

**CLI**: `waxseal anchor <path> --witness <url>` (lặp được) — publish, fail → exit 1;
`waxseal verify <path|url> --witness <url>` — per-witness line: consistent / `INCONSISTENT
at seq=N: <reason> — evidence of split-view or history rewrite` → exit **1** /
`unreachable — NOT checked` (in luôn, không đổi exit; `--strict-witness` defer).
`AuditReport.witnesses: tuple[WitnessVerdict, ...] | None`.

**Giới hạn còn lại phải ghi rõ (vào SPEC §14 + THREATMODEL)**: (a) N witness thông đồng
với server — witness thu hẹp split-view, không loại bỏ trust; (b) eclipse client — kẻ nắm
toàn bộ đường mạng giả được mọi witness (urllib có TLS nhưng không CA-pinning);
(c) cửa sổ sau checkpoint cuối chưa được witness; (d) witness nói dối bằng cách bớt
checkpoint → coverage giảm âm thầm, báo `checked=K`, không bao giờ là "complete".

## P5 — RFC 3161 attested time (câu 3)

Nhờ P3, sink ký-bytes attest `sha256(checkpoint_frame(cp))` — frame v2 đã chứa agg binding,
nên TSA token đồng thời niêm phong cả aggregate commitment.

**File mới `src/waxseal/domain/rfc3161.py`** (thuần, chỉ hashlib/dataclasses/typing):
- `encode_timestamp_req(message, *, nonce: int | None = None) -> bytes` — DER TimeStampReq:
  version=1, messageImprint = AlgorithmIdentifier(sha256 OID `2.16.840.1.101.3.4.2.1` +
  NULL params) + OCTET STRING sha256(message), nonce INTEGER optional (minimal two's
  complement, pad `00` khi MSB set), certReq=TRUE. Nonce được inject, không sinh trong
  domain (tinh thần rule 8). Helpers riêng: `_tlv`, `_der_len`, `_der_int`.
- `TimestampToken(status, gen_time, gen_time_iso, imprint_sha256, serial_number, nonce)`.
- `parse_timestamp_resp(der) -> TimestampToken | None` — walk tối thiểu:
  TimeStampResp → PKIStatusInfo.status; ContentInfo OID phải là id-signedData →
  SignedData → EncapsulatedContentInfo OID phải là id-ct-TSTInfo → OCTET STRING TSTInfo →
  version/policy(skip)/MessageImprint (sha256 OID, params NULL **hoặc absent** — biến thể
  format không phải tampering, đúng lớp migration-060)/serialNumber/GeneralizedTime genTime
  (phải kết thúc `Z`, chấp nhận fractional seconds)/optionals theo tag để tìm nonce.
  Certificates/signerInfos bị skip opaque.
- `check_timestamp_resp(der, expected_message, *, expected_nonce=None) -> str | None` —
  reasons: `malformed_token` | `timestamp_rejected` | `receipt_imprint_mismatch` |
  `nonce_mismatch` | `unsupported_digest_algorithm`. **Không bao giờ raise** trên input bất
  kỳ: definite length only (reject `0x80` indefinite, `>0x84`), bounds-check mọi TLV,
  reject trailing bytes, backstop `try/except Exception → malformed_token`; không reason
  nào chứa chữ "tamper".
- **Ngoài scope, ghi rõ trong docstring + SPEC**: verify chữ ký CMS/X.509 — uỷ quyền
  `openssl ts -verify -in receipt.tsr -data frame.bin -CAfile tsa-chain.pem` (recipe trong docs).

**File mới `src/waxseal/adapters/rfc3161.py`**: `Rfc3161AnchorSink(url, *, transport=None,
nonce_fn=None, timeout=10.0)` — entropy ở adapter, injectable. `anchor(cp)`: POST TSQ
(`Content-Type: application/timestamp-query`, `Accept: application/timestamp-reply`) qua
Transport; non-200 → raise; `check_timestamp_resp(body, frame, expected_nonce)` khác None
→ raise (không bao giờ lưu token không attest đúng frame này); receipt =
`"rfc3161:" + base64(body)`.

**Seam lưu receipt — hoà giải với P3/P4 (cùng chạm `adapters/anchors.py`)**:
`AuditLog.anchor()` hiện vứt receipt. Thêm vào `anchors.py`:
- `AnchorRecord(checkpoint, sink, receipt, ts)` + `read_anchor_records(trail) -> Iterator[AnchorRecord]`
  — reader DUY NHẤT, tolerant record cũ (receipt null) **và** version-aware cho record
  `"v": 2` của P3 (`"v"` lạ → unverifiable marker, exit 2, không crash). `FileAnchorSink.records()`
  reimplement trên hàm này.
- `RecordingAnchorSink(trail_path, external: AnchorSink, *, now_fn=None)` — gọi sink ngoài,
  external raise → propagate và KHÔNG ghi record; thành công → append record kèm
  `sink=external.name`, receipt, 0600.

**CLI `verify --anchors` — dispatch theo prefix receipt** (mở rộng `_anchor_summary`,
sau bước `verify_checkpoint` sẵn có):

| Receipt | Kết quả | Exit |
|---|---|---|
| null / sink file/http | như hiện tại | như cũ |
| `rfc3161:` hợp lệ, check pass | `attested time (RFC 3161, structural only — signature NOT verified): <gen_time_iso>` | 0 |
| `rfc3161:` malformed/rejected/unsupported-digest | unverifiable receipt — biến thể format TSA không được gây báo động giả (lớp unknown-fingerprint) | **2** |
| `rfc3161:` `receipt_imprint_mismatch`/`nonce_mismatch` | ANCHOR BROKEN — checked-and-false: token không attest record cạnh nó (kèm caveat chưa verify chữ ký) | **1** |
| `ots:` | note `pending OpenTimestamps proof (not checkable by this library...)` — opaque-by-design ≠ báo động | như cũ |
| prefix lạ | unverifiable receipt (forward-compat, RFC 6962 §4.6) | 2 |

Lưu ý tương phản có chủ đích: sidecar JSON hỏng (format CỦA TA) vẫn là `malformed_anchor`
→ exit 1 như hiện tại; bytes bên-thứ-ba không đọc được → exit 2.

**CLI `waxseal anchor <path> [--tsa-url URL | --ots-calendar URL]`** — build
`RecordingAnchorSink(trail, Rfc3161AnchorSink(...)/OtsAnchorSink(...))`; không flag = giữ
`FileAnchorSink` như cũ; network fail → exit ≠ 0, không ghi record.

**Vectors**: file MỚI `tests/vectors/rfc3161.json` (thêm file = "gain vectors", hợp lệ;
`vectors.json` bất biến): TSQ vectors (no-nonce + fixed-nonce, frame lấy từ entry hashes
đã đóng băng), một TSR thật capture MỘT LẦN từ TSA công cộng (vd freetsa.org) kèm expected
fields, corpus malformed (mọi truncation prefix + mutations). Script cross-check độc lập
`tools/gen_rfc3161_vectors.py` so bytes với `openssl ts -query -data frame.bin -sha256
-cert -no_nonce` (openssl không inject được nonce cố định → chiều nonce cross-check ngược:
parser của ta đọc query random-nonce của openssl; ghi rõ bất đối xứng này trong script).

Quyết định lưu token: trong field `receipt` của record `.anchors` (đã tồn tại, per-checkpoint,
append-only, 0600; TSR 1–6 KB → b64 ổn cho JSONL) — KHÔNG tạo file `.tsr` rời (tránh chủ
sở hữu atomic-write thứ hai + linkage dangle). Extract cho openssl: one-liner base64 trong
docs; subcommand `anchor-receipt` là stretch ngoài critical path.

## P6 — OpenTimestamps sink + docs blockchain (yêu cầu blockchain)

**File mới `src/waxseal/domain/ots.py`** (thuần, mỏng): `OTS_ACCEPT =
"application/vnd.opentimestamps.v1"`, `ots_digest(message) -> bytes` (32 bytes sha256 của
checkpoint frame). **Cố ý không viết parser proof OTS**: serialization ops do calendar
kiểm soát, reimplement một phần sẽ chế ra verdict "malformed" giả — receipt opaque
by design, có nhãn (rule 6).

**File mới `src/waxseal/adapters/ots.py`**: `OtsAnchorSink(calendar_url, *, transport=None,
timeout=10.0)` — POST 32 bytes raw tới `<calendar>/digest`, header `Accept:
application/vnd.opentimestamps.v1` (client chuẩn không set Content-Type — test không assert
nó); non-200/body rỗng → raise; receipt = `"ots:" + base64(body)` (proof PENDING).
Một calendar mỗi sink; redundancy = nhiều anchor event (MultiAnchorSink là follow-up).

**Giới hạn upgrade (library làm gì vs docs nói gì)**: library lưu pending proof và DỪNG —
không poll calendar, không hoàn tất proof. Docs nói rõ: proof hoàn tất sau Bitcoin
confirmation (giờ→ngày), hoàn tất/verify bằng `opentimestamps-client` (`ots upgrade`/`ots
verify`).
- Wire protocol `/digest` đã được agent xác minh từ source opentimestamps-server
  (`otsserver/rpc.py`) + python-opentimestamps (`calendar.py`), 2026-08-23.
- [Unverified] Ngữ nghĩa commitment cho GET `/timestamp/<hex>` khi upgrade và recipe dựng
  file `.ots` detached từ raw calendar response — phải xác minh với `python-opentimestamps`
  trước khi publish recipe; [Unverified] danh sách URL calendar pool công cộng — sink nhận
  URL bắt buộc qua constructor, docs liệt kê pools kèm ghi chú "verify current".

**Docs mới `docs/anchoring-external-time.md`** (+`.vi`): recipe openssl ts delegation,
recipe OTS upgrade/verify (kèm nhãn Unverified ở trên), pools, và hướng dẫn viết AnchorSink
cho chain khác (EVM/Hyperledger/private) — khớp mục 6 của P7. Hook `Verifier` injectable
cho verify path: **defer** (YAGNI, CLI chưa có chỗ config).

## P7 — THREATMODEL.md + docs (câu 1, 2, 4, 5, 6)

`docs/security/threat-model.md` (+`.vi`), cấu trúc:
1. **Tamper-evident vs tamper-proof** (câu 1): tamper-proof tuyệt đối là bất khả trong
   phần mềm thuần trên storage kẻ tấn công ghi được — chứng minh bằng lập luận: mọi bytes
   local đều rewrite được; cái duy nhất phần mềm làm được là làm cho rewrite **bị phát hiện**
   khi so với một bản sao nằm ngoài quyền ghi của kẻ tấn công. "Proof" thực tế = tổ hợp:
   anchor đa trust-domain (RFC 3161 TSA / OTS-Bitcoin / witness) + seal key tách quyền
   quản trị + WORM storage (S3 Object Lock — docs, không code).
2. **Chain integrity ≠ trail completeness** (câu 2): seq liền kề không chứng minh không có
   write bị drop trước khi vào chain; `.drops` là measured minimum; `None ≠ 0`; bảng
   "verify ok nghĩa là gì / không nghĩa là gì".
3. **Byzantine chain server** (câu 4): ma trận detect được (rollback, rewrite, reorder,
   truncate — bằng pin/anchor/consistency) vs bất khả (split-view không kênh ngoài — nêu
   lập luận fork-consistency [Mazières & Shasha, SUNDR]: server kiểm soát mọi response thì
   hai client không giao tiếp không thể phân biệt hai lịch sử fork; witness = kênh ngoài).
4. **Attacker có quyền ghi** (câu 5): bảng quyền hạn attacker × cơ chế × kết quả;
   FssAgg + anchor binding (P3) đóng ca replay; điều kiện tiên quyết: anchor sink/witness/
   seal key nằm dưới quyền quản trị KHÁC.
5. **Non-assertion** (câu 6): scope statement, hướng dẫn trích dẫn đúng cách output waxseal
   trong audit/compliance.
6. Hướng dẫn viết AnchorSink cho chain khác (EVM contract event, Hyperledger, private chain)
   — phần "docs" của quyết định blockchain.

## SPEC.md sections mới (append-only)

§13 Pinned-head (TOFU) · §14 Witness cross-check · §15 Checkpoint v2 + aggregate binding ·
§16 Scope statement · §17 RFC 3161 structural anchoring (TSQ byte layout normative, receipt
format, reason names + exit classes, honest limits + recipe openssl) · §18 OpenTimestamps
(digest POST, receipt pending, opaque-present semantics, các mục [Unverified]).
REMOTE.md: §8 witness read-back, §9 anchor POST body MAY carry agg fields.
(Số section thực tế = nối tiếp SPEC hiện hành; hai thiết kế nhánh dùng số trùng nhau,
đánh lại khi implement.)

## Test plan (TDD, mỗi test viết fail trước; coverage ≥ 90)

- P1: `"scope"` trong JSON, `## Scope` trong markdown, trailing line verify trên exit 0/1/2,
  exit codes không đổi.
- P2: domain reason mapping (4 ca), round-trip parse/render, malformed ≠ unknown-version;
  pinstore atomic 0600; CLI: TOFU label + file tạo, auto-advance, fail KHÔNG advance
  (assert bytes pin file không đổi sau exit 1), từng reason → đúng exit, remote qua
  `FakeChainServer` gồm repro server-rewrite-history.
- P3: frame v1 bytes bất biến khi agg=None (regression với frozen vectors), vectors v2,
  `verify_anchored_aggregate` happy / replay-sealagg-cũ+truncate → `anchored_aggregate_epoch_mismatch`
  / commit giả / malformed không raise; records `"v"` lạ → unverifiable không crash.
- P4: domain trichotomy (consistent/inconsistent đúng seq+reason/checked=0 không là pass);
  adapter GET/404/parse-fail/auth/ignore-unknown-keys; CLI multi-witness mixed verdicts.
- P5 domain: TSQ hex đóng băng (no-nonce + fixed-nonce + nonce MSB pad + nonce 0),
  determinism; parse golden TSR thật (status/genTime/imprint/serial), biến thể
  grantedWithMods + params-absent; checked-false: wrong message → `receipt_imprint_mismatch`,
  wrong nonce, status-2 → `timestamp_rejected`, sha1 OID → `unsupported_digest_algorithm`;
  corpus malformed (empty, mọi truncation prefix, indefinite length, length vượt buffer,
  sai OID, genTime thiếu Z, trailing garbage) + hypothesis fuzz `binary()`: không exception,
  reason không chứa "tamper".
- P5 adapters: sink POST đúng bytes/headers, receipt đúng format, non-200/rejected/mismatch
  raise; `RecordingAnchorSink` ghi record + 0600, external raise → sidecar không đổi;
  `read_anchor_records` đọc record cũ lẫn mới.
- P5 CLI: bảng exit-code receipt ở trên đóng băng bằng test (kể cả "output chứa 'attested
  time' VÀ 'signature NOT verified'"); sidecar legacy → hành vi byte-identical hôm nay.
- P6: sink POST đúng 32 bytes raw + Accept header (không assert Content-Type), 200 →
  `ots:` receipt, non-200/empty raise; CLI in note pending, exit không đổi.
- Architecture: domain purity cho pinning/witnessing/rfc3161/ots; `__all__` không drift
  (hoặc update cùng commit kèm rationale).

## Quyết định mở (khuyến nghị kèm)

1. Nghĩa exit 2 mở rộng thành "intact nhưng một check được yêu cầu là unverifiable-by-name"
   (pin version lạ, receipt không đọc được) → chấp nhận + ghi SPEC (exit code mới phá
   script nhiều hơn); áp dụng nhất quán cho cả P2 lẫn P5.
2. Pin cùng đĩa với trail local không phải trust domain khác → SHOULD-language + nhãn trong
   output TOFU.
3. `--strict-witness` (all-unreachable → escalate) → defer.
4. CLI `--seal-key-file` cho anchored-aggregate → defer (API-only trước; secret-handling
   review riêng).
5. Structural check RFC 3161 không phải authentication: kẻ viết lại được CẢ record lẫn
   receipt chỉ bị bắt bởi verify đầy đủ được uỷ quyền — nêu trong SPEC honest-limits và
   trong mọi dòng output verify liên quan.
6. [Unverified] hai điểm OTS (commitment upgrade, pool URLs) — giữ nhãn trong SPEC/docs
   cho tới khi implementer xác minh với python-opentimestamps.
7. Receipt nhiều KB trong `.anchors` với `anchor_every=1` trên trail nóng → note trong docs.
8. Lập luận bảo mật agg-commit ([Inference] từ model SPEC §11: commitment che `mu`, replay
   bị bắt qua `anchored_epoch` vs số row khả dụng) — restate trong SPEC §15 và cross-check
   khi review trước freeze v1.0.

## Verification cuối

`uv run pytest --cov=waxseal` toàn xanh + floor 90; chạy lại
`examples/banking-poc/tamper_demo.py` (8 scenario tự assert exit codes);
script cross-check vectors độc lập vẫn pass; `waxseal verify` trên trail cũ (pre-upgrade)
cho kết quả byte-identical trừ dòng scope.
