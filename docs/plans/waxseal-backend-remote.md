# Kế hoạch: Cải thiện waxseal từ nền tảng học thuật + RemoteBackend + kiến trúc adapter

## Context

DESIGN.md của waxseal tự ghi sẵn các "con đường nâng cấp" (anchoring §3, FssAgg §7, Merkle
graduation §2, đo completeness §8). User muốn hiện thực chúng, kèm một remote chain audit
backend (tham chiếu chainproof.ai — đã xác minh qua WebFetch 2026-08-21: dịch vụ hosted
hash-chain REST, tự thừa nhận "ChainProof only knows what your agent tells it", không có
anchoring), và chuẩn hóa kiến trúc clean cho nhiều adapter local + remote.

**Quyết định đã chốt với user (owner):**
- Mức độ: code + tests (TDD, coverage ratchet ≥90% branch).
- Remote: Backend đầy đủ (RemoteBackend HTTP ngang hàng JSONL/SQLite/S3) — threat model
  ghi rõ: server là writer phải được tin; tài liệu bắt buộc khuyến nghị anchor head độc lập.
- Làm cả 4 cải thiện: anchoring tự động, FssAgg aggregate, Merkle graduation, đo drops.
- Normative text: wire contract → **REMOTE.md** (file mới); 4 format mới → **append SPEC.md
  §9–§12** (owner đã cho phép; chỉ THÊM mục, không sửa nội dung/vector hiện có).
- CLI hỗ trợ target remote NGAY đợt này (verify/tail/inspect/head/checkpoint nhận URL).

**Ràng buộc bất biến (CLAUDE.md):** dependencies=[] (client inject hoặc stdlib);
layer DAG domain←ports←adapters←cli; registry/vectors append-only; verify chỉ báo cáo;
None≠0, unverifiable≠tampered; fail-open có nhãn; read-tail+append = 1 critical section
kèm falsifiability receipt; public API frozen bởi TestPublicApiFrozen (sửa test cùng
commit + rationale); KHÔNG đụng tests/vectors/**, domain/fingerprint.py, CLAUDE.md, LICENSE.

**Lưu ý hook:** `.claude/settings.json` có PreToolUse hook chặn Edit/Write lên SPEC.md.
Owner đã phê duyệt append §9–§12 → bước M8 sẽ tạm sửa settings.json để bỏ SPEC.md khỏi
danh sách chặn (hoặc user tự gỡ), append xong có thể khôi phục. Không đụng các path khác.

## Hiện trạng then chốt (đã khảo sát, giữ nguyên khi thực thi)

- `ports/backend.py`: WriterBackend.append(build: Callable[[int,str],Entry])->Entry —
  backend giữ MỘT critical section; ReaderBackend.entries() theo thứ tự ghi (không sort seq).
  S3 gọi build() nhiều lần khi thua CAS race — hợp đồng re-entrancy CHƯA ghi trong docstring.
- Envelope `_to_obj/_from_obj` copy-paste ở jsonl.py:59-90 và s3.py:131-162; guard
  payload-None lặp 4 chỗ; dựng Entry thủ công 5 chỗ.
- `AuditLog.open` (log.py:71-94): if/elif đuôi file — nơi duy nhất auto-construct backend.
- CLI (cli.py:58-64): Path.exists() → exit 3 TRƯỚC khi mở; test `head` so dict EXACT
  (tests/test_cli.py:99-115) → lệnh mới, không sửa head.
- `domain/anchoring.py` ĐÃ CÓ Merkle RFC 6962 thuần: batch_root/membership_proof/
  verify_membership (public API); THIẾU consistency proof, Checkpoint, persistence.
- Attestation đầy đủ (FileAttestor, sidecars .attest/.sealkey, verdicts theo 3 CVE journald);
  2 falsifiability receipts hiện có (test_concurrency.py:1-7, test_sealed_log.py:302-311).
- Kiểm chéo vector độc lập: tools/gen_vectors.py (không import waxseal) + FROZEN_VECTORS_SHA256.
- Test scaffolding chuẩn: build_entry (tests/adapters/test_jsonl.py:12), fake high-fidelity
  (FakeS3Client test_s3.py:37-75; FakeConn assert lock-trước-đọc), suite thật gated env
  (WAXSEAL_PG_DSN), parity entry_hash chéo backend, tamper matrix.
- pyproject: chỉ extra `dev`; architecture test cấm import non-stdlib trong src/
  (urllib/http.client OK trong adapters/, cấm trong domain/).
- Doc drift: `__init__.py:3` nêu tests/architecture/test_public_api.py (không tồn tại;
  thật là test_invariants.py) — sửa ở M8.

## Milestones (mỗi milestone: test trước, code sau, xanh + coverage ≥90 rồi mới sang tiếp)

### M0 — Groundwork refactor (không đổi hành vi, byte-identical)
- MỚI `src/waxseal/adapters/_envelope.py`: `to_obj(entry, *, backend) -> dict` (mang guard
  payload-None, message giữ chữ "payload"), `from_obj(obj) -> Entry`,
  `entry_from_fields(...) -> Entry` (cho row SQL).
- MỚI `tests/adapters/test_envelope.py`; MỚI `tests/adapters/backend_contract.py`:
  class `BackendContractTests` (không prefix Test) + fixture `backend` abstract; case:
  append đầu = (0, genesis); nối tiếp đúng; entries() theo thứ tự ghi; payload-None bị
  từ chối; round-trip entry_hash; smoke N-thread không fork. Subclass cho memory/jsonl/
  sqlite/s3-fake/postgres-fake trong các file test hiện có.
- SỬA jsonl.py + s3.py (dùng _envelope, xóa bản chép), sqlite.py + postgres.py
  (entry_from_fields), `ports/backend.py` (CHỈ docstring: "build MAY be invoked more than
  once… builders MUST be side-effect-free and deterministic given (seq, prev_hash)").
- Gate: mọi test layout/line hiện có pass KHÔNG sửa; không "cải tiến" key order của JSON.

### M1 — Domain thuần: Checkpoint + consistency proof (nền cho anchoring & Merkle)
- MỚI `src/waxseal/domain/checkpoint.py`:
  `CHECKPOINT_FRAME_PREFIX = b"waxseal-checkpoint-v1\n"`;
  `Checkpoint(seq, entry_hash, root)` frozen+slots (root = batch_root toàn bộ entry_hash);
  frame = prefix || u64be(3) || lp(str(seq)) || lp(entry_hash) || lp(root) — tái dùng
  lp/u64be từ domain/hashing.py; KHÔNG timestamp (frame tái lập được từ trail; dịch vụ
  anchor cung cấp thời gian);
  `checkpoint_frame(cp)`, `checkpoint_for(hashes)` (ValueError khi rỗng),
  `verify_checkpoint(hashes, cp) -> str|None` fail-closed, reasons: anchor_beyond_head |
  anchor_entry_hash_mismatch | anchor_root_mismatch | malformed_checkpoint.
- SỬA `domain/anchoring.py` (append): `consistency_proof(hashes, old_size)` (RFC 6962
  §2.1.2; IndexError khi old_size ngoài [1, n] — giống membership_proof) và
  `verify_consistency(old_root, old_size, new_root, new_size, proof) -> bool`
  (RFC 9162 §2.1.4.2; fail-closed, không bao giờ raise — giống verify_membership).
- Public API thêm: `Checkpoint, checkpoint_frame, consistency_proof, verify_consistency`
  → sửa `__init__.py` + `tests/architecture/test_invariants.py:95-111` CÙNG COMMIT, kèm
  rationale (DESIGN.md §2 trigger 1-2, §3). AnchorSink/DropRecorder KHÔNG vào __all__
  (tiền lệ Signer/Verifier: deep-import).
- Test: `tests/domain/test_checkpoint.py` (byte-exact frame pinned; ma trận reason;
  fail-closed); `test_anchoring.py` append TestConsistencyKnownAnswerVectors (chép từ
  transparency-dev/merkle — cùng nguồn vectors hiện có; kiểm chéo bằng script tools/
  trước khi pin; sau đó write-once), RoundTrip (mọi cặp old/new size 1..~66),
  TamperRejection (root sai, proof cắt/nối, size đảo, non-hex, suffix-rewrite fail).

### M2 — CLI `waxseal checkpoint`
- SỬA cli.py: subcommand mới in EXACT `{"seq": N, "entry_hash": "...", "root": "..."}`;
  exit 0; exit 1 trail rỗng; exit 3 path không tồn tại (guard sẵn có). KHÔNG đụng `head`.
- Test tests/test_cli.py::TestCheckpoint: exact-dict; root == batch_root(hashes);
  empty→1; missing→3; bytes của trail không đổi sau khi chạy (chứng minh read-only).

### M3 — Anchoring tự động hóa
- MỚI `src/waxseal/ports/anchor.py`: `AnchorSink` Protocol: attr `name: str`;
  `anchor(checkpoint: Checkpoint) -> str|None` (receipt opaque hoặc None; raise khi fail).
  Docstring nêu OTS/RFC3161/git là sink do user tự hiện thực (cần tooling ngoài).
- MỚI `src/waxseal/adapters/anchors.py`: `FileAnchorSink(trail_path, *, now_fn=None)`
  → sidecar `<trail>.anchors` JSONL O_APPEND 0600 (pattern attest.py:87), record sorted-keys:
  `{"entry_hash","receipt","root","seq","sink":"file","ts","v":1}`; `records()` để verify.
  (HTTPAnchorSink để M6 — dùng chung transport của RemoteBackend.)
- SỬA log.py: `anchor_sink=None, anchor_every=None` (init + open); `anchor() -> Checkpoint`
  (ValueError khi trail rỗng/thiếu sink); `anchor_failures` property; anchor_every=N chạy
  best-effort NGOÀI _append_lock sau append thành công khi (seq+1)%N==0; lỗi không bao giờ
  raise ra append/try_append — đếm anchor_failures (tiền lệ attest_failures). Duplicate
  anchor do race = vô hại (nội dung idempotent), có test ghi nhận.
- SỬA cli.py: `waxseal anchor <path>` (append sidecar qua FileAnchorSink, in checkpoint
  JSON ra stdout để pipe `ots stamp`…; exit 0/1-rỗng/3-missing; ghi chú: sidecar ≠ log —
  cùng lớp với .attest/.sealkey); `waxseal verify --anchors <path>`: sau verdict chain,
  chạy verify_checkpoint cho từng record với hash ĐỌC LẠI từ trail; reason bất kỳ →
  `ANCHOR BROKEN at seq=…: <reason>` exit 1; record hỏng → malformed_anchor exit 1
  (verdict, không crash); không có sidecar → "no anchors found (anchor coverage
  unmeasured)" + GIỮ exit code của chain (absence ≠ failure); ok → "anchors ok
  (checked=K, latest=seq S)". Không exit code nào đổi nghĩa.
- Tamper matrix (mỗi dòng 1 test trong tests/test_cli.py::TestVerifyAnchors +
  tests/test_anchored_log.py): suffix rewrite sau anchor → anchor_root_mismatch;
  truncate qua anchor → anchor_beyond_head; tráo entry cùng seq → anchor_entry_hash_mismatch;
  record rác → malformed_anchor không crash; forge NHẤT QUÁN cả .anchors + chain →
  KHÔNG phát hiện local (honest-limit test + ghi rõ: bảo mật nằm ở receipt/bản sao ngoài).
- Falsifiability receipt: test thread anchor_every (N thread × M append → không fork,
  số anchor trong dung sai duplicate) ghi nhận fail khi bỏ _append_lock (chạy đo thật,
  ghi ngày + số lần vào docstring).
- Receipt verification (OTS/TSA proof) NGOÀI phạm vi verify --anchors — ghi trong help + SPEC §9.

### M4 — FssAgg aggregate (`fs-hmac-agg-sha256-v1`)
Quyết định chịu lực: accumulator PHẢI keyed bằng epoch key và CHỈ lưu bản mới nhất
(file replace-only) — lưu mu per-record sẽ tự mở lại lỗ truncation (attacker copy
mu_{t'-1} từ record); fold không key thì ai cũng refold được từ tag công khai.
- SỬA `domain/sealing.py` (append): `FS_HMAC_AGG_SCHEME`, `AGG_FRAME_PREFIX =
  b"waxseal-agg-v1\n"`, `AGG_GENESIS = "0"*64`;
  `mu_i = hex(HMAC-SHA256(A_i, AGG_FRAME_PREFIX || bytes.fromhex(mu_{i-1}) || lp(value_i)))`
  với value_i = attestation.value đã lưu (fold tổng quát mọi scheme, epoch clock đã
  advance qua row lạ); `aggregate_step(epoch_key, prev_agg, value)`,
  `verify_aggregate(attestations, initial_key, *, agg_start, epoch, agg) -> str|None`
  (aggregate_mismatch | aggregate_epoch_mismatch | malformed_aggregate); verify_seals thêm
  1 nhánh additive cho scheme mới (tag per-entry giống hệt fs-hmac). Attestation KHÔNG đổi.
- SỬA `adapters/attest.py`: `scheme: str = FS_HMAC_SCHEME` param (ValueError scheme lạ;
  bỏ qua/từ chối ở signer mode); sidecar mới `<trail>.sealagg` ghi bằng atomic_write_bytes
  (owner duy nhất của os.replace) 0600: `{"agg","agg_start","epoch"}`; thứ tự ghi trong
  attest(): keyfile replace → .sealagg replace → append .attest (mỗi cửa sổ crash ra một
  verdict riêng, không tự "sửa"); `read_aggregate() -> (agg_start, epoch, agg)|None`;
  agg_start cho phép bật giữa đời trail (row < agg_start vẫn được keyfile check phủ).
- SỬA log.py verify_attestations: sau continuity check, nếu attestor có read_aggregate:
  thiếu aggregate khi có row agg-scheme → aggregate_missing; có → verify_aggregate, map
  reason vào AttestResult.
- Tamper matrix (append tests/test_sealed_log.py + test_sealing.py): truncate nhất quán
  trail+.attest+keyfile-mất → aggregate_*; verify off-box chỉ với trail/.attest/.sealagg
  + A_0 (KHÔNG ship keyfile) → bắt được; .sealagg refold không key → aggregate_mismatch
  (chứng minh keying chịu lực); tag giả trên row agg → seal_mismatch; replay .sealagg cũ
  + truncate khớp → KHÔNG phát hiện (honest-limit: aggregate cũ giới hạn như anchor cũ —
  A và B bổ trợ nhau, ghi vào SPEC §11); sidecar fs-hmac cũ verify NGUYÊN TRẠNG (regression);
  row scheme lạ → unverifiable, không lỗi (pin regression).

### M5 — Đo completeness (`.drops` sidecar)
Ngữ nghĩa trung thực: count từ sidecar = "TỐI THIỂU N drop đã đo được", không bao giờ
"chính xác N"; sidecar bị xóa ≡ chưa đo (None); drop-của-drop-record là giới hạn cơ bản
(một write hỏng không thể tự làm chứng trên chính medium hỏng) — có honest-limit test.
- MỚI `ports/drops.py`: `DropRecorder` Protocol: `record(*, reason, payload_type=None,
  source="library") -> None` — implementation KHÔNG BAO GIỜ raise.
- MỚI `adapters/drops.py`: `FileDropRecorder(trail_path, *, now_fn=None, source="library")`,
  `count()`, module fn `read_drop_count(trail_path) -> int|None`; sidecar `<trail>.drops`
  JSONL O_APPEND 0600; record CHỈ metadata `{"payload_type","reason","source","ts","v":1}` —
  TUYỆT ĐỐI không chứa nội dung payload (chưa qua redact-before-hash).
- SỬA `domain/verify.py`: VerifyResult thêm field cuối `drops_source: str|None = None`
  (trailing default — mọi construction/replace hiện có giữ nguyên).
- SỬA log.py: `drop_recorder` param + `open(..., record_drops=False)`; try_append fail →
  _dropped+=1 VÀ recorder.record() nếu có (AttestationFailure KHÔNG tính drop — entry đã
  persist); verify(measure_drops=True): có recorder → count() + drops_source="sidecar",
  không → counter process + "process"; False → None/None.
- SỬA cli.py: verify/inspect đọc sidecar → in `dropped_writes >= N (measured minimum,
  from <trail>.drops)`; không có sidecar → như cũ (None); KHÔNG ảnh hưởng exit code
  (drops = completeness, không phải integrity); dòng hỏng đếm riêng, không crash.
- SỬA 7 integration (claude_code, codex, cursor, langchain, crewai, openai_agents,
  hermes/hermes_gateway): open(record_drops=True); nhánh fail trước-khi-mở gọi thẳng
  FileDropRecorder(trail).record() best-effort; stderr label giữ nguyên.
- Test: 2 AuditLog instance (giả lập 2 hook process) mỗi cái drop 1 → CLI báo >= 2;
  None≠0 (không sidecar → None; sidecar rỗng → 0 + "sidecar"); recorder không raise trên
  thư mục không ghi được; xóa sidecar → None; test_failopen_paths: mọi path vẫn exit 0 /
  stdout im lặng VÀ để lại record.

### M6 — RemoteBackend + HTTPAnchorSink
- MỚI `src/waxseal/adapters/remote.py`:
  `RemoteRequest(method, url, headers, body)` / `RemoteResponse(status, headers, body)`
  frozen dataclass; `Transport = Callable[[RemoteRequest], RemoteResponse]`;
  `urllib_transport(*, timeout=10.0) -> Transport` (stdlib; HTTPError → RemoteResponse,
  URLError/timeout → propagate); `RemoteError(RuntimeError)`;
  `RemoteBackend(base_url, *, transport=None, api_key=None, chain_id="default",
  timeout=10.0)` — transport là "ống câm" trả cả non-2xx; Authorization: Bearer khi có
  api_key; CAS: POST envelope, 409 → đọc lại head → re-invoke build → retry (tối đa 32,
  tiền lệ S3); 400/401/403/5xx → RemoteError (thành drop của try_append).
- Wire contract v1 (đặc tả đầy đủ trong REMOTE.md), base `{base_url}/v1/chains/{chain_id}`:
  GET /head → 200 {"seq","entry_hash"} (authoritative, transactional) | 404 = rỗng;
  POST /entries body = envelope JSONL verbatim (SPEC §7 layout → parity byte miễn phí) →
  201 | 409 khi (seq, prev_hash) không nối đúng head hiện tại (server kiểm ATOMIC);
  GET /entries?cursor= → 200 {"entries":[...], "next_cursor"} THEO THỨ TỰ GHI | 404.
- MỚI `tests/adapters/test_remote.py`: `FakeChainServer` (threading.Lock, enforce
  precondition atomic, flag enforce_precondition, page size nhỏ để test cursor) +
  fake_transport; subclass TestRemoteBackendContract(BackendContractTests); test
  localhost http.server thật (127.0.0.1 ephemeral, in-process thread) phủ nhánh
  urllib_transport; tamper matrix: sửa/xóa/chèn/đảo envelope TRONG fake server → local
  verify_chain báo đúng broken_seq+reason (chứng minh "server untrusted at read time");
  re-entrancy test (409 lần đầu → build gọi 2 lần với (seq, prev_hash) mới);
  parity entry_hash vs JSONL.
- 2 falsifiability receipts: (1) race test 4 worker × 2 RemoteBackend trên 1 fake strict,
  docstring ghi số lần fail đo được với enforce_precondition=False; (2) test tất định
  `test_racy_server_forks_chain`: POST 2 envelope cùng (seq, prev_hash) vào server
  permissive → cả hai được nhận → verify_chain báo fork.
- MỚI trong adapters/anchors.py: `HTTPAnchorSink(url, *, transport=None, api_key=None)` —
  POST checkpoint frame/JSON tới endpoint, trả receipt từ response; test bằng fake transport.
- Trust model (docstring + REMOTE.md + DESIGN.md §10): server = trusted writer; chain
  chống bên thứ ba + hỏng ngẫu nhiên, KHÔNG bound server ác ý → bắt buộc khuyến nghị
  anchor head độc lập (đúng điều chainproof tự nhận); FileAttestor là single-writer-host
  (nhiều writer → AttestationFailure to tiếng — document, không code).

### M7 — Open() URL dispatch + CLI remote + extras
- SỬA log.py `AuditLog.open`: TRƯỚC khi Path(path) — nếu str bắt đầu http://|https:// →
  RemoteBackend(path, api_key=os.environ.get("WAXSEAL_API_KEY")). (Path() sẽ băm nát URL
  nếu check sau.)
- SỬA cli.py: target URL bỏ qua Path.exists(); mọi lỗi kết nối/đọc head → exit 3
  ("nothing read, nothing created" giữ tinh thần); credential CHỈ qua env WAXSEAL_API_KEY,
  không argv (lộ process list). verify/tail/inspect/head/checkpoint đều nhận URL.
  verify --anchors và anchor với URL: anchor sidecar là file local cạnh gì? → với target
  URL, `anchor` ghi sidecar theo đường dẫn do --out chỉ định hoặc từ chối với thông báo
  rõ (quyết định khi implement, mặc định: từ chối `anchor` cho URL trừ khi có --out).
- SỬA tests/test_cli.py + test_auditlog.py: dispatch (URL → RemoteBackend qua monkeypatch
  env + fake transport không khả thi qua CLI → dùng localhost fake server thật cho CLI e2e);
  filesystem path không bị ảnh hưởng.
- SỬA pyproject.toml: extras `s3 = ["boto3>=?"]` (xác minh version tối thiểu hỗ trợ
  IfNoneMatch khi implement — chưa xác minh), `postgres = ["psycopg[binary]>=3.1"]`;
  KHÔNG extra `remote` rỗng. dependencies=[] giữ nguyên.

### M8 — Tài liệu + SPEC append + dọn
- MỚI `REMOTE.md`: wire contract v1 normative + trust model + kỷ luật append-only.
- SỬA `.claude/settings.json`: bỏ SPEC.md khỏi PreToolUse block-list (owner đã phê duyệt
  trong hội thoại này) → append SPEC.md các mục MỚI:
  §9 Checkpoints & external anchoring (frame bytes, .anchors format, reasons, "sidecar là
  record — bảo mật nằm ở receipt/bản sao ngoài");
  §10 Merkle consistency proofs (RFC 6962 §2.1.2 / RFC 9162 §2.1.4.2, fail-closed, nguồn
  vector transparency-dev/merkle, write-once);
  §11 Aggregate scheme fs-hmac-agg-sha256-v1 (byte-level mu, .sealagg format, quy tắc
  normative: KHÔNG lưu accumulator trung gian + fold PHẢI keyed, off-box flow: ship
  .sealagg không ship .sealkey, giới hạn replay);
  §12 Drop records (.drops format, "measured minimum", None≠0, không bao giờ chứa payload).
  → khôi phục hook sau khi xong (hoặc theo ý user).
- SỬA DESIGN.md: append §10 Remote backend rationale (CAS vs lock, trust model, quan hệ
  FileAttestor) + cập nhật ghi chú §6/§7 trỏ tới scheme agg mới.
- SỬA README.md / README.vi.md / README.zh.md (bảng backend + remote + anchor + checkpoint),
  CHANGELOG.md ([0.2.0]), `__init__.py:3` doc drift (test_public_api.py → test_invariants.py),
  `__version__ = "0.2.0"`.
- Chú ý TestNoInternalNames quét *.md: REMOTE.md/DESIGN.md không chứa token cấm.

## Tái dùng (không viết lại)
- lp/u64be: `domain/hashing.py`; batch_root & vectors: `domain/anchoring.py` +
  tests/domain/test_anchoring.py:22-53; atomic_write_bytes: `adapters/atomic.py`;
  pattern sidecar O_APPEND 0600: `adapters/attest.py:87`; CAS retry: `adapters/s3.py:42-70`;
  build_entry: tests/adapters/test_jsonl.py:12; fake-client style: test_s3.py:37-75;
  counter fail-open có nhãn: log.py attest_failures.

## Verification (điều kiện "xong" cho mỗi milestone và toàn bộ)
1. `uv run --extra dev pytest --cov=waxseal` — xanh toàn bộ, coverage ≥90 branch.
2. `uv run --extra dev mypy` (strict) và `uv run --extra dev ruff check .` sạch.
3. Falsifiability receipts MỚI (M3 anchor_every, M6 remote race) phải được ĐO THẬT:
   tạm gỡ guard, chạy ≥5 lần, ghi ngày + tỉ lệ fail vào docstring, khôi phục guard.
4. Consistency-proof vectors kiểm chéo bằng script độc lập (mở rộng tools/gen_vectors.py
   hoặc script mới KHÔNG import waxseal) trước khi pin; sau pin là write-once.
5. E2E CLI: tạo trail JSONL → append → `checkpoint` → `anchor` → sửa 1 byte entry giữa →
   `verify --anchors` exit 1 đúng reason; truncate → exit 1 anchor_beyond_head.
6. E2E remote: chạy localhost fake server → `waxseal verify http://127.0.0.1:PORT/...`
   exit 0; tắt server → exit 3; tamper trên server → exit 1 đúng broken_seq.
7. Golden vectors cũ: FROZEN_VECTORS_SHA256 không đổi (nếu đổi = DỪNG).
8. Tất cả existing tests pass KHÔNG sửa (trừ 2 file được phép sửa cùng commit:
   test_invariants.py cho public API, test_cli.py chỉ THÊM class mới).

## Rủi ro
- Coverage drag từ nhánh retry/error của remote.py → test localhost server phủ urllib.
- Byte-identity M0 dựa trên dict shape + dumps flags y nguyên — layout tests là guard.
- Trust-model wording: không bao giờ viết "prevents tampering" — chỉ tamper-evident +
  giả định server trung thực + anchor ngoài.
- boto3 minimum version cho IfNoneMatch: chưa xác minh — kiểm khi implement.
- VerifyResult thêm field default cuối: downstream destructuring vị trí có thể nhận ra —
  rủi ro thấp, ghi CHANGELOG.
- Windows O_APPEND interleaving cho .anchors/.drops: cùng profile với .attest — thêm 1 test
  interleave đa process nếu suite chưa có.
