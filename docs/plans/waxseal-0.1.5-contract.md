# Plan: waxseal 0.1.5 — hiệu năng, vá thiếu sót thẩm định, trail theo dự án, và tầng hợp đồng on-chain

## Bối cảnh

Ba nguồn hợp thành release này:

1. **Nợ 0.2.0 tìm lại được**: chủ repo đã khóa 4 quyết định cho tầng hợp đồng on-chain
   (chain-agnostic port; đọc stdlib / ghi qua Signer inject hoặc extra; `contracts/` cùng
   repo; làm cả ba contract ALC + registry + bond). Kế hoạch 5 phase đầy đủ nằm ở
   `~/.claude/plans/to-n-b-epic-ng-woolly-possum.md`, chưa bắt đầu. **Chủ repo quyết định
   (31/08/2026): kéo toàn bộ vào 0.1.5** thay vì để 0.2.0 riêng.
2. **Các điểm nợ từ thẩm định Fable (31/08/2026)**: (a) `waxseal install` in `python3`
   trần — đã gây lỗi thật trên máy chủ repo: interpreter PATH không import được waxseal,
   mọi entry rơi có nhãn nhưng trail rỗng; (b) khoảng trống xác thực chữ ký RFC 3161
   (CMS/X.509) — chỗ dễ ngộ nhận nhất giữa "đã neo" và "đã neo + đã xác thực"; (c) tên
   hằng checkpoint `_V2` đọc nhầm thành cặp phiên bản cũ–mới (chính chủ repo đã nhầm);
   (d) chưa có "production preflight" cho biết cấu hình hiện tại chống được bậc nào trong
   thang năng lực kẻ tấn công; (e) CHANGELOG 0.1.4 trích sai bảng đo của chính nó
   ("22.9s for a single append" — thực ra là 22.890s TỔNG cho 4000 append, 5.723ms/append).
3. **Điểm chủ repo phát hiện**: một `trail.jsonl` duy nhất gom MỌI dự án với tần suất
   hook cực lớn (~1.9KB/entry, Pre+Post mỗi tool call) → tăng vô hạn, trộn dự án
   (privacy + nhiễu pháp chứng), và `_integrity_scan` đọc cả tệp mỗi 1000 append →
   tích lũy O(n²/N).

Khảo sát hiệu năng (Explore, 31/08/2026) định vị chính xác: `_tail()` ở `cli.py:2151`
nạp CẢ trail để in N dòng; `report`/`export-proof`/`consistency`/`checkpoint`/pin/witness
đều materialize toàn bộ qua `entry_hashes()` hoặc `list(entries())`; `jsonl.py:103` mkdir
thừa mỗi append; `verify_chain` thuần thì ĐÃ streaming đúng (không sửa).

Board beads trống — toàn bộ release này lên board mới.

## Quyết định phạm vi của chủ repo (31/08/2026)

**Mọi tính năng mới trong 0.1.5 bật mặc định, không cờ tắt, không biến môi trường
mới.** Ngoại lệ duy nhất — opt-in: tính năng kéo thư viện ngoài (extra `rfc3161`) và
toàn bộ tầng blockchain (F: cần RPC URL + địa chỉ contract do operator cung cấp, tự
thân đã là opt-in). Biến `WAXSEAL_TRAIL` có từ trước được giữ vì tương thích, và chỉ
đổi VỊ TRÍ ghi, không tắt được tính năng nào.

## Ràng buộc bất biến (CLAUDE.md — không bàn lại)

- Zero hard runtime deps; mọi thứ nặng vào optional extras.
- CLI không bao giờ append chain entry. SPEC.md + CLAUDE.md là frozen path — mỗi lần
  APPEND vào chúng cần chủ repo duyệt riêng (P-docs bên dưới gom các điểm xin duyệt).
- Vector vàng write-once; TDD; coverage 100% line+branch giữ nguyên; Condition R
  (reachability): tiêu chí "in ra/báo cáo" phải có test chạy `main()`/subprocess.
- Ternary Evidence Principle cho mọi trạng thái mới (on-chain reads, segment missing,
  extra chưa cài).

---

## Workstream A — Hiệu năng (không đổi hành vi, không đổi bytes)

**A1. `_tail()` streaming** — `cli.py:2151`: thay `entries = list(log.entries())` +
`[-n:]` bằng `collections.deque(maxlen=n)`. Test: byte-counting như
`tests/adapters/test_jsonl.py` TestCostReceipt (mẫu có sẵn), assert tail 5 dòng trên
trail 2000 entry không đọc quá X byte; falsifiability: bỏ deque → vi phạm.

**A2. Bỏ mkdir thừa mỗi append** — `jsonl.py:103`: lock (`filelock.py:20`) đã mkdir
parent; giữ một lần, bỏ lần hai. Test hiện có phải xanh nguyên.

**A3. `_integrity_scan` resumable theo offset** — `jsonl.py:133-153`: lưu offset đã
scan sạch (trong bộ nhớ instance là đủ — scan là hàng phòng thủ mỗi-process, docstring
đã nói rõ nó không phải verify), chỉ scan phần mới từ offset. Tích lũy O(n²/N) → O(n).
Giữ nguyên semantics `JSONLCorruptionError`. Test: byte-counting assert scan lần 2 không
đọc lại phần đã scan; falsifiability receipt.

**A4. Vá lớp materialize còn lại ở mức rẻ**: `log.entry_hashes()` (log.py:505) giữ
nguyên chữ ký (list là inherent cho `batch_root`), nhưng `report`/`_export_proof` đang
gọi CẢ `verify()` (streaming) lẫn `list(entries())` — gom một lượt đọc thay vì hai.
Không đổi public API. (Các lệnh cần Merkle root thì list là bản chất — ghi rõ trong
docstring, không "tối ưu" sai.)

**A5. Benchmark có biên nhận**: thêm `tests/adapters/test_perf_receipts.py` kiểu
byte-counting (KHÔNG wall-clock — quy tắc "tests never sleep"), số đo trước/sau ghi vào
CHANGELOG. Sửa luôn câu trích sai trong CHANGELOG 0.1.4 (mục 2e bối cảnh) — sửa CÂU
TRÍCH, không sửa số đo gốc.

## Workstream B — Trail theo dự án + xoay vòng (sealed segments)

**B1. Định tuyến theo dự án.** Khóa dự án = `cwd` từ hook event (đã có sẵn trong
payload, claude_code.py:49-52; `session_id` bị loại — đổi mỗi phiên, sinh nghìn trail).
Slug = `sanitize(basename(cwd))[:32] + "-" + sha256(cwd)[:12]` (chữ thường, [a-z0-9-],
hash trên chuỗi cwd NGUYÊN VĂN — không resolve() symlink vì mỗi host resolve khác nhau
sẽ tách một dự án thành hai slug). Va chạm 48-bit: chỉ gộp hai dự án vào một trail
(giảm tách bạch privacy, không bao giờ phá chain). Layout:
`~/.claude/waxseal/trails/<slug>/trail.00000.jsonl` (+ ordinal tăng, zero-padded —
lexicographic = chronological; tên timestamp bị loại vì clock skew đảo thứ tự).
Sidecar `.attest`/`.sealagg`/`.drops`/`.anchors` đã derive qua `with_name(name+suffix)`
(attest.py:68, drops.py:35, anchors.py:136) → tự nằm cạnh segment của nó, **zero code
change**.

**Quyết định chủ repo (31/08/2026): mọi tính năng mới BẬT MẶC ĐỊNH, không cờ tắt,
không biến môi trường mới.** Hệ quả cho định tuyến:
- Không có `WAXSEAL_TRAIL_ROOT`. Root cố định `~/.claude/waxseal/trails/` (HOME trước
  Path.home(), đúng quy tắc ntpath sẵn có).
- `WAXSEAL_TRAIL` (biến CŨ, giữ vì tương thích) vẫn thắng về VỊ TRÍ — nhưng xoay vòng
  vẫn áp dụng lên path đó (không phải công tắc tắt rotation): khi vượt ngưỡng, segment
  kế tiếp sinh cạnh nó theo cùng quy ước tên.
- Routing theo slug + rotation chạy mặc định cho mọi hook, không cần cấu hình gì.
- Trail cũ `~/.claude/waxseal/trail.jsonl`: KHÔNG migrate, KHÔNG đóng băng cưỡng bức —
  hook mới định tuyến theo slug nên trail cũ tự nhiên ngừng nhận append; nó verify mãi
  mãi bằng `waxseal verify` thường. Một dòng stderr có nhãn ở lần append routed đầu
  ghi rõ đường chuyển. (Auto-adopt tổng quát vẫn không làm: segment 0 là ordinal thấp
  nhất hiện diện thì không cần binding — nhưng với trail đứng tên đích danh qua
  `WAXSEAL_TRAIL`, lần xoay đầu tiên TỰ adopt nó làm segment gốc: binding do writer
  ghi tại thời điểm xoay, đúng luật CLI-không-append.)

**B2. Trigger xoay vòng: theo byte, O(1) tại open, mặc định bật.** Một `os.stat` trên
segment đang hoạt động trong `open_segmented()`. Theo-count bị loại (kích thước entry
lệch ~100x); chỉ-thủ-công bị loại (hook chạy không người trông — tăng vô hạn chính là
bug). Ngưỡng là HẰNG SỐ trong mã: **16 MiB** (~8.8k entry ở mức đo 1.9KB/entry), không
biến môi trường điều chỉnh (quyết định chủ repo). API thư viện `open_segmented()` vẫn
nhận `max_segment_bytes` làm tham số tường minh cho caller lập trình (tham số hàm,
không phải cấu hình); hook dùng hằng số. Thông báo xoay vòng in giá trị + xuất xứ:
`rotated at 16777216 bytes (built-in default)` — fail-open/ngưỡng đều có nhãn (rule 6).

**B3. Cơ chế xoay vòng: không rename, chỉ tạo mới.** Segment hoạt động = ordinal cao
nhất. Độc quyền `os.replace` của atomic.py không bị đụng. Binding: payload type MỚI
`application/vnd.waxseal.rotation-binding+json` mang đúng bộ ba (chain_id, seq,
head_hash) — **tái dùng nguyên văn** `HandoffBinding`/`from_payload`/`binding_holds`
(domain/handoff.py); chỉ hằng payload-type + quy ước chain_id (`<slug>/trail.NNNNN`)
là mới. Tái dùng HANDOFF_PAYLOAD_TYPE bị loại: trộn ủy quyền với xoay vòng làm bẩn
`verify-handoff`, và rotation-binding là BẮT BUỘC-tại-seq-0 (vắng mặt là verdict)
trong khi handoff-binding là tùy chọn. Trình tự (trong `sources/rotation.py` mới,
hook gọi trước khi append event):
1. Lấy `file_lock(dir/"segments.lock")` (tái dùng filelock.py — vùng găng trải hai
   tệp segment, rule 7 nâng một tầng).
2. Dưới lock, re-resolve + re-stat; nếu < ngưỡng thì process khác đã xoay → trả
   `AuditLog.open(active)`.
3. Đọc đuôi O(1) segment đang đóng (`_read_last_line`) → (last_seq, last_entry_hash).
4. Checkpoint cuối best-effort cho segment đóng qua `checkpoint_for` + anchor sink đã
   cấu hình → `.anchors` của nó (carve-out đã spec, không phải chain append). Lỗi in
   nhãn stderr, không bao giờ chặn (rule 6).
5. Append entry genesis của segment mới: chain MỚI (seq 0, prev_hash 64 số 0), payload
   là bộ ba binding — nối xuyên segment CHỈ bằng binding, không bao giờ nối prev_hash.
6. Nhả lock; caller append event qua đường `try_append`/drops thường.
Cửa sổ crash: trước bước 5 → chưa có tệp mới, lần open sau thử lại, không mất gì;
giữa bước 5 (dòng đầu rách) → nổi lên như corruption khi đọc/scan, báo cáo chứ không
sửa (rule 4); giữa 5 và 6 → event kích hoạt đi qua drop-accounting sẵn có (`.drops`
cạnh segment mới); nhiều writer đua → bước 2 re-check dưới lock bảo đảm xoay đúng
một lần.

**B4. Verify đa-segment: lệnh read-only `waxseal segments <dir>`.** Duyệt
`trail.*.jsonl` theo ordinal; mỗi segment: verdict `verify_chain`; mọi segment sau
ordinal thấp nhất hiện diện: parse entry seq-0 làm rotation binding, kiểm bằng
`binding_holds` với hash thật của segment tiền nhiệm. Trạng thái per-segment:
`ok | broken | unverifiable | missing`; verdict gộp qua `Verdict.join`; exit 0/1/2
qua `to_exit_code`, 3 = dir không tồn tại hoặc không có segment nào. Từ vựng reason:
- `rotation_binding_missing` — segment không-đầu mà seq 0 không phải binding → BROKEN.
- `rotation_binding_mismatch` — binding có; hash tiền nhiệm tại seq đó khác → BROKEN
  (so sánh tất định, cùng nền tảng với exit 1 của verify-handoff).
- `rotation_binding_unreadable` — payload không parse được → UNVERIFIABLE (rule 5).
- `segment_missing` — tiền nhiệm ĐƯỢC binding sống sót gọi tên nhưng vắng mặt →
  trạng thái riêng `missing`, không bao giờ in "tampered"; **gộp thành BROKEN**
  (khuyến nghị): binding là bằng chứng dương tính segment từng tồn tại, khớp semantics
  fail-closed của `binding_holds`; phương án UNVERIFIABLE sẽ cho đòn xóa-segment hạ
  cấp xuống exit 2. → **ĐÃ CHỐT (chủ repo, 31/08/2026): BROKEN, exit 1.** SPEC mục
  Sealed segments sẽ là §20 (§19 đã bị `.receipts` của J2 lấy) — gói SPEC append đã
  được duyệt trước, xem P-docs.
- Reason bên trong chain đi qua nguyên bộ của `verify_chain` + `broken_seq`, tiền tố
  tên segment; fingerprint lạ vẫn UNVERIFIABLE, không bao giờ exit 1.

**Tệp mới/đổi (đúng layer DAG):** MỚI `domain/segments.py` (thuần: payload type,
`project_slug`, `segment_name/ordinal/chain_id`, `verify_segments` trên input đã đọc);
MỚI `sources/rotation.py` (`open_segmented()` — import domain, adapters.filelock,
facade AuditLog: hợp lệ cho sources); sửa `integrations/claude_code.py`/`codex.py`/
`cursor.py` (routing + open_segmented); `cli.py` thêm `segments`; export public mới
(nếu có) cập nhật TestPublicApiFrozen cùng commit.

**Test (TDD, viết trước):** (1) slug tất định/sanitize/cwd khác → dir khác; (2) happy:
vượt ngưỡng → đúng một segment mới, binding seq-0 giữ, `segments` exit 0; (3) crash
giữa xoay (chưa có tệp → thử lại; genesis rách → corruption báo cáo không sửa);
(4) mất segment giữa → exit 1 `segment_missing`, in trạng thái từng segment; (5) binding
bị sửa / đuôi tiền nhiệm bị viết lại → `rotation_binding_mismatch` nêu đúng segment;
(6) fingerprint lạ một segment → gộp exit 2 không phải 1; (7) N writer đua ngưỡng →
một lần xoay, không fork, không event nằm hai segment — kèm biên nhận khả phủ chứng
(bỏ segments.lock → test đỏ); (8) tương thích ngược: trail cũ verify nguyên trạng;
`WAXSEAL_TRAIL` đổi vị trí nhưng KHÔNG tắt rotation — trail đích danh vượt ngưỡng vẫn
xoay và được adopt làm segment gốc; (9) drop trong lúc xoay nằm trong `.drops` của
segment mới; (10) hook dùng hằng số 16 MiB và in nhãn `built-in default`; helper nhận
`max_segment_bytes` tường minh từ caller lập trình.

## Workstream C — Extra `waxseal[rfc3161]`: xác thực CMS/X.509 tùy chọn

- `pyproject.toml`: extra `rfc3161 = ["cryptography>=..."]` (tiền lệ s3/postgres —
  core KHÔNG import; adapter import trong hàm, lỗi import → trạng thái riêng).
- `adapters/rfc3161_verify.py` (mới): xác thực chữ ký CMS của token + chuỗi X.509 tới
  CA bundle do OPERATOR chỉ định (`--tsa-ca-file` — không bịa trust anchor mặc định,
  cùng kỷ luật với cadence). Không đụng `domain/rfc3161.py` (kiểm cấu trúc giữ nguyên).
- **Instance thứ 8 của Ternary Evidence Principle**: kết quả ba-giá-trị
  `signature_valid` / `signature_invalid` (exit 1 — checked-and-false) /
  `signature_unchecked` (extra chưa cài HOẶC operator không đưa CA bundle — exit 2,
  in nhãn rõ "unchecked: install waxseal[rfc3161] and pass --tsa-ca-file"). Extra thiếu
  mà im lặng exit 0 = false confidence — cấm.
- CLI: `verify`/`report` thêm cờ `--tsa-ca-file`; `receipt` giữ nguyên (đường openssl
  vẫn là đường được tài liệu hóa, extra là lựa chọn thứ hai, không thay thế).
- CLAUDE.md: cập nhật đoạn Ternary (6→8 instances, gồm cả tickets đã tự nhận là #7) —
  cần chủ repo duyệt (frozen path, gom vào P-docs).
- Test: token hợp lệ (vector tự ký trong test, sinh bằng cryptography trong dev env),
  token chữ ký sai → invalid, extra vắng (monkeypatch import) → unchecked exit 2,
  falsifiability cho nhánh unchecked.

## Workstream D — Vá install + đổi tên checkpoint prose

**D1. `sys.executable` thay `python3` trần** — `_install.py:200` (`_config_snippet`) và
`:89-93` (openclaw `python -m ...`). Zero blast radius test/doc (đã kiểm: không test nào
assert chuỗi "python3"). Thêm test assert snippet chứa `sys.executable` thật. Shim giữ
shebang `env python3` (fail-open đã đúng) nhưng config snippet trỏ interpreter đang chạy
install — đúng interpreter có waxseal.

**D2. Đổi tên hằng checkpoint, GIỮ NGUYÊN bytes**: `CHECKPOINT_FRAME_PREFIX` →
`CHECKPOINT_FRAME_PREFIX_BARE` + alias cũ, `_V2` → `CHECKPOINT_FRAME_PREFIX_AGG_BOUND`
+ alias cũ (hoặc tên chủ repo chọn). Bytes `waxseal-checkpoint-v1\n`/`-v2\n` bất động
(đã nằm trong receipt TSA ngoài). Sửa 3 tệp test import theo; KHÔNG đụng
`tools/gen_checkpoint_vectors.py` (độc lập là chủ đích); SPEC.md:184 giữ nguyên (bytes
không đổi nên spec vẫn đúng) — chỉ THÊM một câu ghi chú "v1/v2 là hình dạng khung song
song theo nội dung, không phải phiên bản cũ–mới" vào SPEC (append, cần duyệt) hoặc chỉ
vào docs thường nếu chủ repo không muốn đụng SPEC.

**D3. Đồng nhất `WAXSEAL_TRAIL`**: hermes/hermes_gateway + 3 integration thư viện hiện
không honor env override (4/9 honor). Thêm honor `WAXSEAL_TRAIL` (ctor param vẫn thắng
env ở 3 cái thư viện — tham số tường minh > môi trường). Test per-integration.

## Workstream E — `waxseal preflight` (production preflight)

Lệnh CLI read-only mới: đọc trail + sidecars + pin + cấu hình thấy được, in ra **bậc
thang năng lực kẻ tấn công** (bảng threat-model.md:215-222) mà cấu hình hiện tại chống
được: có seal? có anchor ngoài? mấy sink, mấy domain? có witness? pin có tách đĩa
(khai báo)? → "cấu hình này dừng kẻ tấn công ở bậc N, bậc N+1 cần X". Không phán quyết
mới, chỉ trình bày lại τ + declared_topology + anchor records theo ngôn ngữ thang bậc.
J4 bổ sung hai dòng output: prefix bất biến (cơ chế + checkpoint) và đuôi chỉ-evident.
Exit 0 luôn (là lệnh thông tin, không phải verdict) — trừ 3 khi trail không tồn tại.
Condition R: test subprocess assert stdout. CLI contract (CLAUDE.md) thêm dòng — gom
P-docs.

## Workstream F — Tầng hợp đồng on-chain (nguyên kế hoạch 5 phase đã khóa)

Thi hành đúng `~/.claude/plans/to-n-b-epic-ng-woolly-possum.md` Phase 1→5, đổi mỗi
"0.2.0" thành "0.1.5" (quyết định chủ repo 31/08/2026):

- **F1 = Phase 1**: `ports/ledger.py` (LedgerReader/LedgerSink/Signer),
  `domain/liveness.py` (ternary), `domain/bond.py` (EquivocationProof/NonExtensionProof,
  tái dùng `verify_consistency`), `domain/abi.py` (ABI static-types stdlib, selectors
  đóng băng từ `forge inspect`), `RegistryCrossCheck` (reason `registry_disagreement`,
  exit 2, không bao giờ broken). `domain/fingerprint.py` không đụng.
- **F2 = Phase 2**: `contracts/` Foundry — FingerprintRegistry.sol (sha256 precompile,
  append-only tuyệt đối), AnchoringLiveness.sol (seq tăng nghiêm ngặt + chữ ký writer),
  BondedCheckpoints.sol (2 ecrecover + RFC 9162 consistency bằng sha256 khớp byte với
  Python — vector chéo `tools/gen_contract_vectors.py`). CI job `forge test` + so
  selectors.
- **F3 = Phase 3**: `adapters/evm.py` — EvmLedgerReader (≥2 RPC bất đồng →
  LedgerDisagreement, block tag finalized, Transport sẵn có của remote.py: allowlist
  http/https, từ chối redirect), EvmLedgerSink (Signer inject), EvmAnchorSink.
  Extra `evm = []` — không dep bắt buộc.
- **F4 = Phase 4**: CLI `ledger-status` (exit 0/1/2/3 đúng semantics reconcile-tickets),
  wiring `verify --rpc/--liveness/--registry` (reasons mới đều exit 2), lệnh ghi
  `registry publish` / `bond deposit|prove` (ngoài chain entries — tiền lệ `anchor`).
  Credentials: `WAXSEAL_EVM_SIGNER_CMD`, không bao giờ key trong argv.
- **F5 = Phase 5**: SPEC mục Ledger layer (APPEND — cần duyệt riêng; kế hoạch gốc ghi
  "§14" đã lỗi thời — SPEC hiện đã tới §19, §14 là witness cross-check; số mục lấy số
  kế tiếp lúc append), CLAUDE.md CLI
  contract + Ternary instances (cần duyệt riêng), public API mở rộng → cập nhật
  TestPublicApiFrozen cùng commit kèm lý do, threat-model mục ledger, conformance:
  3 row on-chain → [Shipped], row liveness [Partial] → [Shipped] — cập nhật CẢ HAI
  bản .md/.vi.md + sửa các câu đếm, theo đúng kỷ luật ledger.

Mọi phép đọc chain ternary: live/delinquent/unreachable, agrees/disagrees/unreachable,
bonded/slashed/unreachable; falsifiability receipt cho từng predicate (bỏ nhánh
unreachable → test đỏ). Test dùng fake Transport trả ABI đã encode; test anvil đánh dấu
skip CÓ NHÃN khi thiếu anvil.

## Workstream G — Nghiên cứu: SaaS backend, định vị cạnh tranh, chính sách deps

Deliverable là TÀI LIỆU (docs/research/), không phải code — trừ G3 chỉ là xác nhận
chính sách đã có.

**G1 → nâng thành Workstream I (xây thật trong 0.1.5, quyết định chủ repo
31/08/2026)** — xem Workstream I bên dưới. Phần nghiên cứu của G1 rút gọn thành mục
mở đầu của chính docs của server (bối cảnh + threat model), không còn là doc riêng.

**G2. Định vị cạnh tranh** (`docs/research/landscape.md`) — dữ kiện đã kiểm chứng
31/08/2026 qua GitHub API:
- **vajramatt/chainproof** (Go, MIT, tạo 2026-08-16 — TRƯỚC waxseal 0.1.0 ngày
  2026-08-21 năm ngày; 0 sao): "local-first provenance ledger + cockpit TUI", một
  binary Go + SQLite. Chain: SHA-256, genesis 64 số 0, seq liền kề — cùng cấu trúc
  kinh điển. Khác biệt bản chất waxseal phải ghi rõ trong docs: (1) chainproof hash
  CANONICAL JSON của TOÀN event gồm payload lồng nhau — đúng lớp "hash serialization
  không kiểm soát" waxseal cấm; (2) `schema_version` là chuỗi thứ tự `"1"` — đúng mẫu
  ordinal-version mà waxseal sinh ra để loại bỏ (không fingerprint); (3) không thấy
  forward-secure seal / RFC3161 / witness / pin trong spec v1. Kết luận về "giống":
  hội tụ trên cùng bài toán + cùng kỹ thuật chuẩn mực công khai (hash chain là kiến
  thức chung); timeline công khai cho thấy không bên nào chép bên nào [Inference —
  dựa trên ngày tạo repo và độ sâu khác biệt thiết kế]. **Quyết định chủ repo
  (31/08/2026): không adopt gì từ chainproof.** Hướng riêng của waxseal, **làm luôn
  trong 0.1.5**: tính năng "imported" — ingest + verify các trail jsonl/db từ hệ
  thống/dự án KHÁC, nơi nhận là backend tự host (Workstream I); nguồn gốc ý tưởng là
  nhu cầu của chính chủ repo (verify tập trung trail ngoại lai), không phải học từ
  chainproof — tiền lệ trong repo đã có sẵn: `sources/openclaw.py` chính là một
  importer.
- **microsoft/agent-governance-toolkit** (Python, MIT, tạo 2026-03-02, 6.155 sao):
  policy enforcement + zero-trust identity + sandbox + SRE, phủ OWASP Agentic Top 10.
  KHÁC TẦNG với waxseal: AGT là mặt phẳng ĐIỀU KHIỂN (chặn hành động trước khi xảy
  ra), waxseal là mặt phẳng BẰNG CHỨNG (chứng minh hồ sơ không đổi sau khi xảy ra).
  Audit log của AGT ghi "tamper-evident" nhưng chiều sâu cơ chế (schema evolution,
  ternary, FssAgg, external anchoring, proof bundles) là đúng chỗ waxseal chuyên sâu
  [Unverified — chưa đọc mã audit của AGT, chỉ đọc README]. Không phải "hơn/kém" mà
  bổ trợ. **Quyết định chủ repo (31/08/2026): làm luôn `integrations/agt.py` trong
  0.1.5** — xem Workstream H.
- **degenlegion-com/waxseal-sdk** (TypeScript, MIT, tạo 2026-06-22 — trước waxseal
  0.1.0 hai tháng; 1 sao; dịch vụ tại waxseal.id): **TRÙNG TÊN, KHÁC SẢN PHẨM, KHÁC
  NGÔN NGỮ** — danh tính Ed25519 (keypair + fingerprint + hồ sơ on-chain + MCP server
  ký/xác minh cho Claude/Cursor/Windsurf), KHÔNG có hash chain / audit trail /
  tamper-evidence nào (grep README: 0 kết quả). Không phải đối thủ về chức năng: họ
  trả lời "AI là ai" (danh tính/chữ ký), waxseal trả lời "chuyện gì đã xảy ra và hồ
  sơ có nguyên vẹn không". Rủi ro thật là NHẦM LẪN THƯƠNG HIỆU: họ giữ waxseal.id +
  npm scope @waxseal và có mặt công khai trước; chủ repo giữ tên gói PyPI `waxseal`;
  cả hai cùng nhắm không gian AI agent. Việc cần làm trong doc landscape: một mục
  phân định rõ ("waxseal trên PyPI = audit hash chain; WaxSeal SDK trên npm =
  identity") + câu khuyến cáo trong README waxseal để người tìm nhầm khỏi lạc; quyết
  định có đổi tên/đăng ký thương hiệu hay không là của riêng chủ repo, kế hoạch này
  không đề xuất. Không dùng dịch vụ của họ, không tích hợp.

**G4. Học thiết kế của Hedera để viết tính năng cho waxseal**
(`docs/research/hedera-lessons.md`). **Chủ repo làm rõ (31/08/2026): KHÔNG dùng dịch
vụ Hedera, không trả phí mạng của họ, không viết adapter cho họ, không phát triển giúp
họ** — chỉ mổ xẻ thiết kế công khai của họ để rút ý hay thành tính năng waxseal sở hữu.
Ba ý đã nhận diện sơ bộ (dữ kiện nền kiểm chứng 31/08: docs HCS hoạt động; mirror node
công khai trả REST JSON không cần xác thực):
1. **Mẫu mirror-node**: điểm đọc công khai, chỉ-đọc, KHÔNG credential, tách hẳn khỏi
   đường ghi → adopt thẳng vào spec backend tự host (G1): server waxseal có read-API
   công khai để BÊN THỨ BA verify trail/checkpoint mà không cần được cấp quyền — tách
   thẩm quyền đọc/ghi thành kiến trúc, không chỉ thành credential.
2. **Running hash + consensus timestamp per topic**: HCS gắn mỗi message vào một
   running hash phía dịch vụ → adopt: server tự host (G1) duy trì CHUỖI BIÊN NHẬN của
   chính nó (running hash trên các checkpoint đã nhận) để server không thể sắp lại
   lịch sử nó đã xác nhận — nâng semantics witness từ "trả lời câu hỏi" lên "tự bị
   xích bởi câu trả lời của mình". Đây là tính năng waxseal tự viết, chạy trên hạ
   tầng tự host, không đồng nào rời ví.
3. **Mô hình phí cố định dự đoán được** → không adopt code gì, chỉ đối chiếu vào
   tham số `c` của `domain/cadence.py` như một case study trong doc.
Deliverable: doc + danh sách "ý adopt → tính năng waxseal" — cả hai ý 1 và 2 đã được
đưa thẳng vào spec Workstream I và XÂY trong 0.1.5 (không để lại backlog). Mọi mô tả
hành vi Hedera lấy từ tài liệu công khai của họ, gắn nhãn [Unverified] nếu chưa tự
kiểm được bằng lệnh thật.

**G3. Chính sách mở rộng deps**: câu trả lời cho "cho phép cài deps để mở rộng năng
lực" là cơ chế ĐÃ TỒN TẠI và 0.1.5 đang dùng nó: optional extras (`s3`, `postgres`,
nay thêm `rfc3161`, `evm`) — core zero-dep bất động (CLAUDE.md rule 1), năng lực mở
rộng qua extra + inject. Deliverable: một mục "Capability extras" trong README liệt kê
extras hiện có/kế hoạch, để người dùng thấy đường mở rộng chính thống thay vì nghĩ
zero-dep là trần năng lực. KHÔNG thêm hard dep nào — đổi rule 1 là quyết định sửa
CLAUDE.md của riêng chủ repo, kế hoạch này không đề xuất.

## Workstream I — `server/`: backend tự host (Python + giao diện web, Docker)

**Quyết định chủ repo (31/08/2026), đã chốt không bàn lại**: xây server backend nguồn
mở tự host NGAY trong 0.1.5 — Python, có giao diện, đóng gói Docker. "SaaS" nghĩa là
ship mã cho mọi người tự host, không phải dịch vụ do waxseal vận hành.

- **Vị trí & luật deps**: thư mục `server/` trong repo, KHÔNG vào wheel waxseal (tiền
  lệ `contracts/` — rule 1 chỉ áp cho `[project] dependencies` của wheel). Server là
  ứng dụng riêng, được phép có deps riêng trong `server/pyproject.toml` (**stack ĐÃ
  CHỐT bởi chủ repo 31/08/2026: FastAPI + uvicorn**). Cài từ Docker image là đường
  chính danh.
- **Kiến trúc "Python gọi waxseal"**, tôn trọng hiến chương: đường GHI (POST entry,
  CAS trên (seq, prev_hash) theo REMOTE.md) dùng waxseal làm THƯ VIỆN (`AuditLog` —
  luật "CLI không bao giờ append" giữ nguyên tuyệt đối); mọi mặt ĐỌC/verify (verify,
  report, segments, inspect, tail, receipt, consistency…) server gọi đúng **CLI
  waxseal** như subprocess và trình kết quả + exit code 0/1/2/3 lên giao diện — CLI là
  hợp đồng ổn định, server không đụng backend internals (`log._backend` cấm, đúng luật
  sources/).
- **Phạm vi endpoint** (khớp REMOTE.md + bổ sung): chain store đa-trail (`chain_id`),
  `/head` + append CAS, witness endpoint (`WAXSEAL_WITNESS_API_KEY` — tách credential
  đúng ranh giới sẵn có), anchor sink endpoint, pin store, và **read-API công khai
  không credential** cho bên thứ ba verify (ý adopt số 1 từ G4 — mẫu mirror-node).
  Server duy trì **chuỗi biên nhận của chính nó** — running hash trên các checkpoint
  đã nhận (ý adopt số 2 từ G4) để server không sắp lại được lịch sử đã xác nhận.
- **Tính năng "imported" (từ G2, làm luôn 0.1.5)**: upload/ingest trail jsonl/db
  ngoại lai qua giao diện → server chạy `waxseal verify`/`segments`/`report` trên bản
  nhận, hiển thị verdict ternary + reason; trail nhập được lưu read-only, không bao
  giờ ghi tiếp vào chain nhập (nó là bằng chứng, không phải trail sống).
- **Giao diện web**: dashboard trail (danh sách chain, verdict mỗi chain in đúng ba
  trạng thái + scope statement nguyên văn), xem entry (payload đã redact, decode
  base64 chỉ để hiển thị), nút verify/report/export-proof (đều read-only), màn hình
  preflight (tái dùng E qua CLI), màn hình import. KHÔNG có nút nào sửa/xóa entry —
  verify reports, never repairs áp cho cả UI.
- **Đóng gói**: `server/Dockerfile` (image chứa waxseal wheel + server app),
  `docker-compose.yml` mẫu (volume cho trail store), doc triển khai. Auth bearer qua
  env đúng chuẩn `WAXSEAL_API_KEY` hiện có; TLS terminate ở reverse proxy (doc nói
  rõ, không tự bịa PKI).
- **Threat model ghi thẳng trong docs của server**: server tự host vẫn là trusted
  writer (không BFT); thông đồng server-với-writer là bậc cuối thang năng lực;
  self-host đổi AI giữ miền quản trị chứ không đổi định lý. Đội A host cho đội B ghi
  = tách thẩm quyền nội bộ, τ tăng thật, preflight (E) lên bậc.
- **Test**: contract test server-vs-`adapters/remote.py` (client hiện có chạy nguyên
  bộ test remote ĐỐI ĐẦU server thật trong CI — server đúng REMOTE.md khi client
  không phân biệt được với fake); test CAS đua (hai writer, một 409); test import
  hiển thị đúng verdict; test read-API công khai không lộ endpoint ghi. Coverage
  100% áp cho `src/waxseal` như cũ; `server/` có suite riêng với ngưỡng riêng ghi
  trong `server/pyproject.toml` (không trộn vào gate của wheel).

## Workstream H — `integrations/agt.py`: waxseal làm audit sink cho Microsoft AGT

Đích tích hợp thứ 9, theo đúng khuôn 8 cái sẵn có. Kiểu THƯ VIỆN (như langchain/
crewai/openai_agents): người dùng attach trong mã của họ, không có bước install,
không thêm dep (import `agent_governance_*` chỉ xảy ra khi người dùng dùng module —
đúng cách langchain.py chỉ import langchain-core lúc dùng).

- **Bước 0 bắt buộc (Condition R của integration)**: xác minh điểm mở rộng thật của
  AGT trên phiên bản pin cụ thể — README nói audit log/policy decision được ghi qua
  `govern()`; cần đọc mã AGT để tìm hook/listener chính danh (audit backend interface?
  event bus?) [Unverified — module docstring phải ghi đúng phiên bản upstream + URL
  tài liệu đã kiểm, như 8 module hiện có đều làm].
- Hợp đồng quan sát viên GIỮ NGUYÊN: không bao giờ veto (mọi lỗi của chính sink →
  exit/return sạch + stderr có nhãn + dropped write có đếm), ghi TRƯỚC khi thực thi
  khi điểm mở rộng cho phép, redact trước hash (`RegexRedactor`), clip có nhãn
  (`MAX_FIELD_CHARS` 4096).
- Payload type mới `application/vnd.waxseal.agt-event+json`; trường tối thiểu: policy
  đang hiệu lực, hành động agent yêu cầu, phán quyết allow/deny + lý do, agent
  identity — đúng bộ ba câu hỏi audit của chính AGT ("policy nào active, agent xin gì,
  vì sao cho/chặn"). Ánh xạ được sang `DecisionRecord` khi hình dạng khớp
  (`decision_type`, `human_oversight` unrecorded nếu AGT không nói).
- Trail path: dùng chuẩn mới của B (routing theo dự án khi có cwd; ctor param thắng;
  honor `WAXSEAL_TRAIL` theo D3).
- `waxseal install agt` vào `TARGETS` nhóm _LIBRARY_USAGE (chỉ in cách attach, không
  ghi tệp — tiền lệ langchain, _install.py:70-83).
- Test: khuôn `tests/integrations/` sẵn có — event giả → entry đúng payload type,
  redact hoạt động, lỗi sink không lan (never-veto), drop có đếm; fake module AGT
  trong test (không thêm dep dev nặng) trừ khi upstream có gói test nhẹ.
- Docs: README bảng integrations 8→9; DESIGN.md mục observer contract thêm dòng.
- Rủi ro ghi rõ: AGT đang "Public Preview — may have breaking changes before GA"
  (README của họ) → pin phiên bản đã kiểm trong docstring, CI không phụ thuộc AGT
  (test dùng fake), breakage của upstream là việc của bản vá sau, không phải lý do
  kéo dep vào.

## Workstream J — Evident → proof: nền bất biến (immutability substrate)

**Câu hỏi nghiên cứu (31/08/2026): áp dụng plan này xong, waxseal có tamper-proof
chưa?** Kết luận: **KHÔNG toàn phần — và không bao giờ toàn phần**, vì hai lý do
nằm ngoài mọi cơ chế hash:

1. Writer được tin ở thời điểm ghi: không cơ chế nào ngăn ghi sai hoặc bỏ sót lúc
   ghi (scope statement SPEC 16 đã nói thẳng; D2 tickets là câu trả lời một phần
   cho bỏ sót). Tamper-proof ≠ truth-proof.
2. Đuôi trail sau checkpoint/anchor cuối luôn là cửa sổ ghi-được — bằng cấu trúc,
   không bằng lỗi thiết kế (threat-model §4 residual 3 cùng bản chất).

Cái ĐẠT ĐƯỢC — và F đã mua được phần lớn — là **tamper-proof CÓ PHẠM VI**:
(a) prefix đã neo lên ledger finalized (F): hai hàng cuối bảng
threat-model.md:215-222 ("nothing this library can offer") đổi thành "ledger giữ
bản ghi kẻ tấn công không sửa được, equivocation bị slash"; (b) segment đã seal
nằm trên storage WORM: storage TỪ CHỐI ghi đè thay vì chỉ phát hiện. Plan trước J
đưa waxseal lên (a) nhưng còn ba khoảng trống để claim (b) và để (a) không rỗng
ruột. J vá đúng ba khoảng đó:

**J1. S3 Object Lock (WORM) cho segment đã đóng** — extra `s3` sẵn có, adapter
`s3.py` thêm hỗ trợ đặt retention Object Lock khi upload segment đã seal; bucket
compliance-mode do OPERATOR cấu hình và khai báo (không bịa policy/trust mặc
định — cùng kỷ luật `--tsa-ca-file`). [Unverified — semantics Object Lock
compliance mode lấy từ tài liệu AWS, kiểm lại bằng docs chính thức khi bắt đầu
bead.] **Instance mới của Ternary Evidence Principle**: `worm_locked` /
`worm_unlocked` (bucket không bật lock — checked-and-false, in nhãn) /
`worm_unknown` (không đủ quyền hỏi trạng thái lock — không bao giờ in như
locked). Opt-in đúng ngoại lệ đã chốt (kéo hạ tầng ngoài, như rfc3161/evm).

**J2. Biên nhận per-append phía client — đóng cửa sổ giữa hai anchor khi dùng
remote backend.** Server (I) đã có chuỗi biên nhận của chính nó (ý adopt G4 #2);
bổ sung hai đầu: (i) response append của server trả head chuỗi biên nhận
(REMOTE.md đã có tiền lệ `{"receipt": ...}` opaque ở anchor sink — mở rộng sang
đường append, cần APPEND REMOTE.md → P-docs); (ii) client `adapters/remote.py`
lưu head đó vào sidecar `.receipts` (append-only, đặt cạnh trail đúng quy ước
`.anchors`). `verify` đối chiếu khi sidecar có mặt: mismatch giữa trail và biên
nhận đã lưu tại seq đó là so sánh TẤT ĐỊNH (cùng nền tảng
`rotation_binding_mismatch`/verify-handoff) → exit 1 reason `receipt_mismatch`;
sidecar vắng → `receipts: not recorded`, không bao giờ fail (rule 5); record
hỏng trong version ĐÃ BIẾT → exit 1 (asymmetry SPEC §17: bytes hỏng trong
format của chính dự án là break), chỉ `v` lạ từ build mới hơn → exit 2. ĐÃ SPEC
thành §19 (chủ repo duyệt 31/08/2026). Hệ quả: rewrite cục bộ mâu thuẫn với
biên nhận NGAY TỪ append kế tiếp, không phải đợi đến checkpoint kế — cửa sổ
co từ cadence N xuống một entry.

**J3. Lưu trữ nội dung, không chỉ hash.** On-chain (F) và `.anchors` chỉ giữ
hash: kẻ có quyền ghi đĩa XÓA được lịch sử — phát hiện được (anchor còn đó)
nhưng không khôi phục được; "proof" mà không có availability là proof về một
xác chết. Rotation (B3) thêm bước best-effort có nhãn sau bước 4: đẩy segment
vừa đóng lên server import API (I — trail nhập là bằng chứng read-only, khớp
semantics sẵn có) hoặc S3 (J1). Lỗi in nhãn stderr, không bao giờ chặn xoay
vòng (rule 6).

**J4. Ngôn ngữ trung thực.** `preflight` (E) in thêm hai dòng: "prefix bất
biến đến checkpoint nào, nhờ cơ chế nào (finalized ledger / WORM / không có)"
và "đuôi từ seq N trở đi: tamper-evident only". threat-model.md thêm mục
"Tamper-evident vs tamper-proof": mọi claim tamper-proof của waxseal đều CÓ
PHẠM VI (prefix đã neo trên ledger finalized; segment đã archive WORM), không
bao giờ áp cho đuôi sống, không bao giờ áp cho tính trung thực lúc ghi. Không
output nào của thư viện in chữ "tamper-proof" mà không kèm phạm vi — README
cũng giữ nguyên tự mô tả "tamper-evident" làm danh xưng chính.

**Test (TDD):** fake S3 theo mẫu test s3 sẵn có (ba trạng thái WORM đủ nhánh);
receipt: sửa 1 byte trail sau append qua remote → verify với `.receipts` exit 1
đúng seq; sidecar vắng → không đổi verdict, in "not recorded"; receipt rách →
exit 2; archive rotation lỗi → xoay vòng vẫn hoàn tất + stderr nhãn;
falsifiability receipt cho từng nhánh ternary mới. Coverage 100% như cũ.

## P-docs — gói xin duyệt frozen paths (một lần, danh mục rõ)

SPEC.md (append): §19 "Sealed segments" (layout, payload type, quy tắc binding, từ vựng
reason, VÀ quyết định semantics `segment_missing` gộp BROKEN — khuyến nghị ở B4; sẽ
là §20), ghi chú checkpoint v1/v2 (D2, tùy chọn), mục Ledger (F5, số kế tiếp), reason/
exit mới của C. **ĐÃ LANDED 31/08/2026 (chủ repo duyệt tường minh)**: SPEC §19
(sidecar `.receipts` + bảng reason, J2); REMOTE.md §10 (receipt chain server + head
trong response append, J2); DESIGN.md §11 (doctrine "proof chỉ có phạm vi", J4);
SECURITY.md (false negative đối với corroboration đã ghi = in-scope; out-of-scope thu
hẹp theo cửa sổ mới); CLAUDE.md (Ternary 6→7 chính danh hóa tickets, doctrine scoped
tamper-proof vào Locked design). CÒN CHỜ (chỉ ghi khi lệnh/instance SHIP, đúng kỷ
luật [Written, unwired] ≠ [Shipped]): CLAUDE.md CLI contract (preflight, ledger-status,
registry publish, bond, segments) + các instance Ternary tương lai (C signature, J1
WORM) → 10+; threat-model.md mục "Tamper-evident vs tamper-proof" + cập nhật hai hàng
cuối bảng năng lực (J4 — làm cùng bead J). **DUYỆT GÓI TRƯỚC (chủ repo, 31/08/2026)**:
toàn bộ các mục SPEC append còn lại (Sealed segments §20 với semantics segment_missing
= BROKEN, mục Ledger layer, reason/exit của C, ghi chú checkpoint v1/v2) được duyệt
trọn gói — bead worker append thẳng (CHỈ append, không đổi text cũ), diff nằm trong
commit để chủ repo soát lại; không cần chờ duyệt từng diff nữa. CLAUDE.md đã được chủ
repo cho phép sửa không kèm điều kiện (31/08/2026) — vẫn giữ kỷ luật chỉ ghi
instance/CLI-contract khi SHIP.

## Thứ tự & phụ thuộc

A (độc lập, làm trước — nhỏ, hạ rủi ro) → D (độc lập, nhỏ) → B (thiết kế xong mới code)
→ C (độc lập) → E (sau B để preflight biết segments) → H (sau D3+B để dùng chuẩn trail
mới; bước 0 xác minh điểm mở rộng AGT có thể chạy song song sớm) → F1∥F2 → F3 → F4 →
F5 → I (server cuối cùng: cần REMOTE.md contract + segments B + preflight E + CLI ổn
định để bọc; G4 xong trước khi chốt spec server vì hai ý adopt đổ vào đó) → J
(J1 độc lập, làm được bất kỳ lúc nào sau A; J2 cần REMOTE.md append duyệt trước +
server I trả head; J3 sau B + I; J4 sau E + F — nó chỉ trình bày lại cái đã xây).
G (nghiên cứu, docs-only) chạy song song bất kỳ lúc nào.
**TẤT CẢ release trong v0.1.5 — không để lại backlog 0.2.x nào** (quyết định chủ repo
31/08/2026). Một epic beads `waxseal-0.1.5`, bead theo workstream; TDD từng bead
(workstream G là docs nên tiêu chí đóng là nội dung + nhãn [Unverified] đầy đủ).
**Bản chính danh là `docs/plans/waxseal-0.1.5-contract.md`**. Hành động ĐẦU TIÊN sau
khi duyệt — plan mode khóa ghi tệp repo nên bản này đã đi trước bản repo nhiều delta
(H, I, G1 thu gọn, G2, G4, dòng này): đồng bộ TOÀN VĂN bản này đè lên bản repo.

## Xác minh end-to-end

1. `uv run pytest --cov=waxseal` xanh, 100.00% line+branch, mọi receipt falsifiability mới có mặt.
2. Perf: byte-counting receipts A1/A3 trước–sau ghi vào CHANGELOG; trail 100k entry
   (sinh bằng script scratch): `tail -n 5` và append đơn lẻ không đọc quá ngưỡng assert.
3. Segments (WS-B): tạo trail dự án X + Y qua hook giả lập → hai thư mục riêng; ép xoay
   vòng → segment cũ verify ok, binding ở segment mới verify ok, xóa segment giữa →
   reason đúng từ vựng, không "tampered" khi chỉ absent; kill -9 giữa xoay vòng → không
   mất write không nhãn (.drops có bản ghi).
4. RFC3161 extra: cài extra → token tự ký valid/invalid đúng exit; gỡ extra → unchecked
   exit 2 có nhãn.
5. Install: `waxseal install claude-code` từ venv in đường dẫn interpreter tuyệt đối;
   chạy snippet trên máy không có waxseal ở python3 PATH → vẫn ghi được entry.
6. On-chain: đúng mục "Xác minh end-to-end" của kế hoạch gốc (anvil: deploy 3 contract,
   delinquent/unreachable/disagreement đúng exit, bond slash, consistency proof
   byte-for-byte Python↔Solidity).
7. `waxseal preflight` trên cấu hình mặc định in bậc thấp nhất + gợi ý bậc kế; trên cấu
   hình đủ 4 tách biệt in bậc cao nhất.
8. AGT sink (H): script ví dụ attach vào `govern()`-flow giả lập → entry payload type
   `agt-event` xuất hiện trên trail đúng dự án, redact chạy, sink tự lỗi → host không
   bị chặn + drop có đếm; `waxseal install agt` in hướng dẫn attach, không ghi tệp.
9. Server (I): `docker compose up` → giao diện lên; client `adapters/remote.py` hiện
   có ghi/đọc qua server đúng REMOTE.md (bộ test remote chạy nguyên đối đầu server
   thật); hai writer đua CAS → một 409; upload trail ngoại lai → verdict ternary đúng
   trên giao diện; read-API công khai verify được checkpoint mà không có credential;
   không endpoint/nút nào sửa được entry.
10. Evident→proof (J): ghi qua remote backend, sửa 1 byte trail cục bộ → verify với
    `.receipts` exit 1 tại đúng seq (không đợi checkpoint); xóa sidecar → verdict
    không đổi, in "receipts: not recorded"; segment archive (J3) khôi phục được sau
    khi xóa bản gốc — verify bản khôi phục ok; fake S3 ba trạng thái WORM in đúng
    nhãn, `worm_unknown` không bao giờ hiện như locked; `preflight` in dòng prefix
    bất biến + dòng đuôi chỉ-evident trên cả cấu hình có và không có ledger/WORM.
