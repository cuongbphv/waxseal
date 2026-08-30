# waxseal 0.1.4 — Hardening: encoding injectivity, verdict lattice, τ, liveness, và bug O(n²)

> **TRẠNG THÁI: ĐÃ GIAO (0.1.4), VỚI MỘT THAY ĐỔI LỚN SAU KHI GIAO.**
> Cả 7 khối W1–W7 đã implement, verify độc lập và merge. Sau đó owner quyết định đi xa
> hơn kế hoạch: **gỡ bỏ hẳn lp64v1** thay vì mang song song hai encoding. Kết quả cuối
> cùng khác kế hoạch bên dưới ở đúng điểm này, và phần W6 dưới đây phải đọc như tài liệu
> lịch sử về đường đi, không phải mô tả trạng thái hiện tại.
>
> Trạng thái hiện tại: một encoding duy nhất tên `lp64` (tag `0x00`/`0x01`, đơn ánh vô
> điều kiện), không còn hậu tố `v1`/`v2` ở bất kỳ hàm, hằng số hay module nào. Public API
> đổi `fingerprint_v1` → `fingerprint`. Golden vectors (`vectors.json`, `checkpoint.json`)
> đã re-freeze; `vectors_v2.json` không còn tồn tại. `CLAUDE.md` rule 3 ghi lại lần
> re-freeze này như một ngoại lệ một lần có chủ đích, kèm lý do, để nó không bị hiểu
> thành tiền lệ. SPEC.md gộp §2/§2b thành một §2 duy nhất.
>
> Cái giá đã trả, ghi thẳng: trail viết bởi 0.1.0–0.1.3 **không build hiện tại nào verify
> được nữa** — chúng được báo *unverifiable by name*, đúng theo giáo lý, chứ không phải
> *tampered*. Chấp nhận được vì chưa có trail nào như vậy tồn tại ngoài môi trường phát
> triển (owner xác nhận; PyPI có 0.1.0–0.1.3 nhưng chưa có người dùng thật).
>
> Kết quả đo: 100.00% coverage, 0 test đỏ, ruff + mypy sạch. Tài liệu đã đồng bộ:
> `SPEC.md`, `CLAUDE.md`, `DESIGN.md` §4, `docs/security/threat-model.md` (+`.vi`),
> `docs/paper/outline.md` (+`.vi`) §3.4, cả 3 README, 8 e2e demo và banking-poc.
>
> Một điều chỉnh khác so với kế hoạch: bẫy `max()` trên exit code mà bài luận nêu **không
> tồn tại** — kiểm chứng lại trên code đang chạy thì `cli._combine()` vốn đã đúng; W2 vẫn
> được làm nhưng để biến quy ước đó thành cấu trúc, không phải để sửa một bug tưởng tượng.

## Context

Một bài luận dạng arXiv (14 định lý) kèm một bản review ở mức code đưa ra hai finding
(F1 encoding không đơn ánh, F2 anchoring-policy downgrade), một doctrine chưa được gọi
tên (nguyên lý ba trạng thái), và một danh sách việc cần làm. Kế hoạch này kiểm chứng lại
từng claim trên code v0.1.3 đang chạy, bổ sung những gì bài luận bỏ sót, và biến tất cả
thành các chuỗi commit TDD.

> Hai tài liệu nguồn đó **không nằm trong repo** (gitignore) — chúng là đầu vào của
> 0.1.4, không phải thứ waxseal ship. Mọi thứ rút ra từ chúng đã được chép vào chính tài
> liệu này và vào `## [0.1.4]` của [CHANGELOG.md](../../CHANGELOG.md), gồm cả hai claim
> của bài luận **không trụ được** khi kiểm chứng lại — nên không cần đọc bản gốc mới
> theo được lập luận ở đây.

### Kiểm chứng lại bài luận (đã chạy code, không chỉ đọc)

| Claim | Trạng thái | Bằng chứng |
|---|---|---|
| **F1** `lp(NULL)` trùng byte với `lp(s)` khi `s` là chuỗi 6 ký tự `U+0000 N U L L U+0000` | **[Verified]** | Reproduce trên v0.1.3, cả hai ra `0000000000000006004e554c4c00`. `NULL_SENTINEL` **là** UTF-8 hợp lệ, nên nó decode ngược được thành một `str` bình thường — đó là toàn bộ finding |
| F1 chưa khai thác được ở call site hiện tại | **[Verified]** | Grep 16 call site `lp()`: header 6 field đều `str` non-null; `Checkpoint.__post_init__` chặn half-binding; `sealing.py:148` nhận `str` |
| `expected_prev = entry.entry_hash` nằm ngoài `if/else` | **[Verified]** | `domain/verify.py:76` — đúng như mô tả, và **không có test nào bảo vệ nó** |
| "Bẫy `max()` trên exit code" | **Bài luận đoán sai** | `cli.py:351-361` `_combine()` đã đúng, có comment *"Deliberately not `max`"*. Nhưng đúng nhờ **quy ước thủ tục** — xem W2 |
| **F2** anchoring-policy downgrade | **[Inference]** | `domain/pinning.py` đọc đầy đủ: pin state không có field nào ghi kỳ vọng chính sách. Chưa dựng PoC |

### Cái bài luận bỏ sót: bug hiệu năng bậc hai

Bài luận tự khai *"Chưa đọc: `adapters/`"*. Đó là chỗ có bug nặng nhất.

`JSONLBackend.append()` gọi `_tail_locked()`, hàm này duyệt **toàn bộ file từ đầu**, parse
JSON + base64-decode **mọi payload**, chỉ để lấy 2 giá trị của dòng cuối
(`adapters/jsonl.py:52-58`). O(n) mỗi append → **O(n²)** tổng. Và nó nằm **trong file lock**,
nên chặn cả writer khác.

Benchmark **[Verified]** trên v0.1.3:

```
n=  500  total=  0.387s  per-append=  0.774ms
n= 1000  total=  1.454s  per-append=  1.454ms   ← 3.8× khi n gấp đôi
n= 2000  total=  5.695s  per-append=  2.848ms   ← 3.9×
n= 4000  total= 22.890s  per-append=  5.723ms   ← 4.0×
```

Tỉ lệ 4× mỗi lần gấp đôi n = bậc hai. **[Inference]** ngoại suy: 100k entry ≈ 4 giờ. Với AI
agent trail (mỗi tool call một entry) đây là mức không dùng được. `sqlite.py` không dính
(tail đọc qua index), `s3.py` không dính (head hint + probe).

Ý nghĩa bảo mật, không chỉ là hiệu năng: **thư viện chống giả mạo bị tắt vì quá chậm thì
τ tụt về 0.** Attacker không cần phá chain, chỉ cần đợi operator tự tắt nó. Định lý 8.1
trong paper xét coverage attack chủ động; đây là **vector coverage bị động**, và nó chưa có
trong paper.

### Bốn khái niệm mới (không có trong bài luận)

- **C1 — Verdict lattice thành *kiểu*, không phải quy ước.** Bài luận đoán sai chỗ `max()`
  vì code đã đúng — nhưng đúng nhờ *một comment và kỷ luật người viết*. Đó chính xác là an
  toàn **thủ tục** đứng ở chỗ có sẵn an toàn **cấu trúc**, đúng lập luận F1 dùng để đòi sửa
  `lp()`. Sau C1, `max()` trên verdict không còn là thứ viết ra được.
- **C2 — τ là đại lượng ba trạng thái.** Bài luận đòi "in τ ra report". Nhưng in `τ=1` khi
  operator chưa khai báo topology là **tự tin giả** — đúng định lý sụp đổ 4.2 áp lên chính
  τ. Thêm nữa: **τ khai báo** và **τ quan sát** là hai số khác nhau, và chênh lệch giữa
  chúng là một finding.
- **C3 — Silence deadline cục bộ, không cần blockchain.** Bài luận nói chỉ ALC contract mới
  biến im lặng thành bằng chứng. **[Inference]** phát biểu đó quá mạnh: contract cần thiết
  để *bên thứ ba* đánh giá delinquency công khai, nhưng **verifier tự nó** đánh giá được
  nếu Δ nằm trong trust domain của nó — tức trong pin state, thứ vốn đã tách đĩa. Không
  thay thế ALC; phủ phần lớn giá trị với 0 đồng on-chain.
- **C4 — "Cost receipt": bất biến độ phức tạp thành test.** Repo đã có falsifiability
  receipt cho concurrency. Mở rộng sang hiệu năng: test đếm số byte `append` đọc, assert
  không tăng theo n. Bug O(n²) tồn tại được vì không test nào phát biểu *"append không được
  quét trail"*.

### Quyết định đã chốt với owner

- Cho phép sửa **toàn bộ frozen path**, kể cả `SPEC.md`, `domain/fingerprint.py`, `CLAUDE.md`.
- Làm hết một lượt (W1–W7 trong một đợt), không tách release.
- **Dev trên nhánh `feature/0.1.4-hardening`, tuyệt đối không commit vào `main`.**
- **KHÔNG opt-in.** lp64v2 là default thật, wired end-to-end, chạy thật. Không cờ,
  không nhánh chết, không code đường-cụt. Vì `hash_version` mặc định đổi → **0.1.4**.
- Pin state **giữ v1**, field mới là optional — không bump `PIN_STATE_VERSION`.
- **Ràng buộc nghiệm thu (owner nhấn mạnh): TDD, cover 100% cả testcase mới lẫn hiện trạng.**

## Baseline hiện trạng (đo trước khi sửa)

**[Verified]** `uv run pytest --cov=waxseal` trên v0.1.3, commit `cf7d135` (= origin/main):

```
1501 passed, 11 skipped in 28.10s
TOTAL  3452 statements, 1068 branches, 0 missing, 100.00%
Required test coverage of 100.0% reached.
```

Đây là con số mọi khối phải giữ. Không khối nào được kết thúc với coverage < 100%, với một
test cũ đỏ, hay với `# pragma: no cover` thêm vào để lách.

## Ràng buộc bất biến (CLAUDE.md)

- Zero runtime dependencies; `domain/` thuần, không I/O, không import `ports/`/`adapters/`.
- SPEC.md append-only — thêm **section mới**, không sửa một chữ của section cũ.
- Golden vectors write-once — thêm **file mới**, `vectors.json` bất động.
- Version registry append-only: không sửa nghĩa của fingerprint đã phát hành.
- Unknown/unparseable → `unverifiable`, không bao giờ `tampered`; `None ≠ 0`; fail-open phải
  được dán nhãn.
- Verify reports, never repairs.
- Read-tail + append là một critical section (rule 7) — W1 **không được** nới lỏng điều này.
- Timestamps injectable (`now_fn`) — W4 phải theo.
- Public API frozen: mở rộng phải sửa `tests/architecture/test_invariants.py`
  (`TestPublicApiFrozen`) cùng commit kèm rationale.
- Exit codes: 0 intact / 1 broken / 2 unverifiable / 3 path missing.
- `TestVersionIsStatedOnce` bắt `pyproject.toml`, `__version__`, và CHANGELOG phải khớp
  nhau. Bump lên `0.1.4` phải làm đồng thời ở cả ba, trong cùng một commit — nếu không test
  này đỏ.
- `TestDocumentationLinks` **[Verified]** chỉ quét `*.md` ở thư mục gốc repo, không quét
  `docs/`. Nên file spec này không bị nó kiểm. Nhưng nếu W6/W7 thêm link vào `README*.md`
  hay `SPEC.md` thì path được link phải tồn tại **và** không bị gitignore.
  **[Verified]** `.gitignore` hiện không có luật nào cho `docs/`, nên `docs/plans/` commit
  được bình thường.

## Điều kiện nghiệm thu chung cho mọi khối

Mỗi khối W1–W7 là một chuỗi commit TDD độc lập. Không khối nào được coi là xong nếu chưa
thoả đủ 5 điều:

1. **Test đỏ trước.** Commit đầu của khối chứa test fail, kèm output chứng minh nó fail.
2. **Code làm nó xanh**, không hơn.
3. `uv run pytest --cov=waxseal` → **100.00%**, `fail_under = 100` không đổi.
4. **1501 test hiện trạng vẫn xanh.** Một test cũ đỏ là tín hiệu thiết kế sai, **không phải**
   test cần sửa. Nếu buộc phải đổi một test cũ, phải ghi rationale vào commit message và
   nêu ra cho owner, không tự quyết.
5. Không thêm `# pragma: no cover` để lách floor. Pragma chỉ được dùng đúng mục đích đã có
   trong repo: nhánh chỉ chạy trên một OS, và phải dán nhãn CI job chạy nó.

## Thứ tự triển khai

Thứ tự có chủ đích: **W1** (bug đang gây hại thật) → **W2, W3, W4, W5** (khái niệm mới, xây
trên nền ổn định) → **W7** (dựng lưới test cho phần rủi ro) → **W6** (lp64v2, rủi ro nhất,
làm cuối khi lưới đã có).

---

### W1 — Sửa bug O(n²) trong JSONL append

**Thay đổi.** `_tail_locked()` seek từ **cuối** file lùi lại tìm newline cuối, parse **đúng
một dòng**. Thêm `tail_fields(obj) -> tuple[int, str]` vào `adapters/_envelope.py` để không
base64-decode payload. Vẫn nằm nguyên trong `file_lock` — rule 7 không đổi.

**Trade-off — quyết định của owner: KHÔNG bỏ, giữ bằng cơ chế riêng.** Hôm nay `append`
*vô tình* parse mọi dòng, nên nó tình cờ phát hiện JSON hỏng ở giữa file. Sửa tail-read
làm mất tác dụng phụ đó. Owner chọn **giữ nó lại tường minh** bằng một periodic full-scan,
tách khỏi đường hot-path:

- `JSONLBackend.__init__(self, path, *, integrity_scan_every: int | None = 1000)`.
  Mặc định **1000, không phải `None`** — cùng triết lý "wired thật, không opt-in" áp dụng
  cho lp64v2: an toàn không nên là thứ operator phải nhớ bật.
- Sau một append thành công, nếu `(seq + 1) % integrity_scan_every == 0`: quét toàn bộ
  file, parse từng dòng bằng `json.loads` (không base64-decode payload — chỉ cần biết dòng
  parse được, không cần verify hash). Dòng hỏng đầu tiên → raise
  `JSONLCorruptionError(line_no, byte_offset, cause)`. Đây **không phải** verify — không so
  hash, không quyết định `broken`/`unverifiable` (rule 4: verify reports, never repairs, và
  đây không phải verify nên không claim verdict gì); nó chỉ là kiểm tra tính toàn vẹn lưu
  trữ thô, một tầng dưới tamper-evidence.
- `integrity_scan_every=None` tắt hẳn — phải là lựa chọn tường minh của caller, không phải
  default.
- Vẫn giữ đúng tính chất W1 sửa: quét định kỳ là **amortized O(n/integrity_scan_every) mỗi
  append**, không phải O(n) mỗi append. Test C4 (cost receipt) đo đúng cái này, không đo
  "không bao giờ quét".

**Test (đỏ trước).**
- `test_append_does_not_scan_the_trail` — cost receipt (C4). Phát biểu chính xác, không
  dùng thời gian tường (flaky trên CI): bọc `open()` của backend, cộng dồn số byte mà
  `append` đọc; assert **amortized**: tổng byte đọc qua `n` append tăng tuyến tính theo
  `n / integrity_scan_every`, không theo `n`. Cụ thể: với `integrity_scan_every=1000`,
  `bytes_read_total(n=2000) <= bytes_read_total(n=1000) * 2.5` (biên độ cho 2 lần quét đầy
  đủ trong 2000 append, so với baseline chỉ có 1 lần quét trong 1000 append đầu — không
  phải tăng trưởng bậc hai). **Fail hôm nay** (tỉ lệ thực ~O(n)).
- Falsifiability receipt: ghi lại bằng chứng test này fail khi khôi phục full scan mỗi
  append (`integrity_scan_every=1`).
- Test corruption thật: ghi hỏng thủ công một dòng giữa file trước append thứ
  `integrity_scan_every`; assert `JSONLCorruptionError` raise đúng lúc, đúng `line_no`.
- Test `integrity_scan_every=None` tắt hẳn quét — không raise dù file hỏng.
- Edge case bắt buộc: file không tồn tại; file rỗng; file chỉ có newline; dòng cuối không
  có newline kết; dòng cuối dài hơn chunk size (buộc lặp seek lùi nhiều vòng); dòng trắng ở
  cuối; file 1 entry (tail = genesis + 1).
- Parity: JSONL và SQLite cùng payload → cùng `entry_hash` byte-for-byte (test đã có, phải
  còn xanh).
- Concurrency test hiện có phải còn xanh — đây là hàng rào cho rule 7.

---

### W2 — C1: Verdict lattice thành kiểu

**Thay đổi.** `domain/verdict.py` mới (pure): `Verdict.{OK, UNVERIFIABLE, BROKEN}`,
`join()`, `to_exit_code()`. `int` chỉ tồn tại ở đúng một hàm tại biên CLI. `cli._combine()`
gọi `Verdict.join`.

**Test (đỏ trước).**
- `join` là join-semilattice: kết hợp, giao hoán, lũy đẳng, đơn vị `OK`. Test trên toàn bộ
  3×3 (và 3×3×3 cho tính kết hợp) — không sampling.
- `to_exit_code` **không** bảo toàn thứ tự — viết ra thành assert tường minh, vì đó mới là
  cái bẫy bài luận cảnh báo.
- `BROKEN.join(UNVERIFIABLE) is BROKEN` — hồi quy trực tiếp cho bẫy `max()`.
- Architecture test: `max(` không xuất hiện trên đường compose verdict.

---

### W3 — C2: τ (separation degree) ba trạng thái

**Thay đổi.** `domain/separation.py` mới (pure): `SeparationTopology` liệt kê authority
(`writer` luôn có, `seal_escrow`, mỗi `anchor_sink` ngoài, `witness`, `pin_separate`);
`separation_degree() -> int | None`.

Hai con số, không phải một:
- **τ khai báo** — operator nói ai vận hành cái gì. waxseal **không** tự đo được.
- **τ quan sát** — suy từ `.anchors` records + witness verdicts thực tế có trong trail.

Chênh lệch giữa hai số là finding riêng ở **exit 2**. Chưa khai báo → `τ = None`, in ra
`"not declared"`, **không bao giờ** in `1`.

**Nơi khai báo — quyết định của owner: field mới trong pin state, giữ v1.** Nhất quán với
W4/W5 đang thêm field vào đúng chỗ này; đọc được cùng lúc với verify/pin, không thêm file
format mới.

```json
{"v": 1, "target": "...", ...,
 "declared_topology": {
   "seal_escrow": true,
   "anchor_sinks": 2,
   "witness": true,
   "pin_separate": true
 }}
```

`declared_topology` là optional (vắng mặt → `τ khai báo = None`, "not declared"). Khi
**có mặt**, cả 4 field con đều **bắt buộc** — không có khai báo "một phần": một object
thiếu `pin_separate` là `PinMalformed`, không phải suy ra `False`. `pin_separate` đặc biệt
không tự suy ra được từ bất cứ đâu khác (không có tín hiệu nào trong trail hay `.anchors`
nói lên việc pin có tách đĩa hay không) — luôn phải người khai báo tường minh.

`separation_degree()` = 1 (writer, luôn có) + `seal_escrow` + `anchor_sinks` + `witness` +
`pin_separate` (mỗi bool đếm 1 nếu true).

**Test (đỏ trước).**
- `τ = None` khi `declared_topology` vắng mặt; render ra chữ, không ra số.
- `τ` không bao giờ render `None` thành `0` hay `1` (hồi quy rule 5).
- `declared_topology` có mặt nhưng thiếu 1 trong 4 field → `PinMalformed`, không phải
  suy ra giá trị mặc định.
- τ khai báo > τ quan sát → exit 2, reason riêng, **không phải** exit 1.
- τ đơn điệu: thêm authority không làm τ giảm.
- `pin_separate` không tự suy ra được — phải khai báo tường minh; test rằng bỏ trống cho
  `None` (cả object), không cho `False` (field con).
- Pin v1 cũ (không có `declared_topology`) đọc được bởi build mới → `τ = None`, không lỗi.

---

### W4 — C3: `anchor_stale` (silence deadline cục bộ)

**Thay đổi.** Pin state thêm `max_anchor_age_s: int | None` (optional, **giữ v1**). Verify:
nếu set và record `.anchors` mới nhất cũ hơn Δ → reason `anchor_stale`, **exit 2**. `now_fn`
injectable (rule 8) — test không được `sleep`.

**Test (đỏ trước).**
- Δ set, anchor mới → exit 0. Δ set, anchor cũ hơn Δ → exit 2 + reason `anchor_stale`.
- Δ set, **không có** anchor nào → exit 2 (vắng anchor = vắng bằng chứng), không phải exit 1.
- Δ không set → không check, và **không** mặc định là "pass" trong report.
- `ts` không parse được → unverifiable, không phải broken.
- Pin v1 cũ (không có field) đọc được bởi build mới; pin mới đọc được bởi parser v1.

---

### W5 — F2/R2: `expect_anchor_binding`

**Thay đổi.** Pin state thêm `expect_anchor_binding: bool` (optional, giữ v1). Nếu `true` mà
không record nào có `agg_commit is not None` tại/sau seq đã pin → reason
`anchor_policy_downgrade`, **exit 2**. `AnchorRecord` đã sẵn `agg_commit`/`agg_epoch`/
`version` nên **không** cần đổi format sidecar.

W4 và W5 dùng chung đường đọc `read_anchor_records()` đã có.

**Test (đỏ trước).**
- Cờ bật + chỉ có record v1 → exit 2 + `anchor_policy_downgrade` (đây là PoC biến F2 từ
  [Inference] thành [Verified]).
- Cờ bật + có record mang `agg_commit` tại/sau pinned seq → exit 0.
- Cờ bật + record mang binding nhưng **trước** pinned seq → exit 2.
- Cờ tắt → không check.
- `unreadable_versions` không rỗng → unverifiable, không được đọc thành "không có binding".

---

### W6 — F1: lp64v2 làm DEFAULT (rủi ro nhất, đụng frozen path, làm cuối)

**Thay đổi.**
- `hashing.py`: thêm `ENCODING_V2 = "lp64v2"`, `lp2()` (`0x00` cho absent, `0x01‖UTF8` cho
  string) → đơn ánh **vô điều kiện**. `lp()` giữ **nguyên byte**, chỉ thêm guard
  `raise ValueError` khi chuỗi trùng sentinel. Sửa docstring `_Null` — bỏ mệnh đề *"not
  representable as any string"* đã bị bác bỏ, thay bằng bất biến thật.
- `fingerprint.py` *(frozen — owner đã cho phép)*: **thêm** `ENCODING_V2` và
  `fingerprint_for_v2()`. Không chạm `fingerprint_for`/`ENCODING`/`HEADER_V1_FIELDS`.
- `registry.py`: `encoder_for(fp) -> Callable | None`; `compute_entry_hash(header, encode=…)`.
  `None` vẫn nghĩa là **unverifiable**, không phải broken.
- `SPEC.md`: **section mới** §2b, không sửa một chữ nào của §2.
- `tests/vectors/`: **file mới** `vectors_v2.json`; `vectors.json` bất động.
- CHANGELOG: ghi đúng câu — *cơ chế mà project phát minh ra (fingerprint từ descriptor)
  chính là cơ chế cho phép nó sửa an toàn encoding của chính nó.*

**Default — quyết định của owner: KHÔNG opt-in.** lp64v2 là encoding **mặc định** của mọi
trail mới, wired end-to-end: `AuditLog` ghi dưới v2, `fingerprint_v2()` là fingerprint mặc
định trong header, registry dispatch encoder theo fingerprint, CLI verify chạy đúng cả hai.
Không có cờ, không có nhánh chết, không có code đường-cụt chờ ai đó bật.

Hệ quả phải nhận rõ, không được giấu:

- `hash_version` của mọi trail mới **đổi**. Đây là thay đổi quan sát được từ bên ngoài.
- Trail viết bởi ≤ 0.1.3 vẫn verify `ok` dưới lp64v1 — đó chính là điều cơ chế fingerprint
  sinh ra để bảo đảm, và W6 là phép thử thật đầu tiên của nó.
- Build cũ (≤ 0.1.3) đọc trail mới sẽ thấy fingerprint lạ → `unverifiable`, **exit 2**,
  không phải `broken`. Đúng hành vi mong muốn, và là chính lớp lỗi beads-v1.2.2. Phải có
  test khẳng định điều này chứ không chỉ nói.
- **Version giữ `0.1.4`** — quyết định của owner. `hash_version` mặc định đổi, nhưng số
  hiệu release là quyền của owner, không phải hệ quả tôi tự suy ra. Bump đồng thời ở
  `pyproject.toml`, `__version__`, CHANGELOG (`TestVersionIsStatedOnce` bắt cả ba).
  CHANGELOG phải nói rõ `hash_version` của trail mới đổi — giấu chuyện đó mới là làm ẩu.

`lp()`/`fingerprint_for`/`HEADER_V1_FIELDS`/`vectors.json` vẫn bất động byte-for-byte — v1
không bị xoá, chỉ thôi làm mặc định. Registry vẫn append-only.

**Test (đỏ trước).**
- Property test `lp()` với generator gồm sentinel / lone surrogate / NUL byte —
  **fail hôm nay**, đó là F1.
- `lp2` đơn ánh vô điều kiện: `lp2(NULL) != lp2(s)` với mọi `s`, kể cả sentinel.
- Guard `lp()` raise `ValueError` khi gặp sentinel — và đây là lỗi **caller**, không phải
  verdict về dữ liệu đã lưu (cùng logic `membership_proof` raise còn `verify_membership`
  thì không).
- Mọi golden vector cũ vẫn cho đúng hash cũ, byte-for-byte.
- Trail viết dưới v1 vẫn verify `ok` sau khi v2 tồn tại.
- `fingerprint_for_v2` sinh fingerprint **khác** `fingerprint_for` với cùng field tuple.
- Trail v2 đọc bởi registry chỉ biết v1 → `unverifiable`, **không phải** `broken`
  (đây là chính lớp lỗi repo sinh ra để chống).

**Test wiring — owner yêu cầu "chạy thật, không làm ẩu". Đây là phần bắt buộc:**
- `AuditLog.append()` mặc định sinh header có `hash_version == fingerprint_v2()`. Assert
  trên giá trị hex thật, không mock.
- End-to-end qua **CLI thật**: `waxseal verify` trên trail mới ghi → exit 0. Không gọi hàm
  nội bộ, chạy qua `main(argv)`.
- End-to-end **trail hỗn hợp**: trail có cả row v1 (dựng bằng fixture byte cũ) lẫn row v2 →
  verify `ok`, `checked` đếm đủ cả hai. Đây là test chứng minh registry dispatch chạy thật
  chứ không phải chỉ v2 hoạt động.
- **Parity JSONL ↔ SQLite dưới v2**: cùng payload → cùng `entry_hash` byte-for-byte.
- Mọi backend đều đi qua đường v2: JSONL, SQLite, memory, S3, postgres. Test parity phải
  phủ hết, không được chỉ test JSONL rồi suy ra.
- `export-proof` / `verify-proof` / `checkpoint` / `consistency` / `report` chạy đúng trên
  trail v2 — mỗi lệnh một test qua CLI thật.
- **Không nhánh chết**: coverage 100% tự nó chứng minh mọi nhánh v1 lẫn v2 đều có test
  chạy qua. Nếu một nhánh chỉ đạt được bằng cách gọi trực tiếp hàm nội bộ mà không đường
  nào từ API công khai tới được, đó là code đường-cụt → phải bỏ, không phải phủ bằng test.

---

### W7 — Lưới test theo đơn thuốc của bài luận (làm trước W6)

1. `tests/domain/test_knowledge_monotonicity.py` — ma trận rollback `R' ⊆ R` trên **toàn bộ**
   tập con (`itertools.combinations`, không sampling), assert không bao giờ chuyển thành
   `broken`. **Kèm falsifiability receipt**: bằng chứng test fail khi đẩy
   `expected_prev = entry.entry_hash` vào nhánh `else`.
2. Comment tại `domain/verify.py:76` nêu đúng phản chứng (row 5/6/7), theo rule 9.
3. `CLAUDE.md`: viết **Nguyên lý Ba Trạng thái** thành rule có tên, tham chiếu từ 6 chỗ đã
   áp dụng: verdict chain, `dropped_writes`, `human_oversight.mode`, `ModelRef.digest`,
   witness `unreachable`, nonce RFC 3161 vắng mặt. Rule 5 hiện nói đúng ý này nhưng dưới
   dạng ví dụ cụ thể chứ không dạng nguyên lý tổng quát.

---

## Rủi ro đã biết

- **W6 chạm 2 frozen path** và thêm một trục dispatch (encoding) vào đường verify. Làm cuối,
  sau khi W7 dựng xong lưới test. Nếu W6 làm vỡ vector cũ → **DỪNG**, đó là spec break, không
  phải "cập nhật vector" (rule 3).
- **`TestPublicApiFrozen` sẽ đỏ** khi thêm `Verdict` và `SeparationTopology` vào `__all__`.
  Đây là lần đỏ *được phép*, và phải sửa cùng commit kèm rationale — CLAUDE.md quy định vậy.
- **[Unverified]** `integrations/` (9 module) và phần lớn 75 file test chưa được đọc. Các
  thay đổi này **[Inference]** sẽ làm vỡ test ở chỗ chưa lường được. Khi gặp: báo owner,
  không tự nới floor và không tự sửa test cũ.
- **W1 đổi hành vi** như đã nêu. Nếu owner coi "append phát hiện JSON hỏng giữa file" là
  tính chất cần giữ, W1 phải thiết kế lại (ví dụ: quét đầy đủ sau mỗi N append) — cần hỏi
  trước khi làm, không tự quyết.

---

## Kết quả thực tế sau khi đóng 0.1.4 (ghi bổ sung, 2026-08-29)

Ghi lại đúng như đã đo, không như đã dự định. Sổ đầy đủ:
[`docs/paper/conformance.vi.md`](../paper/conformance.vi.md).

- **W1–W2, W4–W7 đạt như viết.** Coverage 100.00%, toàn bộ test xanh.
- **W3 đóng thiếu một nửa.** Tiêu chí W3 viết `τ = None` thì "**in ra** `not declared`".
  `separation_degree()` và `render_separation_degree()` được viết và test đầy đủ, nhưng
  **không đường code nào trong `src/` gọi tới** — chỉ `separation_shortfall()` được nối vào
  `cli.py`. Nên không lệnh nào in τ, `report --json` không có trường τ, và
  `SeparationTopology` không nằm trong public API. Khối được coi là xong vì test đơn vị
  xanh và coverage 100%; **cả hai tín hiệu đó đều không đo được tính với tới**. Đây là bài
  học rút ra của đợt này: một tiêu chí nghiệm thu nói "in ra" phải có một test *chạy lệnh
  thật và đọc stdout*, nếu không nó là tiêu chí về hàm chứ không phải về sản phẩm.
- **Ba khai báo pin mới không có đường ghi.** `expect_anchor_binding`, `max_anchor_age_s`,
  `declared_topology` chỉ đặt được bằng cách sửa tay file pin state. Không kế hoạch nào
  (W3/W4/W5) đặt ra việc thêm cờ CLI, nên đây là thiếu sót của bản kế hoạch, không phải
  của người thi hành.
- **Mục "Not implemented" của CHANGELOG ban đầu chỉ nêu 3 mục contract-layer**, trong khi
  phần còn lại của bài luận còn có admission ticket, cost-optimal anchoring, handoff
  binding, τ chưa in, và 5/8 mục quy trình đánh giá. Đã sửa lại cho đủ trong cùng đợt ghi
  chú này.
