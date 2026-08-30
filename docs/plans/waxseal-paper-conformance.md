# waxseal — Đáp ứng bài luận 100%: chuyển mọi khẳng định về code từ *phát biểu* sang *đã chạy*

### Mục tiêu

Sổ đối chiếu [`docs/paper/conformance.vi.md`](../paper/conformance.vi.md) liệt kê chính xác
phần bài luận đòi mà repo chưa đáp ứng. Epic này đóng **toàn bộ** phần đó, với một tiêu chuẩn
bằng chứng cao hơn hiện tại: mỗi bead kết thúc bằng **output của một lượt chạy thật**, không
phải bằng một hàm có test đơn vị xanh.

### Ranh giới của "100%" — đọc trước khi mở bead

**[Verified]** Không phải mọi nhãn `[Unverified]`/`[Inference]` trong bài luận đều chuyển
thành `[Proved]` được, và một kế hoạch hứa ngược lại là hứa thứ không giao được. Sáu dòng sau
đứng yên vĩnh viễn, lý do đầy đủ ở mục 6 của sổ đối chiếu:

- SHA-256 kháng va chạm; HMAC-SHA-256 là MAC an toàn — giả định của ngành, không phải tính
  chất của repo này.
- Xoá khoá epoch có hiệu lực — **đã biết là sai theo nghĩa chặt**, CPython không zeroise được.
- Anchor/witness thuộc thẩm quyền khác — phần mềm không cưỡng chế được, là nghĩa vụ operator.
- Các authority hỏng độc lập — lựa chọn mô hình hoá, và là lựa chọn lạc quan.
- Mọi con số tiền tệ/độ trễ/pháp lý — đo được cho một triển khai, không chuyển sang chỗ khác.
- Đánh giá tính mới so với prior art — cần khảo cứu tài liệu hệ thống, không phải việc của code.

**Phạm vi thật của epic:** mọi khẳng định mà **chủ ngữ là code trong repo này**. Đó là 100%
đạt được, và là thứ epic này bị bó vào. Ba construction contract-layer (ALC on-chain, bonded
checkpoint, registry on-chain) **không** vào epic này: chúng cần thành phần on-chain, mâu
thuẫn `dependencies = []`, và đã được khai báo là [Out of scope] trong sổ.

### Bài học từ 0.1.4 — điều kiện nghiệm thu của epic này khác trước

Khối W3 của 0.1.4 đóng với test đơn vị xanh và coverage 100%, nhưng
`render_separation_degree()` **không đường code nào trong `src/` gọi tới**. Cả hai tín hiệu
"test xanh" và "coverage 100%" **đều không đo được tính với tới**. Vì vậy mọi bead dưới đây
thêm một điều kiện nghiệm thu mà 0.1.4 không có:

> **Điều kiện R (reachability).** Nếu bead nói một thứ được *in ra*, *báo cáo*, hay *người
> dùng bật được*, thì phải có một test **chạy `main()` thật (hoặc subprocess) và assert trên
> stdout/exit code/JSON**, không chỉ test hàm thuần. Một tiêu chí nói "in ra" mà chỉ có test
> hàm là tiêu chí về hàm, không phải về sản phẩm.

### Ràng buộc chung cho mọi bead (từ CLAUDE.md)

1. **TDD bắt buộc** — commit đầu chứa test đỏ kèm output chứng minh nó đỏ.
2. `uv run pytest --cov=waxseal` → **100.00%**, `fail_under = 100` không đổi. Không thêm
   `# pragma: no cover` để lách.
3. **Baseline hiện tại phải giữ xanh**: **[Verified]** `1703 passed, 11 skipped`, coverage
   100.00%, `ruff check` sạch. Một test cũ đỏ là tín hiệu thiết kế sai, không phải test cần sửa.
4. Zero runtime dependency. `domain/` thuần: không I/O, không import `ports/`/`adapters/`.
5. `SPEC.md`, `tests/vectors/**`, `domain/fingerprint.py`, `CLAUDE.md`, `LICENSE` là frozen
   path — bead nào cần sửa phải **dừng lại hỏi owner**, không tự quyết.
6. Public API đóng băng: thêm vào `__all__` phải sửa `TestPublicApiFrozen` **cùng commit**
   kèm rationale.
7. Exit code: 0 intact / 1 broken / 2 unverifiable / 3 path missing. Không bead nào được
   escalate một "thiếu bằng chứng" lên exit 1.
8. Mỗi bead **cập nhật đúng dòng của nó** trong `docs/paper/conformance.md` **và** bản `.vi`
   — đổi trạng thái, thêm đường dẫn bằng chứng. Sổ sai là sổ vô dụng.

### Thứ tự và va chạm file

`cli.py` là điểm nghẽn: 5 bead chạm nó. `bead-fleet` chạy một worktree mỗi bead rồi rebase
ff-only, nên các bead chạm cùng file phải **nối tiếp**, không song song.

- **Làn 1 (nối tiếp, chạm `cli.py`)**: C1 → C2 → C3 → C4
- **Làn 2 (song song, không chạm `cli.py`)**: T1, T2, T3, T4, T5
- **Làn 3 (song song, domain thuần trước khi nối CLI)**: D1, D2, D3
- **Cuối cùng**: Z1 (chỉ chạy khi mọi bead trên đã đóng)

---

### Quyết định của owner (2026-08-29) — bắt buộc, không suy diễn lại

1. **Toàn bộ đợt này nằm trong v0.1.4. Tuyệt đối không tự suy ra v0.2.0.**
   **[Verified]** tag mới nhất là `v0.1.3`; `pyproject.toml:7`, `__init__.py:54` và
   `CHANGELOG.md:8` đều đã ghi `0.1.4`, tức 0.1.4 chưa phát hành. Mọi bead ghi thành quả vào
   **mục `## [0.1.4]` sẵn có**. Không bead nào được sửa `version`/`__version__`, không tạo mục
   `[Unreleased]`, không đặt số phiên bản mới. `TestVersionIsStatedOnce` bắt cả ba chỗ phải
   khớp — một bead tự bump sẽ làm đỏ test đó, và đó là tín hiệu bead làm sai, không phải test sai.

2. **Được sửa mục "CLI contract" của `CLAUDE.md` — và chỉ mục đó.** Uỷ quyền hẹp cho C4 và D2
   khi thêm một lệnh **read-only**: cập nhật danh sách lệnh trong mục đó, kèm rationale trong
   commit message. Mọi mục khác của `CLAUDE.md` và mọi frozen path khác (`SPEC.md`,
   `tests/vectors/**`, `domain/fingerprint.py`, `LICENSE`) **vẫn cấm tuyệt đối** — gặp thì DỪNG
   và hỏi owner.

3. **Mở cả ba tên vào public API**: `Verdict`, `SeparationTopology`, `separation_degree` vào
   `__all__` của `src/waxseal/__init__.py`, sửa `TestPublicApiFrozen` **cùng commit** kèm
   rationale. Việc này thuộc **C1**. Lý do owner chọn cả ba thay vì hai: caller tự join verdict
   sẽ tự nghĩ ra `max()` — đúng thứ `Verdict` sinh ra để không viết được nữa; giấu nó đi là
   đẩy an toàn cấu trúc ngược về an toàn thủ tục ở phía người dùng.

4. **T1 chạy hai mức**: mỗi lượt CI chạy một `N` khả thi **có seed**, cộng một workflow
   `schedule` hàng tuần chạy đủ 10⁶. Con số `N` bị hạ **phải được ghi ra** trong test và trong
   sổ đối chiếu — một cận bị hạ mà không nói ra là một cận bịa. T1 **giữ `auto-partial`**: nửa
   code làm trong repo, nhưng điều kiện đóng là CI thật xanh, thứ không xác nhận được từ trong repo.

### Rủi ro đã biết

- **T2 có thể chạm frozen vector.** Nếu chốt hành vi lone surrogate làm đổi byte của `lp()`
  cho đầu vào đang dùng → DỪNG, hỏi owner (rule 3).
- **Public API: owner đã chốt** (quyết định 3) — C1 mở cả ba tên và sửa
  `TestPublicApiFrozen` cùng commit. Không cần hỏi lại. Đây là cam kết tương thích lâu dài:
  ba tên đó từ nay không được đổi tên hay bỏ đi mà không phải là breaking change.
- **D2/D3 thêm kiểu payload mới — và điều đó KHÔNG sinh fingerprint mới.** Đã đo lại vì
  bản nháp đầu của kế hoạch này nói ngược: **[Verified]** fingerprint tính trên (algorithm,
  encoding, **tên** của 6 trường header) tại `domain/fingerprint.py:29-36`. `payload_type`
  là một *tên trường*; *giá trị* của nó thay đổi theo từng entry. Có 8 tiền lệ sẵn trong
  `integrations/`. Registry append-only chỉ bị động tới nếu **tập trường header** đổi, mà
  D2/D3 không đổi. Bead nào thấy mình sắp thêm fingerprint mới là đang làm sai thiết kế.
- **[Unverified]** Chưa đọc hết `integrations/` (9 module) và phần lớn 75+ file test. D3
  **[Inference]** sẽ làm vỡ test ở chỗ chưa lường. Khi gặp: báo owner, không tự nới floor,
  không tự sửa test cũ.
- **Làn 1 nối tiếp là bắt buộc.** Bốn bead cùng chạm `cli.py`; chạy song song thì rebase
  ff-only của fleet sẽ gãy.

---

## C1 — Báo cáo τ và liệt kê các authority được đếm (đóng G1)

**Vì sao.** Bài luận: hai triển khai mật mã giống hệt nhau, τ khác nhau, **không** an toàn
ngang nhau — nên report bỏ τ là bỏ đúng đại lượng duy nhất thay đổi. `separation_degree()`
và `render_separation_degree()` đã có, test đầy đủ, và **không ai gọi**.

**File.** `domain/report.py`, `cli.py`, `tests/domain/test_report.py`, `tests/test_cli*.py`.

**Việc.**
- `ReportResult` mang τ và **danh sách authority được đếm** (không chỉ con số — bài luận đòi
  "enumerate the authorities counted", vì τ là thứ assessor kiểm được bằng cách hỏi ai vận
  hành cái gì).
- `verify` và `report` in dòng τ; `report --json` có trường τ.
- Chưa khai báo → in `not declared`, JSON là `null`. **Không bao giờ** `0` hay `1`.

**Test (đỏ trước).**
- Điều kiện R: chạy `main()` thật, assert stdout có `not declared` khi pin không khai báo.
- Pin có `declared_topology` → stdout in đúng số, JSON có đúng số, và liệt kê đủ authority.
- Không `--pin` → τ vẫn là `not declared`, không phải vắng mặt im lặng.
- Regression rule 5: không đường nào render `None` thành số.

**Xong khi.** Điều kiện R đạt; sổ đối chiếu dòng G1 và dòng "Tightness" chuyển sang [Shipped].

---

## C2 — Cờ CLI khai báo kỳ vọng của pin (đóng G2)

**Phụ thuộc.** C1.

**Vì sao.** `expect_anchor_binding`, `max_anchor_age_s`, `declared_topology` được parse,
được kiểm, được giữ qua pin advance, đặc tả ở SPEC 13.1 — và **không cờ CLI nào ghi chúng**.
Đường duy nhất là sửa tay JSON. Ba phép kiểm đọc lên như tính năng bật được trong khi thực
tế phải biết format file mới bật được.

**File.** `cli.py`, `adapters/pinstore.py` (nếu cần), test CLI.

**Việc.** Thêm cờ ghi ba khai báo vào pin state. `declared_topology` phải nhận **đủ 4 thành
phần** — khai báo một phần là `PinMalformed`, không suy ra mặc định (SPEC 13.1).

**Test (đỏ trước).**
- Điều kiện R: chạy CLI ghi pin, đọc lại file, assert JSON đúng format SPEC 13.1.
- Khai một phần `declared_topology` → lỗi có nhãn, không tự điền `False`.
- Pin advance sau đó **giữ nguyên** khai báo.
- Pin cũ không có ba trường → đọc được, không lỗi.

**Xong khi.** Điều kiện R đạt; sổ G2 → [Shipped]; ba README bỏ câu "chưa có cờ CLI".

---

## C3 — Một lượt `anchor` tới được nhiều domain độc lập (đóng G3)

**Phụ thuộc.** C2.

**Vì sao.** Corollary chọn anchor: publish **cùng một** checkpoint frame sang TSA (cửa sổ
phút) **và** calendar (non-repudiation dài hạn); τ tăng một cho mỗi domain độc lập. Hiện
`--tsa-url` và `--ots-calendar` nằm trong mutually exclusive group.

**File.** `cli.py`, `adapters/anchors.py`, test CLI + adapter.

**Việc.** Bỏ ràng buộc loại trừ; cả hai sink chạy trên **cùng một** checkpoint frame, mỗi
sink một record sidecar. Một sink hỏng **không** được làm mất record của sink kia — record
tồn tại phải nghĩa là một lần publish đã xảy ra (luật sẵn có của `RecordingAnchorSink`).

**Test (đỏ trước).**
- Điều kiện R: một lượt CLI với cả hai cờ → sidecar có 2 record, cùng `entry_hash`/`root`.
- TSA hỏng, calendar chạy → vẫn có record của calendar, và **có nhãn** cho cái hỏng (rule 6).
- Một cờ → hành vi cũ không đổi.

**Xong khi.** Điều kiện R đạt; sổ G3 → [Shipped]; README ba thứ tiếng sửa lại.

---

## C4 — Nối `waxseal cadence` vào CLI

**Phụ thuộc.** C3 và D1.

**Việc.** Lệnh read-only in `N*`, khoảng clamp `[λδ, λT_max]`, tỉ số phẳng, và fleet
dividend từ tham số operator đưa. **In một dải, không in một điểm** — bài luận: `N*` tỉ lệ
`(wρ)^(-1/2)`, sai mười lần ở đầu vào khó biết nhất chỉ dịch tối ưu 3.2 lần và tốn 1.67 lần,
nên công thức dùng được với ước lượng cỡ độ lớn, và đó là *định lý* chứ không phải hy vọng.

**Test (đỏ trước).** Điều kiện R trên stdout; `δ > T_max` → báo "sai công nghệ anchor, không
phải sai cadence", có nhãn, không phải một con số bịa ra.

---

## T1 — Mục 1: đối chiếu ngẫu nhiên với bản cài đặt lại độc lập

**Việc.** `tools/` đã implement văn xuôi SPEC mà không import waxseal, nhưng chỉ chạy trên
tập vector cố định. Thêm một lượt differential trên header ngẫu nhiên, so byte-for-byte giữa
bản độc lập và `domain/hashing.py`. Bài luận đòi 10⁶; chạy full trong CI là quá chậm —
**chọn một con số chạy được và ghi rõ con số đó**, cộng một job dài chạy theo lịch. Một cận
bị hạ xuống mà không nói ra là một cận bịa.

**Test.** Sinh có seed (tái lập được), assert 0 sai khác. Kèm **falsifiability receipt**:
sửa một byte trong bản độc lập → lượt đối chiếu phải đỏ.

## T2 — Mục 2: generator phủ lone surrogate (đóng G4)

**Việc.** `st.characters(codec="utf-8")` **không thể** sinh lone surrogate. Đó là strategy
đúng cho văn bản hợp lệ và sai cho phép thử bài luận kê. Chốt hành vi của `lp()` khi nhận
chuỗi Python cho phép mà UTF-8 không: raise có nhãn hay encode — **quyết định rồi assert**,
không để không xác định.

**File.** `tests/domain/test_properties.py`, có thể `domain/hashing.py` (nếu chốt là raise
có nhãn thì cần một exception có tên).

**Lưu ý.** Nếu quyết định làm đổi byte đầu ra của `lp()` cho **bất kỳ** đầu vào nào đang
dùng → **DỪNG**, đó là spec break chạm frozen vector, phải hỏi owner.

## T3 — Mục 5: fault injection giữa các lần ghi sidecar phụ thuộc

**Việc.** Tiêm lỗi giữa hai lần ghi sidecar phụ thuộc nhau (`.anchors` ↔ `.sealagg`,
`.attest` ↔ trail). Assert kết quả là một **mismatch có nhãn**, không phải crash và không
phải pass im lặng (rule 6).

## T4 — Mục 6: chiến dịch mutation testing đo hai tỉ lệ **tách riêng**

**Việc.** Đột biến một record (sửa/xoá/chèn/đảo/sửa bit trong payload/sửa hash), đo **tách
riêng**: (a) tỉ lệ phát hiện, (b) độ chính xác của `reason` **và** `broken_seq`. Hai số, in
riêng. Một verifier phát hiện 100% mà gọi sai lý do thì operator vẫn hành động sai.

**Xong khi.** Test in ra hai tỉ lệ và assert ngưỡng; ngưỡng nào < 100% phải có nhãn giải
thích lớp đột biến nào không phát hiện được và **vì sao đó là đúng** (ví dụ: rewrite toàn
trail là phát hiện được từ ngoài, không phải từ trong).

## T5 — Mục 7: fuzzing never-raise quét **mọi** verifier entry point

**Việc.** Liệt kê mọi entry point của verifier bằng cách quét module (không hardcode danh
sách — danh sách hardcode sẽ mục), ném bytes/JSON/DER thù địch vào từng cái, assert **không
cái nào raise**. Đây là luật normative sẵn có của repo, hiện chỉ được kiểm rời rạc.

**Xong khi.** Một test **tự phát hiện entry point mới** và đỏ khi có entry point chưa được
fuzz — nếu không, test này mục ngay lần thêm module sau.

---

## D1 — Cost-optimal anchoring (`domain/cadence.py`)

**Việc.** `N* = √(2cλ/(Mwρ))`, tính lồi, tính chất cân bằng (tại `N*`, chi cho anchor bằng
tổn thất kỳ vọng), cận phẳng `½(x + x⁻¹)`, clamp `[λδ, λT_max]`, fleet dividend `√M`. Thuần
số học, stdlib, `domain/`.

**Test (đỏ trước).** Tính chất cân bằng ở `N*`; sai hệ số 2 tốn 25%, hệ số 3 tốn 67% (định
lý phẳng); `δ > T_max` → **infeasible có nhãn**, không phải một số. Đơn điệu: tăng `M` không
làm `N*` mỗi agent tăng.

**Không làm.** Không đoán giá trị mặc định cho `w`, `ρ`, `c`. Đó là đầu vào của operator;
bịa một mặc định là bịa một phép đo.

## D2 — Admission ticket ngoại sinh

**Vì sao.** Construction **duy nhất** trong bài luận biến một write bị mất thành một write
*bị phát hiện dương tính* — đối trọng của định lý bất khả thi về coverage. Bài luận: đòn rẻ
nhất không phải sửa log, mà là chặn write.

**Việc.** Kiểu ticket đơn điệu trong payload + một lượt đối soát (vé đã phát vs vé có trên
trail). Vé thiếu = drop **phát hiện dương tính**. Với lease size `L`: chi phí round-trip
khấu hao còn `1/L` mỗi action, và **tối đa `L-1` drop mỗi cửa sổ lease vẫn không phát hiện
được** — con số đó phải được **báo cáo**, không được giấu.

**Test.** Vé thiếu → phát hiện dương tính, nêu đúng khoảng. `L-1` drop trong cửa sổ →
báo cáo nói rõ đó là vùng mù, **không** báo "sạch". Bên phát vé không tới được → *unmeasured*
(exit 2), không phải "không có drop".

## D3 — Handoff binding liên trail + anchoring bắc cầu

**Vì sao.** `integrations/openai_agents.py` ghi phase handoff mang **tên** agent. Một cái tên
không cam kết gì. Bài luận đòi bộ ba (chain id, sequence, head hash) nằm trong payload, để
`payload_hash` của B cam kết vào head của A.

**Việc.** Một kiểu entry handoff **tối thiểu và không bao giờ bị xoá**, chỉ mang bộ ba con
trỏ, **không mang dữ liệu nghiệp vụ** — nên không có cơ sở pháp lý nào đòi xoá nó. Đây là
cách bài luận giải căng thẳng giữa anchoring bắc cầu và quyền xoá dữ liệu.

**Test.** Anchor trail của agent sink → prefix của agent nguồn bị ghim bắc cầu. Payload
handoff bị xoá → **unverifiable**, không phải broken (xoá payload không được tạo ra verdict
gãy — luật sẵn có). Đồ thị delegation nhiều bậc: ghim sink ghim mọi prefix thượng nguồn.

---

## Z1 — Kiểm toán lại và đóng sổ

**Phụ thuộc.** Mọi bead trên.

**Việc.**
- Kiểm lại **từng dòng** `docs/paper/conformance.md` + `.vi` bằng chứng cứ chạy được, không
  bằng trí nhớ. Dòng nào còn [Partial]/[Not built] phải nêu lý do, không được im lặng.
- Xác nhận `separation_degree`/`render_separation_degree` **không còn** là code không ai gọi
  — và quét xem có hàm nào khác trong `src/` cũng ở tình trạng đó. Đợt này sinh ra vì một
  hàm như thế; nếu còn hàm thứ hai, tìm ra bây giờ.
- Ghi thành quả vào **mục `## [0.1.4]` sẵn có** của CHANGELOG. Không bump version,
  không tạo mục mới (quyết định 1 của owner).
- Nếu bất kỳ mục nào **không** đóng được: ghi vào sổ với lý do đo được. Một mục đóng không
  nổi và nói ra thì tốt hơn một mục đánh dấu xong mà không ai với tới.

---
