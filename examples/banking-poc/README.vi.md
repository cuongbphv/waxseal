# PoC ngân hàng — nhật ký quyết định AI có thể kiểm chứng

*[English](README.md)*

Bản trình diễn end-to-end chạy được, dùng waxseal làm **lớp bằng chứng bên dưới một AI
agent ra quyết định tài chính**. Một agent sàng lọc AML quyết định trên các lệnh thanh
toán; mọi quyết định được ghi vào chuỗi chống sửa đổi, và về sau kiểm toán viên có thể
kiểm tra một quyết định đơn lẻ mà không cần được trao toàn bộ nhật ký.

Toàn bộ dữ liệu ở đây là **tổng hợp (synthetic)**. Không có dữ liệu khách hàng, không có
tổ chức nào, không có cá nhân nào, và không có mô hình thật — "agent" là một tập luật
tất định, nên demo cho ra cùng một kết quả ở mọi lần chạy và có thể lập luận được về
trail. Thứ được trình diễn là lớp bằng chứng, không phải mô hình.

Không file nào trong thư mục này được thư viện import. Chỉ dùng stdlib, giống bản thân
waxseal, và không thêm dependency nào.

---

## Cách chạy

```bash
python examples/banking-poc/simulate.py --out examples/poc-out     # có animation minh hoạ luồng dữ liệu
python examples/banking-poc/simulate.py --out examples/poc-out --no-animation   # CI / khi pipe output
python examples/banking-poc/tamper_demo.py --out examples/poc-out  # tám kịch bản bên dưới
```

`--out` được tạo lại ở mỗi lần chạy. Animation tự tắt khi stdout không phải terminal, và
tự lùi về ký tự ASCII trên console không encode được ký tự khung (`NO_COLOR=1` hoặc
`WAXSEAL_DEMO_PLAIN=1` cũng buộc chế độ văn bản thuần).

Cả hai script đều được phủ bởi `tests/test_examples_banking_poc.py`, test này kiểm chứng
đúng những khẳng định trang này đưa ra. Một ví dụ đã lệch khỏi thư viện mà không ai biết
thì còn tệ hơn không có ví dụ — nó dạy sai một cách rất tự tin — nên nó được test như code.

---

## Mô phỏng làm gì

Sáu lệnh thanh toán tổng hợp được sàng lọc. Với mỗi lệnh:

| Bước | Việc xảy ra | Vì sao đúng thứ tự này |
|---|---|---|
| `decide` | agent luật-cơ-bản trả về approve / deny / escalate | đóng vai mô hình |
| `redact` | `RegexRedactor` che bí mật trong input | **trước** mọi phép băm |
| `commit` | `input_commitment = sha256(canonical_json(input_đã_che))` | input được cam kết, không bao giờ được lưu |
| `canon` | bản ghi quyết định → JSON chuẩn tắc | khoá đã sắp xếp, không khoảng trắng, một chủ sở hữu duy nhất |
| `hash` | `payload_hash = sha256(payload)` | payload chỉ được tham chiếu qua hash |
| `chain` | `EntryHeader` liên kết tới `prev_hash` | chuỗi băm header, không băm payload |
| `seal` | niêm phong HMAC forward-secure, khoá tiến hoá | khoá ký entry *n* đã biến mất ở *n+1* |

Sau đó, cứ 4 entry thì một checkpoint Merkle được neo (anchor).

### Khẳng định về redaction, được kiểm chứng

Một giao dịch mang ghi chú vận hành có chứa credential (`Bearer sk-live-…`). Cuối lần
chạy, script grep toàn bộ số byte mà nó đã ghi:

```
Cleartext secret present anywhere in the trail: False
```

Test làm điều tương tự trên trail *và* mọi sidecar bên cạnh. Commitment được tính trên
input **đã redact** một cách có chủ ý: nếu cam kết trên cleartext, bất kỳ ai giữ nhật ký
đều có thể xác nhận một phán đoán về bí mật bằng cách tính lại hash.

### Một quyết định cố tình không ghi nhận giám sát của con người

Một nhánh code để `human_oversight` trống. Report phải hiển thị đó là *oversight not
recorded*, đếm tách khỏi `automated` — đây là hai khẳng định khác nhau, gộp chúng lại
chính là báo cáo "thiếu bằng chứng" thành "bằng chứng"
(CLAUDE.md quy tắc 5: `None` ≠ `0`, chưa đo ≠ không có).

### Lần chạy ghi ra những gì

```
examples/poc-out/
  decisions.jsonl           trail
  decisions.jsonl.anchors   các Merkle root đã công bố (bản ghi VỀ trail)
  decisions.jsonl.attest    các niêm phong forward-secure
  decisions.jsonl.sealkey   epoch khoá hiện tại
  sealkey.escrow            A₀ — xem cảnh báo bên dưới
```

Không có sidecar `.drops` vì không có write nào bị rớt. Report ghi
`Dropped writes: >= 0 (measured minimum, source: sidecar)` — một **cận dưới đã đo**, không
phải bảo đảm về tính đầy đủ. Bản thân sidecar có thể bị xoá, và một ổ đĩa hỏng tới mức
không ghi nổi bản ghi rớt thì cũng không thể làm chứng cho chính sự cố của nó.

> **`sealkey.escrow` là hiện vật của demo.** A₀ được ghi cạnh trail ở đây chỉ vì demo
> không có chỗ nào khác để đặt. Trong triển khai thật, đây là bí mật **không được** nằm
> trên máy ghi log — nó thuộc về bên verifier. Kịch bản 6 bên dưới chỉ bị phát hiện vì
> verifier giữ một khoá mà kẻ tấn công không có.

---

## Hướng dẫn cho kiểm toán viên — tám kịch bản

`tamper_demo.py` sao chép trail một lần cho mỗi kịch bản, tấn công bản sao, rồi in ra lệnh
mà kiểm toán viên sẽ chạy kèm exit code thật. **Trail gốc không bao giờ bị sửa** (có test
kiểm chứng). Script tự assert kết quả kỳ vọng của từng kịch bản và thoát khác 0 nếu có
kịch bản nào lệch — đó là biên nhận khả-phủ-định (falsifiability receipt) cho bảng này.

| # | Kịch bản | Phát hiện bởi | Exit |
|---:|---|---|---:|
| 1 | Sửa một quyết định | chuỗi: `payload_hash` không còn khớp | 1 |
| 2 | Xoá một quyết định | chuỗi: `seq_gap` | 1 |
| 3 | Đảo thứ tự lịch sử | chuỗi: `prev_hash_mismatch` | 1 |
| 4 | Chèn thêm một quyết định | chuỗi: `prev_hash_mismatch` | 1 |
| 5 | Viết lại **toàn bộ** trail một cách nhất quán | anchor — riêng chuỗi báo `ok` | 1 |
| 6 | Cắt đuôi trail, cắt cả sidecar | niêm phong forward-secure — riêng chuỗi báo `ok` | 1 |
| 7 | Một dòng từ phiên bản phần mềm **mới hơn** | không gì cả — báo *không kiểm chứng được*, **không phải** bị sửa | 2 |
| 8 | Cung cấp một quyết định cho kiểm toán viên | membership proof (bundle hợp lệ thoát 0) | 1 |

### Kịch bản 1–4: chuỗi tự làm việc của nó

Sửa, xoá, đảo thứ tự và chèn thông thường đều làm đứt một liên kết. `verify` in ra chỗ
đứt đầu tiên kèm số thứ tự và lý do, rồi dừng. Nó **báo cáo**, không bao giờ **sửa chữa**.
Dòng nào là dòng bị can thiệp là quyết định chỉ người vận hành mới được đưa ra.

### Kịch bản 5: vì sao phải neo ở nơi khác

Kẻ tấn công có quyền ghi vào trail có thể sửa một dòng **rồi tính lại mọi hash phía sau**.
Khi đó chuỗi nối lại hoàn hảo:

```
$ waxseal verify .../05-rewrite/decisions.jsonl
ok (checked=6)
exit 0
```

Đó là hành vi đúng, không phải bug: mọi liên kết đều thực sự khớp. Thứ kẻ tấn công không
viết lại được là một root đã được công bố ở nơi khác:

```
$ waxseal verify --anchors .../05-rewrite/decisions.jsonl
ANCHOR BROKEN at seq=3: anchor_entry_hash_mismatch
exit 1
```

Trong demo này, sidecar anchor nằm ngay cạnh trail — điều đó chứng minh cơ chế, nhưng
không chứng minh thuộc tính an toàn: kẻ đã viết lại được trail thì cũng xoá được sidecar
bên cạnh. **Hãy neo vào một miền tin cậy mà máy ghi log không kiểm soát.**

### Kịch bản 6: vì sao khoá niêm phong phải nằm chỗ khác

Cắt đuôi trail *cùng với* các niêm phong đã phủ phần đuôi đó để lại một chuỗi và một
sidecar khớp với nhau:

```
$ waxseal verify .../06-truncate/decisions.jsonl
ok (checked=3)
exit 0
```

Niêm phong forward-secure bắt được, vì epoch khoá trên đĩa không thể quay ngược về epoch
trước đó — `A_{j+1} = SHA-256(A_j)` là hàm một chiều:

```
$ log.verify_attestations(initial_key=A_0)   # ký quỹ ngoài máy ghi
ok=False reason=keyfile_epoch_mismatch
```

### Kịch bản 7: điểm khác biệt đã sinh ra thư viện này

Một dòng do bản build mới hơn ghi mang schema fingerprint mà bản build hiện tại không nhận
ra. Nó **không** bị báo là bị can thiệp:

```
$ waxseal verify .../07-unknown-schema/decisions.jsonl
ok (checked=5) but 1 unverifiable row(s) at seq=[5]
  — unknown schema fingerprint, NOT evidence of tampering
exit 2
```

Exit 2 là một phán quyết riêng. Verifier không được tính lại một dòng theo bộ trường mà
dòng đó không được ký cùng: báo một dòng là nguyên vẹn dựa trên một hash mà nó không tái
tạo được chính là lời nói dối duy nhất mà cơ chế tamper-evidence không bao giờ được phép
nói — còn gọi đó là *bị can thiệp* chính là cảnh báo sai hàng loạt mà thư viện này ra đời
để làm cho không thể xảy ra (RFC 6962 §4.6: kiểu không nhận diện được là mờ đục, không
phải lỗi).

### Kịch bản 8: trả lời một câu hỏi mà không phải công bố cả nhật ký

Cơ quan quản lý hỏi về một khách hàng. Xuất toàn bộ trail sẽ tiết lộ thừa mọi khách hàng
khác trong đó. Một proof bundle là một entry cộng với đường dẫn Merkle của nó:

```
$ waxseal export-proof decisions.jsonl 3 > proof-seq3.json
bundle: 1687 bytes, one entry + its Merkle path

$ waxseal verify-proof proof-seq3.json      # trail đã bị xoá ở thời điểm này
ok: seq=3 verified against root a00438772c5d… (batch of 6)
exit 0
```

Can thiệp vào bundle thì nó fail-closed:

```
BROKEN at seq=3: payload_hash_mismatch
exit 1
```

Kiểm toán viên cần bundle và root đã neo. Họ không cần trail, không cần quyết định của các
khách hàng khác, và không cần bất kỳ quyền truy cập nào vào máy ghi log.

---

## Báo cáo mà kiểm toán viên đọc

```bash
waxseal report examples/poc-out/decisions.jsonl            # Markdown
waxseal report examples/poc-out/decisions.jsonl --json     # dạng máy đọc
waxseal report examples/poc-out/decisions.jsonl --anchors  # đồng thời phát lại sidecar anchor
```

Báo cáo nêu phán quyết về chuỗi, tính đầy đủ (`dropped_writes` kèm nguồn), kiểm kê theo
payload type và schema fingerprint, thống kê quyết định theo loại và theo chế độ giám sát,
cùng trạng thái của từng kiểm tra sidecar. Kiểm tra **không được chạy** sẽ in là *not
checked* — không bao giờ in là đạt. Một báo cáo nói "ok" cho thứ nó đã bỏ qua sẽ thổi
phồng bằng chứng, đúng cái sai lầm mà cả lớp này sinh ra để tránh.

---

## PoC này **không** chứng minh điều gì

- **waxseal là tamper-evident, không phải tamper-proof.** Kẻ tấn công có quyền ghi vẫn có
  thể viết lại trail. Kịch bản 5 và 6 chỉ bị bắt vì có một root đã được neo và một khoá
  niêm phong đã tiến hoá ở ngoài tầm với của kẻ đó.
- **Toàn vẹn chuỗi không phải là tính đầy đủ của trail.** Một write chưa từng xảy ra thì
  không để lại khoảng trống seq nào. `dropped_writes` đo tính đầy đủ một cách tách bạch,
  và `None` ở đó nghĩa là *chưa đo* — không bao giờ là 0.
- **Cam kết trên input entropy thấp là có thể xác nhận được.** Nếu input chỉ có ít giá trị
  khả dĩ, ai cũng có thể liệt kê hết rồi dò khớp hash. Commitment không phải mã hoá.
- **Không có gì ở đây là một phán quyết về tuân thủ.** Lớp này tạo ra bằng chứng kỹ thuật
  có thể hỗ trợ cho một nghĩa vụ lưu trữ hồ sơ; nó không xác lập rằng nghĩa vụ đó đã được
  đáp ứng. Quản trị (governance), kiểm soát truy cập, cưỡng chế thời hạn lưu trữ và tài
  liệu mô hình đều nằm ngoài phạm vi. Xem
  [docs/compliance/mapping.vi.md](../../docs/compliance/mapping.vi.md) để có phân tích
  khoảng trống trung thực.
