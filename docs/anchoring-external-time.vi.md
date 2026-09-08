# Neo vào thời gian bên ngoài

*[English](anchoring-external-time.md)*

Một chuỗi hash chống được việc sửa *phía sau* đỉnh chuỗi. Nó không chống được kẻ tấn công
viết lại toàn bộ tệp, vì mọi `prev_hash` nằm sau chỗ bị sửa đều tính lại được. Cách phòng
vệ duy nhất trước điều đó là một bản sao trạng thái của chuỗi được giữ ở nơi kẻ tấn công
không ghi được - và đó chính là việc neo (anchoring).

Trang này trình bày hai sink bên ngoài mà waxseal cung cấp sẵn, cách kiểm chứng thứ chúng
tạo ra bằng đúng những công cụ sở hữu các định dạng đó, và cách viết một sink cho một chuỗi
mà waxseal không biết tới.

> Không điều gì trên trang này làm cho một trail trở nên tamper-*proof*. Nó làm cho việc
> viết lại trở nên *phát hiện được* bằng cách đối chiếu với một bên nằm dưới quyền quản trị
> khác. Xem [mô hình mối đe doạ](security/threat-model.vi.md) để biết điều đó mua được gì
> và không mua được gì.

---

## RFC 3161 - một Time-Stamp Authority

Một TSA ký một tuyên bố dạng "tôi đã thấy digest này vào thời điểm này". waxseal gửi cho nó
`SHA-256(checkpoint_frame(checkpoint))` - chính là bộ byte mà mọi sink khác cùng chứng
kiến, và đó là lý do ràng buộc aggregate forward-secure nằm bên trong frame chứ không nằm
cạnh frame.

```bash
waxseal anchor trail.jsonl --tsa-url https://freetsa.org/tsr
```

Token được lưu ở dạng mã hoá base64 trong trường `receipt` của bản ghi `.anchors`, với tiền
tố `rfc3161:`. Không có gì được ghi lại nếu TSA không kết nối được, từ chối, hoặc trả lời
về một bộ byte khác.

```bash
waxseal verify trail.jsonl --anchors
# anchors ok (checked=3, latest=seq 240)
#   note: seq=240: attested time (RFC 3161, structural only - signature NOT
#         verified): 2026-08-23T09:22:17+00:00
```

### "structural only" nghĩa là gì

waxseal đối chiếu status của token, `messageImprint` của nó, thuật toán digest của nó, và
nonce của nó. Nó **không** kiểm chứng chữ ký CMS hay chuỗi chứng thư X.509 của TSA - việc
đó cần path validation và xác minh RSA/ECDSA, thứ mà một thư viện không phụ thuộc không có
lý do gì để tự cài lại. Một phép kiểm tra chữ ký tự chế sai một cách tinh vi còn tệ hơn là
không có, vì nó báo cáo một tính xác thực mà không ai thiết lập.

Vậy một structural check đạt nghĩa là *token này đúng định dạng và cam kết đúng bộ byte
này*. Nó không bao giờ nghĩa là *token này là thật*.

### Uỷ thác phần kiểm chứng đầy đủ cho OpenSSL

Trích token và đúng bộ byte nó được yêu cầu đóng dấu, rồi để OpenSSL làm phần mà
waxseal từ chối làm:

```bash
# 1. trích mọi receipt đã lưu cùng frame mà nó chứng thực
waxseal receipt trail.jsonl --out receipts/
# wrote receipts/seq-240.tsr (RFC 3161 timestamp token, seq=240)
# wrote receipts/seq-240.frame (checkpoint frame the receipt attests, seq=240)

# 2. phép kiểm chứng mà waxseal uỷ thác
openssl ts -verify -in receipts/seq-240.tsr -data receipts/seq-240.frame \
    -CAfile tsa-chain.pem
```

`--seq N` giới hạn việc trích vào các bản ghi được neo tại seq đó (các bản ghi
trùng lặp tại cùng một seq mỗi bản nhận một tệp đánh số riêng); exit 3 nghĩa là
trail hoặc sidecar không tồn tại (không gì được tạo ra, kể cả `--out`), và exit
2 nghĩa là sidecar không chứa receipt nào khớp - sự vắng mặt, không phải thành
công và không phải giả mạo.

`tsa-chain.pem` là chuỗi chứng thư của TSA, lấy từ đơn vị vận hành TSA qua kênh ngoài băng
(out of band). Kiểm chứng với một chuỗi mà chính kẻ tấn công đó cũng cung cấp được thì
không chứng minh điều gì.

### Xem xét một token bằng tay

```bash
openssl ts -reply -in receipts/seq-240.tsr -text
```

### Giới hạn trung thực

- Kẻ tấn công viết lại **cả** bản ghi neo lẫn receipt của nó chỉ bị bắt bởi phép kiểm chứng
  chữ ký được uỷ thác ở trên, không bao giờ bởi structural check của waxseal.
- TSA là một bên thứ ba được tin cậy. Nó có thể nói dối về thời gian; nó không thể nói dối
  về *digest nào* nó đã đóng dấu mà không làm mất hiệu lực chính chữ ký của mình.
- Một receipt nặng vài kilobyte. Với `anchor_every=1` trên một trail ghi dày, sidecar
  `.anchors` sẽ phình ra tương ứng - hãy neo theo lịch, đừng neo mỗi lần append.

---

## OpenTimestamps - một calendar trên Bitcoin

OpenTimestamps gộp các digest lại và gấp chúng vào một block Bitcoin. Một khi đã được xác
nhận, tuyên bố về thời gian dựa trên đúng thẩm quyền của chính block chain, và đây là mức
phân tách mạnh nhất có được ở đây.

```bash
waxseal anchor trail.jsonl --ots-calendar https://alice.btc.calendar.opentimestamps.org
```

Calendar trả về một proof ở trạng thái **pending**, được lưu với tiền tố `ots:`. Pending
nghĩa đúng như tên gọi: calendar đã nhận digest, và attestation trên Bitcoin chưa tồn tại
cho tới khi có một block xác nhận - mất hàng giờ tới hàng ngày.

waxseal cố ý không cung cấp bộ phân tích proof OpenTimestamps nào. Định dạng serialize là
một cây attestation-op do chính dự án OpenTimestamps sở hữu; một bản cài lại một phần ở đây
sẽ chế ra phán quyết "malformed" cho những proof hoàn toàn hợp lệ, và đó đúng là lớp lỗi mà
thư viện này sinh ra để ngăn chặn. Vì vậy một receipt `ots:` được báo là pending và chưa
kiểm tra, và không làm thay đổi exit code:

```bash
waxseal verify trail.jsonl --anchors
# anchors ok (checked=1, latest=seq 240)
#   note: seq=240: pending OpenTimestamps proof - opaque to this library by
#         design, NOT checked here; complete and verify it with
#         `ots upgrade` / `ots verify`
```

### Hoàn tất và kiểm chứng một proof

Cài client (`pip install opentimestamps-client`), trích proof ra, rồi upgrade và verify:

```bash
waxseal receipt trail.jsonl --out receipts/
# wrote receipts/seq-240.ots (pending OpenTimestamps proof, seq=240)
# wrote receipts/seq-240.frame (checkpoint frame the receipt attests, seq=240)

ots upgrade receipts/seq-240.ots     # sau khi block Bitcoin xác nhận
ots verify  receipts/seq-240.ots -f receipts/seq-240.frame
```

> **`[Unverified]`** Bộ byte chính xác mà một calendar trả về từ `/digest` ở đây được coi là
> một tệp `.ots` tách rời. Điều này chưa được xác nhận đối chiếu với
> `python-opentimestamps`, và ngữ nghĩa upgrade của `GET /timestamp/<hex>` cũng chưa được
> xác nhận. Hãy kiểm chứng cả hai với client OpenTimestamps trước khi dựa vào công thức này
> trong môi trường sản xuất.

> **`[Unverified]`** Những calendar công khai nào còn sống thì thay đổi theo thời gian. Chính
> vì vậy waxseal không cung cấp URL calendar mặc định nào - hãy truyền vào tường minh, và
> xác nhận rằng nó còn hiệu lực. Các calendar thường được nhắc tới trong tài liệu
> OpenTimestamps gồm `alice.btc.calendar.opentimestamps.org`,
> `bob.btc.calendar.opentimestamps.org`, và `finney.calendar.eternitywall.com`.

### Dự phòng

Mỗi sink một calendar, một cách có chủ ý. Dự phòng trong OpenTimestamps nghĩa là gửi cùng
một digest tới nhiều calendar, mà ở đây tương ứng với nhiều lần chạy `waxseal anchor` với
các giá trị `--ots-calendar` khác nhau. Một sink gộp sẽ phải quyết định thất bại một phần
nghĩa là gì, và đó là lựa chọn của người vận hành chứ không phải một mặc định của thư viện.

---

## Viết một sink cho chuỗi khác

Một `AnchorSink` chỉ có một method (xem `src/waxseal/ports/anchor.py`):

```python
class AnchorSink(Protocol):
    name: str

    def anchor(self, checkpoint: Checkpoint) -> str | SinkReceipt | None: ...
```

Ba quy tắc, tất cả đều rút ra theo cách khó khăn:

1. **Cam kết vào `checkpoint_frame(checkpoint)`, không phải vào một trường của nó.** Frame
   là dạng mã hoá byte chuẩn tắc, và nó là nơi chứa ràng buộc aggregate. Chỉ neo
   `checkpoint.root` sẽ âm thầm làm rơi mất ràng buộc đó.
2. **Ném lỗi khi thất bại. Không bao giờ trả về `None` như thể nó đã thành công.** `None`
   nghĩa là "sink này không có receipt nào để đưa" - một trạng thái hợp lệ cho một sink có
   bằng chứng nằm ở nơi khác. Nó tuyệt đối không được mang nghĩa "việc công bố đã thất bại".
3. **Trả về một receipt mờ đục kèm tiền tố.** `"<type>:<payload>"`. waxseal điều phối theo
   tiền tố, và báo một tiền tố nó không biết là không-kiểm-chứng-được-theo-tên thay vì đoán
   mò bộ byte. Một sink cần lưu vật liệu request cạnh receipt để re-verify về sau (nonce
   RFC 3161) thì trả về `waxseal.domain.checkpoint.SinkReceipt` thay cho một chuỗi trần.

`RecordingAnchorSink` đảm nhận phần sổ sách sidecar - nó công bố trước và ghi sau, nên một
lần công bố thất bại không để lại bản ghi nào. `AuditLog` tự động bọc sink của một trail có
đường dẫn cục bộ trong lớp này; bọc tường minh như dưới đây là tương đương:

```python
from waxseal import AuditLog
from waxseal.adapters.anchors import RecordingAnchorSink

log = AuditLog.open("trail.jsonl").with_anchor_sink(
    RecordingAnchorSink("trail.jsonl", MyChainSink(...))
)
log.anchor()
```

### Sự kiện hợp đồng EVM

waxseal giờ đã cung cấp sẵn cái này (0.1.5, Workstream F) - xem
`src/waxseal/adapters/evm.py::EvmAnchorSink`. EVM không còn là "một chuỗi mà
waxseal không biết tới" nữa; hãy dùng sink thật thay vì tự viết lại:

```bash
waxseal anchor trail.jsonl --evm-rpc https://rpc.example \
    --evm-liveness 0xLIVENESS_CONTRACT_ADDRESS
```

Lưu `sha256(frame)` vào calldata của một hợp đồng hoặc phát nó ra làm topic của một event;
chain id, số block, và transaction hash cùng nhau tạo thành receipt. Bên ký giao dịch không
bao giờ là một tham số dòng lệnh hay một biến môi trường chứa private key: đó là một tiến
trình bên ngoài được đặt tên qua `WAXSEAL_EVM_SIGNER_CMD`, một giao thức ba động từ
(`address` / `sign-digest` / `sign-tx`) - xem đoạn về CLI contract trong CLAUDE.md.

Các lưu ý riêng cho EVM, vẫn đúng dù sink có sẵn của waxseal xử lý việc này hay bạn áp dụng
lại hình dạng đó cho một chuỗi tương thích EVM mà nó chưa bao phủ: một giao dịch bị revert
phải ném lỗi chứ không được trả về (sink có sẵn đã làm đúng điều này); một lần reorg có thể
huỷ một anchor đã xác nhận, nên hãy chờ đủ độ sâu xác nhận mà mô hình mối đe doạ của bạn yêu
cầu trước khi coi receipt là bằng chứng (`confirm_tag` của `EvmLedgerSink` mặc định là
`finalized` chính vì lý do đó); và digest thì công khai vĩnh viễn, điều đó không sao - nó là
hash của một hash, và payload không bao giờ rời khỏi kho lưu trữ của bạn.

### Hyperledger Fabric

Gọi một hàm chaincode với digest làm tham số; receipt là tên channel cộng với transaction
ID. Chính endorsement policy của Fabric là thứ mang lại cho anchor sự phân tách thẩm
quyền - một anchor chỉ được endorse bởi đúng tổ chức đang vận hành audit trail thì không
phải là
nhân chứng bên ngoài.

### Một chuỗi riêng tư hoặc chuỗi liên minh

Hình dạng vẫn như vậy, và vẫn cùng một câu hỏi quyết định nó có đáng gì hay không: *bên có
thể viết lại trail có viết lại được cả anchor không?* Nếu có, anchor là sổ sách chứ không
phải bằng chứng. Một chuỗi riêng tư do chính đội vận hành ứng dụng vận hành thuộc nhóm đó.

### Công bố sang một witness thay vì neo

Nếu bên kia sẵn sàng trả lại các checkpoint của họ, thì đó là một *witness* chứ không phải
anchor sink, và nó mua thêm khả năng phát hiện fork bên cạnh khả năng phát hiện việc viết
lại:

```bash
waxseal anchor trail.jsonl --witness https://notary.example/anchors
waxseal verify trail.jsonl --witness https://notary.example/anchors
```

Định dạng wire nằm ở REMOTE.md mục 8.
