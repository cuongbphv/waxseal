# Mô hình mối đe doạ của waxseal

*[English](threat-model.md)*

Thư viện này phát hiện được gì, không phát hiện được gì, và vì sao. Mọi khẳng định dưới đây
đều nhằm để kiểm tra được đối chiếu với code và test; chỗ nào hoàn toàn không phát hiện
được thì lập luận cho điều đó được viết ra chứ không chỉ được tuyên bố.

Tài liệu này tồn tại vì một công cụ tamper-evidence tự nói quá về mình còn tệ hơn là không
có: nó tạo ra một văn bản mà ai đó sẽ trích dẫn trong một cuộc kiểm toán, và trích dẫn ấy
mang theo nhiều tự tin hơn mức mà bằng chứng có được.

---

## 1. Tamper-evident không phải tamper-proof

**Câu hỏi:** waxseal chỉ là tamper-evident. Làm sao đi tới *proof*?

**Trả lời: không có cách nào, nếu chỉ bằng phần mềm, và không thư viện nào tuyên bố ngược
lại mà nói thật.**

Lập luận rất ngắn. Kẻ tấn công có quyền ghi vào kho lưu trữ đang giữ trail có thể thay thế
từng byte của nó. Chuỗi hash không ngăn được điều này: mỗi `entry_hash` là một hàm thuần
tuý của header, và mỗi `prev_hash` là `entry_hash` trước đó, nên việc tính lại toàn bộ
chuỗi từ một dòng đã bị viết lại chỉ là thao tác máy móc. Niêm phong làm tăng chi phí — một
HMAC forward-secure cần epoch key — nhưng kẻ tấn công nắm ổ đĩa thì cũng nắm luôn keyfile,
và tuy khoá đã *tiến hoá* vượt qua các epoch cũ, kẻ tấn công hoàn toàn có thể bắt đầu một
chuỗi mới từ khoá hiện tại rồi trình bày nó như toàn bộ lịch sử.

Thứ mà phần mềm *làm được* là khiến việc viết lại trở nên **phát hiện được bằng cách đối
chiếu với một bản sao mà kẻ tấn công không ghi được**. Mọi thứ trong waxseal vượt ra ngoài
một chuỗi hash thuần đều tồn tại để tạo ra những bản sao như vậy:

| Cơ chế | Bản sao do ai giữ | Phát hiện được |
|---|---|---|
| Neo (SPEC 9) vào một sidecar cục bộ | chính ổ đĩa đó | hỏng dữ liệu ngoài ý muốn, bug trung thực. Không phải kẻ tấn công. |
| TSA theo RFC 3161 (SPEC 17) | TSA | việc viết lại lịch sử đã neo, và khẳng định thời gian |
| OpenTimestamps (SPEC 18) | Bitcoin | như trên, mà không cần bên thứ ba được tin cậy |
| Witness (SPEC 14) | một host khác | việc viết lại *và* split view |
| Head đã ghim (SPEC 13) | verifier | việc viết lại phần lịch sử mà verifier này đã thấy |
| Niêm phong forward-secure (SPEC 11) | keyfile đang tiến hoá | việc chèn và cắt đuôi, chừng nào người giữ khoá còn trung thực |

"Proof" trên thực tế là một *tổ hợp*, và tổ hợp chỉ mạnh bằng mức phân tách yếu nhất của
nó:

1. Neo tới ít nhất hai thẩm quyền không chung một đơn vị vận hành.
2. Giữ khoá niêm phong dưới một quyền quản trị khác với ứng dụng đang ghi trail.
3. Đặt kho lưu trữ trên phương tiện write-once ở những nền tảng có hỗ trợ (chẳng hạn S3
   Object Lock ở chế độ compliance). waxseal không cung cấp code nào cho việc này — đó là
   cấu hình lưu trữ, và một thư viện không cưỡng chế được.
4. Ghim (pin), và giữ tệp pin ở nơi bên ghi trail không với tới được.

Bỏ sót bất kỳ điều nào trong số này thì đòn tấn công tương ứng quay lại. Đó là hình dạng
trung thực của câu trả lời: không phải một tính năng để bật lên, mà là một tập các phân
tách phải duy trì.

---

## 2. Toàn vẹn chuỗi không phải tính đầy đủ của trail

**Câu hỏi:** toàn vẹn chuỗi không phải là tính đầy đủ của trail?

**Trả lời: đúng, và sự phân biệt này là chịu lực.**

`verify` duyệt các entry đã ghi và xác nhận từng entry liên kết với entry trước. Một lần
ghi thất bại *trước khi tới được kho lưu trữ* không để lại khoảng trống nào cho lượt duyệt
đó tìm ra: số thứ tự vẫn liền mạch, mọi `prev_hash` đều khớp, và phán quyết là `ok`. Không
điều gì ở một chuỗi hợp lệ nói rằng chuỗi đó là đầy đủ.

waxseal báo cáo tính đầy đủ như một đại lượng riêng, được đo một cách tường minh:

- `dropped_writes: int | None`. `None` nghĩa là **chưa bao giờ được đo**. Nó không phải
  `0`, không bao giờ được hiển thị thành `0`, và không bao giờ được bỏ khỏi báo cáo như thể
  câu hỏi chưa từng được đặt ra.
- Sidecar `.drops` (SPEC 12) cho con số đó một lớp lưu bền độc lập với bộ nhớ của bất kỳ
  tiến trình nào. Bật bằng `AuditLog.open(path, record_drops=True)`.
- Con số lấy từ sidecar là một **cận dưới đã đo**, không bao giờ là tổng số. Một sự cố tệ
  tới mức ngăn cả việc ghi bản ghi rớt của chính nó thì không làm chứng được cho chính nó.

`verify` trả về ok nghĩa là gì và không nghĩa là gì:

| Nó có nghĩa là | Nó không có nghĩa là |
|---|---|
| mọi entry đã ghi đều liên kết với entry trước nó | mọi sự kiện đã xảy ra đều được ghi lại |
| không entry đã ghi nào bị sửa, xoá hay đảo thứ tự | không lần ghi nào bị rớt trước khi tới kho lưu trữ |
| các fingerprint của những entry đã ghi đều được bản build này biết tới | các payload là đúng sự thật |
| trail nhất quán về mặt nội tại | trail là toàn bộ câu chuyện |

Cách duy nhất để chặn trên phần *thiếu* là đối chiếu với một nguồn nằm ngoài trail — số
lượng message của một broker, số dòng của một cơ sở dữ liệu, hồ sơ của một đối tác. Phép
đối chiếu đó là biện pháp kiểm soát ở mức ứng dụng. Việc của waxseal là bảo đảm rằng không
bao giờ *trông như thể* phép đối chiếu đó đã được thực hiện rồi.

---

## 3. Thời gian đáng tin cậy

**Câu hỏi:** tích hợp RFC 3161 để `ts` trở thành được chứng thực thay vì chỉ được khẳng
định.

Trường `ts` của một entry do chính tiến trình append nó ghi ra, từ đồng hồ của tiến trình
đó. Nó là một khẳng định của bên ghi, và trước kẻ tấn công kiểm soát bên ghi thì nó chẳng
đáng gì.

Neo theo RFC 3161 (SPEC 17) khắc phục điều đó cho *checkpoint*, chứ không phải cho từng
entry: TSA đóng dấu `SHA-256(checkpoint_frame(cp))`, việc này chặn trên mọi entry tới `seq`
của checkpoint đó thành "đã tồn tại không muộn hơn `genTime` của token". Kết hợp với
checkpoint liền trước, một entry được kẹp giữa hai mốc thời gian đã chứng thực.

waxseal kiểm tra gì và uỷ thác gì được nói rõ trong
[neo vào thời gian bên ngoài](../anchoring-external-time.vi.md). Ngắn gọn: structural check
xác nhận token cam kết đúng bộ byte này; chữ ký CMS do `openssl ts -verify` kiểm chứng,
không bao giờ ở đây. Mọi dòng output có nhắc tới một token đều nói rõ điều đó, vì một
structural check bị đọc thành xác thực chính là kiểu nói quá mà tài liệu này sinh ra để
ngăn.

Rủi ro còn lại: một TSA có thể nói dối về *thời gian*. Nó không thể nói dối về *digest nào*
nó đã đóng dấu mà không làm mất hiệu lực chính chữ ký của mình. Hãy neo tới nhiều hơn một
thẩm quyền nếu tuyên bố về thời gian là chịu lực.

---

## 4. Một chain server Byzantine

**Câu hỏi:** trước một server bất lương, một phép kiểm tra phía client phát hiện được gì,
và điều gì là chứng minh được là bất khả?

### Phát hiện được

| Tấn công | Phát hiện bởi | Lý do được báo |
|---|---|---|
| sửa một entry | `verify` (chuỗi hash) | `entry_hash_mismatch` / `prev_hash_mismatch` |
| xoá hoặc đảo thứ tự | `verify` (duyệt seq + chuỗi) | `seq_gap` / `prev_hash_mismatch` |
| quay ngược trail | pin (SPEC 13) | `pin_beyond_head` |
| viết lại phần lịch sử client đã thấy | pin | `pin_mismatch` |
| viết lại phần lịch sử một witness đã thấy | witness (SPEC 14) | `inconsistent` |
| phục vụ một trail mâu thuẫn với một anchor | `--anchors` | `anchor_root_mismatch` |
| cắt đuôi một trail đã niêm phong | epoch của keyfile (SPEC 11) | `keyfile_epoch_mismatch` |
| replay một aggregate cũ lên một trail đã bị cắt | ràng buộc đã neo (SPEC 15) | `anchored_aggregate_epoch_mismatch` |

### Chứng minh được là bất khả nếu không có kênh bên ngoài

**Split view.** Một server cho client A xem một lịch sử và cho client B xem một lịch sử
khác, nhất quán về nội tại, thì không client nào một mình bắt được. Đây là fork
consistency, và lập luận là một lập luận mô phỏng: server kiểm soát từng byte mà mỗi client
nhận được, nên với bất kỳ phép kiểm tra nào A thực hiện, server đều tính được một phản hồi
nhất quán với toàn bộ quá khứ của A. Góc nhìn của A là *không phân biệt được* với một thế
giới mà cái fork đó không tồn tại. Không lượng mật mã phía client nào thay đổi được điều
đó, vì thông tin còn thiếu không mang tính mật mã — nó là việc B đã thấy một thứ khác.

(Mazières và Shasha, *Building Secure File Systems out of Byzantine Storage*, đã thiết lập
điều này cho lưu trữ; yêu cầu gossip của RFC 6962 là cùng kết quả đó cho certificate
transparency.)

Cách khắc phục duy nhất là một kênh mà server không làm trung gian. Một witness *chính là*
kênh đó, được làm cho tường minh và tối giản: client công bố các checkpoint sang một bên
thứ hai rồi sau đó hỏi bên đó đã thấy gì. Nếu hai lịch sử phân kỳ, một trong hai là fork.

Điều này thu hẹp phạm vi tin cậy; nó không loại bỏ tin cậy. Các rủi ro còn lại, nói tường
minh:

1. Các witness thông đồng với server thì cùng thấy góc nhìn đã bị fork và cùng đồng ý.
2. Một client có toàn bộ đường mạng nằm trong tay đối phương (một cuộc eclipse) sẽ tới được
   witness của kẻ tấn công, không phải witness thật. waxseal dùng TLS qua `urllib` và
   **không** ghim certificate authority.
3. Mọi thứ sau checkpoint được chứng kiến cuối cùng đều không có nhân chứng, theo cấu trúc.
4. Một witness trả về ít checkpoint hơn số nó đang giữ sẽ âm thầm làm giảm độ phủ. Đó là lý
   do mọi phán quyết đều báo `checked=K` và không bao giờ báo "complete".

---

## 5. Kẻ tấn công có quyền ghi

**Câu hỏi:** kẻ tấn công có quyền ghi vẫn viết lại được trail; neo và niêm phong
forward-secure giới hạn điều đó, và chỉ khi chúng nằm dưới một quyền quản trị khác.

**Trả lời: hoàn toàn đúng, và vế thứ hai mới là tất cả.**

| Kẻ tấn công nắm giữ | Viết lại có được không? | Thứ chặn lại |
|---|---|---|
| chỉ tệp trail | không | niêm phong: giả mạo một cái cần epoch key |
| trail + keyfile | có, ở cục bộ | neo: một bản ghi bên ngoài về root cũ |
| trail + keyfile + `.anchors` | có, ở cục bộ | anchor bên ngoài: TSA / calendar / witness giữ bản sao của riêng nó |
| trail + keyfile + `.sealagg` | trước đây là có (replay + cắt đuôi) | ràng buộc aggregate trong một checkpoint đã neo (SPEC 15) |
| toàn bộ tệp cục bộ + anchor sink | có | không gì mà thư viện này đưa ra được |
| toàn bộ tệp cục bộ + mọi witness | có | không gì — đây là trường hợp thông đồng |

Dòng thay đổi trong bản phát hành này là dòng thứ tư. SPEC 11 có ghi lại một rủi ro còn
lại: kẻ tấn công cắt đuôi trail có thể chép một `.sealagg` cũ hơn trở lại chỗ cũ, và mọi
phép kiểm tra cục bộ — `verify`, `verify_attestations`, kể cả aggregate — đều đồng ý, vì
tất cả chúng đọc cùng những tệp đã bị viết lại. Việc ràng buộc cam kết aggregate vào bên
trong checkpoint đã neo đưa tuyên bố đó ra ngoài tầm với của kẻ tấn công: anchor vẫn nói
năm dòng đã được gấp vào, còn trail bây giờ chỉ giữ hai.
(`tests/test_anchored_aggregate_log.py` mang theo falsifiability receipt: bản giả mạo qua
được `verify()` và `verify_attestations()` và chỉ thất bại khi đối chiếu với anchor.)

Thứ được cam kết là một *commitment*,
`sha256(prefix || u64be(2) || lp(epoch) || lp(agg))`, không bao giờ là bản thân accumulator
— công bố các accumulator trung gian sẽ trao cho kẻ tấn công cắt đuôi đúng giá trị mà lược
đồ cấm lưu lại.

**Yêu cầu vận hành, nói thẳng:** khoá niêm phong, anchor sink và witness mỗi thứ đều phải
nằm dưới một quyền quản trị *khác* với tiến trình ghi trail. Nếu cùng một đội, cùng một
service account, hoặc cùng một host bị chiếm kiểm soát cả hai phía, thì cơ chế ghi lại cuộc
tấn công chứ không phát hiện ra nó. Không cờ cấu hình nào thay thế được điều này, và
waxseal không kiểm tra hộ bạn được.

---

## 6. Những gì không output nào của thư viện này khẳng định

**Câu hỏi:** không output nào khẳng định rằng một nghĩa vụ đã được đáp ứng, và không output
nào nên được trích dẫn như thể nó khẳng định điều đó.

**Trả lời: đồng ý, và điều này giờ được ghi thẳng vào mọi output.**

Mọi báo cáo đều mang một tuyên bố phạm vi cố định, máy nhận diện được (`waxseal-scope-v1`,
SPEC 16), và `waxseal verify` in một dạng rút gọn của nó ở dòng cuối cho mọi phán quyết —
exit 0, 1 hay 2. Tuyên bố đầy đủ:

> This output attests hash-chain integrity and completeness measurements of
> RECORDED entries only. It does not attest that any obligation was met, that
> payload content is truthful, or that unrecorded events did not occur.

### Cách trích dẫn output của waxseal cho đúng

**Bảo vệ được:**

- "Nhật ký quyết định cho kỳ X đã kiểm chứng là nguyên vẹn: 12.480 entry, không đứt chuỗi,
  không khoảng trống, đối chiếu với một token RFC 3161 đề ngày Y."
- "Trail ghi nhận 340 quyết định tự động và 12 quyết định có ghi nhận người review; 8 dòng
  hoàn toàn không ghi chế độ giám sát nào."
- "Tính đầy đủ đã được đo: ít nhất 3 lần ghi bị rớt trong kỳ X."
- "Tính đầy đủ không được đo cho kỳ W."

**Không bảo vệ được, kèm lý do cụ thể cho từng trường hợp:**

- ~~"waxseal chứng minh chúng tôi đã tuân thủ Điều 12."~~ Chuỗi nói rằng bản ghi không bị
  sửa. Nó không nói gì về việc hành vi đã ghi có thoả mãn điều gì hay không.
- ~~"verify trả về ok, nên không sót gì cả."~~ Toàn vẹn không phải tính đầy đủ (mục 2).
- ~~"Mọi quyết định đều được người review."~~ Một dòng không ghi giám sát là
  `oversight_unrecorded`, thứ đó không phải `automated` và cũng không phải `reviewed`.
- ~~"Các dấu thời gian đã được chứng minh."~~ Structural check không phải kiểm chứng chữ ký
  (mục 3).
- ~~"Nhật ký là tamper-proof."~~ Mục 1.

### Dành cho người đánh giá đọc một báo cáo waxseal

Ba câu hỏi quyết định báo cáo đó đáng giá tới đâu, và báo cáo trả lời tường minh cả ba:

1. **Có gì được neo ra ngoài tầm kiểm soát của hệ thống này không, và neo tới ai?** Một
   trail không được neo là một sự tự chứng thực.
2. **Tính đầy đủ có được đo không?** `dropped_writes: null` nghĩa là câu hỏi chưa bao giờ
   được đặt ra.
3. **Những kiểm tra không được thực hiện thì phủ những gì?** Một kiểm tra vắng mặt khỏi báo
   cáo là kiểm tra không được thực hiện, và việc vắng mặt một kiểm tra không bao giờ là một
   lần đạt — báo cáo gắn nhãn cho từng cái thay vì bỏ qua chúng.
