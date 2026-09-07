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
chuỗi từ một dòng đã bị viết lại chỉ là thao tác máy móc. Niêm phong làm tăng chi phí - một
HMAC forward-secure cần epoch key - nhưng kẻ tấn công nắm ổ đĩa thì cũng nắm luôn keyfile,
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
| Checkpoint đã finalize trên ledger (0.1.5 Workstream F, mục 7) | các validator của chính chain đó | equivocation trên một prefix đã neo và đã finalize - không bao giờ là một lời nói dối mới, nhất quán nội tại, chỉ ký một lần |
| Segment đã lưu trữ và khoá WORM (S3 Object Lock, `adapters/s3.py`, Workstream J1) | nhà cung cấp lưu trữ, chỉ ở chế độ COMPLIANCE | việc ghi đè hoặc xoá một segment đã niêm phong và đã lưu trữ - ngăn chặn, không phải phát hiện |

"Proof" trên thực tế là một *tổ hợp*, và tổ hợp chỉ mạnh bằng mức phân tách yếu nhất của
nó:

1. Neo tới ít nhất hai thẩm quyền không chung một đơn vị vận hành.
2. Giữ khoá niêm phong dưới một quyền quản trị khác với ứng dụng đang ghi trail.
3. Đặt kho lưu trữ trên phương tiện write-once ở những nền tảng có hỗ trợ. Kể từ 0.1.5
   Workstream J1, waxseal cung cấp hỗ trợ trong `adapters/s3.py` cho S3 Object Lock trên
   các segment đã niêm phong và đã lưu trữ - nhưng NHÀ VẬN HÀNH vẫn là bên cấu hình và khai
   báo chế độ retention của bucket (COMPLIANCE hay GOVERNANCE); waxseal không đặt sẵn giá
   trị mặc định nào, cùng kỷ luật mà `--tsa-ca-file` đã tuân theo cho RFC 3161. Chỉ chế độ
   COMPLIANCE mới là một bảo đảm trước chính nhà vận hành của tài khoản đó (`WormStrength`,
   `adapters/s3.py`) - GOVERNANCE vẫn có thể bị vượt qua bởi bất kỳ ai nắm quyền
   `s3:BypassGovernanceRetention`.
4. Ghim (pin), và giữ tệp pin ở nơi bên ghi trail không với tới được.

Bỏ sót bất kỳ điều nào trong số này thì đòn tấn công tương ứng quay lại. Đó là hình dạng
trung thực của câu trả lời: không phải một tính năng để bật lên, mà là một tập các phân
tách phải duy trì.

**Tamper-evident so với tamper-proof, nói cho chính xác.** Hai trong số các mục ở trên
không còn là khát vọng nữa - Workstream F và Workstream J1 đã đưa chúng vào bản phát hành
0.1.5 - nên từ vựng nay đã cố định ở khắp codebase này (CLAUDE.md, DESIGN.md §11):
**Tamper-evident là khẳng định chính; "tamper-proof" chỉ luôn được dùng khi đã GIỚI HẠN
PHẠM VI: prefix đã neo trên một ledger bên ngoài đã finalize, các segment đã lưu trữ và
khoá WORM - không bao giờ là phần đuôi còn sống (live tail), không bao giờ là sự trung
thực tại thời điểm ghi.** Hai giới hạn vẫn tồn tại qua cả hai cơ chế, do cấu trúc chứ không
phải do ngân sách (DESIGN.md §11):

1. **Sự trung thực tại thời điểm ghi.** Không hash nào ngăn được việc ghi một lời nói dối
   hay bỏ sót một sự kiện tại thời điểm ghi. Tamper-proof ≠ truth-proof.
2. **Phần đuôi còn sống (live tail).** Bất cứ thứ gì chưa được đưa ra ngoài - chưa neo,
   chưa được xác nhận, chưa lưu trữ - đều viết lại được bởi một kẻ tấn công có quyền ghi.
   Các cơ chế thu hẹp cửa sổ này; không cơ chế nào đóng nó lại hoàn toàn.

Mục 7 nói rõ nửa phần ledger của điều này, theo từng trạng thái kẻ tấn công. Nửa phần WORM
là `WormReport` của `adapters/s3.py` (`worm_locked` / `worm_unlocked` / `worm_unknown`,
được `render_worm_state` hiển thị) - đã kiểm tra-và-khoá, đã kiểm tra-và-chưa-khoá, hoặc
chưa đo - không bao giờ bị gộp lại thành một trong hai giá trị nhị phân (CLAUDE.md quy tắc
5). `waxseal preflight` in ra, dưới dạng một cách chia prefix/tail có gắn nhãn, cơ chế nào
trong hai cơ chế trên - nếu có - mà lần chạy này xác nhận được là chặn trên một prefix bất
biến, và nói rõ điều đó mà không mở bất kỳ kết nối mạng nào để tự mình kiểm tra cơ chế đó
(mục 5).

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

Cách duy nhất để chặn trên phần *thiếu* là đối chiếu với một nguồn nằm ngoài trail - số
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
| gỡ ràng buộc aggregate khỏi sidecar | pin `expect_anchor_binding` (SPEC 13.1) | `anchor_policy_downgrade` |
| ngừng anchor rồi chờ | pin `max_anchor_age_s` (SPEC 13.1) | `anchor_stale` |
| trình ra ít thẩm quyền độc lập hơn đã khai báo | pin `declared_topology` (SPEC 13.1) | `separation_shortfall` |

Ba dòng cuối là **exit 2, không phải exit 1**, và sự phân biệt này mang tải trọng chứ
không phải câu nệ. Mỗi dòng nói rằng *sự chứng thực mà chính sách của deployment này
kỳ vọng đã không được quan sát thấy* - đó là sự thật về độ phủ, không phải về trail.
Verdict của chain được báo riêng và không bị ảnh hưởng. Người đánh giá đọc chúng thành
"đã phát hiện giả mạo" là nói quá; đọc thành "không sao" là nói thiếu. Nghĩa đúng là:
kiểm tra lại đường anchoring, rồi chạy lại.

Hai trong số đó đáng gọi tên vì bản phát hành trước hoàn toàn không thấy được:

- **Hạ cấp chính sách anchoring.** Một checkpoint frame không mang field aggregate thì
  giống hệt từng byte với một frame viết trước khi các field đó tồn tại. Nên attacker
  giữ được sidecar `.anchors` chỉ cần trình ra toàn record không ràng buộc là âm thầm
  gỡ bỏ bảo vệ replay-plus-truncate của SPEC 15: mọi check còn lại đều pass, và không
  gì trong trust domain của chính verifier ghi rằng đã từng kỳ vọng có ràng buộc. Thứ
  thiếu là **chính sách** ngoại sinh, không phải **giá trị** ngoại sinh - và khác với
  bản thân aggregate commitment (không recompute được nếu không có seal key), một kỳ
  vọng dạng boolean là thứ verifier kiểm được. Record sidecar mà build này không parse
  nổi sẽ báo `anchor_binding_unreadable`: vắng mặt trong số các record đọc được không
  phải bằng chứng của vắng mặt.
- **Sự im lặng.** Anchoring bị động chỉ trả lời khi được hỏi. Một timestamp authority
  đáp khi có người hỏi; nó không thể nhận ra là **không ai hỏi**. Attacker có quyền ghi
  chỉ cần *ngừng anchor* rồi rewrite thong thả - và trạng thái lưu trữ sau đó không
  phân biệt được với một hệ thống vốn nhàn rỗi. `max_anchor_age_s` khép lỗ hổng này cho
  verifier nào giữ deadline trong trust domain của chính nó: im lặng quá hạn trở thành
  một finding được báo cáo thay vì một sự vắng mặt của finding. Điều này **không** làm
  cho sự im lặng trở nên phân xử được công khai - muốn vậy cần một bên thứ ba giữ
  deadline. Kể từ 0.1.5, bên thứ ba đó có thể là hợp đồng liveness on-chain mà chính văn
  bản này từng gọi là "phác trong `docs/paper/`, đã thiết kế, chưa được xây" - nay nó đã
  được xây (mục 7 bên dưới); một bên thứ ba KHÔNG LIÊN QUAN có thể đọc `waxseal
  ledger-status` đối chiếu với hợp đồng đó mà không cần sự hợp tác của nhà vận hành, khép
  lại lỗ hổng mà đoạn này từng gọi là còn để ngỏ.

### Chứng minh được là bất khả nếu không có kênh bên ngoài

**Split view.** Một server cho client A xem một lịch sử và cho client B xem một lịch sử
khác, nhất quán về nội tại, thì không client nào một mình bắt được. Đây là fork
consistency, và lập luận là một lập luận mô phỏng: server kiểm soát từng byte mà mỗi client
nhận được, nên với bất kỳ phép kiểm tra nào A thực hiện, server đều tính được một phản hồi
nhất quán với toàn bộ quá khứ của A. Góc nhìn của A là *không phân biệt được* với một thế
giới mà cái fork đó không tồn tại. Không lượng mật mã phía client nào thay đổi được điều
đó, vì thông tin còn thiếu không mang tính mật mã - nó là việc B đã thấy một thứ khác.

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
| toàn bộ tệp cục bộ + anchor sink | có, cho phần đuôi còn sống (live tail) và bất cứ thứ gì chưa từng được neo | không gì mà thư viện này đưa ra được ở đó; ngoại lệ duy nhất là prefix đã neo trên một ledger bên ngoài đã finalize (0.1.5 Workstream F, mục 7) - lịch sử đã được xác nhận trong prefix đó không thể kể lại khác đi mà không tạo ra một bằng chứng equivocation có thể bị slash (DESIGN.md §11) |
| toàn bộ tệp cục bộ + mọi witness | có, cho phần đuôi còn sống (live tail) và bất cứ thứ gì chưa từng được neo | không gì ở đó - đây là trường hợp thông đồng; ngoại lệ ledger-đã-finalize ở trên vẫn giữ nguyên, vì các validator của chính ledger nằm dưới một quyền quản trị khác với bất kỳ witness nào, nên sự thông đồng của witness không chạm tới được nó |

Ba dòng thay đổi trong bản phát hành này: dòng thứ tư, và hai dòng cuối. SPEC 11 có ghi lại
một rủi ro còn lại cho dòng thứ tư: kẻ tấn công cắt đuôi trail có thể chép một `.sealagg` cũ
hơn trở lại chỗ cũ, và mọi phép kiểm tra cục bộ - `verify`, `verify_attestations`, kể cả
aggregate - đều đồng ý, vì tất cả chúng đọc cùng những tệp đã bị viết lại. Việc ràng buộc
cam kết aggregate vào bên trong checkpoint đã neo đưa tuyên bố đó ra ngoài tầm với của kẻ
tấn công: anchor vẫn nói năm dòng đã được gấp vào, còn trail bây giờ chỉ giữ hai.
(`tests/test_anchored_aggregate_log.py` mang theo falsifiability receipt: bản giả mạo qua
được `verify()` và `verify_attestations()` và chỉ thất bại khi đối chiếu với anchor.)

Hai dòng cuối mang theo đúng một ngoại lệ mà DESIGN.md §11 ghi lại - không hơn không kém.
Ngoại lệ đó bị giới hạn phạm vi theo ba cách cùng lúc: giới hạn ở PREFIX đã được neo và đã
finalize trước khi kẻ tấn công này xuất hiện (không bao giờ là live tail được ghi sau đó);
giới hạn ở một writer EQUIVOCATE để che giấu việc viết lại (bảng của chính mục 7: một lời
nói dối mới, nhất quán nội tại, chỉ ký một lần thì không tạo ra mâu thuẫn nào để
`BondedCheckpoints.proveEquivocation` bắt được); và giới hạn ở việc phát hiện, không bao giờ
là khôi phục (các byte của chính trail vẫn là bất cứ thứ gì kẻ tấn công đã viết cục bộ -
ledger chỉ cho phép một bên thứ ba CHỨNG MINH rằng điều đó mâu thuẫn với những gì nó đã
finalize). `waxseal preflight` (chính cái thang của mục 5, `domain/preflight.py`) in ra
ngoại lệ này dưới dạng một cách chia prefix/tail có gắn nhãn thay vì gộp nó vào các bậc
PRESENT/ABSENT của cái thang, chính là để nó không thể bị đọc thành việc nâng bậc 5 hay bậc
6.

Thứ được cam kết là một *commitment*,
`sha256(prefix || u64be(2) || lp(epoch) || lp(agg))`, không bao giờ là bản thân
accumulator - công bố các accumulator trung gian sẽ trao cho kẻ tấn công cắt đuôi đúng giá
trị mà lược
đồ cấm lưu lại.

**Yêu cầu vận hành, nói thẳng:** khoá niêm phong, anchor sink, witness và ledger mỗi thứ
đều phải nằm dưới một quyền quản trị *khác* với tiến trình ghi trail. Nếu cùng một đội,
cùng một service account, hoặc cùng một host bị chiếm kiểm soát cả hai phía, thì cơ chế ghi
lại cuộc tấn công chứ không phát hiện ra nó. Không cờ cấu hình nào thay thế được điều này,
và waxseal không kiểm tra hộ bạn được (`_OPERATIONAL_REQUIREMENT` trong
`domain/preflight.py` lặp lại đúng câu này để `waxseal preflight` in ra, nên hai bản sao
không thể trôi lệch nhau).

---

## 6. Những gì không output nào của thư viện này khẳng định

**Câu hỏi:** không output nào khẳng định rằng một nghĩa vụ đã được đáp ứng, và không output
nào nên được trích dẫn như thể nó khẳng định điều đó.

**Trả lời: đồng ý, và điều này giờ được ghi thẳng vào mọi output.**

Mọi báo cáo đều mang một tuyên bố phạm vi cố định, máy nhận diện được (`waxseal-scope-v1`,
SPEC 16), và `waxseal verify` in một dạng rút gọn của nó ở dòng cuối cho mọi phán quyết -
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
   lần đạt - báo cáo gắn nhãn cho từng cái thay vì bỏ qua chúng.

---

## 7. Lớp ledger on-chain (0.1.5, Workstream F)

**Câu hỏi:** việc neo vào một smart contract có làm thay đổi ranh giới tin cậy mà phần còn
lại của tài liệu này vạch ra không?

**Trả lời: không. Ba hợp đồng này là một loại bản sao bên ngoài THỨ BA, gia nhập bảng của
mục 1, và mỗi hợp đồng đều kế thừa CÙNG một khẳng định đã giới hạn phạm vi: chúng phát hiện
việc viết lại và equivocation trên chính những khẳng định ĐÃ KÝ của writer, không bao giờ
phát hiện sự thiếu trung thực tại thời điểm ghi.** Học thuyết vẫn là học thuyết của
DESIGN.md §11, được nhắc lại ở đây cho lớp làm nó trở nên cụ thể: ranh giới trusted-writer
vẫn áp dụng đầy đủ. Một writer đã bị chiếm vẫn có thể append bất cứ thứ gì vào trail rồi ký
một checkpoint lên trên đó; một hợp đồng chỉ bao giờ thấy các head đã ký thì chỉ so sánh
được điều CÙNG một signer đã khẳng định ở hai thời điểm hoặc hai vị trí khác nhau, và không
gì hơn.

| Hợp đồng | Nó bổ sung gì vào bảng của mục 1 | Nó KHÔNG làm gì |
|---|---|---|
| `AnchoringLiveness` | một bản sao trên ledger đã finalize của checkpoint đã ký mới nhất của WRITER, đọc được bởi một bên thứ ba không liên quan mà không cần sự hợp tác của nhà vận hành (khép lại lỗ hổng mà mục 4 từng gọi là còn để ngỏ) | khẳng định rằng mọi entry giữa hai checkpoint là trung thực; phát hiện một writer vẫn tiếp tục anchor trong khi âm thầm sửa thứ nó đang anchor |
| `FingerprintRegistry` | một bản công bố append-only của một header descriptor, nên một registry CỤC BỘ bị đầu độc giờ cần hoặc một collision SHA-256 hoặc quyền kiểm soát chain thì mới lọt qua mà không bị phát hiện | cấp phép cho build này TÍNH LẠI một dòng dưới một fingerprint mà nó đồng ý là có thật, theo tên gọi; đồng ý về một cái tên không phải là đồng ý về một hasher (RFC 6962 §4.6, chính học thuyết của `domain/registry.py`) |
| `BondedCheckpoints` | một CÁI GIÁ đặt lên một kiểu bất trung thực cụ thể - ký hai checkpoint khác nhau ở cùng một vị trí (equivocation) | khiến equivocation trở nên bất khả; phát hiện một writer không bao giờ tự mâu thuẫn (bỏ sót, bịa đặt, hay sửa âm thầm mà không bao giờ tạo ra hai head đã ký mâu thuẫn nhau); hoặc bảo vệ một writer có bond đáng giá thấp hơn lời nói dối |

Mở rộng bảng của mục 5 với trạng thái mà lớp này đưa vào:

| Kẻ tấn công nắm giữ | Viết lại có được không? | Thứ chặn lại |
|---|---|---|
| khoá ký của writer, chưa đặt bond | có, tự do | không gì ở đây - `AnchoringLiveness` chỉ phát hiện SỰ IM LẶNG (writer ngừng anchor), không bao giờ phát hiện một việc viết lại đang sống, tự nhất quán; các dòng gốc của mục 5 không đổi |
| khoá ký của writer, đã đặt bond, và nó EQUIVOCATE để che giấu việc viết lại | bị bắt ngay khi có ai đó nắm được cả hai head đã ký | `BondedCheckpoints.proveEquivocation` - bằng chứng tích cực tự đủ, không cần thêm ngữ cảnh nào khác |
| khoá ký của writer, đã đặt bond, và nó không bao giờ equivocate (một lời nói dối nhất quán, chỉ ký một lần) | có | không gì - hợp đồng không bao giờ thấy một mâu thuẫn để chứng minh, vì không có mâu thuẫn nào cả |

### Những bề mặt phát hiện mới mà lớp này thêm vào

- **`LedgerDisagreement`** (`ports/ledger.py`) là một loại finding mới, trực giao với phán
  quyết chuỗi `ok`/`broken`/`unverifiable`: hai hay nhiều RPC endpoint trả lời CÙNG một câu
  hỏi về trạng thái on-chain mà không khớp nhau. Đây là một quan sát có hình dạng eclipse về
  TRANSPORT, không phải một phán quyết về trail, và client từ chối chọn ra một bên thắng -
  báo cáo cặp không khớp nhau (quy tắc 6) là toàn bộ phản hồi. Rủi ro còn lại, kế thừa từ
  phần thảo luận về eclipse ở mục 4: hai RPC endpoint là một ngưỡng sàn do nhà vận hành cấu
  hình, không phải bằng chứng của tính độc lập. Hai provider cùng proxy về một node upstream
  chung thì hoàn toàn chưa nâng τ lên chút nào, và waxseal không thể phát hiện điều đó từ
  phía client cũng như nó không thể kiểm chứng ai đang vận hành một witness.
- **Revert như một câu trả lời ba chiều.** `AnchoringLiveness.isDelinquent`/`.lastSeen`
  REVERT đối với một trail chưa đăng ký hoặc chưa từng được neo, thay vì nói dối bằng
  `false` - `bool` chỉ có hai giá trị còn câu trả lời trung thực thì có ba giá trị. Adapter
  (`adapters/evm.py`) đọc một revert ĐÃ NHẬN DIỆN ĐƯỢC như một sự vắng mặt đã đo (chain đã
  trả lời, một cách xác định, rằng nó không giữ gì cả), một revert CHƯA NHẬN DIỆN ĐƯỢC như
  chưa đo nhưng có GẮN NHÃN bằng selector bốn byte mà nhà vận hành có thể tra cứu, và một
  lỗi mạng thật sự như không tới được (unreachable) mà không mang nhãn nào cả. Trên đường
  ghi (WRITE path), hình dạng đó đảo ngược lại: một giao dịch bị hợp đồng từ chối là một sự
  từ chối TÍCH CỰC - hợp đồng đã trả lời không - không bao giờ bị gộp vào "không hỏi được".
  Phần Ledger layer của SPEC.md định nghĩa toàn bộ ánh xạ đó; danh sách Named-principle của
  `CLAUDE.md` ghi lại các trường hợp 11-13 cho ba giá trị ternary do hợp đồng hậu thuẫn mà
  lớp này tạo ra (liveness, bond, registry), và ghi lại vì sao `LedgerDisagreement` cùng
  khuôn mẫu revert được tài liệu hoá ở đây và trong SPEC.md thay vì được tính là instance
  thứ tư/thứ năm của Named-principle: không cái nào trong hai cái đó là một trạng thái
  chưa-đo bị gộp vào một nhị phân theo cách mà collapse theorem mô tả; cả hai đều là những
  sự thật đã đo về TRANSPORT hoặc kết quả GHI, nằm bên dưới ba ternary kể trên.

Tham chiếu chéo: ba dòng on-chain ở mục 3 của `docs/paper/conformance.md` ghi lại những gì
đã ship và trích dẫn các test; phần Ledger layer của SPEC.md là hợp đồng ở mức byte và mã
exit.
