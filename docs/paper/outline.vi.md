# Đề cương bài báo — nhật ký quyết định chống sửa đổi, an toàn với tiến hoá schema cho AI agent

*[English](outline.md)*

Đề cương làm việc cho một bài báo hệ thống–an toàn dựa trên waxseal. Tài liệu này không ghi
tác giả hay tổ chức nào; bổ sung khi nộp bài.

**Tiêu đề làm việc:** *Schema-Evolution-Safe, Tamper-Evident Decision Logs for AI Agents in
Financial Services*

**Các cách đóng khung thay thế**, tuỳ theo cộng đồng phản biện mà bài báo nhắm tới:

| Cách đóng khung | Hướng tiêu đề | Phù hợp nhất |
|---|---|---|
| Lớp lỗi (failure class) | *Unverifiable Is Not Tampered: Version Identity in Tamper-Evident Logs* | workshop của S&P/CCS, DIMVA |
| Hệ thống | *An Evidence Layer for AI Agents: Design and Evaluation* | ACSAC |
| Pháp lý | *Verifiable Decision Records for Regulated AI Deployment* | FC / WTSC |

Cách đóng khung theo lớp lỗi là mạnh nhất. Đóng góp cốt lõi không phải một cấu trúc mật mã
mới — mà là quan sát rằng một lớp bug triển khai lặp đi lặp lại (định danh phiên bản theo
thứ tự + coi phiên bản lạ là lỗi) là **có thể loại bỏ được ngay từ cấu trúc**, cộng với một
hệ thống làm được điều đó và một phép đo chi phí của nó.

---

## Các đóng góp được tuyên bố

Nêu sớm những điều này và giữ bài báo trung thực đúng với bốn điểm này:

1. **Một lớp lỗi, được đặt tên và mô tả đặc trưng.** Hai sự cố sản xuất độc lập (§1) có
   chung một nguyên nhân gốc: định danh phiên bản mang tính *thứ tự và thủ công*, và một
   phiên bản không nhận diện được bị coi là lỗi thay vì được coi là *thiếu thông tin*. Ta
   chỉ ra rằng điều này gộp hai phán quyết khác nhau — *bản ghi này sai* và *tôi không kiểm
   tra được bản ghi này* — thành một, và chính sự gộp đó biến một lần rollback vô hại thành
   hoặc một cảnh báo sai hàng loạt, hoặc một cơ chế an toàn bị vô hiệu hoá âm thầm.
2. **Một cấu trúc làm cho lớp lỗi đó không biểu diễn được.** Định danh phiên bản là
   *fingerprint suy ra từ nội dung* của bộ mô tả trường chuẩn tắc, nên việc mở rộng bộ
   trường bị băm không thể làm âm thầm; kết hợp với một không gian kết quả ba giá trị
   (nguyên vẹn / đứt gãy / không-kiểm-chứng-được-theo-tên) được đưa ra tận exit code của
   tiến trình.
3. **Một lớp bằng chứng cho bản ghi quyết định AI**, bao gồm tiết lộ chọn lọc: một quyết
   định đơn lẻ cộng với membership proof là kiểm tra được offline mà không cần phần còn lại
   của nhật ký, và không cần tin bên đang giữ nhật ký.
4. **Một đánh giá thực nghiệm** bao trùm chi phí append/verify, chi phí biên của từng lớp
   phòng vệ (neo, niêm phong forward-secure), và một case study đối kháng trong đó mỗi lớp
   tấn công được ánh xạ tới đúng cơ chế phát hiện nó và đúng giả định tin cậy mà cơ chế đó
   đòi hỏi.

**Những điều rõ ràng KHÔNG phải đóng góp**, nêu trong bài để tránh người phản biện đọc
quá: không có hàm băm mới, không có accumulator mới, không có hệ chứng minh mới, không có
giao thức đồng thuận, không tuyên bố chống sửa đổi *tuyệt đối*, và không tuyên bố rằng bất
kỳ nghĩa vụ pháp lý nào đã được hoàn thành.

---

## 1. Giới thiệu

Mở đầu bằng hai sự cố, vì chúng chuyển tải lập luận tốt hơn bất kỳ mô hình đe doạ nào.

- **Sự cố A ("migration 060").** Một hệ thống sản xuất mở rộng tập trường được phủ bởi hash
  của một dòng mà không đổi bất kỳ định danh phiên bản nào. Toàn bộ các dòng lịch sử sau đó
  fail verification: verifier tính lại các dòng cũ theo bộ trường mới và — hoàn toàn đúng
  theo logic của chính nó — thấy sai lệch. Kết quả là một cảnh báo can thiệp sai hàng loạt
  trên toàn bộ lịch sử.
- **Sự cố B (một công cụ theo dõi issue, v1.2.2, 08/2026).** Một bản phát hành nhầm đã
  migrate schema từ v53 lên v65. Bản binary được revert coi phiên bản lạ-nhưng-cao-hơn là
  lỗi nghiêm trọng. Lối thoát duy nhất là một biến môi trường vô hiệu hoá hoàn toàn cơ chế
  kiểm tra schema — biến một tình huống thiếu thông tin một phần thành lựa chọn nhị phân
  giữa "từ chối chạy" và "chạy mà không có an toàn nào".

Cả hai là cùng một bug: **verifier không có cách nào để nói "tôi không kiểm tra được cái
này."** Sự cố A trả lời *bị can thiệp* trong khi câu trả lời trung thực là *không kiểm
chứng được*; Sự cố B trả lời *lỗi nghiêm trọng* cho cùng tình huống đó. RFC 6962 §4.6 đã
nêu sẵn câu trả lời đúng cho các kiểu không nhận diện được — coi chúng là mờ đục, không
phải lỗi — nhưng nguyên tắc này được phát biểu cho định dạng wire và trên thực tế không
được mang vào các verifier của audit log.

Sau đó nêu động lực cho bối cảnh AI agent: quyết định của agent nay là đối tượng của các
nghĩa vụ lưu trữ hồ sơ (EU AI Act Điều 12/19/26(6); RTS của DORA yêu cầu log phải được bảo
vệ khỏi bị can thiệp và bị xoá), schema quyết định của một hệ thống agent thay đổi nhanh
thường xuyên hơn nhiều so với schema cơ sở dữ liệu, và bên vận hành agent thường cũng chính
là bên giữ nhật ký của nó — đúng cấu hình mà ở đó một bản ghi không giả mạo được và được
neo ra bên ngoài mới có giá trị.

**Cấu trúc lập luận:** tốc độ biến động schema của các hệ thống AI làm cho lớp lỗi này *dễ
xảy ra hơn*, còn mức độ hệ trọng về mặt bằng chứng làm cho nó *đắt hơn*. Đó là lý do tổ hợp
này xứng đáng một bài báo chứ không phải một bug report.

---

## 2. Nền tảng và công trình liên quan

Tổ chức thành bốn mạch, và với mỗi mạch nói thẳng nó cho gì và để ngỏ gì.

**Logging chuỗi-hash và forward-secure.** Audit log forward-secure của Schneier & Kelsey;
định nghĩa forward-security của Bellare & Yee; chữ ký tổng hợp FssAgg của Ma & Tsudik.
*Cho*: phát hiện cắt đuôi và viết lại sau khi khoá bị lộ. *Để ngỏ*: không nói gì về định
danh schema — bộ trường được băm được giả định là cố định.

**Transparency log.** History tree của Crosby & Wallach; RFC 6962 (Certificate
Transparency) với membership và consistency proof; RFC 9162 §2.1.4. *Cho*: bộ máy chứng
minh mà công trình này tái sử dụng trực tiếp cho tiết lộ chọn lọc, cùng nguyên tắc §4.6 về
kiểu không nhận diện được mà công trình này tổng quát hoá. *Để ngỏ*: CT giả định một định
dạng leaf duy nhất đã biết rõ; bài toán tiến hoá schema không phát sinh ở đó nên không được
xử lý.

**Nguồn gốc nội dung (content provenance).** C2PA và các công trình lân cận về nguồn gốc
phương tiện. *Cho*: cách đóng khung một tuyên bố kiểm chứng được về lịch sử của một hiện
vật. *Để ngỏ*: thiết kế cho tài sản phương tiện, không phải luồng quyết định chỉ-ghi-thêm,
và không xử lý trường hợp verifier-không-kiểm-tra-được.

**Trách nhiệm giải trình và kiểm toán AI.** Model card, datasheet, kiểm toán thuật toán, và
bản thân các văn bản pháp quy. *Cho*: yêu cầu. *Để ngỏ*: những thứ này mô tả *cái gì* nên
được ghi lại và gần như không bao giờ mô tả *làm sao để bản ghi đó đáng tin trước chính bên
đang giữ nó* — đúng khoảng trống mà công trình này lấp.

**Tuyên bố lập trường cho phần công trình liên quan:** mọi nguyên thuỷ dùng ở đây đều là
chuẩn mực sẵn có. Đóng góp nằm ở cách tổ hợp và, cụ thể hơn, ở thiết kế định danh và không
gian kết quả mà bản thân các nguyên thuỷ không cung cấp.

---

## 3. Thiết kế

### 3.1 Tách envelope

Chuỗi chỉ băm một `EntryHeader` có hình dạng cố định
(`seq, ts, hash_version, payload_type, payload_hash, prev_hash`). Payload là byte tuỳ ý,
chỉ được tham chiếu qua `payload_hash`. **Hệ quả: thay đổi schema payload không bao giờ
chạm tới chuỗi.** Đây là thứ làm cho tiến hoá an toàn trong trường hợp phổ biến, và đáng
được phát biểu như một quy tắc thiết kế chứ không phải một chi tiết cài đặt.

### 3.2 Định danh phiên bản dưới dạng fingerprint

`hash_version = SHA-256(bộ mô tả chuẩn tắc)`, trong đó bộ mô tả gồm tên trường theo thứ tự
cộng với thuật toán và quy tắc mã hoá. Ba tính chất cần lập luận tường minh:

- **Không thể giả mạo bằng cách bỏ sót.** Mở rộng bộ trường bị băm sẽ đổi bộ mô tả, do đó
  đổi fingerprint, một cách tự động. Sự cố A trở nên không biểu diễn được: không có cách nào
  đổi bộ trường mà giữ nguyên định danh.
- **Không có thứ tự.** Không có fingerprint nào "cao hơn" hay "thấp hơn", nên không verifier
  nào kết luận được "cái này đến từ tương lai, vậy là lỗi nghiêm trọng". Tiền đề của Sự cố B
  biến mất.
- **Registry chỉ-ghi-thêm.** Một bộ trường mới là một mục mới, không bao giờ là một lần sửa.
  Các dòng cũ verify được mãi mãi dưới fingerprint của chính chúng.

### 3.3 Không gian kết quả ba giá trị

Hình thức hoá: `verify` trả về một trong *intact*, *broken(seq, reason)*, *unverifiable(tập
fingerprint)*. Tính chất đúng đắn then chốt mang dạng phủ định và nên được phát biểu như vậy:

> Một verifier không bao giờ tính lại một bản ghi theo bộ trường mà bản ghi đó không được ký cùng.

Báo một bản ghi là nguyên vẹn dựa trên một hash mà nó không tái tạo được là lời nói dối duy
nhất mà cơ chế tamper-evidence không bao giờ được phép nói; báo nó là *bị can thiệp* chính
là Sự cố A. Chỉ tránh được cả hai khi có giá trị kết quả thứ ba, và giá trị đó phải sống sót
tới tận exit code — một phân biệt ở tầng API mà sụp đổ ở biên tiến trình thì coi như không
được triển khai.

### 3.4 Mã hoá chuẩn tắc

lp64v1: tiền tố độ dài 8 byte big-endian cho mỗi trường, giá trị UTF-8, một sentinel NULL
tường minh khác với chuỗi rỗng, đóng khung kiểu PAE với tiền tố phân tách miền và số lượng
trường. Lập luận vì sao dùng tiền tố độ dài thay vì ký tự phân cách (không có nhập nhằng
in-band), và vì sao sentinel NULL là một thể hiện của chủ đề xuyên suốt bài báo: *vắng mặt*
và *rỗng* là hai khẳng định khác nhau, và một mã hoá chuẩn tắc gộp chúng lại sẽ cho phép hai
bản ghi khác nhau băm ra giống hệt nhau.

### 3.5 Redact trước khi hash

Redaction chạy trước khi tính `payload_hash`, nên bí mật không bao giờ chạm đĩa. Nêu hệ quả
một cách trung thực: một lần redaction sót là không cứu được — cleartext chính là thứ lẽ ra
đã được cam kết. Thứ tự chính là biện pháp giảm thiểu, không phải một bước tuỳ chọn.

### 3.6 Bản ghi quyết định và cam kết

Bộ trường của `DecisionRecord` và lý do của nó (định danh hệ thống, tên/phiên bản/digest mô
hình, kết quả, căn cứ, phiên bản policy, độ tin cậy, chế độ giám sát của con người). Hai
điểm thiết kế đáng mỗi điểm một đoạn:

- **Cam kết input được tính trên input đã redact.** Cam kết trên cleartext sẽ cho phép bất
  kỳ ai giữ nhật ký xác nhận một phán đoán về bí mật bằng cách tính lại hash — nhật ký khi
  đó trở thành một oracle xác nhận phán đoán cho đúng những bí mật mà redaction đã gỡ bỏ.
- **Giám sát chưa được ghi nhận là một giá trị khác với giám sát tự động.** Gộp chúng lại là
  báo cáo "thiếu bằng chứng" thành "bằng chứng". Đây chính là kỷ luật ba giá trị ở §3.3, áp
  dụng cho một trường dữ liệu, và bài báo nên vạch rõ đường nối đó: nó xuất hiện lần nữa ở
  `dropped_writes` (§5.3).

### 3.7 Tiết lộ chọn lọc

Một proof bundle = một entry header + payload + đường membership + batch root. Kiểm chứng
được offline đối chiếu với một root đã công bố độc lập. Lập luận tính chất giảm thiểu tiết
lộ: trả lời một câu hỏi về một chủ thể không đòi hỏi phải trao ra quyết định về mọi chủ thể
khác.

---

## 4. Cài đặt

Ngắn gọn. Kiến trúc phân lớp (domain thuần / ports là protocol / adapters / CLI mỏng) với
việc phân lớp được cưỡng chế bằng test chứ không bằng quy ước; không dependency runtime;
nhiều backend (file, SQLite, Postgres, S3, remote HTTP) mà mỗi cái cưỡng chế "đọc-tail cộng
append là một critical section" bằng cơ chế bản địa của kho đó.

Hai điểm đáng nói hơn một dòng vì đó là chỗ thiết kế chạm vào thực tế:

- **Critical section.** Hai writer đồng thời không bao giờ được cùng nối tiếp một
  `prev_hash`. Một hệ thống sản xuất trước đây đã ship đúng bug rẽ nhánh này qua thread pool
  của web server. Test đồng thời mang theo một **biên nhận khả-phủ-định**: bằng chứng có
  ghi chép rằng nó fail khi gỡ lock đi. Một test đồng thời chưa từng được chứng minh là có
  thể fail thì không phải bằng chứng cho điều gì cả.
- **Vector liên-cài-đặt.** Golden test vector là ghi-một-lần và được đối chiếu chéo bởi một
  script độc lập cài đặt trực tiếp phần văn xuôi của đặc tả, thay vì import thư viện — nếu
  không thì vector chỉ đang kiểm tra cài đặt bằng chính nó.

---

## 5. Phân tích an toàn

### 5.1 Mô hình đe doạ

Các bậc kẻ tấn công, nêu ra để giữ các tuyên bố có biên giới:

| Bậc | Năng lực | Điều gì vẫn đứng vững |
|---|---|---|
| T1 | đọc nhật ký | tính bí mật của các bí mật đã redact; cam kết không đảo ngược được (nhưng xem §5.4) |
| T2 | append vào nhật ký | không giả mạo được lịch sử; rẽ nhánh bị chặn bởi critical section |
| T3 | viết lại nhật ký tuỳ ý | phát hiện được **chỉ** qua neo và niêm phong forward-secure, và chỉ khi chúng nằm dưới một quyền quản trị khác |
| T4 | viết lại nhật ký **và** kiểm soát đích neo hoặc giữ một epoch khoá sớm | **không phát hiện được.** Nói thẳng điều này |

**waxseal là tamper-evident, không phải tamper-proof.** Tuyên bố trung thực là: khả năng
phát hiện sống sót qua T3 *với một giả định phân tách*, và thất bại ở T4. Một bài báo không
nói bảo đảm của nó dừng ở đâu thì đang mời người phản biện tự tìm ra ranh giới đó rồi không
tin phần còn lại.

### 5.2 Bản đồ tấn công → cơ chế

Case study đánh giá (§6.3) đi qua tám tấn công cụ thể. Mỗi dòng nêu tấn công, cơ chế bắt
được nó, và — quan trọng nhất — giả định tin cậy mà cơ chế đó phụ thuộc vào. Viết lại toàn
bộ trail bị bắt bởi neo *chỉ khi miền neo được quản trị tách biệt*; cắt đuôi bị bắt bởi niêm
phong forward-secure *chỉ khi khoá ban đầu được ký quỹ ngoài máy ghi*. Chính các mệnh đề
điều kiện này là đóng góp hữu ích nhất của bài báo cho người làm thực tế.

### 5.3 Toàn vẹn không phải là đầy đủ

Một write chưa từng xảy ra thì không để lại khoảng trống thứ tự nào và không làm đứt liên
kết nào, nên một thất bại về tính đầy đủ là vô hình với việc kiểm chứng chuỗi ngay từ cấu
trúc. `dropped_writes` đo nó một cách tách bạch và báo một **cận dưới đã đo**, với `None`
nghĩa là *chưa đo* — không bao giờ là 0. Bản thân sidecar ghi rớt cũng có thể mất, và một ổ
đĩa hỏng tới mức không ghi nổi một bản ghi rớt thì không làm chứng được cho chính sự cố của
nó. Đây là lần xuất hiện thứ ba của chủ đề xuyên suốt (§3.3, §3.6), và phần thảo luận nên
nói rõ: kỷ luật thiết kế này tổng quát hoá cho *mọi* thước đo mà ở đó việc "không đo" có thể
bị nhầm thành "đo được là không có".

### 5.4 Giới hạn

- Cam kết trên input entropy thấp là xác nhận được bằng cách liệt kê; cam kết không phải mã
  hoá.
- Một chain server từ xa là *trusted writer*, không phải Byzantine-fault-tolerant: một
  server bất lương có thể phục vụ một bản viết lại giả mạo nhất quán mà riêng phép kiểm
  chuỗi không phát hiện được. Pinned head và witness cross-check thu hẹp điều này xuống
  còn: client lần đầu kết nối, witness thông đồng, hoặc client bị eclipse — chúng không
  loại bỏ được sự tin cậy.
- Dấu thời gian do bên gọi khẳng định, không được chứng thực; thời gian được chứng thực đòi
  hỏi một bên có thẩm quyền bên ngoài.
- Lưu trữ chỉ-ghi-thêm căng thẳng với quyền được xoá; biện pháp giảm thiểu (chỉ dùng tham
  chiếu bút danh) là ràng buộc lên người tích hợp, không phải một tính chất của hệ thống.

---

## 6. Đánh giá thực nghiệm

### 6.1 Chi phí

Thông lượng và độ trễ của append và verify trên các backend; chi phí biên của niêm phong
forward-secure cho mỗi entry và của một checkpoint Merkle cho mỗi *N* entry; chi phí kiểm
chứng theo độ dài trail, và mức cải thiện khi kiểm chứng tăng dần bằng consistency proof từ
checkpoint đã neo gần nhất. Báo cáo phân phối, không phải giá trị trung bình — độ trễ đuôi
trên đường audit mới là thứ người vận hành thực sự cảm nhận.

### 6.2 Kích thước proof bundle

Kích thước bundle theo kích thước batch, và tỷ lệ giảm thiểu tiết lộ (số byte tiết lộ cho
một quyết định so với số byte của toàn bộ trail). Cài đặt hiện tại cho ra bundle cỡ 1,7 KB
với batch sáu entry; đường cong đáng quan tâm là tăng trưởng logarit của đường proof so với
tăng trưởng tuyến tính của trail.

### 6.3 Case study đối kháng

Bài trình diễn tám kịch bản từ triển khai tham chiếu, chạy như một thí nghiệm chứ không phải
một demo: kết quả kỳ vọng của mỗi kịch bản đều được assert, và harness fail nếu bất kỳ kịch
bản nào ngừng hành xử như tài liệu mô tả. Đưa vào cả các đối chứng âm một cách tường minh —
hai kịch bản mà việc kiểm chứng chuỗi thuần tuý báo "nguyên vẹn" một cách *đúng đắn*, và
kịch bản mà câu trả lời đúng là *không kiểm chứng được* chứ không phải *bị can thiệp*. Một
bảng mà dòng nào cũng ghi "đã phát hiện" là một bảng không ai nên tin.

### 6.4 Thí nghiệm tiến hoá schema

Phép đo nói trực tiếp tới lớp lỗi. Ghi bản ghi dưới schema phiên bản *A*, tiến hoá sang *B*,
rollback binary, rồi verify. So sánh ba thiết kế verifier trên cùng một dữ liệu:

| Verifier | Kết quả trên dữ liệu đã rollback |
|---|---|
| Phiên bản theo thứ tự, lạ = lỗi | từ chối chạy (Sự cố B) |
| Tính lại theo bộ trường hiện tại | báo can thiệp hàng loạt (Sự cố A) |
| Fingerprint + kết quả ba giá trị | báo dòng nguyên vẹn là nguyên vẹn, dòng lạ là không kiểm chứng được, exit code phân biệt cả hai với can thiệp |

Đây là một thí nghiệm nhỏ và nó là trung tâm của bài báo. Mọi thứ khác là phần kỹ thuật xây
quanh nó.

---

## 7. Thảo luận: bối cảnh pháp lý

Ngắn, và khiêm tốn có chủ ý — đây là bài báo hệ thống, không phải bài báo luật.

Một lớp toàn vẹn có thể và không thể đóng góp gì cho các nghĩa vụ lưu trữ hồ sơ (EU AI Act
Điều 12/19/26(6); yêu cầu trong RTS của DORA rằng log phải được bảo vệ khỏi bị can thiệp và
bị xoá, và rằng lỗi của hệ thống ghi log phải phát hiện được; các kỳ vọng về tài liệu trong
quản trị rủi ro mô hình). Cách đóng khung trung thực: các văn bản này đòi hỏi bản ghi phải
được *giữ*, và phần lớn không quy định rằng chúng phải *không giả mạo được trước chính bên
giữ*. Tamper-evidence do đó là tư thế mạnh hơn mức hầu hết văn bản đòi hỏi — đó là lý lẽ để
áp dụng nó, và là lý lẽ chống lại việc tuyên bố rằng có văn bản nào bắt buộc nó.

Cũng đáng một đoạn: cái bẫy "hiện vật tuân thủ". Một nhật ký đã kiểm chứng của một hệ thống
không được quản trị sẽ chứng minh rất trung thực rằng các quyết định đó không được quản trị.
Toàn vẹn là điều kiện cần cho trách nhiệm giải trình, không bao giờ là vật thay thế cho nó.

---

## 8. Giới hạn và hướng phát triển

- Thời gian đáng tin: tích hợp gắn dấu thời gian RFC 3161 để `ts` trở thành được chứng thực
  thay vì được khẳng định.
- Chain server Byzantine: một kiểm tra phía client có thể phát hiện được gì trước một server
  bất lương, và điều gì chứng minh được là không thể.
- Nhật ký quyết định bảo toàn riêng tư: liệu membership proof zero-knowledge có gỡ bỏ được
  phần tiết lộ mà một proof bundle vẫn còn kéo theo hay không.
- Xoá dữ liệu trên nền chỉ-ghi-thêm: crypto-shredding payload trong khi vẫn giữ toàn vẹn
  chuỗi, và liệu bằng chứng còn lại có còn giá trị gì không.
- Chuỗi liên tổ chức: neo lẫn nhau giữa các đối tác như một vật thay thế cho bên thứ ba đáng
  tin cậy.

---

## Ứng viên hội nghị

| Hội nghị | Mức phù hợp | Ghi chú |
|---|---|---|
| **ACSAC** | mạnh | hệ thống an toàn ứng dụng kèm câu chuyện triển khai; case study hợp phong cách |
| **DIMVA** | mạnh | đóng khung theo lớp lỗi và phát hiện nằm đúng phạm vi |
| **FC — workshop WTSC** | tốt | đóng khung dịch vụ tài chính; dòng dõi transparency log quen thuộc với cộng đồng đó |
| **Workshop của IEEE S&P / CCS** (SafeThings, AISec) | tốt | đường ngắn nhất nếu góc trách nhiệm giải trình AI dẫn dắt |
| **USENIX Security** | khó | cần một tuyên bố về tính mới mạnh hơn hẳn "tổ hợp cộng thiết kế định danh" |

**Đánh giá artefact.** Phần cài đặt có giấy phép MIT, không dependency, và đi kèm golden
vector cộng một case study đối kháng chạy được — hãy nhắm tới huy hiệu artefact ở hội nghị
nào có, và trích dẫn artefact thay vì kể lại đầu ra của nó trong bài.

---

## Danh mục kiểm tra khả năng tái lập

- [ ] Mọi thí nghiệm chạy từ repository công khai tại một commit đã gắn tag
- [ ] Chỉ dữ liệu tổng hợp; case study không chứa khách hàng, tổ chức hay mô hình thật nào
- [ ] Golden vector được đối chiếu chéo bởi một cài đặt độc lập của phần văn xuôi đặc tả
- [ ] Harness benchmark báo cáo phân phối, phần cứng, và phiên bản backend
- [ ] Thí nghiệm tiến hoá schema (§6.4) được script hoá end-to-end, gồm cả hai verifier
      baseline thất bại
- [ ] Mọi trích dẫn pháp lý đã xác minh từ nguồn sơ cấp, hoặc được gắn nhãn chưa xác minh
