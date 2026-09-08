# Ánh xạ tuân thủ - waxseal chứng minh được gì, và không chứng minh được gì

*[English](mapping.md)*

**Đọc phần này trước.** waxseal là lớp toàn vẹn và bằng chứng. Nó có thể tạo ra bằng chứng
kỹ thuật *hỗ trợ* cho một nghĩa vụ về lưu trữ hồ sơ, truy vết, hoặc toàn vẹn nhật ký. Nó
**không** làm cho bất kỳ tổ chức nào tuân thủ bất kỳ điều gì, và không dòng nào trong các
bảng dưới đây được đọc thành "yêu cầu này đã được đáp ứng". Việc một nghĩa vụ có được thoả
mãn hay không phụ thuộc vào quản trị, phạm vi, chính sách, biện pháp kiểm soát và diễn giải
pháp lý - tất cả đều nằm hoàn toàn ngoài thư viện này, và là việc xác định thuộc về bộ phận
tuân thủ và pháp chế của tổ chức triển khai.

Tài liệu này không phải tư vấn pháp lý, và không nêu tên tổ chức, sản phẩm hay cá nhân nào.

### Cách đọc nhãn trong bảng

| Nhãn | Ý nghĩa |
|---|---|
| **Trực tiếp** | waxseal tạo ra bằng chứng đi thẳng vào nội dung của yêu cầu |
| **Một phần** | waxseal phủ một phần; phần còn lại thuộc về tổ chức hoặc nằm ngoài phạm vi |
| **Ngoài phạm vi** | liệt kê ra để không ai mặc định là đã được phủ - nó không được phủ |

Mọi điều khoản được trích dưới đây đều được truy xuất từ nguồn nêu tại
[§8 Nguồn và mức xác minh](#8-nguồn-và-mức-xác-minh) vào ngày 2026-08-23, trừ cụm văn bản
pháp luật AI của Việt Nam ở §7b, truy xuất ngày 2026-09-07. Chỗ nào không
xác minh được từ nguồn chính thức hoặc nguồn sơ cấp thì được gắn nhãn `[Unverified]`
ngay tại chỗ và cần được kiểm tra lại trước khi sử dụng.

---

## 1. waxseal thực sự tạo ra những gì

Trước khi ánh xạ bất cứ điều gì, đây là danh sách đầy đủ các nguyên thuỷ bằng chứng. Mọi
ô "Trực tiếp" bên dưới đều quy về một trong số này.

| Nguyên thuỷ | Bằng chứng nó tạo ra | Ở đâu |
|---|---|---|
| Chuỗi hash trên `EntryHeader` | một bản ghi đã tồn tại ở vị trí *n*, theo thứ tự này, không đổi từ đó | `domain/hashing.py`, `domain/verify.py` |
| Schema fingerprint | dòng đó được ký dưới bộ trường nào; không nhận ra -> *không kiểm chứng được*, không bao giờ là *bị sửa* | `domain/fingerprint.py` |
| `DecisionRecord` | định danh hệ thống AI, tên/phiên bản/digest mô hình, kết quả, căn cứ, phiên bản policy, độ tin cậy, chế độ giám sát của con người | `domain/decision.py` |
| `input_commitment` | input mà mô hình đã thấy, cam kết bằng hash sau khi redact, không lưu bản gốc | `sources/decisions.py` |
| Redact trước khi hash | bí mật không bao giờ chạm đĩa ở dạng cleartext | `adapters/redactors.py` |
| Checkpoint Merkle + neo | một root đã công bố sang miền tin cậy khác trước khi việc sửa có thể xảy ra | `domain/anchoring.py` |
| Niêm phong forward-secure | việc viết lại phần đuôi hoặc cắt đuôi là phát hiện được, với khoá đã ký quỹ | `domain/sealing.py` |
| Proof bundle | một quyết định, kiểm tra được offline, không tiết lộ phần còn lại của nhật ký | `domain/export.py` |
| `dropped_writes` | **cận dưới đã đo** của số write thất bại; `None` = chưa đo | `adapters/drops.py` |
| Báo cáo kiểm toán | tất cả những thứ trên, cộng với chữ *not checked* tường minh cho những gì chưa chạy | `domain/report.py` |
| Bản ghi sự cố | một bản ghi sự cố đã tồn tại ở vị trí *n* và không đổi từ đó; một tham chiếu tới việc nộp được lưu lại - không bao giờ là việc bản nộp đã tới đích | `domain/incident.py` |
| Bản ghi can thiệp của con người | một quyết định dừng, override hoặc thu hồi đã được ghi ở vị trí *n* và không đổi từ đó, dù nó có thuộc về một quyết định cụ thể hay không | `domain/intervention.py` |

**Hai hàng cuối về cùng bản phát hành này; chúng không có trong 0.1.5.** Các module được nêu
đang hạ cánh song song với tài liệu này chứ chưa được phát hành. Chúng được viết ở đây ngay
bây giờ để phần ánh xạ và phần code thôi trôi xa nhau - nhưng cho đến khi một phiên bản đã
phát hành export chúng, chúng không phải bằng chứng đang có và không được trích dẫn như vậy.
Mọi hàng còn lại ở trên đều có trong 0.1.5.

---

## 2. Đạo luật AI của EU - Quy định (EU) 2024/1689

### Trước hết là phạm vi áp dụng

Phụ lục III điểm 5(b) xếp vào nhóm rủi ro cao các "hệ thống AI dùng để đánh giá mức độ tín
nhiệm tín dụng của thể nhân hoặc thiết lập điểm tín dụng của họ, **ngoại trừ các hệ thống
AI dùng cho mục đích phát hiện gian lận tài chính**".

Ngoại lệ đó rất quan trọng và rất dễ bị đọc lệch, theo hướng có lợi hoặc bất lợi cho tổ
chức triển khai. Trường hợp quét rủi ro/gian lận trong [PoC](../../examples/risk-poc/README.vi.md)
theo cách đọc thông thường nằm trong nhóm được loại trừ, còn chấm điểm tín dụng thì không.
Việc xác định một hệ thống cụ thể rơi vào nhóm nào là câu hỏi pháp lý, không phải kỹ
thuật - các bảng dưới đây áp dụng ở nơi Đạo luật áp dụng.

### Điều 12 - Lưu trữ hồ sơ (Record-keeping)

> **12(1)** "Hệ thống AI rủi ro cao phải cho phép về mặt kỹ thuật việc tự động ghi lại các
> sự kiện (log) trong suốt vòng đời của hệ thống."
>
> **12(2)** "…năng lực ghi log phải cho phép ghi lại các sự kiện liên quan tới: (a) nhận
> diện các tình huống có thể khiến hệ thống AI rủi ro cao gây ra rủi ro theo nghĩa Điều
> 79(1) hoặc dẫn tới thay đổi đáng kể; (b) tạo thuận lợi cho việc giám sát hậu thị trường
> nêu tại Điều 72; và (c) giám sát hoạt động của hệ thống AI rủi ro cao nêu tại Điều 26(5)."

| Điều khoản | Mức phủ | waxseal cung cấp gì | Còn cần gì |
|---|---|---|---|
| 12(1) tự động ghi trong suốt vòng đời | **Một phần** | chuỗi chỉ-ghi-thêm ghi lại từng sự kiện quyết định kèm bằng chứng toàn vẹn của chính nó; không có gì trong thư viện xoá dữ liệu | *sự kiện nào* được ghi là quyết định của phần tích hợp, không phải của thư viện; "suốt vòng đời" là một chương trình lưu trữ và xoay vòng |
| 12(2)(a) sự kiện liên quan nhận diện rủi ro | **Một phần** | kết quả, căn cứ, độ tin cậy, phiên bản policy và phiên bản mô hình đều nằm trong bản ghi, nên một sự dịch chuyển quy được về một phiên bản | phân loại rủi ro và việc phát hiện "thay đổi đáng kể" thuộc về tổ chức |
| 12(2)(b) hỗ trợ giám sát hậu thị trường (Điều 72) | **Trực tiếp** | `waxseal report --json` là nguồn dữ liệu truy vấn được, đã kiểm toàn vẹn, theo loại quyết định, chế độ giám sát và phiên bản mô hình | bản thân kế hoạch giám sát |
| 12(2)(c) giám sát hoạt động theo Điều 26(5) | **Một phần** | `human_oversight` được ghi cho từng quyết định, với *not recorded* phân biệt rõ khỏi *automated* | quy trình giám sát phải là thật |
| 12(3) log tối thiểu cho Phụ lục III điểm 1(a) | **Ngoài phạm vi** | - | 12(3) dành riêng cho hệ thống sinh trắc học (thời gian sử dụng, cơ sở dữ liệu tham chiếu, dữ liệu đầu vào khớp, người xác minh); bộ trường của `DecisionRecord` không được thiết kế cho việc đó |

### Điều 19 - Log tự động sinh (nhà cung cấp)

> "Nhà cung cấp hệ thống AI rủi ro cao phải giữ các log nêu tại Điều 12(1), do hệ thống AI
> rủi ro cao của mình tự động sinh ra, trong phạm vi các log đó nằm dưới quyền kiểm soát
> của họ. … các log phải được giữ trong khoảng thời gian phù hợp với mục đích sử dụng dự
> kiến của hệ thống AI rủi ro cao, **ít nhất là sáu tháng**, trừ khi pháp luật Liên minh
> hoặc quốc gia áp dụng quy định khác, đặc biệt là pháp luật Liên minh về bảo vệ dữ liệu cá
> nhân.
>
> Nhà cung cấp là tổ chức tài chính thuộc diện các yêu cầu về quản trị nội bộ, cơ chế hoặc
> quy trình theo pháp luật dịch vụ tài chính của Liên minh phải duy trì các log do hệ thống
> AI rủi ro cao của mình tự động sinh ra như một phần hồ sơ tài liệu lưu giữ theo pháp luật
> dịch vụ tài chính liên quan."

| Khía cạnh | Mức phủ | Ghi chú |
|---|---|---|
| Giữ log, không bị sửa, trong suốt thời hạn | **Một phần** | chỉ-ghi-thêm theo cấu trúc, nên không mất gì do hành vi của chính thư viện; **waxseal không cưỡng chế thời hạn lưu trữ** và không có cơ chế hết hạn |
| Tính toàn vẹn của log được lưu | **Trực tiếp** | đây chính là toàn bộ thư viện. Điều 19 tự nó không đòi hỏi tamper-evidence, nhưng một nhật ký không chứng minh được là chưa bị sửa thì là bằng chứng yếu cho bất cứ điều gì |
| Đường "hồ sơ tài liệu của tổ chức tài chính" | **Ngoài phạm vi** | chế độ tài liệu nào hấp thụ các log này là việc xác định pháp lý |

### Điều 26(6) - Thời hạn lưu log của bên triển khai

> "Bên triển khai hệ thống AI rủi ro cao phải giữ các log do hệ thống AI rủi ro cao đó tự
> động sinh ra, trong phạm vi các log đó nằm dưới quyền kiểm soát của họ, trong khoảng thời
> gian phù hợp với mục đích sử dụng dự kiến của hệ thống, **ít nhất là sáu tháng**, trừ khi
> pháp luật Liên minh hoặc quốc gia áp dụng quy định khác."

Mức phủ giống Điều 19. Điểm hữu ích về mặt vận hành là cụm "**trong phạm vi các log đó nằm
dưới quyền kiểm soát của họ**": bên triển khai vận hành tầng agent thì kiểm soát nhật ký
quyết định ngay cả khi mô hình là của bên thứ ba - nên đây đúng là lớp mà bên triển khai có
thể tự sở hữu. [Kiến trúc tham chiếu](../architecture/deployment.vi.md#6-lưu-trữ-dr-và-dung-lượng)
trình bày việc xoay vòng chuỗi như là cơ chế lưu trữ.

### Căng thẳng: chỉ-ghi-thêm và quyền được xoá

Điều 19 đặt nghĩa vụ lưu trữ dưới "pháp luật Liên minh về bảo vệ dữ liệu cá nhân". Một
chuỗi chỉ-ghi-thêm không thể xoá payload mà không phá chính bằng chứng mà nó sinh ra để
cung cấp. Câu trả lời của waxseal là **không được để dữ liệu cá nhân nào vào payload**:
`subject_ref` và `reviewer_ref` được quy định là tham chiếu bút danh tới các hệ thống có
thể xoá. Đây là ràng buộc thiết kế đối với phần tích hợp, và làm sai thì không cứu được
về sau.

---

## 3. NIST AI RMF 1.0 (AI 100-1)

Nội dung subcategory dưới đây trích từ NIST AI RMF Playbook.

| Subcategory | Nội dung | Mức phủ | waxseal cung cấp gì |
|---|---|---|---|
| GOVERN 1.4 | "Quy trình quản trị rủi ro và kết quả của nó được thiết lập thông qua các chính sách, thủ tục và biện pháp kiểm soát minh bạch…" | **Một phần** | `policy_version` trên mọi quyết định làm cho câu hỏi "policy nào đang hiệu lực cho quyết định này" trả lời được về sau |
| GOVERN 1.6 | cơ chế kiểm kê các hệ thống AI | **Một phần** | `system_id` và phần kiểm kê theo fingerprint trong báo cáo cho ra một bản kiểm kê *suy từ thực tế sử dụng*, không phải một sổ đăng ký quản trị |
| GOVERN 4.2 | "Các nhóm trong tổ chức lập tài liệu về rủi ro AI và tác động tiềm tàng, và truyền đạt các phát hiện một cách rộng rãi" | **Một phần** | `report --json` là hiện vật bền vững, đã kiểm toàn vẹn, để truyền đạt từ đó |
| GOVERN 6.1 | chính sách rủi ro AI từ bên thứ ba | **Một phần** | tên/phiên bản/**digest** mô hình ghim chính xác hiện vật bên thứ ba nào đã tạo ra quyết định |
| MEASURE 2.4 | "Chức năng và hành vi của hệ thống AI và các thành phần của nó được giám sát khi ở môi trường sản xuất" | **Trực tiếp** | nhật ký quyết định *chính là* bản ghi hành vi sản xuất; thống kê theo loại quyết định và kết quả nằm trong báo cáo |
| MEASURE 2.8 | "Rủi ro liên quan tới tính minh bạch và trách nhiệm giải trình được xem xét và lập tài liệu" | **Trực tiếp** | trách nhiệm giải trình đòi hỏi một bản ghi không thể bị âm thầm sửa lại; đó là chức năng của thư viện |
| MEASURE 2.9 | "Mô hình AI được giải thích, kiểm định và lập tài liệu, và đầu ra được diễn giải trong bối cảnh của nó" | **Một phần** | `rationale` và `input_commitment` nắm bắt bối cảnh của từng quyết định; chất lượng giải thích là vấn đề của mô hình |
| MANAGE 4.1 | "Kế hoạch giám sát hệ thống AI sau triển khai được thực hiện…" | **Một phần** | cung cấp nền tảng giám sát; kế hoạch thuộc về tổ chức |
| MANAGE 4.3 | "Sự cố và lỗi được truyền đạt tới các chủ thể AI liên quan; quy trình theo dõi và khôi phục được lập tài liệu" | **Trực tiếp** | một quyết định đang bị điều tra có thể trích xuất thành proof bundle và chứng minh là nguyên vẹn một cách độc lập với bên đang giữ nhật ký |

**NIST AI 600-1 (Generative AI Profile).** `[Unverified]` - các mã định danh hành động
cụ thể của GenAI Profile không được truy xuất cho tài liệu này. Các hành động về truy vết
và nguồn gốc (provenance) trong đó là phần liên quan; hãy kiểm tra trực tiếp trước khi
trích dẫn.

---

## 4. DORA - Quy định (EU) 2022/2554 và RTS kèm theo

Chỗ khớp nhất trong họ DORA không phải bản thân Quy định mà là **Quy định uỷ quyền của Uỷ
ban (EU) 2024/1774, Điều 12 (Logging)** - RTS về công cụ, phương pháp, quy trình và chính
sách quản trị rủi ro ICT.

| Yêu cầu (RTS Điều 12) | Mức phủ | waxseal cung cấp gì |
|---|---|---|
| "các biện pháp bảo vệ hệ thống ghi log và thông tin log khỏi **bị can thiệp, bị xoá và truy cập trái phép** ở trạng thái lưu trữ, trên đường truyền, và khi đang được sử dụng nếu liên quan" | **Trực tiếp** với can thiệp và xoá | chuỗi phát hiện việc sửa; neo phát hiện việc viết lại toàn bộ nhật ký một cách nhất quán; niêm phong forward-secure phát hiện việc cắt đuôi. **Không** phải kiểm soát truy cập hay mã hoá - đó là việc của phần triển khai, không phải của thư viện |
| "các biện pháp **phát hiện lỗi của hệ thống ghi log**" | **Một phần** | `dropped_writes` đo đúng chế độ hỏng này, và báo `None` khi chưa đo thay vì ngầm hiểu là 0. Đây là cận dưới đã đo: bản thân sidecar cũng có thể bị mất |
| thời hạn lưu trữ đặt theo mục tiêu kinh doanh, an toàn thông tin và kết quả đánh giá rủi ro | **Ngoài phạm vi** | waxseal không cho gì hết hạn |
| "đồng bộ đồng hồ … theo một nguồn thời gian tham chiếu đáng tin cậy được lập tài liệu" | **Ngoài phạm vi** | **`ts` của waxseal do bên gọi cung cấp** (`now_fn` có thể tiêm vào, một cách có chủ ý, để test không bao giờ phải sleep). Đó là một khẳng định về thời gian được ghi lại, không phải thời gian được chứng thực. Nếu cần thời gian được chứng thực, hãy neo vào một TSA theo RFC 3161 - khi đó dấu thời gian đến từ TSA, không phải từ máy ghi |

DORA Điều 10(1)/(3) (phát hiện hoạt động bất thường, giám sát hoạt động người dùng) ở mức
**Một phần**: một nhật ký quyết định đã kiểm toàn vẹn là đầu vào cho việc phát hiện, nhưng
waxseal tự nó không phát ra cảnh báo nào ngoài các exit code của verifier.

---

## 5. Quản trị rủi ro mô hình - SR 11-7 và các văn bản kế thừa

SR 11-7 / OCC Bulletin 2011-12, *Supervisory Guidance on Model Risk Management* (2011), là
văn bản tham chiếu lâu năm. **`[Unverified]`** Cục Dự trữ Liên bang đã ban hành **SR
26-2, "Revised Guidance on Model Risk Management"**, và OCC ban hành một bulletin tương ứng
năm 2026; danh mục văn bản đã được xác nhận nhưng **nội dung bản sửa đổi chưa truy xuất
được**, và việc nó thay thế SR 11-7 toàn bộ hay một phần thì chưa xác minh. Hãy kiểm tra
văn bản nào đang áp dụng trước khi dựa vào phần này.

Đối chiếu với các chủ đề của SR 11-7:

| Chủ đề | Mức phủ | waxseal cung cấp gì |
|---|---|---|
| Kiểm kê mô hình (model inventory) | **Một phần** | `system_id` + tên/phiên bản/digest mô hình trên từng quyết định cho ra một bản kiểm kê *suy từ thực tế sử dụng* - cái gì thực sự đã chạy, đối lập với cái mà sổ đăng ký nói đáng lẽ phải chạy. Đối chiếu hai bản này là một biện pháp kiểm soát thực sự hữu ích |
| Tài liệu đủ để một bên độc lập hiểu được việc đã làm | **Một phần** | nguồn gốc từng quyết định, không phải tài liệu phát triển mô hình |
| Effective challenge / kiểm định độc lập | **Một phần** | kiểm định cần một bản ghi không thể chối cãi về việc môi trường sản xuất thực sự đã quyết định gì; một nhật ký mà chủ sở hữu mô hình sửa được thì không đỡ nổi việc phản biện. Phần phân tách nhiệm vụ trong [kiến trúc](../architecture/deployment.vi.md#3-phân-tách-nhiệm-vụ) mới là thứ làm điều này thành thật |
| Giám sát liên tục và phân tích kết quả | **Một phần** | cung cấp bản ghi kết quả; phần phân tích thuộc về tổ chức |
| Kiểm soát thay đổi theo phiên bản mô hình | **Một phần** | một thay đổi phiên bản hiện ra trong nhật ký ngay khi quyết định đầu tiên dưới phiên bản đó được ghi |

---

## 6. SOC 2 (AICPA Trust Services Criteria)

Bộ tiêu chí của AICPA không được trích nguyên văn ở đây (chúng không được công bố mở). Các
mã định danh dưới đây dùng ở mức mô tả; **`[Unverified]`** so với văn bản TSC chính thức.

| Tiêu chí | Lĩnh vực | Mức phủ |
|---|---|---|
| CC4.1-CC4.2 | hoạt động giám sát | **Một phần** - kiểm chứng theo lịch tạo ra bằng chứng rằng một biện pháp kiểm soát đã vận hành, kèm exit code cho mỗi lần chạy |
| CC7.2 | phát hiện và giám sát sự kiện hệ thống | **Một phần** - trail là bằng chứng được giám sát; việc cảnh báo thuộc về phần triển khai |
| CC7.3-CC7.4 | đánh giá và ứng phó sự kiện an ninh | **Một phần** - exit 1 là tín hiệu sự cố kèm số thứ tự và lý do cụ thể; exit 2 tường minh **không** phải sự cố |

Lập luận SOC 2 mạnh nhất cho lớp này không nằm ở một tiêu chí đơn lẻ nào - nó nằm ở chỗ
bằng chứng mà service auditor lấy mẫu có thể chứng minh được đúng là bằng chứng đã được
tạo ra tại thời điểm đó, chứ không phải một bản export do chính bên bị kiểm toán sinh ra
sau này.

---

## 7. Việt Nam - thí điểm thị trường tài sản mã hoá (Nghị quyết 05/2025/NQ-CP)

**Nghị quyết 05/2025/NQ-CP** (ngày 09/09/2025), thí điểm thị trường tài sản mã hoá trong 5
năm, tại **Điều 15(2)(l)** yêu cầu tổ chức cung cấp dịch vụ:

> "Lưu trữ trên hệ thống máy chủ tại Việt Nam tối thiểu 10 năm về lịch sử giao dịch, thông
> tin về người khởi tạo, người thụ hưởng (tối thiểu tên, địa chỉ, địa chỉ ví), lịch sử địa
> chỉ thiết bị đăng nhập hoặc địa chỉ giao thức Internet…"

Nội dung này khớp giống hệt nhau trên một cổng thông tin của Chính phủ và một cơ sở dữ liệu
pháp luật thương mại, nhưng **chưa** đối chiếu với bản công báo chính thức - hãy coi việc
đánh số điều khoản là *đã xác minh bởi hai nguồn thứ cấp đồng thuận*, không phải nguồn sơ cấp.

| Khía cạnh | Mức phủ | Ghi chú |
|---|---|---|
| Lưu trữ 10 năm trên máy chủ tại Việt Nam | **Ngoài phạm vi** | đây là quyết định về triển khai và nơi lưu trú dữ liệu. Backend của waxseal chạy ở đâu là do triển khai, và nó không cho gì hết hạn |
| Tính toàn vẹn của thứ được lưu | **Trực tiếp** | Nghị quyết yêu cầu *lưu trữ*, không yêu cầu tamper-evidence. Lưu trữ chống sửa đổi là tư thế **mạnh hơn** mức văn bản đòi hỏi - hãy trình bày đúng như vậy, đừng trình bày như một yêu cầu mà văn bản áp đặt |
| Tên và địa chỉ người khởi tạo/thụ hưởng | **Xung đột** | Nghị quyết yêu cầu dữ liệu *định danh*; waxseal yêu cầu payload phải là *bút danh* vì chuỗi không xoá được. Cách hoá giải: giữ kho định danh tách riêng và tham chiếu qua `subject_ref` - chuỗi khi đó chứng minh quyết định, còn kho định danh đáp ứng nghĩa vụ lưu trữ |

**Quyết định 96/QĐ-BTC** (ngày 20/01/2026) công bố các thủ tục hành chính mới (cấp phép,
điều chỉnh, thu hồi giấy phép) triển khai Nghị quyết 05/2025/NQ-CP. Văn bản này liên quan
tới **thủ tục cấp phép**, không phải yêu cầu về audit trail hay ghi log, và được liệt kê ở
đây chỉ để không ai mặc định rằng nó áp đặt một yêu cầu như vậy.

`[Unverified]` Yêu cầu chứng nhận an toàn hệ thống thông tin cấp độ 4 được ghi nhận là
nằm ở Điều 8(7) của Nghị quyết; số điều khoản chưa được xác nhận từ nguồn sơ cấp.

---

## 7b. Việt Nam - Luật Trí tuệ nhân tạo số 134/2025/QH15 và các văn bản thi hành

### Trước hết là phạm vi áp dụng

Hai vai trò gánh gần như toàn bộ nghĩa vụ bên dưới, và Luật chốt chúng tại **Điều 3**:

> **3(4)** "Nhà cung cấp là tổ chức, cá nhân đưa hệ thống trí tuệ nhân tạo ra thị trường hoặc
> đưa vào sử dụng dưới tên, thương hiệu hoặc nhãn hiệu của mình, không phụ thuộc hệ thống đó
> do họ tự phát triển hay được phát triển bởi bên thứ ba."
>
> **3(5)** "Bên triển khai là tổ chức, cá nhân sử dụng hệ thống trí tuệ nhân tạo thuộc phạm vi
> kiểm soát của mình trong hoạt động nghề nghiệp, thương mại hoặc cung cấp dịch vụ; không bao
> gồm trường hợp sử dụng cho mục đích cá nhân, phi thương mại."

Một tầng agent dựng trên mô hình của bên thứ ba thường là **nhà cung cấp** của hệ thống đã lắp
ghép, và giữ mô hình đó trong phạm vi kiểm soát của chính mình - cũng chính là điểm "trong phạm
vi các log đó nằm dưới quyền kiểm soát của họ" mà §2 nêu về Điều 26(6) của Đạo luật AI EU, chỉ
đi tới từ một hướng khác. Việc một tổ chức cụ thể đứng ở vai trò nào là câu hỏi pháp lý, không
phải kỹ thuật.

Việc phân loại diễn ra **trước** khi đưa vào sử dụng, và do nhà cung cấp tự làm:

> **10(1)** "Nhà cung cấp tự phân loại hệ thống trí tuệ nhân tạo trước khi đưa vào sử dụng. Hệ
> thống được phân loại là rủi ro trung bình hoặc rủi ro cao phải có hồ sơ phân loại kèm theo."

Tự phân loại không có nghĩa là tự đặt ra tiêu chí. **Điều 13(4)** đặt nhóm rủi ro cao vào một
**Danh mục do Thủ tướng Chính phủ ban hành** ("Thủ tướng Chính phủ quy định Danh mục hệ thống
trí tuệ nhân tạo có rủi ro cao, bao gồm danh mục hệ thống trí tuệ nhân tạo phải chứng nhận sự
phù hợp trước khi đưa vào sử dụng"), và Điều 6(3)(a) Nghị định định nghĩa rủi ro cao *chính là
việc thuộc Danh mục đó*. Nghĩa là mức rủi ro được chốt bởi một danh mục đã công bố cộng với các
điều kiện rủi ro trung bình tại Điều 9 Nghị định - không phải bởi cách một kỹ sư đọc rủi ro.
Việc một hệ thống cụ thể có nằm trong danh mục nào hay không là câu hỏi pháp lý, đúng như Phụ
lục III trong §2; bảng dưới đây áp dụng ở nơi Luật áp dụng.

`[Unverified]` Một Quyết định 33/2026/QĐ-TTg được ghi nhận là Danh mục nói trên, và một Thông tư
05/2026/TT-BKHCN được ghi nhận là Khung đạo đức trí tuệ nhân tạo quốc gia ban hành theo Điều 26
của Luật. Cả hai văn bản đều chưa truy xuất được - căn cứ: chỉ có bản tóm tắt từ nguồn thứ cấp.
Số hiệu, ngày ban hành và phạm vi của chúng chưa được đối chiếu với nguồn sơ cấp; hãy xác nhận
cả hai trước khi dựa vào bất kỳ văn bản nào trong số đó.

| Văn bản | Hiệu lực | Chuyển tiếp |
|---|---|---|
| Luật 134/2025/QH15 | 01/03/2026 (Điều 34), trừ các nội dung Điều 35 dời lại | Điều 35(1), với hệ thống đã đưa vào hoạt động trước ngày đó: **18 tháng** cho y tế, giáo dục và tài chính (35(1)(a)); **12 tháng** cho các hệ thống còn lại (35(1)(b)) |
| Nghị định 142/2026/NĐ-CP | 01/05/2026 (Điều 45) | Điều 46: khi Cổng thông tin điện tử một cửa chưa được công bố vận hành chính thức, việc thông báo và báo cáo qua phương thức điện tử được công bố thay thế có "giá trị pháp lý tương đương" |

Điều 35(2) cho phép các hệ thống đó tiếp tục hoạt động trong thời hạn chuyển tiếp. Vì vậy một
trail bắt đầu hôm nay có thể sẽ trải qua đúng thời điểm nghĩa vụ của hệ thống mình phát sinh, và
sống lâu hơn một phiên bản của "ghi những gì" - đó là lý do bộ trường mà một dòng được ký dưới
là một fingerprint theo từng dòng, không phải một quyết định toàn cục, và là lý do một fingerprint
mà build này không nhận ra được báo là *không kiểm chứng được*, không bao giờ là *bị sửa*.

### Bảng nghĩa vụ

Ba điều khoản gánh phần lớn trọng lượng, nên được trích trước bảng.

> **Luật Điều 14(1)(c)** "Lập, cập nhật, lưu giữ hồ sơ kỹ thuật và nhật ký hoạt động ở mức cần
> thiết cho việc đánh giá sự phù hợp và kiểm tra sau khi đưa vào sử dụng; cung cấp các thông
> tin này cho cơ quan nhà nước có thẩm quyền theo nguyên tắc cần thiết, tương xứng với mục
> đích kiểm tra và không làm lộ bí mật kinh doanh."

> **Nghị định Điều 11(5)**, câu cuối: "…nhà cung cấp, bên triển khai phải lưu trữ đầy đủ nhật ký
> vận hành và các quyết định can thiệp để phục vụ công tác thanh tra, kiểm tra."

> **Nghị định Điều 19(3)(c)** "Thời điểm xác nhận sự cố quy định tại khoản này được tính từ khi
> tổ chức, cá nhân có đủ cơ sở thông tin ban đầu để xác định sự cố đã thực sự xảy ra và có khả
> năng cao bắt nguồn từ lỗi của hệ thống trí tuệ nhân tạo, không đợi đến khi hoàn thành điều
> tra toàn diện nguyên nhân kỹ thuật."

Đồng hồ 72 giờ cho báo cáo sơ bộ tại Điều 19(3)(a) chạy từ **thời điểm xác nhận** đó, không phải
từ thời điểm phát hiện. Chính sự phân biệt này là lý do hàng về sự cố bên dưới dừng ở chỗ nó dừng.

| Điều khoản | Yêu cầu (rút gọn) | Mức phủ | Ghi chú |
|---|---|---|---|
| Luật Điều 14(1)(c) | lưu giữ hồ sơ kỹ thuật và nhật ký hoạt động phục vụ đánh giá sự phù hợp và hậu kiểm, và cung cấp khi có yêu cầu | **Một phần** | **Trực tiếp** với *tính toàn vẹn, thứ tự và vị trí* của những gì được lưu - một dòng đã tồn tại ở vị trí *n*, theo thứ tự này, không đổi từ đó. **Một phần** trên tổng thể vì hai lý do độc lập. Thứ nhất, "ở mức cần thiết" là một phán đoán về phạm vi mà tổ chức triển khai phải tự đưa ra: ghi sự kiện nào, trường nào, giữ bao lâu. Không thư viện nào làm được việc đó, và một thư viện giả vờ làm được thì đang tự quyết phạm vi nghĩa vụ pháp lý của người khác. Thứ hai, điều khoản này yêu cầu *lưu giữ*, không yêu cầu tamper-evidence. Lưu trữ chống sửa đổi là tư thế **mạnh hơn** mức văn bản đòi hỏi và phải được trình bày đúng như vậy - không phải như một yêu cầu mà điều khoản này áp đặt. Hàng về Nghị quyết 05/2025 trong §7 giữ đúng sự cẩn trọng đó |
| Luật Điều 28(3) | khi thanh tra, kiểm tra phải cung cấp "hồ sơ kỹ thuật, nhật ký lưu vết, dữ liệu huấn luyện" | **Một phần** | `waxseal export-proof` xuất một quyết định thành một bundle mà `verify-proof` kiểm tra được offline, nên một dòng duy nhất có thể được tiết lộ và chứng minh là không bị sửa mà không tiết lộ phần còn lại của nhật ký. Điều đó khớp cả với giới hạn "cần thiết, tương xứng" của điều khoản này lẫn với việc Điều 14(1)(e) không cho phép yêu cầu tiết lộ mã nguồn, thuật toán chi tiết hay bộ tham số - một proof bundle không tiết lộ thứ nào trong đó. Hồ sơ kỹ thuật và dữ liệu huấn luyện thì không được phủ: waxseal không giữ cả hai |
| Nghị định Điều 11(5) và Điều 15(2)(c) | lưu trữ nhật ký vận hành **và các quyết định can thiệp**; thiết kế và duy trì cơ chế giám sát, can thiệp của con người | **Một phần** | hiện nay bằng chứng giám sát là `HumanOversight`, gắn theo từng quyết định - chế độ, tham chiếu người rà soát, hành động - nên một can thiệp thuộc về một quyết định cụ thể thì đã được ghi và kiểm toàn vẹn. Một can thiệp không thuộc về quyết định nào (dừng hệ thống, thu hồi, override chính hệ thống chứ không phải một đầu ra) thì chưa có chỗ để ở. Một họ payload can thiệp riêng đang về cùng bản phát hành này (§1); khi nó hạ cánh, hàng này thành **Trực tiếp** *đối với tính toàn vẹn của việc lưu giữ các bản ghi đó* và vẫn là **Một phần** với cả điều khoản, vì việc thiết kế và duy trì cơ chế không phải là việc một nhật ký làm được. **Nửa hướng tới tương lai chưa được phát hành - đừng trích dẫn nó** |
| Luật Điều 10(1) + Nghị định Điều 6 và Điều 12 | tự phân loại trước khi đưa vào sử dụng; lập hồ sơ phân loại rủi ro | **Ngoài phạm vi** | waxseal không có phân loại rủi ro và không đánh giá bất cứ điều gì. Điều xa nhất nó sẽ làm là ghi lại **nguyên văn** mức rủi ro do nhà cung cấp khai, như lời khai của chính nhà cung cấp đó. Ghi lại một lời khai không phải là phân loại - và một thư viện chuẩn hoá "cao" thành "high" thì đang thay phán đoán của mình vào lời khai mà Điều 6(1) Nghị định buộc nhà cung cấp chịu trách nhiệm trước pháp luật |
| Luật Điều 12 + Nghị định Điều 19 | ghi nhận sự cố; báo cáo sơ bộ trong 72 giờ kể từ thời điểm xác nhận | **Ngoài phạm vi** | 0.1.5 không mô hình hoá sự cố. Một họ payload sự cố đang về cùng bản phát hành này (§1); khi nó hạ cánh thì hàng này thành **Một phần**, trên một khẳng định hẹp: waxseal chứng minh được rằng một bản ghi sự cố đã tồn tại ở một vị trí và chưa bị sửa từ đó, và nó lưu được một tham chiếu tới việc nộp. Nó **không** chứng minh được rằng một báo cáo đã tới Cổng - không dòng code nào trong thư viện nói chuyện với Cổng nào - và đồng hồ 72 giờ chạy từ **thời điểm xác nhận** tại Điều 19(3)(c), một thời điểm do người ghi khai, không phải thời điểm waxseal chứng thực. **Chưa được phát hành** |
| Luật Điều 7(4) | cấm cản trở, vô hiệu hoá hoặc làm sai lệch cơ chế giám sát, can thiệp và kiểm soát của con người | **Ngoài phạm vi** | một cơ chế đã bị tắt thì không ghi gì cả, nên không nhật ký nào chứng kiến được sự vắng mặt của chính nó. Đây đúng là lập luận mà CLAUDE.md đã nêu cho việc archiving vô hình đối với tính toàn vẹn của chuỗi: một khiếm khuyết mà không verdict nào thấy được thì phải được khẳng định từ bên ngoài nhật ký, không bao giờ được suy ra từ một lần verify sạch |
| Luật Điều 27(2) | hệ thống AI không thay thế thẩm quyền của người ra quyết định; người đó chịu trách nhiệm về việc xem xét và sử dụng kết quả | **Một phần** | `human_oversight` ghi lại việc *có hay không có* một lần rà soát được ghi nhận, và `oversight_unrecorded` được đếm riêng khỏi mọi chế độ đã ghi - nên "chúng ta không biết có ai rà soát dòng này hay không" không bao giờ hiển thị thành "không ai rà soát" hay thành "hệ thống tự động theo thiết kế". Việc lần rà soát đó có thật hay không, và người rà soát có đủ thẩm quyền hay không, nằm ngoài |
| Luật Điều 13 + Nghị định Điều 13(4) | đánh giá sự phù hợp; điều kiện của tổ chức đánh giá sự phù hợp | **Một phần** | SPEC.md, các golden vector ghi-một-lần, và các trình sinh đối chiếu độc lập trong `tools/` (viết theo đúng lời văn SPEC.md mà không import thư viện) là *đầu vào* để một tổ chức đánh giá kiểm tra lớp này độc lập với chính tác giả của nó. Bản thân chúng không đáp ứng điều gì, và không đầu ra nào của thư viện khẳng định một kết quả đánh giá |
| Nghị định Điều 3(6) "Thẻ hệ thống" | thẻ hệ thống gồm kiến trúc, thành phần, mô hình, mục đích và các biện pháp bảo đảm an toàn, cùng "thông tin về sự cố, lỗ hổng hoặc biện pháp khắc phục có liên quan" | **Một phần** | cùng nền tảng với hàng trên: một nhật ký đã kiểm toàn vẹn là nguồn để *viết ra* các trường về sự cố và biện pháp khắc phục của thẻ. Bản thân thẻ là tài liệu do con người viết; waxseal không tạo ra thẻ nào |
| QĐ 1671 IV.4.c - lưu trữ dữ liệu trong nước | lưu trữ dữ liệu tại Việt Nam trong các trường hợp pháp luật quy định | **Ngoài phạm vi** | thư viện chạy ở đâu thì nằm ở đó, và không cho gì hết hạn. Có một luồng đáng nêu tên vì rất dễ bỏ qua: việc neo gửi một Merkle root hoặc một hash - không bao giờ là payload - tới một TSA theo RFC 3161, một calendar OpenTimestamps, một witness, hoặc một ledger EVM. Nếu điểm nhận được chọn nằm ngoài lãnh thổ thì đó là một luồng dữ liệu xuyên biên giới mà người vận hành phải khai, dù nó không mang payload nào. Hãy đọc IV.4.c tại chỗ trước khi coi nó là một mệnh lệnh - xem mục về QĐ 1671 bên dưới |
| Luật Điều 11 + Nghị định Điều 17 và Điều 18 | đánh dấu kỹ thuật ở định dạng máy đọc và gắn nhãn hiển thị đối với nội dung do AI tạo ra | **Ngoài phạm vi** | waxseal không tạo ra nội dung, nên không có gì của riêng nó để đánh dấu hay gắn nhãn. Liệt kê ở đây để không ai mặc định rằng một audit trail phủ việc này |
| Luật Điều 8 + Nghị định Điều 4 và Điều 14 | đăng ký và thông báo qua Cổng thông tin điện tử một cửa và Cơ sở dữ liệu quốc gia về hệ thống AI | **Ngoài phạm vi** | không có tích hợp nào và không có kế hoạch nào trong bản phát hành này. Điều 14(3)(b) Nghị định có dự liệu một đường API, và Điều 46 giữ các phương thức điện tử khác có giá trị pháp lý tương đương khi Cổng chưa vận hành - nhưng waxseal không nộp gì qua bất kỳ đường nào, và một `report_ref` lưu trên trail là một tham chiếu do người ghi viết xuống, không phải một biên nhận mà waxseal đã kiểm chứng |

### Căng thẳng: hồ sơ lưu suốt thời gian hệ thống hoạt động và quyền được xoá

Nghị định **Điều 12(6)**: "Nhà cung cấp, bên triển khai có trách nhiệm lưu trữ hồ sơ phân loại
trong suốt thời gian hệ thống hoạt động" - hồ sơ phân loại được lưu trong suốt thời gian hệ
thống còn hoạt động, không có mốc kết thúc của riêng nó. Căng thẳng của §2 trở lại ở dạng gắt
hơn: ở đó, Điều 19 đặt sàn sáu tháng và đặt nghĩa vụ lưu trữ dưới pháp luật bảo vệ dữ liệu; ở
đây cái sàn là toàn bộ đời hoạt động của hệ thống, trong khi pháp luật về dữ liệu cá nhân cho
quyền xoá, và chính Nghị định dẫn chiếu tới "pháp luật về bảo vệ dữ liệu cá nhân" tại Điều 16(5).

Cách hoá giải vẫn là cách tài liệu này đã đi tới ở §2 và §7, và nó không đổi chỉ vì thời hạn
lưu trữ dài hơn: **không để dữ liệu cá nhân nào vào payload**, và tham chiếu định danh qua
`subject_ref` / `reviewer_ref` tới một kho *có thể* xoá. Chuỗi khi đó chứng minh quyết định
trong suốt thời gian hệ thống chạy; kho định danh trả lời cho quyền xoá. `[Inference]` Điều
12(7) Nghị định cho phép dùng Hồ sơ đánh giá tác động xử lý dữ liệu cá nhân làm thành phần của
Hồ sơ phân loại rủi ro, việc đó đặt hai chế độ pháp lý vào cùng một tập tài liệu nhưng không nói
chế độ nào thắng khi có một yêu cầu xoá - căn cứ: đọc trực tiếp Điều 12(7), không tìm thấy điều
khoản nào của Nghị định giải quyết xung đột này.

### QĐ 1671/QĐ-TTg là một chiến lược, không phải một nghĩa vụ

**Quyết định 1671/QĐ-TTg** phê duyệt Chiến lược quốc gia về trí tuệ nhân tạo đến năm 2030, tầm
nhìn đến năm 2045. Đây là một *chiến lược*: quan điểm, mục tiêu, trụ cột, giải pháp đột phá, và
một phụ lục nhiệm vụ, mỗi nhiệm vụ giao cho một cơ quan chủ trì kèm thời gian thực hiện. Nó
**phân công công việc cho các cơ quan nhà nước và không áp đặt yêu cầu nào lên một thư viện**.
Không hàng nào trong bảng trên xuất phát từ nó, và không có gì trong nó mà một phần mềm có thể
"tuân thủ". Nó có mặt trong tài liệu này vì hai lý do hẹp: một điều khoản của nó là cụm về lưu
trữ dữ liệu trong nước mà hàng tương ứng trong bảng trả lời, và các ưu tiên nó nêu nói thẳng ra
loại công cụ mà nhà nước đang tìm.

> **I. Quan điểm 4**, đoạn cuối: "…ưu tiên công nghệ nguồn mở, mô hình có trọng số mở và các
> giải pháp cho phép kiểm tra, tùy chỉnh, triển khai độc lập, từng bước giảm phụ thuộc vào bên
> ngoài."

> **III. Trụ cột 9. Quản trị AI an toàn, đáng tin cậy**, điểm (đ): "Xây dựng nền tảng, công cụ
> phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ
> AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI."

> **IV.4.c**, đoạn cuối: "…bảo đảm an toàn dữ liệu, an ninh mạng và lưu trữ dữ liệu tại Việt Nam
> trong các trường hợp pháp luật quy định."

Đọc tại chỗ, IV.4.c là phần cuối của một điểm về thu hút đầu tư trực tiếp nước ngoài chất lượng
cao và xây dựng trung tâm nghiên cứu, phát triển AI tại Việt Nam, và cụm về lưu trữ dữ liệu là
một *điều kiện* gắn với các thoả thuận đó, chứ không phải một quy tắc lưu trú dữ liệu đứng độc
lập. Nhiệm vụ 81 Phụ lục II mang đúng lời văn đó trong cột nhiệm vụ. Hàng về lưu trữ dữ liệu
trong nước ở bảng trên được viết đối chiếu với cụm từ này, không phải với một mệnh lệnh mà
Quyết định không hề chứa.

Ba nhiệm vụ trong Phụ lục II có liên quan tới người đọc tài liệu này, trích từ cột nhiệm vụ:

| Nhiệm vụ | Nội dung | Thời gian |
|---|---|---|
| 64 | "Triển khai, theo dõi, đánh giá và cập nhật Khung đạo đức AI quốc gia; hướng dẫn quản trị và đánh giá tuân thủ." | 2026-2030 |
| 66 | "Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI." | 2026-2030 |
| 89 | "Hình thành các tổ chức đánh giá sự phù hợp hệ thống AI." | 2026-2030 |

Mỗi nhiệm vụ đều nêu một bộ ở trung ương làm cơ quan chủ trì. Một nhiệm vụ trong phụ lục này là
việc nhà nước tự giao cho mình, trên một cửa sổ năm năm, với sản phẩm được mô tả bằng một cụm
từ. Nó không phải một đặc tả, và "nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá"
là một *phạm trù* chứ không phải một tiêu chí mà bất cứ thứ gì có thể đo được vào. `[Inference]`
một lớp toàn vẹn kiểu này là một trường hợp hẹp của điều nhiệm vụ 66 mô tả - nó chứng minh rằng
một bản ghi không bị sửa, và không gì hơn thế - căn cứ: đọc đúng lời văn của nhiệm vụ 66 đối
chiếu với danh sách nguyên thuỷ ở §1. Chưa truy xuất được tiêu chí nào được công bố theo nhiệm
vụ 66, nên đây là một cách đọc, không phải một sự khớp đã được chứng minh.

---

## 8. Nguồn và mức xác minh

Truy xuất ngày 2026-08-23:

| Nguồn | Dùng cho | Trạng thái |
|---|---|---|
| [EU AI Act Điều 12](https://artificialintelligenceact.eu/article/12/), [Điều 19](https://artificialintelligenceact.eu/article/19/), [Điều 26](https://artificialintelligenceact.eu/article/26/), [Phụ lục III](https://artificialintelligenceact.eu/annex/3/) | nguyên văn điều khoản | đã truy xuất; **bản tái bản không chính thức** của Reg. (EU) 2024/1689 - cần đối chiếu EUR-Lex trước khi dùng chính thức |
| [NIST AI RMF Playbook - Govern](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Govern), [Measure](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Measure), [Manage](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Manage) | mã và nội dung subcategory | đã truy xuất từ NIST |
| [Commission Delegated Reg. (EU) 2024/1774](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774) | RTS Điều 12 (Logging) | đã truy xuất từ EUR-Lex (chính thức) |
| [DORA Điều 10](https://www.digital-operational-resilience-act.com/Article_10.html) | các quy định về phát hiện | bản tái bản không chính thức |
| [Danh mục SR letter 2026 của Fed](https://www.federalreserve.gov/supervisionreg/srletters/2026.htm) | sự tồn tại và tiêu đề SR 26-2 | đã xác nhận danh mục; **chưa truy xuất được nội dung** |
| [Toàn văn Nghị quyết 05/2025/NQ-CP](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-quyet-so-5-2025-nq-cp-ve-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-119250909184045221.htm) và [luatvietnam](https://luatvietnam.vn/tai-chinh/nghi-quyet-05-2025-nq-cp-cua-chinh-phu-ve-viec-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-410830-d1.html) | Điều 15(2)(l) | hai nguồn thứ cấp đồng thuận; không phải công báo |
| [Quyết định 96/QĐ-BTC](https://luatvietnam.vn/hanh-chinh/quyet-dinh-96-qd-btc-2026-cong-bo-thu-tuc-hanh-chinh-moi-ve-thi-truong-tai-san-ma-hoa-424349-d1.html) | phạm vi (chỉ thủ tục hành chính) | nguồn thứ cấp |
| ISO/IEC 42001 | - | **chưa truy xuất** - tiêu chuẩn không được công bố mở. Tài liệu này cố ý **không** trích mã điều khoản nào của nó |
| AICPA Trust Services Criteria | mã CC | **chưa truy xuất** - chỉ dùng ở mức mô tả |

Truy xuất ngày 2026-09-07 - cụm văn bản pháp luật AI của Việt Nam (§7b):

| Nguồn | Dùng cho | Trạng thái |
|---|---|---|
| Luật Trí tuệ nhân tạo số 134/2025/QH15 - bản Công báo, **Công báo số 40, ngày 22-01-2026**, từ trang của số Công báo đó trên `congbao.chinhphu.vn` | nguyên văn Điều 3(4)(5), 7(4)(5), 8, 9, 10(1)(3)(5), 11, 12(2)(4), 13, 14(1)(c)(d)(e), 14(2)(b), 26, 27(2)(3), 28(3), 34, 35(1) | **bản Công báo chính thức.** Số Công báo và ngày chạy ở đầu mọi trang của PDF đã tải, và tệp có lớp text - nên phần tiếng Việt trích ở §7b là *copy*, không phải gõ lại từ ảnh. Hãy dẫn số Công báo và trang của số đó, đừng dẫn URL tệp: bản PDF được phục vụ từ một endpoint CDN sau một query string đã ký, sẽ không mở được với người đọc về sau |
| Nghị định 142/2026/NĐ-CP - [PDF ký số](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/4/142-2026-ndcp.signed.pdf) | Điều 3(6), 4(1), 6, 11(5), 12(6)(7), 13(4), 14(3), 15(2)(c), 16(2)(c), 16(5), 17, 18, 19(2)(3)(4), 20, 45, 46, và Phụ lục biểu mẫu | **chính thức**, ký số bởi Văn phòng Chính phủ. **Bản scan, không có lớp text** - số điều khoản và lời văn được đọc từ ảnh trang, nên ở đây vẫn có khả năng sai sót khi ghi lại theo cách mà bản Luật không có. Hãy kiểm tra lại từng điều khoản trước khi trích chính thức |
| Quyết định 1671/QĐ-TTg - [PDF ký số](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/9/1671_qd-ttg_28082026-signed.signed.pdf) | Quan điểm 4, Trụ cột 9(đ), IV.4.c, Phụ lục II nhiệm vụ 64, 66, 81, 89 | **chính thức**, ký số (thời gian ký 03/09/2026), 64 trang, **bản scan** |
| Thông tư 05/2026/TT-BKHCN; Quyết định 33/2026/QĐ-TTg | được nêu tên ở §7b; **không trích điều khoản nào của cả hai** | **chưa truy xuất** - chỉ thấy qua bản tóm tắt từ nguồn thứ cấp. Mọi phát biểu về chúng ở §7b đều mang nhãn `[Unverified]`, và số hiệu, ngày ban hành cũng như phạm vi của chúng đều chưa được đối chiếu với nguồn sơ cấp |

---

## 9. Phân tích khoảng trống trung thực - waxseal **không** làm gì

Nói thẳng, vì tài liệu ánh xạ đúng là nơi việc thổi phồng hay xảy ra nhất.

| Không cung cấp | Vì sao điều đó quan trọng |
|---|---|
| **Quản trị (governance)** | không có phân loại rủi ro, không có luồng phê duyệt, không có vai trò, không có policy engine. Một nhật ký được kiểm chứng hoàn hảo của một hệ thống không được quản trị thì chứng minh rất trung thực rằng các quyết định đó không được quản trị |
| **Kiểm soát truy cập** | thư viện không bao giờ xác thực hay phân quyền. Ai được đọc trail hoàn toàn là vấn đề của phần triển khai |
| **Mã hoá khi lưu / khi truyền** | không cung cấp (`RemoteBackend` dùng TLS theo đúng URL ngụ ý). Toàn vẹn ≠ bảo mật |
| **Cưỡng chế thời hạn lưu trữ** | không có gì hết hạn, không có gì bị xoá. Nghĩa vụ lưu trữ tối thiểu được hỗ trợ; nghĩa vụ lưu trữ tối đa và nghĩa vụ xoá thì bị làm *khó hơn* |
| **Nơi lưu trú dữ liệu** | ở đâu backend chạy thì ở đó |
| **Tài liệu mô hình, kiểm định, kiểm thử thiên lệch, khả năng giải thích** | hoàn toàn nằm ngoài. Nhật ký ghi lại mô hình đã quyết định gì, không bao giờ ghi lại nó *nên* quyết định gì |
| **Thời gian đáng tin cậy** | `ts` do bên gọi khẳng định, không được chứng thực. Hãy neo vào TSA theo RFC 3161 nếu cần thời gian được chứng thực |
| **Tính đầy đủ của trail** | toàn vẹn ≠ đầy đủ. Một quyết định chưa từng được ghi thì không để lại khoảng trống nào. `dropped_writes` là cận dưới đã đo, và `None` nghĩa là chưa đo |
| **Chống sửa đổi tuyệt đối** | chỉ **tamper-evident**. Kẻ tấn công có quyền ghi vẫn viết lại được trail; neo và niêm phong forward-secure giới hạn điều đó, và chỉ khi chúng nằm dưới một quyền quản trị khác |
| **Báo cáo sự cố** | không nộp gì và không liên hệ cổng nào. Một bản ghi sự cố đã ghi thì chứng minh được là đã tồn tại ở một vị trí và không bị sửa; còn việc một báo cáo có tới cơ quan quản lý hay không, và có tới đúng hạn hay không, đều nằm ngoài - cửa sổ thời gian đáng kể chạy từ một *thời điểm xác nhận* do người ghi khai |
| **Phân loại rủi ro** | ghi lại một lời khai, không phải một phép phân loại. Mức rủi ro được khai giữ nguyên văn như lời khai của chính người ghi; không có gì trong thư viện quyết định mức đó có đúng hay không, và *chưa khai* không bao giờ được hiển thị thành mức thấp nhất |
| **Một phán quyết tuân thủ** | không đầu ra nào của thư viện này khẳng định rằng một nghĩa vụ đã được đáp ứng, và không đầu ra nào nên được trích dẫn như thể nó khẳng định điều đó |

---

## 10. Nếu chỉ lấy một điều từ tài liệu này

Khẳng định đáng đưa ra trước người review là hẹp và bảo vệ được:

> *Quyết định này đã được ghi tại vị trí này, dưới phiên bản mô hình này và phiên bản policy
> này, với trạng thái giám sát của con người này, và có thể chứng minh là không bị thay đổi
> kể từ đó - một cách độc lập với bên đang giữ nhật ký, và không tiết lộ bất kỳ quyết định
> nào khác.*

Mọi thứ rộng hơn câu đó đều là biện pháp kiểm soát của người khác.
