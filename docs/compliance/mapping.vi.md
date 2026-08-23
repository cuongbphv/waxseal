# Ánh xạ tuân thủ — waxseal chứng minh được gì, và không chứng minh được gì

*[English](mapping.md)*

**Đọc phần này trước.** waxseal là lớp toàn vẹn và bằng chứng. Nó có thể tạo ra bằng chứng
kỹ thuật *hỗ trợ* cho một nghĩa vụ về lưu trữ hồ sơ, truy vết, hoặc toàn vẹn nhật ký. Nó
**không** làm cho bất kỳ tổ chức nào tuân thủ bất kỳ điều gì, và không dòng nào trong các
bảng dưới đây được đọc thành "yêu cầu này đã được đáp ứng". Việc một nghĩa vụ có được thoả
mãn hay không phụ thuộc vào quản trị, phạm vi, chính sách, biện pháp kiểm soát và diễn giải
pháp lý — tất cả đều nằm hoàn toàn ngoài thư viện này, và là việc xác định thuộc về bộ phận
tuân thủ và pháp chế của tổ chức triển khai.

Tài liệu này không phải tư vấn pháp lý, và không nêu tên tổ chức, sản phẩm hay cá nhân nào.

### Cách đọc nhãn trong bảng

| Nhãn | Ý nghĩa |
|---|---|
| **Trực tiếp** | waxseal tạo ra bằng chứng đi thẳng vào nội dung của yêu cầu |
| **Một phần** | waxseal phủ một phần; phần còn lại thuộc về tổ chức hoặc nằm ngoài phạm vi |
| **Ngoài phạm vi** | liệt kê ra để không ai mặc định là đã được phủ — nó không được phủ |

Mọi điều khoản được trích dưới đây đều được truy xuất từ nguồn nêu tại
[§8 Nguồn và mức xác minh](#8-nguồn-và-mức-xác-minh) vào ngày 2026-08-23. Chỗ nào không
xác minh được từ nguồn chính thức hoặc nguồn sơ cấp thì được gắn nhãn `[Chưa xác minh]`
ngay tại chỗ và cần được kiểm tra lại trước khi sử dụng.

---

## 1. waxseal thực sự tạo ra những gì

Trước khi ánh xạ bất cứ điều gì, đây là danh sách đầy đủ các nguyên thuỷ bằng chứng. Mọi
ô "Trực tiếp" bên dưới đều quy về một trong số này.

| Nguyên thuỷ | Bằng chứng nó tạo ra | Ở đâu |
|---|---|---|
| Chuỗi hash trên `EntryHeader` | một bản ghi đã tồn tại ở vị trí *n*, theo thứ tự này, không đổi từ đó | `domain/chain.py` |
| Schema fingerprint | dòng đó được ký dưới bộ trường nào; không nhận ra → *không kiểm chứng được*, không bao giờ là *bị sửa* | `domain/fingerprint.py` |
| `DecisionRecord` | định danh hệ thống AI, tên/phiên bản/digest mô hình, kết quả, căn cứ, phiên bản policy, độ tin cậy, chế độ giám sát của con người | `domain/decision.py` |
| `input_commitment` | input mà mô hình đã thấy, cam kết bằng hash sau khi redact, không lưu bản gốc | `sources/decisions.py` |
| Redact trước khi hash | bí mật không bao giờ chạm đĩa ở dạng cleartext | `adapters/redactors.py` |
| Checkpoint Merkle + neo | một root đã công bố sang miền tin cậy khác trước khi việc sửa có thể xảy ra | `domain/anchoring.py` |
| Niêm phong forward-secure | việc viết lại phần đuôi hoặc cắt đuôi là phát hiện được, với khoá đã ký quỹ | `domain/sealing.py` |
| Proof bundle | một quyết định, kiểm tra được offline, không tiết lộ phần còn lại của nhật ký | `domain/export.py` |
| `dropped_writes` | **cận dưới đã đo** của số write thất bại; `None` = chưa đo | `adapters/drops.py` |
| Báo cáo kiểm toán | tất cả những thứ trên, cộng với chữ *not checked* tường minh cho những gì chưa chạy | `domain/report.py` |

---

## 2. Đạo luật AI của EU — Quy định (EU) 2024/1689

### Trước hết là phạm vi áp dụng

Phụ lục III điểm 5(b) xếp vào nhóm rủi ro cao các "hệ thống AI dùng để đánh giá mức độ tín
nhiệm tín dụng của thể nhân hoặc thiết lập điểm tín dụng của họ, **ngoại trừ các hệ thống
AI dùng cho mục đích phát hiện gian lận tài chính**".

Ngoại lệ đó rất quan trọng và rất dễ bị đọc lệch, theo hướng có lợi hoặc bất lợi cho tổ
chức triển khai. Trường hợp sàng lọc AML/gian lận trong [PoC](../../examples/banking-poc/README.vi.md)
theo cách đọc thông thường nằm trong nhóm được loại trừ, còn chấm điểm tín dụng thì không.
Việc xác định một hệ thống cụ thể rơi vào nhóm nào là câu hỏi pháp lý, không phải kỹ thuật
— các bảng dưới đây áp dụng ở nơi Đạo luật áp dụng.

### Điều 12 — Lưu trữ hồ sơ (Record-keeping)

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
| 12(3) log tối thiểu cho Phụ lục III điểm 1(a) | **Ngoài phạm vi** | — | 12(3) dành riêng cho hệ thống sinh trắc học (thời gian sử dụng, cơ sở dữ liệu tham chiếu, dữ liệu đầu vào khớp, người xác minh); bộ trường của `DecisionRecord` không được thiết kế cho việc đó |

### Điều 19 — Log tự động sinh (nhà cung cấp)

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

### Điều 26(6) — Thời hạn lưu log của bên triển khai

> "Bên triển khai hệ thống AI rủi ro cao phải giữ các log do hệ thống AI rủi ro cao đó tự
> động sinh ra, trong phạm vi các log đó nằm dưới quyền kiểm soát của họ, trong khoảng thời
> gian phù hợp với mục đích sử dụng dự kiến của hệ thống, **ít nhất là sáu tháng**, trừ khi
> pháp luật Liên minh hoặc quốc gia áp dụng quy định khác."

Mức phủ giống Điều 19. Điểm hữu ích về mặt vận hành là cụm "**trong phạm vi các log đó nằm
dưới quyền kiểm soát của họ**": bên triển khai vận hành tầng agent thì kiểm soát nhật ký
quyết định ngay cả khi mô hình là của bên thứ ba — nên đây đúng là lớp mà bên triển khai có
thể tự sở hữu. [Kiến trúc tham chiếu](../architecture/banking-deployment.vi.md#6-lưu-trữ-dr-và-dung-lượng)
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

**NIST AI 600-1 (Generative AI Profile).** `[Chưa xác minh]` — các mã định danh hành động
cụ thể của GenAI Profile không được truy xuất cho tài liệu này. Các hành động về truy vết
và nguồn gốc (provenance) trong đó là phần liên quan; hãy kiểm tra trực tiếp trước khi
trích dẫn.

---

## 4. DORA — Quy định (EU) 2022/2554 và RTS kèm theo

Chỗ khớp nhất trong họ DORA không phải bản thân Quy định mà là **Quy định uỷ quyền của Uỷ
ban (EU) 2024/1774, Điều 12 (Logging)** — RTS về công cụ, phương pháp, quy trình và chính
sách quản trị rủi ro ICT.

| Yêu cầu (RTS Điều 12) | Mức phủ | waxseal cung cấp gì |
|---|---|---|
| "các biện pháp bảo vệ hệ thống ghi log và thông tin log khỏi **bị can thiệp, bị xoá và truy cập trái phép** ở trạng thái lưu trữ, trên đường truyền, và khi đang được sử dụng nếu liên quan" | **Trực tiếp** với can thiệp và xoá | chuỗi phát hiện việc sửa; neo phát hiện việc viết lại toàn bộ nhật ký một cách nhất quán; niêm phong forward-secure phát hiện việc cắt đuôi. **Không** phải kiểm soát truy cập hay mã hoá — đó là việc của phần triển khai, không phải của thư viện |
| "các biện pháp **phát hiện lỗi của hệ thống ghi log**" | **Một phần** | `dropped_writes` đo đúng chế độ hỏng này, và báo `None` khi chưa đo thay vì ngầm hiểu là 0. Đây là cận dưới đã đo: bản thân sidecar cũng có thể bị mất |
| thời hạn lưu trữ đặt theo mục tiêu kinh doanh, an toàn thông tin và kết quả đánh giá rủi ro | **Ngoài phạm vi** | waxseal không cho gì hết hạn |
| "đồng bộ đồng hồ … theo một nguồn thời gian tham chiếu đáng tin cậy được lập tài liệu" | **Ngoài phạm vi** | **`ts` của waxseal do bên gọi cung cấp** (`now_fn` có thể tiêm vào, một cách có chủ ý, để test không bao giờ phải sleep). Đó là một khẳng định về thời gian được ghi lại, không phải thời gian được chứng thực. Nếu cần thời gian được chứng thực, hãy neo vào một TSA theo RFC 3161 — khi đó dấu thời gian đến từ TSA, không phải từ máy ghi |

DORA Điều 10(1)/(3) (phát hiện hoạt động bất thường, giám sát hoạt động người dùng) ở mức
**Một phần**: một nhật ký quyết định đã kiểm toàn vẹn là đầu vào cho việc phát hiện, nhưng
waxseal tự nó không phát ra cảnh báo nào ngoài các exit code của verifier.

---

## 5. Quản trị rủi ro mô hình — SR 11-7 và các văn bản kế thừa

SR 11-7 / OCC Bulletin 2011-12, *Supervisory Guidance on Model Risk Management* (2011), là
văn bản tham chiếu lâu năm. **`[Chưa xác minh]`** Cục Dự trữ Liên bang đã ban hành **SR
26-2, "Revised Guidance on Model Risk Management"**, và OCC ban hành một bulletin tương ứng
năm 2026; danh mục văn bản đã được xác nhận nhưng **nội dung bản sửa đổi chưa truy xuất
được**, và việc nó thay thế SR 11-7 toàn bộ hay một phần thì chưa xác minh. Hãy kiểm tra
văn bản nào đang áp dụng trước khi dựa vào phần này.

Đối chiếu với các chủ đề của SR 11-7:

| Chủ đề | Mức phủ | waxseal cung cấp gì |
|---|---|---|
| Kiểm kê mô hình (model inventory) | **Một phần** | `system_id` + tên/phiên bản/digest mô hình trên từng quyết định cho ra một bản kiểm kê *suy từ thực tế sử dụng* — cái gì thực sự đã chạy, đối lập với cái mà sổ đăng ký nói đáng lẽ phải chạy. Đối chiếu hai bản này là một biện pháp kiểm soát thực sự hữu ích |
| Tài liệu đủ để một bên độc lập hiểu được việc đã làm | **Một phần** | nguồn gốc từng quyết định, không phải tài liệu phát triển mô hình |
| Effective challenge / kiểm định độc lập | **Một phần** | kiểm định cần một bản ghi không thể chối cãi về việc môi trường sản xuất thực sự đã quyết định gì; một nhật ký mà chủ sở hữu mô hình sửa được thì không đỡ nổi việc phản biện. Phần phân tách nhiệm vụ trong [kiến trúc](../architecture/banking-deployment.vi.md#3-phân-tách-nhiệm-vụ) mới là thứ làm điều này thành thật |
| Giám sát liên tục và phân tích kết quả | **Một phần** | cung cấp bản ghi kết quả; phần phân tích thuộc về tổ chức |
| Kiểm soát thay đổi theo phiên bản mô hình | **Một phần** | một thay đổi phiên bản hiện ra trong nhật ký ngay khi quyết định đầu tiên dưới phiên bản đó được ghi |

---

## 6. SOC 2 (AICPA Trust Services Criteria)

Bộ tiêu chí của AICPA không được trích nguyên văn ở đây (chúng không được công bố mở). Các
mã định danh dưới đây dùng ở mức mô tả; **`[Chưa xác minh]`** so với văn bản TSC chính thức.

| Tiêu chí | Lĩnh vực | Mức phủ |
|---|---|---|
| CC4.1–CC4.2 | hoạt động giám sát | **Một phần** — kiểm chứng theo lịch tạo ra bằng chứng rằng một biện pháp kiểm soát đã vận hành, kèm exit code cho mỗi lần chạy |
| CC7.2 | phát hiện và giám sát sự kiện hệ thống | **Một phần** — trail là bằng chứng được giám sát; việc cảnh báo thuộc về phần triển khai |
| CC7.3–CC7.4 | đánh giá và ứng phó sự kiện an ninh | **Một phần** — exit 1 là tín hiệu sự cố kèm số thứ tự và lý do cụ thể; exit 2 tường minh **không** phải sự cố |

Lập luận SOC 2 mạnh nhất cho lớp này không nằm ở một tiêu chí đơn lẻ nào — nó nằm ở chỗ
bằng chứng mà service auditor lấy mẫu có thể chứng minh được đúng là bằng chứng đã được
tạo ra tại thời điểm đó, chứ không phải một bản export do chính bên bị kiểm toán sinh ra
sau này.

---

## 7. Việt Nam — thí điểm thị trường tài sản mã hoá

**Nghị quyết 05/2025/NQ-CP** (ngày 09/09/2025), thí điểm thị trường tài sản mã hoá trong 5
năm, tại **Điều 15(2)(l)** yêu cầu tổ chức cung cấp dịch vụ:

> "Lưu trữ trên hệ thống máy chủ tại Việt Nam tối thiểu 10 năm về lịch sử giao dịch, thông
> tin về người khởi tạo, người thụ hưởng (tối thiểu tên, địa chỉ, địa chỉ ví), lịch sử địa
> chỉ thiết bị đăng nhập hoặc địa chỉ giao thức Internet…"

Nội dung này khớp giống hệt nhau trên một cổng thông tin của Chính phủ và một cơ sở dữ liệu
pháp luật thương mại, nhưng **chưa** đối chiếu với bản công báo chính thức — hãy coi việc
đánh số điều khoản là *đã xác minh bởi hai nguồn thứ cấp đồng thuận*, không phải nguồn sơ cấp.

| Khía cạnh | Mức phủ | Ghi chú |
|---|---|---|
| Lưu trữ 10 năm trên máy chủ tại Việt Nam | **Ngoài phạm vi** | đây là quyết định về triển khai và nơi lưu trú dữ liệu. Backend của waxseal chạy ở đâu là do triển khai, và nó không cho gì hết hạn |
| Tính toàn vẹn của thứ được lưu | **Trực tiếp** | Nghị quyết yêu cầu *lưu trữ*, không yêu cầu tamper-evidence. Lưu trữ chống sửa đổi là tư thế **mạnh hơn** mức văn bản đòi hỏi — hãy trình bày đúng như vậy, đừng trình bày như một yêu cầu mà văn bản áp đặt |
| Tên và địa chỉ người khởi tạo/thụ hưởng | **Xung đột** | Nghị quyết yêu cầu dữ liệu *định danh*; waxseal yêu cầu payload phải là *bút danh* vì chuỗi không xoá được. Cách hoá giải: giữ kho định danh tách riêng và tham chiếu qua `subject_ref` — chuỗi khi đó chứng minh quyết định, còn kho định danh đáp ứng nghĩa vụ lưu trữ |

**Quyết định 96/QĐ-BTC** (ngày 20/01/2026) công bố các thủ tục hành chính mới (cấp phép,
điều chỉnh, thu hồi giấy phép) triển khai Nghị quyết 05/2025/NQ-CP. Văn bản này liên quan
tới **thủ tục cấp phép**, không phải yêu cầu về audit trail hay ghi log, và được liệt kê ở
đây chỉ để không ai mặc định rằng nó áp đặt một yêu cầu như vậy.

`[Chưa xác minh]` Yêu cầu chứng nhận an toàn hệ thống thông tin cấp độ 4 được ghi nhận là
nằm ở Điều 8(7) của Nghị quyết; số điều khoản chưa được xác nhận từ nguồn sơ cấp.

---

## 8. Nguồn và mức xác minh

Truy xuất ngày 2026-08-23:

| Nguồn | Dùng cho | Trạng thái |
|---|---|---|
| [EU AI Act Điều 12](https://artificialintelligenceact.eu/article/12/), [Điều 19](https://artificialintelligenceact.eu/article/19/), [Điều 26](https://artificialintelligenceact.eu/article/26/), [Phụ lục III](https://artificialintelligenceact.eu/annex/3/) | nguyên văn điều khoản | đã truy xuất; **bản tái bản không chính thức** của Reg. (EU) 2024/1689 — cần đối chiếu EUR-Lex trước khi dùng chính thức |
| [NIST AI RMF Playbook — Govern](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Govern), [Measure](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Measure), [Manage](https://airc.nist.gov/AI_RMF_Knowledge_Base/Playbook/Manage) | mã và nội dung subcategory | đã truy xuất từ NIST |
| [Commission Delegated Reg. (EU) 2024/1774](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401774) | RTS Điều 12 (Logging) | đã truy xuất từ EUR-Lex (chính thức) |
| [DORA Điều 10](https://www.digital-operational-resilience-act.com/Article_10.html) | các quy định về phát hiện | bản tái bản không chính thức |
| [Danh mục SR letter 2026 của Fed](https://www.federalreserve.gov/supervisionreg/srletters/2026.htm) | sự tồn tại và tiêu đề SR 26-2 | đã xác nhận danh mục; **chưa truy xuất được nội dung** |
| [Toàn văn Nghị quyết 05/2025/NQ-CP](https://xaydungchinhsach.chinhphu.vn/toan-van-nghi-quyet-so-5-2025-nq-cp-ve-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-119250909184045221.htm) và [luatvietnam](https://luatvietnam.vn/tai-chinh/nghi-quyet-05-2025-nq-cp-cua-chinh-phu-ve-viec-trien-khai-thi-diem-thi-truong-tai-san-ma-hoa-tai-viet-nam-410830-d1.html) | Điều 15(2)(l) | hai nguồn thứ cấp đồng thuận; không phải công báo |
| [Quyết định 96/QĐ-BTC](https://luatvietnam.vn/hanh-chinh/quyet-dinh-96-qd-btc-2026-cong-bo-thu-tuc-hanh-chinh-moi-ve-thi-truong-tai-san-ma-hoa-424349-d1.html) | phạm vi (chỉ thủ tục hành chính) | nguồn thứ cấp |
| ISO/IEC 42001 | — | **chưa truy xuất** — tiêu chuẩn không được công bố mở. Tài liệu này cố ý **không** trích mã điều khoản nào của nó |
| AICPA Trust Services Criteria | mã CC | **chưa truy xuất** — chỉ dùng ở mức mô tả |

---

## 9. Phân tích khoảng trống trung thực — waxseal **không** làm gì

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
| **Một phán quyết tuân thủ** | không đầu ra nào của thư viện này khẳng định rằng một nghĩa vụ đã được đáp ứng, và không đầu ra nào nên được trích dẫn như thể nó khẳng định điều đó |

---

## 10. Nếu chỉ lấy một điều từ tài liệu này

Khẳng định đáng đưa ra trước người review là hẹp và bảo vệ được:

> *Quyết định này đã được ghi tại vị trí này, dưới phiên bản mô hình này và phiên bản policy
> này, với trạng thái giám sát của con người này, và có thể chứng minh là không bị thay đổi
> kể từ đó — một cách độc lập với bên đang giữ nhật ký, và không tiết lộ bất kỳ quyết định
> nào khác.*

Mọi thứ rộng hơn câu đó đều là biện pháp kiểm soát của người khác.
