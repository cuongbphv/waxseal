# Quyết định 1671/QĐ-TTg (28/08/2026) - Chiến lược quốc gia về AI, và chỗ waxseal thực sự chạm vào

*[English](qd-1671-2026-ai-strategy.md)*

**Đây là một báo cáo nghiên cứu, không phải một tài liệu ánh xạ tuân thủ.** Bảng ánh xạ có
nhãn nằm ở [docs/compliance/mapping.md](../compliance/mapping.md); tài liệu này giải thích
*vì sao* các hàng trong bảng đó được đặt như vậy đối với cụm văn bản pháp luật AI của Việt
Nam, và ghi lại mức xác minh của từng nguồn.

waxseal là một lớp toàn vẹn và bằng chứng. Nó có thể tạo ra bằng chứng kỹ thuật *hỗ trợ*
cho một nghĩa vụ về lưu giữ nhật ký, truy vết hay hậu kiểm. Nó **không** làm cho bất kỳ tổ
chức nào tuân thủ bất kỳ điều gì, và không dòng nào dưới đây được đọc thành "nghĩa vụ này
đã được đáp ứng". Tài liệu này không phải tư vấn pháp lý, và không nêu tên tổ chức, sản
phẩm hay cá nhân nào.

Ngày truy xuất mọi nguồn: **2026-09-07**. Mức xác minh từng nguồn ở
[§7](#7-nguồn-và-mức-xác-minh).

---

## 1. Tóm tắt điều hành

**Quyết định 1671/QĐ-TTg ngày 28/08/2026** của Thủ tướng Chính phủ phê duyệt *Chiến lược
quốc gia về trí tuệ nhân tạo đến năm 2030, tầm nhìn đến năm 2045*. Văn bản gồm 28 trang
thân, Phụ lục I (32 chỉ tiêu) và Phụ lục II (97 nhiệm vụ, giải pháp). Theo Điều 3, Quyết
định có hiệu lực từ ngày ký và thay thế Quyết định 127/QĐ-TTg ngày 26/01/2021.

**Một chiến lược không đặt nghĩa vụ kỹ thuật lên một thư viện.** QĐ 1671 nói bằng ngôn ngữ
quan điểm, mục tiêu, trụ cột, giải pháp và phân công cho các cơ quan nhà nước - nó không
quy định định dạng nhật ký, cơ chế toàn vẹn hay nghĩa vụ nào áp lên một phần mềm cụ thể.
Cấu trúc nhiệm vụ trong Phụ lục II là "cơ quan chủ trì / cơ quan phối hợp / sản phẩm / thời
gian", tức là công việc của bộ máy hành chính, không phải yêu cầu kỹ thuật cho nhà cung
cấp. Đọc QĐ 1671 như một danh sách yêu cầu cần "đáp ứng" là đọc sai loại văn bản.

**Nghĩa vụ ràng buộc nằm ở chỗ khác.** Yêu cầu về *nhật ký hoạt động*, *nhật ký lưu vết*,
*ghi nhận sự cố*, *quyết định can thiệp của con người* và *tự phân loại rủi ro* nằm ở
**Luật Trí tuệ nhân tạo số 134/2025/QH15** và **Nghị định 142/2026/NĐ-CP**. Đó là hai văn
bản mà một lớp bằng chứng toàn vẹn có thể nói gì đó thật; QĐ 1671 chỉ là bối cảnh chính
sách bao quanh chúng, cộng thêm hai điểm chạm gián tiếp đáng chú ý:

- **Quan điểm 4** ưu tiên "công nghệ nguồn mở… các giải pháp cho phép kiểm tra, tùy chỉnh,
  triển khai độc lập" - mô tả đúng hình dạng của một thư viện MIT, chỉ dùng thư viện chuẩn,
  kiểm chứng được offline.
- **Trụ cột 9.đ và Phụ lục II nhiệm vụ 66** đặt việc xây dựng "nền tảng, công cụ phục vụ
  việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI" vào chương trình quốc gia
  2026-2030. waxseal là *một* công cụ theo nghĩa rất hẹp của câu đó: nó chứng minh một bản
  ghi không bị sửa, chứ không đánh giá sản phẩm AI.

**Kết luận thực dụng.** Với waxseal 0.1.5, cơ chế toàn vẹn đã đủ để nói một câu hẹp và bảo
vệ được về *nhật ký* (xem [§4](#4-ma-trận-đáp-ứng)); ba khoảng trống thực sự là (i) không có
trường ghi *mức rủi ro do nhà cung cấp tự khai*, (ii) không có bản ghi *sự cố* và bản ghi
*can thiệp của con người* độc lập với một quyết định AI cụ thể, (iii) không có khối báo cáo
tương ứng. Cả ba đều là *bằng chứng phải ghi thêm*, không phải cơ chế phải sửa
([§5](#5-gap-và-đề-xuất-nâng-cấp)).

Một điều tài liệu này không làm: nó không nói waxseal là tamper-proof. waxseal là
tamper-evident; ranh giới của claim mạnh hơn được nêu trong
[threat model §1](../security/threat-model.md#1-tamper-evident-is-not-tamper-proof).

---

## 2. Cấu trúc QĐ 1671

### 2.1 Sáu quan điểm (Mục I)

| # | Nội dung cốt lõi | Liên quan tới waxseal |
|---|---|---|
| 1 | Chuyển từ "đưa AI vào sản phẩm" sang "lấy AI làm năng lực cốt lõi"; "lấy thể chế và quản trị AI làm đột phá" | bối cảnh |
| 2 | Lãnh đạo, quản lý thống nhất; "hoàn thiện thể chế và quản trị AI an toàn, tin cậy, lấy con người làm trung tâm"; cân bằng đổi mới với "an toàn, an ninh, đạo đức, trách nhiệm giải trình" | đúng bài toán của một lớp bằng chứng: trách nhiệm giải trình cần một bản ghi không thể lặng lẽ sửa |
| 3 | Nhân lực AI là nền tảng quyết định | không |
| 4 | Hạ tầng, dữ liệu, mô hình, nền tảng dùng chung; **"ưu tiên công nghệ nguồn mở, mô hình có trọng số mở và các giải pháp cho phép kiểm tra, tùy chỉnh, triển khai độc lập, từng bước giảm phụ thuộc vào bên ngoài"** | khớp trực tiếp về định vị: MIT, không phụ thuộc runtime, `verify` chạy offline, không gọi dịch vụ ngoài trừ khi operator bật anchor |
| 5 | Doanh nghiệp AI Việt Nam là lực lượng chủ lực; sản phẩm "Make in Viet Nam" | xem chú thích về "Make in Viet Nam" ở [§5.4](#54-xa-hơn-và-cố-ý-không-làm) |
| 6 | Hợp tác quốc tế gắn với tự chủ chiến lược; "không phụ thuộc vào một thị trường, một nền tảng, một mô hình, một nguồn công nghệ hoặc một chuỗi cung ứng duy nhất" | trùng với lý do waxseal không đặt anchor mặc định nào |

Nguyên văn Quan điểm 4, phần liên quan:

> "…ưu tiên công nghệ nguồn mở, mô hình có trọng số mở và các giải pháp cho phép kiểm tra,
> tùy chỉnh, triển khai độc lập, từng bước giảm phụ thuộc vào bên ngoài."

### 2.2 Mục tiêu (Mục II)

**Mục tiêu tổng quát đến 2030**: đưa Việt Nam thành "một trong những trung tâm có năng lực
nghiên cứu, phát triển, ứng dụng và đồng kiến tạo giá trị về AI trong khu vực ASEAN và châu
Á"; AI "trở thành năng lực cốt lõi, được tích hợp sâu, toàn diện vào hoạt động quản trị
quốc gia, cung cấp dịch vụ công…".

**Tầm nhìn 2045**: Việt Nam "thuộc nhóm 10 quốc gia dẫn đầu châu Á về năng lực nghiên cứu,
phát triển, làm chủ AI và chuyển đổi AI quốc gia"; AI "trở thành nền tảng vận hành chủ đạo
của Nhà nước, nền kinh tế và xã hội" (Phụ lục I, chỉ tiêu 32).

Ba chỉ tiêu 2030 tạo ra khối lượng *quyết định hành chính có AI hỗ trợ* mà một lớp bằng
chứng nói được điều gì đó về nó:

| Chỉ tiêu (Phụ lục I) | Nội dung | Cơ quan chủ trì theo dõi |
|---|---|---|
| 7 | "60% quyết định chỉ đạo, điều hành của cơ quan nhà nước được hỗ trợ bởi dữ liệu và AI" | Bộ Khoa học và Công nghệ |
| 14 | "100% dịch vụ công trực tuyến được tích hợp, hỗ trợ bởi AI" | Bộ Khoa học và Công nghệ |
| 15 | "100% hồ sơ TTHC được hỗ trợ xử lý bằng AI" | Bộ Tư pháp |

Mỗi quyết định như vậy đặt ra chính câu hỏi mà một bản ghi quyết định được thiết kế để trả
lời: ai quyết, dựa trên mô hình phiên bản nào, ai rà soát, dưới policy nào.

### 2.3 Chín trụ cột (Mục III)

1. Nhân lực AI và kỹ năng AI toàn dân · 2. Dữ liệu, mô hình AI · 3. Hạ tầng AI ·
4. Nghiên cứu, phát triển AI và làm chủ công nghệ AI · 5. AI trong quản trị quốc gia ·
6. AI cho các ngành, lĩnh vực · 7. AI cho doanh nghiệp nhỏ và vừa, hộ kinh doanh, hợp tác
xã · 8. Hệ sinh thái AI · **9. Quản trị AI an toàn, đáng tin cậy**.

Trụ cột 9 là trụ cột duy nhất mà một lớp toàn vẹn nằm trong phạm vi, và chỉ ở điểm đ:

> "đ) Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm,
> dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm,
> dịch vụ AI."

### 2.4 Sáu nhóm giải pháp đột phá (Mục IV)

1. Hoàn thiện thể chế, chính sách, pháp luật · 2. Điều phối quốc gia và trách nhiệm thực
thi · 3. Huy động nguồn lực, bảo đảm kinh phí · 4. Hợp tác quốc tế và xây dựng tiêu chuẩn,
quy chuẩn · 5. Tuyên truyền, nâng cao nhận thức và văn hóa sử dụng AI có trách nhiệm ·
6. Đo lường, giám sát, đánh giá.

Bốn điểm trong đó là điểm chạm:

- **IV.1.g** - "Xây dựng cơ chế, chính sách kiểm soát luồng dữ liệu trong hoạt động AI
  xuyên biên giới, kiểm soát xuất khẩu công nghệ AI nhạy cảm…". Xem
  [§6](#6-triển-khai-on-shore): anchor/witness ngoài lãnh thổ là *một luồng dữ liệu ra
  ngoài*, dù chỉ là hash.
- **IV.2.d** - nguyên tắc **6 rõ**: "rõ người, rõ việc, rõ thời gian, rõ trách nhiệm, rõ sản
  phẩm, rõ thẩm quyền". Đây là nguyên tắc phân công hành chính, không phải một schema dữ
  liệu; nhưng nó là khung đối chiếu tốt cho từng trường của bản ghi quyết định
  ([§4.2](#42-khung-6-rõ-đối-chiếu-với-bản-ghi-quyết-định)).
- **IV.4.c** - cuối điểm này: "…bảo đảm an toàn dữ liệu, an ninh mạng và lưu trữ dữ liệu tại
  Việt Nam trong các trường hợp pháp luật quy định." **Đọc đúng chỗ nó nằm** (trang 21-22):
  đây là phần đuôi của điểm về *thu hút đầu tư trực tiếp nước ngoài chất lượng cao và các tập
  đoàn công nghệ lớn xây dựng trung tâm nghiên cứu, phát triển AI tại Việt Nam*, và cụm từ về
  lưu trữ dữ liệu là **một điều kiện gắn với những thỏa thuận đó**, không phải một quy tắc
  lưu trú dữ liệu độc lập. Phụ lục II nhiệm vụ 81 mang đúng cụm từ này trong cột nhiệm vụ, ở
  cùng ngữ cảnh FDI. Tài liệu này viết đối chiếu với *cụm từ đó*, không phải với một mệnh lệnh
  mà Quyết định không chứa.
- **IV.4.h, i, l** - hài hòa TCVN/QCVN với tiêu chuẩn quốc tế về AI, và "Hình thành các tổ
  chức đánh giá sự phù hợp hệ thống AI".

### 2.5 Các nhiệm vụ Phụ lục II có chạm tới thư viện này

Trích nguyên văn cột "Nhiệm vụ, giải pháp", "Cơ quan chủ trì", "Sản phẩm/Kết quả" và "Thời
gian thực hiện". Mười ba nhiệm vụ dưới đây là toàn bộ những nhiệm vụ mà một lớp bằng chứng
toàn vẹn có liên quan; 84 nhiệm vụ còn lại không.

| STT | Nhiệm vụ (nguyên văn, rút gọn nơi có "…") | Chủ trì | Sản phẩm/Kết quả | Thời gian |
|---|---|---|---|---|
| **34** | "Xây dựng, triển khai Nền tảng AI hỗ trợ công vụ quốc gia theo hướng AI-First, AI-Native, ưu tiên các nhóm bài toán: trợ lý AI công vụ; AI hỗ trợ cung cấp dịch vụ công; AI hỗ trợ xây dựng, rà soát, hoàn thiện thể chế; AI phục vụ lãnh đạo, chỉ đạo, điều hành." | Bộ Khoa học và Công nghệ | "Cuối năm 2026 có phiên bản đầu tiên của nền tảng AI hỗ trợ công vụ quốc gia. Hoàn thiện mở rộng, tích hợp và vận hành trong các năm tiếp theo." | 2026 - 2030 |
| **63** | "Hỗ trợ cộng đồng AI mở, mã nguồn mở, mô hình mở, công cụ và bộ dữ liệu mở có kiểm soát." | Bộ Khoa học và Công nghệ, Bộ Công an | "Cộng đồng AI mở, mã nguồn mở, mô hình mở và bộ dữ liệu mở có kiểm soát được hỗ trợ và phát triển." | 2026 - 2030 |
| **64** | "Triển khai, theo dõi, đánh giá và cập nhật Khung đạo đức AI quốc gia; hướng dẫn quản trị và đánh giá tuân thủ." | Bộ Khoa học và Công nghệ | "2026: Khung đạo đức AI quốc gia và cơ chế giám sát đạo đức AI được ban hành; triển khai, theo dõi, đánh giá và cập nhật Khung đạo đức AI quốc gia; hướng dẫn quản trị và đánh giá tuân thủ trong các năm tiếp theo." | 2026 - 2030 |
| **65** | "Nghiên cứu, phát triển công nghệ bảo mật cho hệ thống AI; phát hiện, ngăn chặn, giám sát và ứng phó với các mối đe dọa." | Bộ Công an | "Công nghệ bảo mật cho hệ thống AI; phát hiện, ngăn chặn, giám sát và ứng phó với các mối đe dọa được nghiên cứu, phát triển." | 2026 - 2030 |
| **66** | "Xây dựng nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI. Ưu tiên sử dụng công nghệ AI để giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI." | Bộ Khoa học và Công nghệ | "Nền tảng, công cụ phục vụ việc giám sát, kiểm tra, đánh giá các sản phẩm, dịch vụ AI" | 2026 - 2030 |
| **73** | "Xây dựng cơ chế, chính sách kiểm soát luồng dữ liệu trong hoạt động AI xuyên biên giới, kiểm soát xuất khẩu công nghệ AI nhạy cảm, triển khai các biện pháp pháp lý, kỹ thuật phù hợp và hợp tác quốc tế để bảo đảm an toàn thông tin, an ninh không gian mạng, dữ liệu cá nhân và thông tin chiến lược của quốc gia." | Bộ Công an | "Văn bản quy định hoặc hướng dẫn." | 2026 |
| **86** | "Rà soát, cập nhật bảo đảm các tiêu chuẩn quốc gia, quy chuẩn kỹ thuật quốc gia theo hướng hài hòa, phù hợp với tiêu chuẩn quốc tế về AI." | Bộ Khoa học và Công nghệ | "Tiêu chuẩn quốc gia, quy chuẩn kỹ thuật về AI được rà soát và cập nhật." | 2026 - 2030 |
| **87** | "Xây dựng tiêu chuẩn, quy chuẩn kỹ thuật ngành, tiêu chí kỹ thuật áp dụng cho sản phẩm, dịch vụ ứng dụng AI trong các ngành, lĩnh vực." | Các bộ, ngành | "Các tiêu chuẩn, quy chuẩn, tiêu chí kỹ thuật." | 2026 - 2030 |
| **88** | "Tham gia hoạt động tiêu chuẩn hóa AI khu vực và toàn cầu." | Bộ Khoa học và Công nghệ | "Tiêu chuẩn, quy chuẩn kỹ thuật AI được xây dựng, hài hòa và áp dụng phù hợp với tiêu chuẩn khu vực và quốc tế." | 2026 - 2030 |
| **89** | "Hình thành các tổ chức đánh giá sự phù hợp hệ thống AI." | Bộ Khoa học và Công nghệ | "Số lượng tổ chức đánh giá sự phù hợp hệ thống AI." | 2026 - 2030 |
| **94** | "Xây dựng, ban hành và định kỳ rà soát, cập nhật các chỉ tiêu đánh giá mức độ chuyển đổi AI của bộ, ngành, địa phương và quốc gia phù hợp với Chiến lược, điều kiện thực tiễn và thông lệ quốc tế" | Bộ Khoa học và Công nghệ | "Nghiên cứu, xây dựng chỉ tiêu đánh giá mức độ chuyển đổi AI của bộ, ngành, địa phương và quốc gia." | 2026 |
| **95** | "Đánh giá chuyển đổi AI quốc gia và công bố công khai kết quả đánh giá định kỳ hằng năm, làm căn cứ theo dõi, đôn đốc, điều chỉnh Chiến lược…" | Bộ Khoa học và Công nghệ | "Kết quả đánh giá định kỳ hằng năm." | 2026 - 2030 |
| **96** | "Xây dựng, triển khai các giải pháp công nghệ để theo dõi, thống kê, đo lường, giám sát, đánh giá được các mục tiêu, kết quả thực hiện nhiệm vụ của Chiến lược trên môi trường số, bảo đảm tự động tối đa, kịp thời, công khai, minh bạch." | Bộ Khoa học và Công nghệ | "Các giải pháp công nghệ để theo dõi, thống kê, đo lường, giám sát, đánh giá." | 2027 - 2028 |

Đọc theo cụm: 64-66 là cụm quản trị AI an toàn (Trụ cột 9), 86-89 là cụm tiêu chuẩn và tổ
chức đánh giá sự phù hợp, 94-96 là cụm đo lường tự động. Ba cụm này lần lượt là ba lý do
`SPEC.md` + golden vectors, `export-proof`/`verify-proof`, và `report --json` tồn tại - nhưng
không nhiệm vụ nào trong số đó *yêu cầu* một cơ chế toàn vẹn nhật ký, và tài liệu này không
nói ngược lại.

---

## 3. Cây pháp lý

### 3.1 Năm văn bản, theo thứ tự hiệu lực pháp lý

```
Luật Trí tuệ nhân tạo 134/2025/QH15          (Quốc hội, thông qua 10/12/2025)
  │   nghĩa vụ gốc: nhật ký hoạt động, nhật ký lưu vết, tự phân loại, sự cố
  ├── Nghị định 142/2026/NĐ-CP                (Chính phủ, ký 30/04/2026)
  │     chi tiết: hồ sơ phân loại, đánh giá sự phù hợp, đồng hồ 72 giờ, biểu mẫu
  ├── Thông tư 05/2026/TT-BKHCN               (Bộ KH&CN - Khung đạo đức AI quốc gia, Luật Điều 26)
  └── Quyết định 33/2026/QĐ-TTg               (Thủ tướng - Danh mục hệ thống AI rủi ro cao, Luật Điều 13(4))

Quyết định 1671/QĐ-TTg                        (Thủ tướng, ký 28/08/2026)
      chiến lược: quan điểm, mục tiêu, trụ cột, giải pháp, phân công
      không nằm trong chuỗi nghĩa vụ ở trên - nó là chương trình hành động bao quanh
```

### 3.2 Mốc hiệu lực và chuyển tiếp

| Ngày | Sự kiện | Căn cứ |
|---|---|---|
| 10/12/2025 | Quốc hội khóa XV, Kỳ họp thứ 10 thông qua Luật 134/2025/QH15 | dòng cuối Luật |
| 22/01/2026 | Luật đăng Công báo số 40 | bản Công báo |
| **01/03/2026** | Luật 134 có hiệu lực, trừ nội dung tại Điều 35 | Luật Điều 34 |
| 10/03/2026 | Thông tư 05/2026/TT-BKHCN có hiệu lực | `[Unverified - chỉ từ nguồn thứ cấp, chưa đối chiếu bản gốc Thông tư]` |
| 30/04/2026 | Nghị định 142/2026/NĐ-CP được ký | đầu Phụ lục biểu mẫu Nghị định |
| **01/05/2026** | Nghị định 142 có hiệu lực | Nghị định Điều 45 |
| 15/08/2026 | Quyết định 33/2026/QĐ-TTg (Danh mục rủi ro cao) có hiệu lực | `[Unverified - chỉ từ nguồn thứ cấp, chưa tải được bản gốc]` |
| **28/08/2026** | QĐ 1671/QĐ-TTg được ký, có hiệu lực từ ngày ký, thay thế QĐ 127/QĐ-TTg (26/01/2021) | QĐ 1671 Điều 3(1), 3(2) |

**Thời hạn chuyển tiếp, đúng theo lời văn của Luật, không quy ra ngày.** Điều 35(1) đặt hai
thời hạn tính **kể từ ngày Luật có hiệu lực**: **18 tháng** cho hệ thống trong lĩnh vực y tế,
giáo dục và tài chính, **12 tháng** cho các hệ thống còn lại. Hai thời hạn này chỉ áp dụng cho
**hệ thống đã được đưa vào hoạt động trước ngày Luật có hiệu lực**, và chúng **không** gắn với
Danh mục hệ thống AI rủi ro cao - Điều 35(1) không nhắc tới Danh mục. Tài liệu này cố ý **không
in ra ngày lịch quy đổi**: bản thân Luật không in ngày nào, và một ngày do người đọc tự cộng
ra rồi in như một mốc của văn bản là đúng loại lỗi mà cả tài liệu này đang tránh. Điều 35(2)
cho phép hệ thống tiếp tục hoạt động trong thời hạn đó, trừ khi cơ quan quản lý xác định hệ
thống có nguy cơ gây thiệt hại nghiêm trọng.

Nguyên văn điều khoản chuyển tiếp:

> "1. Đối với các hệ thống trí tuệ nhân tạo đã được đưa vào hoạt động trước ngày Luật này
> có hiệu lực thi hành, nhà cung cấp và bên triển khai có trách nhiệm thực hiện các nghĩa
> vụ tuân thủ theo quy định của Luật này trong thời hạn sau đây: a) 18 tháng kể từ ngày
> Luật này có hiệu lực thi hành đối với hệ thống trí tuệ nhân tạo trong lĩnh vực y tế, giáo
> dục và tài chính; b) 12 tháng kể từ ngày Luật này có hiệu lực thi hành đối với các hệ
> thống trí tuệ nhân tạo không thuộc trường hợp quy định tại điểm a khoản này."
>
> - Luật 134/2025/QH15, Điều 35(1)

Có một điều khoản chuyển tiếp thứ hai đáng chú ý, vì nó tạo ra chính loại bằng chứng waxseal
sinh ra. Khi một hệ thống phải phân loại lại thành rủi ro cao, Nghị định Điều 11(5) cho tối
đa 12 tháng và đặt điều kiện:

> "Trong thời hạn chuyển tiếp, hệ thống được phép tiếp tục hoạt động nhưng nhà cung cấp, bên
> triển khai phải thiết lập và duy trì cơ chế giám sát thực chất của con người. Người thực
> hiện giám sát phải được bảo đảm đủ thông tin, thẩm quyền để đánh giá độc lập, can thiệp
> hoặc bác bỏ kết quả của hệ thống; đồng thời, nhà cung cấp, bên triển khai phải lưu trữ đầy
> đủ nhật ký vận hành và các quyết định can thiệp để phục vụ công tác thanh tra, kiểm tra."
>
> - Nghị định 142/2026/NĐ-CP, Điều 11(5)

### 3.3 Văn bản nào đã đọc bản gốc, văn bản nào chưa

| Văn bản | Đã đọc bản gốc? |
|---|---|
| QĐ 1671/QĐ-TTg | **Có** - PDF ký số của Văn phòng Chính phủ, đọc toàn bộ 64 trang (thân + Phụ lục I + Phụ lục II) |
| Luật 134/2025/QH15 | **Có** - bản Công báo số 40 ngày 22/01/2026, có lớp văn bản, đọc trực tiếp các Điều 7, 8, 9, 10, 11, 12, 13, 14, 15, 26, 27, 28, 33, 34, 35 |
| Nghị định 142/2026/NĐ-CP | **Có** - PDF ký số, đọc trực tiếp các Điều 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 43, 44, 45, 46 và các Mẫu AI01a, AI01b, AI02, AI08a |
| Thông tư 05/2026/TT-BKHCN | **Chưa** - chỉ nguồn thứ cấp; mọi phát biểu về nội dung Thông tư trong tài liệu này mang nhãn `[Unverified]` |
| Quyết định 33/2026/QĐ-TTg | **Chưa** - chỉ nguồn thứ cấp; mọi phát biểu về danh mục nhóm rủi ro cao mang nhãn `[Unverified]` |

Hệ quả của hai dòng cuối: tài liệu này **không** kết luận một hệ thống cụ thể có thuộc Danh
mục rủi ro cao hay không, và **không** trích mã điều/khoản nào của Thông tư 05/2026.
`[Unverified]` các nhóm được nêu trong QĐ 33/2026 (giáo dục; dân tộc - tôn giáo; y tế; ngân
hàng, gồm xử lý giao dịch tự động và quyết định tín dụng; tố tụng, sinh trắc; giao thông) -
danh sách này lấy từ nguồn thứ cấp, chưa đối chiếu bản gốc, và số điều khoản không được
trích ở đây vì chưa xác nhận được.

---

## 4. Ma trận đáp ứng

Nhãn dùng đúng ba nhãn của [mapping.md](../compliance/mapping.md): **Trực tiếp** (waxseal
sinh ra bằng chứng đi thẳng vào nội dung của yêu cầu), **Một phần** (phủ một phần; phần còn
lại thuộc về tổ chức hoặc ngoài phạm vi), **Ngoài phạm vi** (liệt kê để không ai mặc định là
đã phủ - nó không phủ).

Không hàng nào nói một nghĩa vụ đã được đáp ứng. Cột "waxseal 0.1.5 làm gì hôm nay" nêu
đường dẫn module để người đọc kiểm chứng được bằng cách đọc mã, không phải bằng cách tin
bảng này.

**Bảng nhãn chính thức là [mapping.md §7b](../compliance/mapping.md#7b-vietnam--law-on-artificial-intelligence-no-1342025qh15-and-its-implementing-instruments)**,
với 12 hàng nghĩa vụ và phần "Applicability first" xác định vai trò nhà cung cấp / bên triển
khai theo Luật Điều 3(4), 3(5). Bảng dưới đây **không** thay thế bảng đó và không đặt nhãn
khác với nó; nó thêm vào ba thứ mà một tài liệu ánh xạ không có chỗ đặt: đường dẫn module cho
từng hàng, các điều khoản của Nghị định mà QĐ 1671 dẫn tới, và cột "gap" trỏ sang
[§5](#5-gap-và-đề-xuất-nâng-cấp). Nếu hai bảng lệch nhau, mapping.md là bản đúng.

### 4.1 Bảng

| Yêu cầu (số điều/khoản) | waxseal 0.1.5 làm gì hôm nay | Nhãn | Gap |
|---|---|---|---|
| Lập, cập nhật, lưu giữ **hồ sơ kỹ thuật và nhật ký hoạt động** "**ở mức cần thiết**" cho đánh giá sự phù hợp và hậu kiểm (Luật Đ.14(1)(c)) | chuỗi hash trên `EntryHeader` (`domain/header.py`, `domain/hashing.py`); fingerprint schema (`domain/fingerprint.py`); `verify`/`report`/`export-proof` (`domain/verify.py`, `domain/report.py`, `domain/export.py`); append-only; verdict ba giá trị (`domain/verdict.py`) | **Một phần** - trong đó *trực tiếp* chỉ cho **toàn vẹn, thứ tự, vị trí** của thứ đã được lưu | hai lý do độc lập khiến cả hàng là "Một phần": (i) "ở mức cần thiết" là một phán đoán về phạm vi mà tổ chức triển khai phải tự làm - ghi sự kiện nào, trường nào, giữ bao lâu; không thư viện nào làm thay được, và một thư viện làm như thể làm thay được là đang quyết định phạm vi nghĩa vụ pháp lý của người khác; (ii) điều khoản đòi *lưu giữ*, **không** đòi tamper-evidence - lưu giữ có bằng chứng chống sửa là một tư thế **mạnh hơn** mức văn bản đòi, và phải được trình bày đúng như vậy, không phải như một yêu cầu do điều khoản này áp đặt. waxseal cũng không cưỡng chế thời hạn lưu giữ và không cho gì hết hạn |
| Cung cấp "hồ sơ kỹ thuật, **nhật ký lưu vết**, dữ liệu huấn luyện" khi thanh tra, kiểm tra (Luật Đ.28(3)) | `export-proof` xuất một quyết định thành bundle kiểm chứng được offline, không tiết lộ các quyết định khác (`domain/export.py`, `verify_proof_bundle`) | **Một phần** | bundle vừa khớp với giới hạn "cần thiết, tương xứng" của điều khoản, vừa khớp với việc Đ.14(1)(e) cấm buộc tiết lộ mã nguồn, thuật toán chi tiết, bộ tham số - một proof bundle không tiết lộ thứ nào trong đó. Nhưng *hồ sơ kỹ thuật* và *dữ liệu huấn luyện* thì không được phủ: waxseal không giữ cái nào; và phạm vi, mức độ, cách cung cấp là quyết định pháp lý của tổ chức |
| Lưu trữ đầy đủ **nhật ký vận hành và các quyết định can thiệp** trong thời hạn chuyển tiếp phân loại lại (NĐ Đ.11(5)); thiết kế và duy trì cơ chế giám sát, can thiệp của con người (Luật Đ.14(1)(d); NĐ Đ.15(2)(c), Đ.15(5)(c)) | `HumanOversight.mode` / `reviewer_ref` / `action` gắn **theo từng quyết định AI** (`domain/decision.py`); `report` đếm riêng `oversight_unrecorded` (`domain/report.py`) | **Một phần** | không có bản ghi can thiệp *độc lập* - dừng khẩn cấp, thu hồi, đình chỉ hệ thống không gắn với một quyết định AI cụ thể thì hiện không có chỗ ghi -> **E2b** ([§5.2](#52-e2---họ-payload-sự-cố-và-can-thiệp-của-con-người)) |
| **Ghi nhận** sự cố nghiêm trọng kịp thời (Luật Đ.12(2)(b); NĐ Đ.19(2)(a)) và báo cáo sơ bộ trong **72 giờ** / **05 ngày làm việc** kể từ **thời điểm xác nhận sự cố** (NĐ Đ.19(3)(a)(b)(c)) | không có | **Ngoài phạm vi** | -> **E2a**. Lưu ý phạm vi: waxseal chỉ chứng minh được rằng *một bản ghi sự cố tồn tại tại vị trí n, mang mốc thời gian t do bên ghi khẳng định, và không bị sửa từ đó* - nó **không** chứng minh báo cáo đã được nộp lên Cổng một cửa, và không bao giờ được in ra như thể có |
| Duy trì, lưu giữ **nhật ký hệ thống**, dữ liệu và thông tin liên quan đến sự cố để xác minh, đánh giá, khắc phục (NĐ Đ.19(4)) | chuỗi hash + `verify --anchors` + niêm phong forward-secure (`domain/sealing.py`) làm cho việc chỉnh sửa nhật ký sau sự cố trở nên phát hiện được | **Một phần** | đây là khoản về *lưu giữ nhật ký*, khác với nghĩa vụ *ghi nhận và báo cáo sự cố* ở hàng trên (Ngoài phạm vi). Phần "duy trì, lưu giữ" là chương trình lưu trữ của tổ chức; waxseal không xoá và cũng không giữ hộ |
| **Tự phân loại** hệ thống trước khi đưa vào sử dụng và chịu trách nhiệm về tính chính xác, trung thực của kết quả (Luật Đ.10(1); NĐ Đ.6(1)); lưu hồ sơ phân loại suốt thời gian hệ thống hoạt động (NĐ Đ.12(6)) | không có; `mapping.md` §9 khai rõ "no risk taxonomy" | **Ngoài phạm vi** | -> **E1**: ghi *mức rủi ro do nhà cung cấp đã khai*, nguyên văn, kèm con trỏ tới hồ sơ phân loại. waxseal không phân loại và không phán xét phân loại của ai |
| Bằng chứng cho tiêu chí loại trừ khỏi rủi ro cao: "người có thẩm quyền có khả năng xem xét độc lập, can thiệp, từ chối hoặc thay đổi quyết định của hệ thống **trước khi quyết định đó có hiệu lực**" (NĐ Đ.8(2)(b)) | `human_oversight` ghi có/không có rà soát cho từng quyết định, với `"unrecorded"` là một giá trị riêng, không phải sự vắng mặt của giá trị | **Một phần** | waxseal chứng minh *bản ghi về việc rà soát* không bị sửa; nó không chứng minh việc rà soát đã thực sự xảy ra, cũng không chứng minh nó xảy ra *trước khi* quyết định có hiệu lực - thứ tự trong chuỗi là thứ tự **ghi**, không phải thứ tự **hành động** |
| Cấm "Cản trở, vô hiệu hóa hoặc **làm sai lệch** cơ chế giám sát, can thiệp và kiểm soát của con người" (Luật Đ.7(4)) | phát hiện sửa/xoá/chèn/đảo các *bản ghi* giám sát (`domain/verify.py`) - nhưng đó là bản ghi, không phải cơ chế | **Ngoài phạm vi** | một cơ chế bị tắt thì không ghi gì, nên không nhật ký nào chứng kiến được sự vắng mặt của chính nó. Đây đúng là lập luận CLAUDE.md đã dùng cho việc archiving vô hình với toàn vẹn chuỗi: một khiếm khuyết mà không verdict nào thấy được thì phải được khẳng định từ bên ngoài nhật ký, không bao giờ suy ra từ một lần `verify` sạch |
| Cấm "Che giấu thông tin bắt buộc phải công khai, minh bạch hoặc giải trình; tẩy xóa, làm sai lệch các thông tin, nhãn, cảnh báo bắt buộc" (Luật Đ.7(5)) | với những gì đã vào trail: sửa hoặc xoá một hàng làm `verify` trả về `broken` kèm `seq` và lý do | **Ngoài phạm vi** | điều khoản nói về thông tin, nhãn và cảnh báo bắt buộc *trong hoạt động AI* - thứ waxseal không tạo, không hiển thị và không phân phối. Việc nó phát hiện được sửa đổi trên một hàng đã vào trail là một sự thật về trail, không phải một sự phủ cho điều khoản này |
| "Hệ thống trí tuệ nhân tạo không thay thế thẩm quyền và trách nhiệm quyết định của người ra quyết định… Người ra quyết định chịu trách nhiệm về việc xem xét và sử dụng kết quả" (Luật Đ.27(2); NĐ Đ.20(6)) | `human_oversight` + `oversight_unrecorded` đếm riêng; `ModelRef.digest = None` nghĩa là "chưa ghim", một claim yếu hơn được ghi nhận đúng là yếu hơn | **Một phần** | `oversight_unrecorded` được đếm tách khỏi mọi mode đã ghi, nên "không biết có ai rà soát hay không" không bao giờ render thành "không ai rà soát" hay "thiết kế là tự động". Nhưng việc rà soát có *thực sự xảy ra* hay không, và người rà soát có *thẩm quyền* hay không, đều nằm ngoài một lớp toàn vẹn |
| "Thẻ hệ thống", gồm "thông tin về sự cố, lỗ hổng hoặc biện pháp khắc phục có liên quan" (NĐ Đ.3(6)) | một nhật ký được kiểm chứng toàn vẹn là *nguồn* để viết các mục về sự cố và biện pháp khắc phục của thẻ | **Một phần** | thẻ hệ thống là một tài liệu do người viết; waxseal không sinh ra thẻ nào |
| Báo cáo đánh giá tác động trong cơ quan nhà nước, gồm "Cơ chế bảo đảm khả năng giám sát và can thiệp của con người" (Luật Đ.27(3); NĐ Đ.20(3)(d), Mẫu AI02 §II.5) | `report --json` (`domain/report.py`) là nguồn số liệu cho mục "cơ chế giám sát" và "mức độ tự động hóa" (Mẫu AI02 §II.4) | **Một phần** | báo cáo đánh giá tác động là văn bản của cơ quan, không phải đầu ra của thư viện |
| Đánh giá sự phù hợp; tổ chức đánh giá sự phù hợp (Luật Đ.13; NĐ Đ.13; QĐ 1671 nv 89) | `SPEC.md`, golden vectors bất biến, script sinh vector độc lập trong `tools/`, `verify-proof` chạy offline | **Một phần** - đầu vào cho một assessor | assessor, tiêu chí và kết luận đều nằm ngoài |
| "Lưu trữ thông tin, tài liệu phục vụ việc kiểm tra, giám sát" (NĐ Đ.16(2)(c)) | append-only theo thiết kế; `verify` báo, không bao giờ sửa | **Một phần** | không cưỡng chế lưu trữ, không có cơ chế hết hạn |
| Thời gian đáng tin cậy cho mốc 72 giờ (NĐ Đ.19(3)) | `ts` là **lời khẳng định của bên gọi**, không phải thời gian được chứng thực; `--tsa-url` cho phép neo vào TSA RFC 3161 bất kỳ, `--tsa-ca-file` do operator chọn; waxseal không đặt trust anchor mặc định nào (`adapters/rfc3161.py`, `adapters/rfc3161_verify.py`) | **Một phần** | `[Unverified]` liệu một tổ chức cung cấp dịch vụ chứng thực thời gian được cấp phép tại Việt Nam có endpoint RFC 3161 dùng được hay không - đây là câu hỏi phải kiểm tra trước khi thiết kế, không phải điều tài liệu này khẳng định |
| Cụm từ "lưu trữ dữ liệu tại Việt Nam trong các trường hợp pháp luật quy định" (QĐ 1671 IV.4.c; Phụ lục II nv 81) | thư viện chạy ở đâu thì dữ liệu ở đó; không có dịch vụ bắt buộc nào ở ngoài | **Ngoài phạm vi** đối với thư viện | đọc đúng chỗ nó nằm trước khi coi là mệnh lệnh: cụm từ này là đuôi của điểm về thu hút FDI và trung tâm R&D AI nước ngoài, và là điều kiện gắn với những thỏa thuận đó ([§2.4](#24-sáu-nhóm-giải-pháp-đột-phá-mục-iv)). Giải quyết ở tầng triển khai ([§6](#6-triển-khai-on-shore)); luồng ra ngoài duy nhất là hash tới anchor/witness và phải được khai báo |
| Kiểm soát luồng dữ liệu AI xuyên biên giới (QĐ 1671 IV.1.g; Phụ lục II nv 73) | mọi lệnh đọc trail đều chạy offline; chỉ `anchor` và `--witness` mở kết nối ra ngoài | **Ngoài phạm vi** đối với thư viện - nhưng là một *sự thật kiến trúc phải khai báo*, xem [§6.3](#63-một-lớp-luồng-ra-ngoài-duy-nhất) | |
| Đăng ký hệ thống AI vào **Cơ sở dữ liệu quốc gia về hệ thống AI** (Luật Đ.8(2); QĐ 1671 Điều 2.3.c) | không có | **Ngoài phạm vi** | xem [§5.4](#54-xa-hơn-và-cố-ý-không-làm) |
| Thông báo/báo cáo qua **Cổng thông tin điện tử một cửa về AI**, kể cả "Gửi thông tin tự động thông qua giao diện lập trình ứng dụng" (Luật Đ.10(3), Đ.12(4); NĐ Đ.14(3)(b), Đ.19(8)) | không có | **Ngoài phạm vi** | xem [§5.4](#54-xa-hơn-và-cố-ý-không-làm) |
| Ghi nhãn, đánh dấu kỹ thuật nội dung do AI tạo ra (Luật Đ.11; NĐ Đ.17, Đ.18) | không có | **Ngoài phạm vi** | waxseal không tạo nội dung |
| Tiếng Việt trong tài liệu và giao diện | toàn bộ `docs/**` có bản `.vi.md`; portal mặc định tiếng Việt | đủ cho mục đích hiện tại | CLI và các từ verdict (`ok`/`broken`/`unverifiable`) **cố ý không dịch**: chúng là từ vựng có kiểm soát mà exit code và tài liệu đều bám vào |

### 4.2 Khung "6 rõ" đối chiếu với bản ghi quyết định

`[Inference]` Đây là phép đối chiếu do tài liệu này đặt ra, không phải một yêu cầu pháp lý
về schema. Nguyên tắc 6 rõ ở QĐ 1671 IV.2.d là nguyên tắc phân công trách nhiệm hành chính;
không văn bản nào nói nó phải ánh xạ thành trường dữ liệu. Nhưng nó là một cách kiểm tra
xem một bản ghi quyết định có bỏ trống chỗ nào không:

| "rõ" | Trường tương ứng | Ghi chú |
|---|---|---|
| rõ người | `human_oversight.reviewer_ref`, `subject_ref` | bút danh, bắt buộc - chuỗi không xoá được |
| rõ việc | `decision_type`, `outcome` | chuỗi mở; giá trị lạ được giữ nguyên văn, không bao giờ là lỗi |
| rõ thời gian | `ts` (bên gọi khẳng định) + cận trên từ receipt anchor | hai loại thời gian khác nhau, không được trộn |
| rõ trách nhiệm | `human_oversight.mode` / `action`, và (E2b) bản ghi can thiệp | `"unrecorded"` là một giá trị, không phải sự vắng mặt |
| rõ sản phẩm | `payload_hash`, `input_commitment`, `model.digest` | `digest = None` nghĩa là "chưa ghim", không phải "khớp" |
| rõ thẩm quyền | `policy_version`, và (E1) `risk_tier` đã khai | tier là *lời khai của nhà cung cấp*, không phải kết luận của waxseal |

---

## 5. Gap và đề xuất nâng cấp

Ba mở rộng dưới đây được mô tả theo *bằng chứng chúng sinh ra*, không theo mã. Không mở rộng
nào thay đổi cơ chế chuỗi: `hash_version` là fingerprint của bộ trường tiêu đề, còn payload
được tham chiếu chỉ bằng `payload_hash` - thêm một họ payload mới không chạm vào chuỗi, và
đó chính là lý do envelope được thiết kế như vậy.

### 5.1 E1 - mức rủi ro **đã khai**, không phải mức rủi ro **được phán xét**

**Bằng chứng nó sinh ra:** với mỗi quyết định AI, một bản ghi không sửa được về *mức rủi ro
mà nhà cung cấp đã tự khai tại thời điểm quyết định đó được ghi*, cộng một con trỏ bút danh
tới hồ sơ phân loại rủi ro tương ứng (mã + phiên bản, không phải đường dẫn có tên người).

**Vì sao là "đã khai":** Luật Đ.10(1) và NĐ Đ.6(1) đặt việc phân loại - và trách nhiệm về
tính chính xác, trung thực của nó - lên nhà cung cấp. Nếu waxseal chuẩn hoá giá trị tier
(quy "cao" về `high`), waxseal đã tự đặt mình vào vị trí phán xét phân loại của nhà cung cấp.
Giá trị được ghi nguyên văn: `"cao"`, `"high"`, `"tier-2"` đều được nhận và đều khác nhau.

**Trạng thái thứ ba:** không khai tier thì bản ghi mang giá trị "chưa khai", và giá trị đó
**không bao giờ** render thành `"thấp"`. Đó là chính lỗi mà `dropped_writes: None` tồn tại
để tránh: một trạng thái chưa đo bị ép vào một trạng thái đã đo. Trong báo cáo, một tier
chưa khai được đếm riêng, không cộng vào bất kỳ tier nào.

**Cái nó không sinh ra:** không có bằng chứng nào rằng mức tier đã khai là *đúng*, rằng hồ
sơ phân loại *tồn tại*, hay rằng nó đã được thông báo cho cơ quan nào.

### 5.2 E2 - họ payload sự cố và can thiệp của con người

**E2a - bản ghi sự cố.** Bằng chứng nó sinh ra: một bản ghi sự cố tồn tại tại vị trí `n`
trong chuỗi, mang các mốc thời gian do bên ghi khẳng định, và không bị sửa từ đó. Các trường
bám sát **Mẫu AI01a** của Nghị định 142 để bản ghi có thể dùng lại khi phải điền báo cáo:
mã định danh hệ thống, mức độ rủi ro, thời điểm phát hiện, **thời điểm xác nhận mối liên hệ
nhân quả**, loại hậu quả, trạng thái vận hành, đánh giá sơ bộ nguyên nhân.

Chi tiết đọc được từ bản gốc và đáng ghi lại: đồng hồ 72 giờ **không** chạy từ thời điểm
phát hiện.

> "c) Thời điểm xác nhận sự cố quy định tại khoản này được tính từ khi tổ chức, cá nhân có
> đủ cơ sở thông tin ban đầu để xác định sự cố đã thực sự xảy ra và có khả năng cao bắt
> nguồn từ lỗi của hệ thống trí tuệ nhân tạo, không đợi đến khi hoàn thành điều tra toàn
> diện nguyên nhân kỹ thuật. Việc nộp báo cáo sơ bộ trong thời hạn quy định không bị coi là
> sự thừa nhận lỗi kỹ thuật hoặc trách nhiệm pháp lý của tổ chức, cá nhân báo cáo."
>
> - Nghị định 142/2026/NĐ-CP, Điều 19(3)(c)

Nghĩa là bản ghi phải mang *cả hai* mốc - phát hiện và xác nhận - và nếu mốc xác nhận không
được ghi thì phép đọc cửa sổ 72 giờ là **chưa đo được**, kèm lý do nêu rõ mốc còn thiếu.
Lấy thời điểm phát hiện thay thế trong im lặng sẽ là việc bịa ra một phép đo, và nó có thể
sai theo cả hai chiều.

**Cái E2a không sinh ra, và không bao giờ được in như thể có:** bằng chứng rằng báo cáo đã
được nộp; bằng chứng rằng thời hạn đã bị vi phạm. Việc *không có bản ghi nộp trên trail này*
không phải là "chưa nộp" - Nghị định Điều 46(1) cho phép nộp qua phương thức điện tử khác
với "giá trị pháp lý tương đương" khi Cổng chưa vận hành chính thức, và một trail không thấy
gì cả cũng không thấy được điều đó.

**E2b - bản ghi can thiệp của con người.** Bằng chứng nó sinh ra: quyết định can thiệp được
lưu giữ nguyên vẹn - dừng khẩn cấp, override, đình chỉ - *không* buộc phải gắn với một quyết
định AI cụ thể, vì trong thực tế nhiều can thiệp không gắn với một quyết định nào. Đây chính
là dữ liệu mà **Mẫu AI08a §V** hỏi thẳng: §V.6 "Người/bộ phận có thẩm quyền giám sát, can
thiệp và **số lần can thiệp**"; §V.9 "**Số lần kích hoạt cơ chế dừng khẩn cấp**, tình huống
kích hoạt và kết quả xử lý".

Và một mục nữa của cùng biểu mẫu là lý do rõ nhất để một lớp toàn vẹn nhật ký tồn tại trong
bối cảnh này:

> "10. Việc lưu giữ nhật ký hệ thống, thời gian lưu giữ và biện pháp bảo đảm tính toàn vẹn
> của nhật ký: …"
>
> - Nghị định 142/2026/NĐ-CP, Phụ lục, Mẫu AI08a §V.10

Không văn bản nào trong cụm này *quy định* một cơ chế toàn vẹn nhật ký. Nhưng biểu mẫu hỏi
thẳng "biện pháp bảo đảm tính toàn vẹn của nhật ký" là gì - tức là cơ quan quản lý coi đó là
một mục phải khai, và một tổ chức phải có câu trả lời nào đó cho nó.

**Cái E2b không sinh ra:** bằng chứng rằng cơ chế giám sát *không bị vô hiệu hoá* (Luật
Đ.7(4)). Cơ chế bị tắt thì không ghi gì, và một chuỗi trống vẫn `ok`. Đây là ranh giới phải
nói ra mỗi lần, không phải một chi tiết kỹ thuật.

### 5.3 E3 - khối báo cáo tương ứng

**Bằng chứng nó sinh ra:** một bản kiểm kê có thể trích ra được từ `report --json` - số bản
ghi sự cố, phân theo mức nghiêm trọng; số bản ghi can thiệp, phân theo loại hành động; phân
bố tier đã khai, với "chưa khai" là một dòng riêng.

Hai quy tắc chi phối cách khối này được render:

1. **Không có bản ghi ≠ không có chuyện gì xảy ra.** Một trail có 0 bản ghi sự cố phải in ra
   *"0 bản ghi sự cố trên trail này - đây là số sự cố ĐÃ ĐƯỢC GHI, không phải bằng chứng
   rằng không có sự cố nào"*. Đây là `dropped_writes` một lần nữa: toàn vẹn chuỗi không phải
   tính đầy đủ của trail.
2. **Chưa quét ≠ quét thấy 0.** Mục sự cố và mục can thiệp phải luôn được render, kể cả khi
   rỗng. Một mục biến mất khỏi báo cáo không phân biệt được "không có" với "không quét", và
   đó đúng là sự sụp đổ ba-giá-trị-thành-hai mà cả codebase này tồn tại để chặn.

Báo cáo là bản kiểm kê, không phải một chiều verdict: khối này **không** làm đổi exit code
của `report`, và không tính cửa sổ 72 giờ - báo cáo không có đồng hồ.

### 5.4 Xa hơn, và cố ý không làm

Ba việc dưới đây nằm trong cụm nghĩa vụ nhưng ngoài phạm vi một lớp toàn vẹn. Chúng được
liệt kê để không ai mặc định là đã có.

- **Đăng ký hệ thống vào Cơ sở dữ liệu quốc gia về hệ thống AI** (Luật Đ.8(2); QĐ 1671 Điều
  2.3.c giao Bộ Công an "Xây dựng, vận hành Cơ sở dữ liệu quốc gia về trí tuệ nhân tạo").
  Đăng ký là một hành vi hành chính với một cơ quan; một lớp bằng chứng có thể chứng minh
  rằng *một bản ghi nói rằng việc đăng ký đã xảy ra* không bị sửa, nhưng không thể chứng
  minh việc đăng ký đã xảy ra - và bán cái thứ nhất như cái thứ hai là chính lỗi mà toàn bộ
  tài liệu này đang cố tránh.
- **Nộp thông báo/báo cáo qua Cổng thông tin điện tử một cửa về AI**, kể cả đường tự động
  bằng API (NĐ Đ.14(3)(b), Đ.19(8)). Một thư viện toàn vẹn không nộp hồ sơ hộ ai: làm vậy
  biến nó thành một client tích hợp với một cơ quan, tức đưa nghĩa vụ vận hành và trách
  nhiệm pháp lý của tổ chức vào trong một thư viện MIT không có ràng buộc dịch vụ nào.
  `[Unverified]` đặc tả công khai của giao diện lập trình ứng dụng đó - chưa tìm được, nên
  ngay cả nếu muốn cũng chưa có gì để bám. Chỗ đúng cho việc này là một trường con trỏ:
  mã/biên nhận nộp, ghi vào trail như một dữ kiện bên ghi khẳng định.
- **Ghi nhãn, đánh dấu kỹ thuật nội dung do AI tạo ra** (Luật Đ.11; NĐ Đ.17, Đ.18). waxseal
  không tạo, không xuất và không phân phối nội dung; nó chỉ nhìn thấy hash của một payload
  đã được che dữ liệu nhạy cảm. Ghi nhãn là nghĩa vụ đặt lên nơi nội dung được sinh ra và
  nơi nội dung được đưa ra công cộng, không phải nơi bằng chứng được lưu.

---

## 6. Triển khai on-shore

### 6.1 Bốn trust domain và vị trí lãnh thổ

[Kiến trúc tham chiếu §1](../architecture/deployment.md#1-topology) đặt bốn miền quản trị
riêng biệt, và tính chất chịu lực không phải bốn cái hộp trên sơ đồ mà là **bốn quyền quản
trị hành chính khác nhau**. Bảng dưới đây thêm một cột mà tài liệu kiến trúc không có: đặt ở
đâu về mặt lãnh thổ.

| Miền | Giữ gì | Đặt on-shore được không | Ghi chú |
|---|---|---|---|
| **Application** (hệ thống AI) | mô hình, redactor, payload | **Được, hoàn toàn** | redactor chạy trước mọi phép hash, nên cleartext không bao giờ ra khỏi miền này |
| **Chain** (chain server, kho append-only) | trail và thứ tự của nó | **Được, hoàn toàn** | JSONL/SQLite/Postgres/S3 tuỳ backend; không có dịch vụ ngoài nào bắt buộc |
| **Anchor** (miền quyền thứ ba) | các root đã công bố, được chứng thực thời gian ở nơi khác | **Được, nhưng đây là chỗ khó** | một anchor on-shore vẫn phải nằm dưới **quyền quản trị khác** với chain - xem [§6.2](#62-cùng-lãnh-thổ-không-có-nghĩa-là-cùng-quyền-quản-trị) |
| **Verifier** (tuyến hai / kiểm toán nội bộ) | khoá niêm phong A₀, job verify, các báo cáo | **Được, hoàn toàn** | A₀ không bao giờ nằm trên host có quyền ghi; file pin không nằm nơi writer chạm được |

### 6.2 "Cùng lãnh thổ" không có nghĩa là "cùng quyền quản trị"

Ba tuỳ chọn triển khai, mọi thành phần đều chạy trong nước:

1. **Tất cả trong một tổ chức, bốn quyền quản trị nội bộ.** Chain server và verifier ở hai
   namespace/cluster khác nhau với RBAC tách, anchor là một hệ thống nội bộ do bộ phận khác
   sở hữu. Rẻ nhất, nhưng miền anchor yếu nhất: nếu người viết trail cũng có quyền vào nơi
   giữ root, kịch bản "viết lại toàn bộ nhật ký một cách nhất quán" quay lại thành không
   phát hiện được.
2. **Anchor là một đối tác trong nước.** Root được công bố sang một tổ chức khác - một cơ
   quan, một đối tác đối ứng, một tổ chức đánh giá sự phù hợp (loại tổ chức mà QĐ 1671
   nhiệm vụ 89 dự kiến hình thành). Quyền quản trị thật sự khác nhau, dữ liệu không ra khỏi
   lãnh thổ.
3. **Air-gap hoàn toàn, không anchor.** Vẫn giữ được toàn vẹn chuỗi, thứ tự, phát hiện
   sửa/xoá/chèn/đảo và niêm phong forward-secure. Mất đi cận trên về thời gian: không có
   anchor thì không có gì nói rằng một root đã tồn tại trước một thời điểm nào đó, và mọi
   mốc thời gian là lời khẳng định của bên ghi. Đây là một sự đánh đổi phải được ghi vào
   thiết kế, không phải một chi tiết vận hành.

### 6.3 Một lớp luồng ra ngoài duy nhất

Nếu, và chỉ nếu, operator bật một trong các anchor domain, waxseal mở kết nối ra ngoài. Nói
rõ nội dung của luồng đó, vì đây là điểm giao với **IV.1.g** (Phụ lục II nhiệm vụ 73, do Bộ
Công an chủ trì, sản phẩm là "Văn bản quy định hoặc hướng dẫn", thời gian 2026) - và với cụm
từ ở IV.4.c, cụm từ mà [§2.4](#24-sáu-nhóm-giải-pháp-đột-phá-mục-iv) đã đặt lại đúng ngữ cảnh
FDI của nó, chứ không phải với một quy tắc lưu trú dữ liệu độc lập:

**Cái được gửi ra:** một Merkle root, hoặc một hash. Cụ thể - một checkpoint root tới TSA
theo RFC 3161 (`--tsa-url`); một digest tới một OpenTimestamps calendar
(`--ots-calendar`); một checkpoint tới một witness (`--witness`); một checkpoint tới một
ledger EVM (`--evm-rpc`). Bốn miền anchor ghi độc lập với nhau.

**Cái không được gửi ra:** payload. Không nội dung quyết định, không `rationale`, không
`input_commitment` gốc, không dữ liệu cá nhân, không tên. Một hash không đảo được thành
payload.

**Nhưng nó vẫn là một luồng dữ liệu xuyên biên giới nếu điểm nhận ở ngoài lãnh thổ**, và một
operator phải khai nó như vậy. Ba điều cần biết khi khai:

- Một hash phát ra theo lịch vẫn là **metadata**: nó tiết lộ rằng có một trail, rằng nó đang
  tăng trưởng, và tăng trưởng vào những thời điểm nào. Đó không phải nội dung, nhưng cũng
  không phải không có gì.
- waxseal **không đặt trust anchor mặc định nào** và không có TSA, calendar, witness hay
  ledger mặc định. Chọn một cái sẽ là quyết định thay operator xem họ tin ai, mà không nói ra
  trên bất kỳ dòng output nào. Hệ quả trực tiếp: không có luồng ra ngoài nào xảy ra nếu
  operator không tự cấu hình nó, và điểm nhận luôn là lựa chọn của operator - kể cả lựa chọn
  đặt nó trong nước.
- Nếu không dùng `--tsa-ca-file`, receipt RFC 3161 chỉ được kiểm tra ở mức cấu trúc, và lần
  chạy đó **nói ra điều này thành tiếng** thay vì đi qua trong im lặng.

### 6.4 Cái "không được đặt cùng nhau"

Ba ràng buộc này quan trọng hơn mọi lựa chọn về hình thức đóng gói (container, Helm,
systemd, cài trực tiếp). Chúng đến từ
[kiến trúc §3](../architecture/deployment.md#3-separation-of-duties) và
[threat model §5](../security/threat-model.md#5-an-attacker-who-can-write):

- **witness ↔ chain**: một witness cài cùng release, cùng quyền quản trị với chain server thì
  không chứng minh gì cả.
- **file pin ↔ writer**: nếu writer chạm được vào trạng thái pin, việc pin không còn phát
  hiện được gì.
- **A₀ ↔ host có quyền ghi**: khoá niêm phong forward-secure nằm trên host viết trail thì
  việc truncation trở lại thành không phát hiện được.

Mọi hình thức triển khai chỉ là cách làm cho ba ràng buộc trên trở thành mặc định thay vì
một việc phải nhớ.

---

## 7. Nguồn và mức xác minh

Truy xuất ngày **2026-09-07**.

| Nguồn | Dùng cho | Trạng thái |
|---|---|---|
| Quyết định 1671/QĐ-TTg ngày 28/08/2026 - [PDF ký số](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/9/1671_qd-ttg_28082026-signed.signed.pdf) | toàn bộ §2: 6 quan điểm, mục tiêu 2030/2045, 9 trụ cột, 6 nhóm giải pháp, Phụ lục I chỉ tiêu 7/14/15/32, Phụ lục II nhiệm vụ 34, 63-66, 73, 81, 86-89, 94-96, Điều 2, Điều 3 | **chính thức**, ký số bởi Văn phòng Chính phủ (thời gian ký 03/09/2026), 64 trang, **bản scan không có lớp văn bản** - nội dung đọc từ ảnh trang. URL đã được kiểm: HTTP 200, `application/pdf`, `content-length` 25131696, khớp đúng byte với bản đã tải về và đọc |
| Luật Trí tuệ nhân tạo số 134/2025/QH15 - bản Công báo, **Công báo số 40 ngày 22/01/2026**, từ trang của số Công báo đó trên `congbao.chinhphu.vn` | Điều 7(4), 7(5), 8, 9, 10(1), 10(3), 11, 12(2)(b), 12(4), 13, 14(1)(c)(d)(e), 14(2)(b), 26, 27(2), 27(3), 28(3), 34, 35(1) | **bản Công báo chính thức, có lớp văn bản** - phần tiếng Việt trích ở đây được sao chép, không phải đọc lại từ ảnh, nên chính xác đến từng ký tự. **Cố ý không đưa URL tệp**: bản PDF được phục vụ từ một endpoint CDN sau một query string đã ký, sẽ không mở được với người đọc sau này; vì vậy dẫn số Công báo và trang của số đó, không dẫn tệp |
| Nghị định 142/2026/NĐ-CP ngày 30/04/2026 - [PDF ký số](https://datafiles.chinhphu.vn/cpp/files/vbpq/2026/4/142-2026-ndcp.signed.pdf) | Điều 6(1), 8(1)(a), 8(2)(b), 11(5), 12(6), 14(3)(b), 15(2)(c), 15(5)(b)(c), 16(2)(c), 19(1)-(4), 19(8), 20(3)(d), 20(6), 45, 46(1); Phụ lục biểu mẫu: AI01a, AI01b, AI02, AI08a | **chính thức**, ký số; đọc trực tiếp các trang đã nêu ở [§3.3](#33-văn-bản-nào-đã-đọc-bản-gốc-văn-bản-nào-chưa). **Bản scan không có lớp văn bản** - số điều khoản và lời văn đọc từ ảnh trang, nên ở đây một lỗi sao chép là khả năng thực tế theo cách không xảy ra với bản Luật. URL đã được kiểm: HTTP 200, `application/pdf`, `content-length` 3661910, khớp đúng byte với bản đã tải về và đọc |
| Thông tư 05/2026/TT-BKHCN - Khung đạo đức AI quốc gia (Luật Điều 26) | ngày hiệu lực, sự tồn tại của văn bản | **chưa truy xuất được bản gốc** - chỉ nguồn thứ cấp (cổng pháp luật thương mại và bản tin). Không mã điều/khoản nào của Thông tư được trích trong tài liệu này, cố ý |
| Quyết định 33/2026/QĐ-TTg - Danh mục hệ thống AI rủi ro cao (Luật Điều 13(4); NĐ Điều 7) | ngày hiệu lực, các nhóm lĩnh vực | **chưa truy xuất được bản gốc** - chỉ nguồn thứ cấp. Danh sách nhóm ở [§3.3](#33-văn-bản-nào-đã-đọc-bản-gốc-văn-bản-nào-chưa) mang nhãn `[Unverified]`; không số điều khoản nào được trích |
| Quyết định 127/QĐ-TTg ngày 26/01/2021 | chỉ nêu vì QĐ 1671 Điều 3(2) thay thế nó | **không truy xuất** - không nội dung nào của nó được dùng |
| `waxseal` tại commit trên nhánh làm việc | cột "waxseal 0.1.5 làm gì hôm nay" trong [§4](#4-ma-trận-đáp-ứng) | **đọc trực tiếp mã nguồn trong repo**; mọi đường dẫn module trong bảng đều kiểm chứng được bằng cách mở file |

Hai lưu ý về chất lượng nguồn, nói thẳng vì đây là chỗ dễ thổi phồng nhất:

1. QĐ 1671 và NĐ 142 là **bản scan không có lớp văn bản**. Nội dung được đọc từ ảnh trang.
   Với các trích dẫn nguyên văn dài, sai sót ở mức dấu và một vài ký tự là khả năng thực tế;
   trước khi dùng chính thức, hãy đối chiếu lại đúng trang của bản gốc.
2. Luật 134 là bản Công báo có lớp văn bản, nên các trích dẫn từ Luật ở đây là chính xác đến
   từng ký tự.

---

## 8. Điều tài liệu này **không** khẳng định

| Không khẳng định | Vì sao phải nói ra |
|---|---|
| **Rằng một nghĩa vụ nào đã được đáp ứng** | không hàng nào trong [§4](#4-ma-trận-đáp-ứng) là một phán quyết tuân thủ. Nhãn "Trực tiếp" nghĩa là *bằng chứng đi thẳng vào nội dung của yêu cầu*, không nghĩa là *yêu cầu đã xong* |
| **Rằng waxseal làm cho ai tuân thủ điều gì** | tuân thủ phụ thuộc vào quản trị, phạm vi, chính sách, kiểm soát và diễn giải pháp lý - tất cả nằm ngoài thư viện, và là việc xác định của bộ phận tuân thủ và pháp chế của tổ chức triển khai |
| **Rằng QĐ 1671 đặt ra một yêu cầu kỹ thuật nào** | nó là một chiến lược. Trình bày nó như một danh sách yêu cầu sẽ tạo ra một nghĩa vụ không tồn tại, và một lời hứa đáp ứng nghĩa vụ đó |
| **Rằng một hệ thống cụ thể thuộc hay không thuộc Danh mục rủi ro cao** | bản gốc QĐ 33/2026 chưa được đọc, và ngay cả khi đã đọc thì việc phân loại là trách nhiệm của nhà cung cấp theo Luật Đ.10(1) và NĐ Đ.6(1), không phải của một tài liệu nghiên cứu |
| **Rằng nội dung Thông tư 05/2026 đúng như mô tả ở đây** | `[Unverified]` - chưa đối chiếu bản gốc. Không mã điều/khoản nào của Thông tư được trích |
| **Rằng waxseal chứng minh một báo cáo sự cố đã được nộp** | nó chứng minh một *bản ghi* tồn tại tại một vị trí và không bị sửa. Nộp hay không nộp là một hành vi với một cơ quan, ở ngoài trail |
| **Rằng một thời hạn đã bị vi phạm** | mốc thời gian trên trail là lời khẳng định của bên ghi; cửa sổ 72 giờ là tham số operator nhập. Không đầu ra nào của waxseal khẳng định "đã vi phạm nghĩa vụ" |
| **Rằng không có bản ghi nghĩa là không có chuyện gì xảy ra** | toàn vẹn chuỗi ≠ tính đầy đủ của trail. Một quyết định, một sự cố, một lần can thiệp chưa từng được ghi thì không để lại khoảng trống nào để phát hiện |
| **Rằng cơ chế giám sát của con người không bị vô hiệu hoá** | Luật Đ.7(4) cấm việc vô hiệu hoá cơ chế; waxseal chỉ phát hiện việc làm sai lệch *bản ghi*. Cơ chế bị tắt thì không ghi gì, và một chuỗi trống vẫn `ok` |
| **Rằng thời gian trên trail là thời gian được chứng thực** | `ts` do bên gọi khẳng định. Thời gian được chứng thực chỉ đến từ một anchor, và chỉ ở dạng *cận trên* - "root này đã tồn tại trước thời điểm t" |
| **Rằng waxseal là chống sửa đổi tuyệt đối** | waxseal là **tamper-evident, không phải tamper-proof**. Kẻ tấn công có quyền ghi vẫn viết lại được trail; neo và niêm phong forward-secure giới hạn điều đó, và chỉ khi chúng nằm dưới một quyền quản trị khác. Xem [threat model §1](../security/threat-model.md#1-tamper-evident-is-not-tamper-proof) |
| **Rằng waxseal đạt tiêu chí "Make in Viet Nam"** | `[Unverified]` - tiêu chí công nhận và thủ tục chưa được kiểm tra. QĐ 1671 Quan điểm 5 và Phụ lục II nhiệm vụ 60, 71 nói về ưu tiên sản phẩm "Make in Viet Nam" trong mua sắm công; việc một dự án có đạt tiêu chí đó hay không là một kết luận hành chính, không phải một sự thật kỹ thuật |
| **Rằng có TSA được cấp phép tại Việt Nam với endpoint RFC 3161 dùng được** | `[Unverified]` - đây là câu hỏi phải kiểm tra khi thiết kế triển khai on-shore, không phải điều tài liệu này biết |
| **Đây là tư vấn pháp lý** | không phải. Tài liệu này không nêu tên tổ chức, sản phẩm hay cá nhân nào, và không thay thế việc đọc bản gốc |

### Nếu chỉ lấy một điều từ tài liệu này

Câu đáng đưa ra trước một người rà soát là hẹp, và chính vì hẹp mà nó bảo vệ được:

> *Bản ghi này - một quyết định AI, một sự cố, một lần can thiệp của con người - đã được ghi
> tại vị trí này trong chuỗi, dưới phiên bản mô hình này và policy này, với trạng thái giám
> sát của con người này, mang mốc thời gian do bên ghi khẳng định, và có thể chứng minh là
> không bị thay đổi kể từ đó - một cách độc lập với bên đang giữ nhật ký, và không tiết lộ
> bất kỳ bản ghi nào khác.*

Mọi thứ rộng hơn câu đó - hệ thống có được phân loại đúng không, báo cáo có được nộp không,
việc rà soát có thật không, nghĩa vụ có được đáp ứng không - là biện pháp kiểm soát của người
khác, và tài liệu này không nhận là đã phủ.
