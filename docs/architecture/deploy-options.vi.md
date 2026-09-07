# Các phương án triển khai - cài gì ở đâu, và cái gì đi ra khỏi biên giới

*[English](deploy-options.md)*

Sáu cách đặt waxseal vào một nơi nào đó, và hai câu hỏi người vận hành phải trả
lời cho từng cách: thành phần này thuộc trust domain nào trong bốn domain, và có
gì vượt biên giới hay không.

Tài liệu này không lặp lại [`deploy/README.md`](../../deploy/README.md) - file
đó sở hữu phần ánh xạ thẩm quyền cho mọi file dưới `deploy/` - cũng không lặp
lại [deployment.md](deployment.vi.md), file sở hữu phần topology và mô hình tin
cậy. Đọc hai file đó trước. File này là để *chọn*.

---

## 1. Các phương án

| Phương án | Cách cài | Phù hợp cho | Domain thường thuộc về |
|---|---|---|---|
| `pip` / `uv tool` / `pipx` | `uv tool install waxseal` | máy lập trình viên, runner CI | application, hoặc verifier |
| `deploy/install.sh` | `curl … \| sh` | host không có sẵn hệ sinh thái Python | verifier, anchor client |
| Zipapp một file | `python3 waxseal-<v>.pyz verify trail.jsonl` | soát xét trên máy ngắt mạng, laptop của cơ quan | verifier |
| Image runtime | `docker run ghcr.io/cuongbphv/waxseal` | job theo lịch, runtime niêm phong | verifier, anchor client |
| Compose | `deploy/compose/compose.yaml` | một máy, môi trường phát triển | **cả bốn cùng lúc - xem §3** |
| Helm, hai chart | `deploy/helm/waxseal-{server,verifier}` | cluster | chain, và verifier tách riêng |

Zipapp đáng được một đoạn riêng. Vì danh sách dependency lúc chạy là rỗng và sẽ
mãi rỗng, một file cộng với `python3` đã là một verifier hoàn chỉnh: không tải gì
thêm, không cài gì thêm, và không phải tin thứ gì ngoài trình thông dịch đã có
trên máy. Đó chính là hình dạng mà một cuộc soát xét ngoại tuyến cần, và nó là
hệ quả trực tiếp của một invariant, không phải một mánh đóng gói.

## 2. Những thành phần tuyệt đối không được dùng chung thẩm quyền

Ba cặp. Mỗi cặp là một cơ chế chỉ còn hiệu lực khi cặp đó bị tách ra, và mỗi cặp
khi bị gộp lại thì hỏng **âm thầm** chứ không hỏng ồn ào.

- **Một witness và chuỗi mà nó làm chứng.** Witness bắt được split view - server
  cho người đọc này thấy một lịch sử và người đọc khác thấy một lịch sử khác.
  Cùng thẩm quyền với server thì nó chỉ thấy đúng những gì server cho thấy. Đó
  là lý do không chart Helm nào ở đây kèm theo một witness.
- **File pin và writer của trail.** Pin bắt được việc lịch sử mà một verifier đã
  xác nhận bị viết lại. Một writer chạm được tới file pin thì dịch được nó. Vì
  vậy chart verifier đặt pin trên claim riêng của nó, unit systemd đặt pin trong
  state directory riêng của verifier, và không bên nào mượn user của chain.
- **Khoá niêm phong `A₀` và bất kỳ host có quyền ghi.** Forward-secure seal chỉ
  phát hiện được việc viết lại phần đuôi khi kẻ tấn công không lấy được một
  epoch khoá trước đó.

## 3. Compose là một thẩm quyền, và nó nói thẳng điều đó

Overlay compose thực sự hữu ích và cũng thực sự không phải một topology sản
xuất: một máy, một người vận hành, một socket `docker`. Mọi điều nói ở trên về
việc tách thẩm quyền đều không thể cưỡng chế ở đó, nên không gì trong nó được
đọc thành bằng chứng về sự tách biệt. Chính file đó nói vậy. Dùng nó để phát
triển, để demo, để học các exit code - rồi chuyển verifier sang nơi khác trước
khi dựa vào một phép phát hiện cần tới hai thẩm quyền mới hoạt động.

## 4. Dữ liệu nằm ở đâu, và cái gì vượt biên giới

Mọi thành phần ở đây chạy tại chỗ. Thư viện đọc và ghi file cục bộ, server giữ
trail trên volume cục bộ, verifier đọc qua HTTP. Không có gì gọi về nhà, và
không có telemetry nào để tắt.

Có đúng một lớp lưu lượng đi ra ngoài, và người vận hành phải mô tả được nó:

| Cái đi ra | Đi tới | Đó là gì |
|---|---|---|
| Một Merkle root, hoặc hash của nó | một timestamp authority theo RFC 3161 | yêu cầu thời gian được chứng thực |
| Một Merkle root | một calendar OpenTimestamps | yêu cầu một proof neo vào Bitcoin |
| Một checkpoint | một witness | một lần gửi ký gửi, để split view bắt được |
| Một checkpoint | một ledger EVM | một giao dịch, để một writer chậm anchor lộ ra |

Không có payload, không có bản ghi quyết định, không có dữ liệu cá nhân, và
không có định danh nào từ payload xuất hiện trong bất kỳ cái nào - một anchor
mang một root và một số thứ tự. Nhưng một hash vẫn là dữ liệu, và một điểm đến
vẫn là một điểm đến, nên đây là luồng phải **khai báo** chứ không phải luồng để
bỏ qua, và điểm đến là thứ người vận hành tự chọn. waxseal không đặt tên một
timestamp authority mặc định nào và không đặt tên một trust anchor mặc định nào:
chọn giúp sẽ là quyết định tổ chức tin ai mà không nói ra ở bất kỳ dòng output
nào.

Với một triển khai phải giữ mọi thứ trong một phạm vi pháp lý, cả bốn sink trên
về nguyên tắc đều có phương án trong nước - RFC 3161 là một giao thức chứ không
phải một nhà cung cấp, và một witness là bất kỳ host nào thuộc thẩm quyền khác
mà trả lời đúng wire contract. `[Unverified]` Việc một tổ chức cung cấp dịch vụ
cấp dấu thời gian được cấp phép tại Việt Nam hiện có endpoint RFC 3161 dùng được
hay không thì chưa được kiểm chứng; hãy coi đó là câu hỏi cần trả lời khi mua
sắm, không phải một giả định để xây lên. Chạy hoàn toàn không có anchor là một
lựa chọn được hỗ trợ và là một lựa chọn trung thực: báo cáo sẽ nói phép kiểm
anchor không được chạy, và điều đó không đồng nghĩa với nói rằng nó đã đạt.

## 5. Kiểm chứng, dù bạn chọn phương án nào

Exit code chính là giao diện, và ở đâu cũng như nhau:

| Exit | Nghĩa | Nên đi tới đâu |
|---:|---|---|
| 0 | nguyên vẹn | không đâu cả |
| 1 | bị phá, kèm seq và lý do của điểm vỡ đầu tiên | bộ phận an ninh - bảo toàn, không sửa |
| 2 | nguyên vẹn, nhưng có hàng bản build này không kiểm được theo tên | quản lý phát hành, không phải bộ phận an ninh |
| 3 | đường dẫn trail không tồn tại | cấu hình |

Tuyệt đối không nối một hành động khắc phục tự động vào exit 1. waxseal báo cáo
và không sửa, và runbook cũng không được sửa: hàng nào là hàng bị can thiệp là
quyết định chỉ con người mới đưa ra được, và một lần "sửa" sẽ phá đúng cái bằng
chứng mà toà án hoặc cơ quan quản lý cần.
