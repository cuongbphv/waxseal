# Những bài học đọc được từ thiết kế công khai của Hedera

*[English](hedera-lessons.md)*

**Tài liệu này không phải là gì.** waxseal không dùng Hedera. Nó không trả phí mạng nào
cho họ, không phát hành adapter nào cho họ, và không làm việc phát triển nào thay họ.
Không điều gì ở đây là một kế hoạch tích hợp và không điều gì ở đây tạo ra một dependency
vào dịch vụ của họ. Phần tiếp theo mổ xẻ thiết kế đã công bố của họ để rút ra những ý
tưởng mà waxseal sở hữu trọn vẹn và chạy trên hạ tầng của riêng mình.

Đọc kiến trúc của người khác thì rẻ và chính đáng; gửi lưu lượng cho họ là một quyết định
khác, và quyết định đó đã không được đưa ra.

**Những gì đã được kiểm tra, và bằng cách nào.** Hai hành vi của mirror node công khai
trên mainnet đã được kiểm chứng trực tiếp vào 2026-08-31 từ repo này bằng `curl`, không
gửi credential nào cả:

```
$ curl -D - https://mainnet-public.mirrornode.hedera.com/api/v1/network/nodes?limit=1
HTTP/2 200
content-type: application/json;charset=UTF-8

$ curl 'https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.3959298/messages?limit=2&order=desc'
HTTP 200
# mỗi message mang theo: consensus_timestamp, sequence_number,
# running_hash, running_hash_version
```

Hai dữ kiện suy ra từ hai lệnh đó và được nêu ở đây như đã kiểm chứng: một endpoint đọc
công khai không cần xác thực trả về REST JSON, và mỗi consensus message nó phục vụ đều
mang một running hash cùng với một số thứ tự liền mạch. Mọi thứ khác về hành vi của Hedera
ở dưới đây — running hash được kiến tạo thế nào, consensus timestamp bảo đảm điều gì, cái
gì tốn bao nhiêu — đều chưa được kiểm chứng bằng lệnh trong phiên làm việc này và được gắn
nhãn tương ứng.

---

## 1. Khuôn dạng mirror-node → điểm đọc công khai

**Ý tưởng.** Một mặt đọc công khai trả lời mà không cần credential, và
[Unverified — theo lượt đọc tài liệu công khai của Hedera ngày 31/08/2026 trong kế hoạch
0.1.5; phiên này chỉ kiểm chứng rằng endpoint đó trả lời các lượt đọc mà không cần
credential, chứ không kiểm chứng rằng nó không thể nhận lượt ghi nào] nó nằm tách khỏi
đường ghi chứ không phải là chính đường ghi với phần xác thực được nới ra. Một bên thứ ba
kiểm toán mạng không cần được bên đã ghi dữ liệu cấp cho bất cứ thứ gì. Lệnh `curl` đã
kiểm chứng ở trên chính là nửa "không cần credential" đang được thực thi: không khoá,
không account, JSON trả về.

**Vì sao đáng tiếp nhận.** Một quyền đọc là một bit mà ai đó có thể bật tắt. Một mặt đọc
riêng biệt, không có đường ghi nào trên đó, là một sự thật thuộc về cấu trúc. Khác biệt
này lộ ra đúng lúc nó quan trọng, tức là khi bên vận hành đường ghi lại chính là bên đang
bị đặt câu hỏi. Mô hình mối đe doạ của waxseal vốn đã xoay quanh sự phân biệt này — một
bản sao được giữ dưới một quyền quản trị khác là thứ duy nhất làm cho một lần viết lại trở
nên thấy được
([docs/security/threat-model.vi.md](../security/threat-model.vi.md) § 1) — và một kiểm
toán viên phải xin chủ trail cấp quyền đọc thì không hề đang giữ một bản sao độc lập theo
bất kỳ nghĩa hữu dụng nào.

**Đã tiếp nhận, và đã xây xong.** Self-hosted server (Workstream I, đã vào trong commit
`9162abf`) phục vụ một điểm đọc công khai không cần credential tại `/public/v1`, trong
`server/waxseal_server/api/public.py`, mà docstring của module nêu đúng cái ràng buộc nó
tồn tại để giữ:

> "This is not 'the same data with authentication turned off'. It is a separate
> surface, and a test asserts that every route on it is `GET`."
>
> *(Nghĩa: đây không phải "cùng dữ liệu đó với phần xác thực bị tắt đi". Nó là một mặt
> riêng biệt, và có một test khẳng định rằng mọi route trên đó đều là `GET`.)*

Các route nó phơi ra là danh sách chain, head của một chain, các entry của nó, và receipt
chain của chính server (gồm cả một lượt verify và một lượt cross-check), cộng thêm khung
nhìn witness và tuyên bố phạm vi. Một bên thứ ba kiểm những thứ đó mà không cần được cấp
gì, và không phần nào trong số đó bị để lại làm backlog.

## 2. Running hash theo từng topic → receipt chain của server

**Ý tưởng.** [Unverified — theo lượt đọc tài liệu HCS công khai của Hedera ngày
31/08/2026 trong kế hoạch 0.1.5; bản thân cách kiến tạo hash chưa được kiểm chứng bằng
lệnh] consensus service ràng mỗi message vào một running hash phía dịch vụ, nên bản ghi
của chính dịch vụ về thứ tự nó đã nhận các message cũng được xâu chuỗi. Nửa quan sát được
thì đã kiểm chứng: mirror node trả về một `running_hash` và một `running_hash_version` cho
mỗi message, tại các số thứ tự liền mạch.

**Vì sao đáng tiếp nhận.** Một witness chỉ trả lời câu hỏi thì sau này có thể trả lời
khác đi. Một witness bị xâu chuỗi bởi chính các câu trả lời của mình thì không thể kể lại
khác đi phần lịch sử nó đã xác nhận mà không để lần kể lại ấy lộ ra với bất kỳ ai đã giữ
một câu trả lời trước đó. Điều đó nâng ngữ nghĩa witness từ "phản hồi một truy vấn" lên
"bị ràng buộc bởi các phản hồi của mình", và nó bịt một khoảng trống mà mô hình
trusted-writer của waxseal trước đây còn để hở ở phía server.

**Đã tiếp nhận, và đã xây xong.** `server/waxseal_server/domain/receipts.py` giữ một
running hash trên các entry mà server đã xác nhận, theo thứ tự xác nhận, đóng frame theo
SPEC.md § 19 và được đặc tả như một wire contract trong REMOTE.md § 10. Docstring của nó
nêu rõ điểm chính:

> "It exists so the server is bound by its own answers: it cannot later re-tell
> the history of what it accepted without the retelling being visible to anyone
> who kept a receipt."
>
> *(Nghĩa: nó tồn tại để server bị ràng buộc bởi chính các câu trả lời của mình: sau này
> nó không thể kể lại phần lịch sử những gì nó đã nhận mà không để lần kể lại ấy lộ ra
> với bất kỳ ai đã giữ một receipt.)*

Frame này dùng lại `lp` import từ thư viện thay vì phát biểu lại encoding, nên server
không thể lệch khỏi đúng bộ byte mà client kiểm chứng. Đây là một tính năng của waxseal
trên hạ tầng self-hosted. Không đồng xu nào rời khỏi ví nào cho việc này.

Một quan sát từ phản hồi đã kiểm chứng, được ghi lại chứ không được hành động theo: trường
`running_hash_version` là một định danh phiên bản dạng số thứ tự trên cách kiến tạo hash,
đúng cái hình dạng danh tính phiên bản mà repo này phản đối cho danh tính schema theo từng
dòng (CLAUDE.md, "migration 060"). Receipt frame của waxseal mang một tiền tố literal cố
định (`waxseal-receipt-v1`) được ghim bởi SPEC.md § 19 chứ không phải một fingerprint của
descriptor. Việc receipt frame có nên được định danh bằng một fingerprint theo cách
`hash_version` làm hay không vẫn là một câu hỏi mở dành cho chủ repository; tài liệu này
không quyết định nó, và receipt chain ở dạng đã phát hành là một frame được phân tách miền
với một spec đã đóng băng, không phải một trường mà verifier chọn đường code từ đó.

## 3. Mô hình phí phẳng dự đoán được → một case study cho `c`, và không gì khác

**Không tiếp nhận code nào.** [Unverified — theo lượt đọc tài liệu công khai của Hedera
ngày 31/08/2026 trong kế hoạch 0.1.5; phiên này không tải trang giá nào] điểm thiết kế
đáng chú ý là phí trên mỗi message thì dự đoán được và gần như phẳng chứ không định giá
theo đấu giá, nên một bên vận hành có thể nêu trước chi phí biên cho mỗi lượt anchoring
thay vì phải ước lượng một phân phối.

Tính dự đoán được ấy là phần duy nhất waxseal vay mượn, và nó vay mượn như một đầu vào số
học chứ không phải như code. `src/waxseal/domain/cadence.py` nhận `c`, chi phí biên cho
mỗi lượt anchor, như một keyword argument bắt buộc không có giá trị mặc định, vì đúng lý
do docstring của nó nêu: `w`, `rho`, và `c` là những phép đo mà chỉ bên vận hành nắm, và
bịa ra một con số nghe có lý cho bất kỳ cái nào trong số đó là bịa ra một phép đo. Vậy
nên một công nghệ anchor phí phẳng là ca dễ cho mô hình đó — `c` là một con số bên vận
hành đọc được từ bảng giá — còn một công nghệ định giá theo đấu giá là ca khó, nơi `c` là
một phân phối mà bên vận hành phải tóm lược lại trước khi `optimal_cadence` chấp nhận nó.
Không điều gì trong chuyện này làm đổi code. Nó là một ví dụ đã làm sẵn về thứ gì khiến
tham số `c` dễ hay khó cung cấp một cách trung thực.

---

## Từ ý tưởng thành tính năng, gom về một bảng

| Ý tưởng đọc được từ thiết kế của họ | Trạng thái trong waxseal | Ở đâu |
|---|---|---|
| Mặt đọc công khai không cần credential, tách khỏi đường ghi | Đã xây trong 0.1.5 | `server/waxseal_server/api/public.py` (`/public/v1`), commit `9162abf` |
| Một dịch vụ bị xâu chuỗi bởi chính các lượt xác nhận của mình | Đã xây trong 0.1.5 | `server/waxseal_server/domain/receipts.py`, SPEC.md § 19, REMOTE.md § 10 |
| Phí trên mỗi lượt thao tác phẳng và dự đoán được | Không tiếp nhận code; chỉ là case study | `src/waxseal/domain/cadence.py`, tham số `c` |

Không ý tưởng nào trong hai ý tưởng đã tiếp nhận đưa bất kỳ lưu lượng hay bất kỳ đồng tiền
nào tới thiết kế mà nó được đọc ra từ đó.
