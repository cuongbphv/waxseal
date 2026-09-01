# waxseal trong bối cảnh của nó

*[English](landscape.md)*

Có ba dự án hiện lên khi ai đó tìm thứ mà waxseal làm, hoặc tìm cái *tên* waxseal. Tài
liệu này ghi lại mỗi dự án là gì, khác biệt thật nằm ở đâu, và đã quyết định gì với từng
dự án. Đây là định vị, không phải bảng điểm. Một khác biệt sự thật giữa hai thiết kế không
phải là phán quyết về năng lực của bất kỳ ai.

**Các dữ kiện dưới đây được kiểm tra thế nào.** Metadata của repository, spec định dạng và
source của ChainProof, cùng hai lần grep README đã được kiểm tra lại trực tiếp vào
2026-08-31 bằng `gh api` đối chiếu với GitHub API công khai, chứ không mang sang từ lượt
khảo sát cùng ngày được ghi trong
[docs/plans/waxseal-0.1.5-contract.md](../plans/waxseal-0.1.5-contract.md)
§ Workstream G. Thứ gì không được kiểm tra theo cách đó thì mang một nhãn. Số sao thì thay
đổi; chúng được nêu kèm ngày đọc, và không điều gì ở đây dựa vào chúng.

---

## 1. vajramatt/chainproof — họ hàng gần nhất về mặt cấu trúc

Go, MIT, repository tạo 2026-08-16, 0 sao (đọc 2026-08-31). Mô tả của chính họ là "Local,
open-source provenance for any AI agent": một ledger provenance cục bộ với một cockpit TUI
và một web explorer, trên một tệp SQLite cục bộ.

Cấu trúc chuỗi là cấu trúc kinh điển, và cũng đúng là cấu trúc waxseal dùng.
`spec/provenance-v1.md` tại HEAD đặc tả SHA-256 trên JSON UTF-8 dạng canonical, một
`previous_hash` đầu tiên gồm 64 chữ số 0, số thứ tự liền mạch tính từ 0, và một verifier
buộc phải kiểm genesis, tính liền mạch, các liên kết prev-hash, và mọi hash sự kiện. Spec
đó cũng thẳng thắn về việc một chuỗi mua được gì và không mua được gì, bằng những lời mà
repo này không có gì để tranh luận:

> "A valid chain establishes continuity of the recorded bytes. It does not
> establish that the report was truthful or complete."
>
> *(Nghĩa: một chuỗi hợp lệ thiết lập tính liên tục của các byte đã được ghi. Nó không
> thiết lập rằng báo cáo là trung thực hay đầy đủ.)*

Ba khác biệt so với waxseal là khác biệt thực chất chứ không phải hình thức.

**Sự kiện được hash bao gồm cả payload lồng bên trong.** Sự kiện được hash của ChainProof
là một object JSON gồm mười hai trường, và trường số 10 là `payload` — một giá trị JSON
tuỳ ý, được hash tại chỗ cùng với `artifacts` và `extensions`. Vậy nên các byte mà chuỗi
cam kết sẽ dịch chuyển mỗi khi hình dạng của payload dịch chuyển. waxseal cố ý tách hai
thứ đó ra: chuỗi chỉ hash `EntryHeader`, và payload đi vào đó dưới dạng một
`payload_hash` duy nhất — đó là lý do một thay đổi schema của payload không bao giờ động
tới chuỗi (SPEC.md § 2, CLAUDE.md "Envelope-based chain"). Dạng canonical cũng khác, và
khác biệt nằm ở các điều kiện phụ. ChainProof canonical hoá JSON — sắp khoá đệ quy, xuất
dạng compact — và phát biểu "Undefined values are rejected", một điều kiện mà cài đặt
phải tiếp tục giữ. Encoding lp64 của waxseal gắn tag cho từng trường (`0x00` cho vắng
mặt, `0x01` + UTF-8 cho một chuỗi) dưới một length prefix 8 byte, nên tính đơn ánh giữ
được vô điều kiện và không có lớp đầu vào nào phải loại bỏ. Hash một serialization JSON là
cách làm mà CLAUDE.md loại trừ cho waxseal ("never hash a serialization you do not
control"); đó là một ràng buộc trên thư viện này, không phải một kết luận về thư viện của
họ.

**`schema_version` là chuỗi thứ tự `1`.** Nó là trường số 1 của sự kiện được hash, kiểu
chuỗi thuần trong `internal/proof/types.go`, không có fingerprint nào trên bộ trường. Đây
đúng là loại danh tính phiên bản mà waxseal tồn tại để loại bỏ. Một số thứ tự viết tay
không thay đổi khi bộ trường được hash thay đổi, và đó chính là cách "migration 060" biến
một bộ trường được nới rộng thành một báo động giả mạo diện rộng, và cách beads v1.2.2
biến một số thứ tự không nhận ra được thành một lỗi chí tử. `hash_version` của waxseal là
SHA-256 của version descriptor dạng canonical, nên việc nới rộng tuple sẽ làm đổi danh
tính bất kể có ai nhớ ra hay không.

**Không có anchoring bên ngoài, không seal, không witness, không head đã ghim trong v1.**
Một lượt grep trên toàn bộ 29 tệp `.go` và `.md` tại HEAD tìm `rfc 3161`, `tsa`,
`opentimestamp`, `witness`, `forward-secure`, `fssagg`, và `pin` trả về một hit duy nhất,
và đó là văn xuôi mô tả chế độ thu thập `observed` ("ChainProof witnessed it directly"),
không phải một giao thức witness. Do vậy mọi thứ trong
[docs/security/threat-model.vi.md](../security/threat-model.vi.md) § 1 về những bản sao
được giữ ngoài tầm với của kẻ tấn công hiện chưa có đối ứng bên đó.

### Về sự giống nhau

Thoạt nhìn hai thiết kế trông giống nhau, và lời giải thích đơn giản là sự hội tụ: một
chuỗi hash trên các sự kiện của agent là kiến thức phổ thông, và cả hai dự án đều với tới
cách kiến tạo tiêu chuẩn cho cùng một vấn đề trong cùng vài tuần. Thêm vài điểm hội tụ
nữa, không phải bằng chứng cho điều gì hơn thế: ChainProof có `integrations/openclaw`,
waxseal có `src/waxseal/sources/openclaw.py`, và cả hai đều dùng từ `imported` — dù cho
những thứ khác nhau. `imported` của ChainProof là một trong bốn chế độ thu thập, nhãn cho
việc một sự kiện đơn lẻ được lấy về bằng cách nào; còn imported trail của waxseal là cả
một trail ngoại lai được nạp vào ở dạng chỉ đọc để kiểm chứng.

[Inference — căn cứ: các ngày tạo công khai (ChainProof 2026-08-16, waxseal 0.1.0 phát
hành 2026-08-21) và độ sâu của những khác biệt thiết kế ở trên, vốn thuộc về kiến trúc
chứ không phải tình cờ] không dự án nào sao chép dự án kia.

**Quyết định (chủ repository, 31/08/2026): không tiếp nhận gì từ ChainProof.** Hướng đi
của riêng waxseal là tính năng imported-trail sẽ ra trong 0.1.5 (Workstream I): nạp và
kiểm chứng các trail jsonl/db ngoại lai trên self-hosted server, lưu ở dạng chỉ đọc,
không bao giờ mở rộng thêm. Nguồn gốc của nó là nhu cầu của chính chủ repo trong việc kiểm
chứng tập trung các trail ngoại lai, và tiền lệ trong repo có trước lượt khảo sát:
`src/waxseal/sources/openclaw.py` vốn đã là một importer.

---

## 2. microsoft/agent-governance-toolkit — một tầng khác, không phải đối thủ

Python, MIT, repository tạo 2026-03-02, 6,164 sao (đọc 2026-08-31; kế hoạch 0.1.5 ghi
6,155 cùng ngày, đúng như những gì một bộ đếm sống vẫn làm). Cưỡng chế policy, định danh
zero-trust, sandbox thực thi, và reliability engineering, với README tuyên bố phủ 10/10
của OWASP Agentic Top 10, và được ghi là "Public Preview -- production-quality public
preview releases. May have breaking changes before GA."

Khác biệt là ở tầng, không phải ở chất lượng. AGT là một **control plane**: nó quyết định
một hành động có xảy ra hay không. [Unverified — chỉ dựa trên README, chưa chạy AGT và
chưa đọc source của nó] README của họ mô tả `govern()` bọc quanh một tool sao cho mọi lần
gọi đều được kiểm tra đối chiếu với một policy YAML, được ghi vào một audit trail, và bị
từ chối bằng `GovernanceDenied` khi policy chặn lại. waxseal là một **evidence plane**: nó
chứng minh rằng bản ghi về những gì đã xảy ra không thay đổi từ lúc đó. Chặn và chứng minh
là hai công việc khác nhau, và một triển khai hoàn toàn có thể hợp lý khi muốn cả hai.

README của AGT mô tả audit log của họ là tamper-evident và liệt kê một đặc tả audit
(`docs/specs/AUDIT-COMPLIANCE-1.0.md`, có nêu Merkle audit, ánh xạ tuân thủ, và một
Decision BOM) trong số các tài liệu của họ.
[Unverified — chỉ dựa trên README, chưa đọc code audit của AGT] không điều gì ở đây so
sánh độ sâu của hai cơ chế audit; spec đó và code bên dưới nó chưa được đọc, và một so
sánh rút ra từ một README sẽ đúng là loại khẳng định mà các quy tắc tài liệu của chính
repo này loại trừ.

Cách họ đặt vấn đề audit đáng được dẫn lại, vì nó chính là câu hỏi mà waxseal trả lời từ
phía bên kia:

> "**3. Can you prove what happened?** Auditors and regulators need
> tamper-evident records of every decision: what policy was active, what the
> agent requested, and why it was allowed or denied."
>
> *(Nghĩa: "**3. Bạn có chứng minh được điều gì đã xảy ra không?** Kiểm toán viên và cơ
> quan quản lý cần các bản ghi tamper-evident cho mọi quyết định: policy nào đang có hiệu
> lực, agent đã yêu cầu gì, và vì sao yêu cầu đó được cho phép hay bị từ chối.")*

**Quyết định (chủ repository, 31/08/2026): xây `integrations/agt.py` trong 0.1.5** —
waxseal như một audit sink phía sau các quyết định governance của AGT, theo đúng khuôn
dạng thư viện của những integration đã có, không thêm dependency nào. Xem § Workstream H
của kế hoạch 0.1.5.

---

## 3. degenlegion-com/waxseal-sdk — cùng tên, khác sản phẩm

TypeScript, MIT, repository tạo 2026-06-22, 1 sao (đọc 2026-08-31), kèm một dịch vụ tại
waxseal.id. Đây là một sản phẩm định danh Ed25519: "One Ed25519 keypair. One 64-character
fingerprint. Permanent on-chain record", phát hành dưới tên `@waxseal/verify` và
`@waxseal/mcp` trên npm, cộng thêm một server MCP để ký và kiểm chứng cho Claude, Cursor,
và Windsurf.

Đây không phải một đối thủ về chức năng, và phép kiểm rất ngắn: một lượt grep README của
họ tìm `hash chain`, `hash-chain`, `audit trail`, `audit log`, và `tamper` trả về 0 hit
(đọc 2026-08-31). Hai dự án trả lời hai câu hỏi khác nhau. Câu của họ là "agent này là
ai, và họ có ký cái này không". Câu của waxseal là "điều gì đã xảy ra, và bản ghi về nó
còn nguyên vẹn không".

Rủi ro ở đây là trùng tên, không phải trùng sản phẩm. README của họ trình bày waxseal.id
như dịch vụ của chính họ, và họ phát hành dưới npm scope `@waxseal`: cả
`@waxseal/verify` và `@waxseal/mcp` đều trả `200` từ npm registry, và waxseal.id trả `200`
(kiểm 2026-08-31; một phản hồi được phục vụ không phải là bằng chứng về việc ai sở hữu
thứ nào, và không có hồ sơ đăng ký tên miền hay nhãn hiệu nào được tra cứu). Họ công khai
trước, 2026-06-22 so với 0.1.0 của waxseal vào 2026-08-21 (CHANGELOG.md). Dự án này giữ
tên `waxseal` trên PyPI, ở 0.1.4. Cả hai đều nhắm vào không gian AI agent, nên cùng một
lượt tìm tên sẽ chạm tới bên nào cũng được.

Việc đổi tên hay đăng ký nhãn hiệu là quyết định của riêng chủ repository. Tài liệu này
không đề xuất bên nào trong hai việc đó, và không nêu quan điểm. Nó cũng không dùng cũng
không tích hợp dịch vụ của họ.

### Phân biệt

| Bạn đang tìm | Bạn muốn | Không phải cái này |
|---|---|---|
| Một audit hash chain: trail chỉ ghi thêm, kiểm chứng tamper-evident, anchoring, phán quyết ba giá trị | `waxseal` trên **PyPI** (Python), chính repository này | — |
| Định danh mật mã: keypair Ed25519, fingerprint, profile on-chain, server ký MCP | **WaxSeal SDK** trên npm (`@waxseal/verify`, `@waxseal/mcp`), waxseal.id | repository này |

Cùng lưu ý đó, gói trong một câu, nằm ở [README.vi.md](../../README.vi.md) trong phần
Cài đặt, nơi người đã cài sai package sẽ thấy nó.

---

## Những gì đã tiếp nhận, gom về một chỗ

| Từ đâu | Đã tiếp nhận | Ở đâu |
|---|---|---|
| ChainProof | Không gì cả (quyết định của chủ repo, 31/08/2026) | — |
| Sự tồn tại của ChainProof | Không đổi hướng. Tính năng imported-trail — thứ trông như thể là một phản ứng với họ — có nguồn độc lập: nhu cầu của chủ repo, tiền lệ `sources/openclaw.py` | Workstream I, 0.1.5 |
| AGT | Tích hợp như một audit sink, không thêm dependency | `integrations/agt.py`, Workstream H, 0.1.5 |
| WaxSeal SDK (npm) | Không gì cả. Chỉ phân biệt tên | tài liệu này, lưu ý ở phần Install của README |

Thiết kế công khai của Hedera được xử lý riêng, trong
[hedera-lessons.vi.md](hedera-lessons.vi.md).
