# Các unit systemd - waxseal khi không dùng Kubernetes

*[English](README.md)*

Ba unit, mỗi unit một timer, và một `*.env.example` bên cạnh mỗi unit.

| Unit | Chạy bằng | Quyền trên trail | Trust domain |
|---|---|---|---|
| `waxseal-verify@.service` | `DynamicUser` (nhất thời) | **chỉ đọc** | verifier |
| `waxseal-anchor@.service` | user `waxseal` của chain | đọc-ghi (sidecar `.anchors` nằm cạnh trail) | chain -> anchor client |
| `waxseal-openclaw-ingest.service` | user `waxseal` của chain | đọc-ghi (nó append) | application -> chain |

Sự phân tách ở cột "Chạy bằng" là luận điểm an ninh, không phải một lựa chọn
hình thức. Mục 1 của `docs/architecture/deployment.vi.md`: tính chất chịu lực
của topology tham chiếu là các domain thuộc những **thẩm quyền quản trị** khác
nhau. Trên một host, một danh tính Unix là biên giới mạnh nhất có sẵn, nên
verifier được cấp một danh tính không phải của bên ghi.

## Cài đặt

```sh
sudo install -o root -g root -m 0644 \
  waxseal-verify@.service waxseal-verify@.timer \
  waxseal-anchor@.service waxseal-anchor@.timer \
  waxseal-openclaw-ingest.service waxseal-openclaw-ingest.timer \
  /etc/systemd/system/

sudo install -d -o root -g root -m 0755 /etc/waxseal
sudo install -o root -g root  -m 0640 verify.env.example          /etc/waxseal/verify.env
sudo install -o root -g waxseal -m 0640 anchor.env.example        /etc/waxseal/anchor.env
sudo install -o root -g waxseal -m 0640 openclaw-ingest.env.example /etc/waxseal/openclaw-ingest.env

sudo systemctl daemon-reload
```

Sau đó **sửa ba file env** - chúng được phát hành với mọi giá trị đã comment
và không có credential thật nào, vì chúng là file ví dụ trong một repository
công khai.

`waxseal-openclaw-ingest.service` còn cần sửa đường dẫn trình thông dịch ở
`ExecStart` trước khi nó chạy được. Xem mục "Trình thông dịch" bên dưới.

## Bật

Tham số instance của hai unit dạng template là **đường dẫn trail**, tuyệt đối
và đã escape. `systemd-escape` không phải tuỳ chọn: một đường dẫn có chứa `/`,
mà đó chính là ký tự phân tách tên instance.

```sh
TRAIL=/var/lib/waxseal/chains/default/trail.jsonl
sudo systemctl enable --now "waxseal-verify@$(systemd-escape "$TRAIL").timer"
sudo systemctl enable --now "waxseal-anchor@$(systemd-escape "$TRAIL").timer"
sudo systemctl enable --now waxseal-openclaw-ingest.timer
```

**Chỉ dùng đường dẫn tuyệt đối, và tuyệt đối không có dấu `~` ở đầu.**
`resolve_trail()` trong `src/waxseal/integrations/_trail.py` lấy `WAXSEAL_TRAIL`
nguyên văn và *từ chối* một giá trị bắt đầu bằng dấu ngã, và docstring của nó
nêu chính các unit systemd là lý do: không có shell nào chạy giữa file unit và
tiến trình, nên dấu ngã còn nguyên và bên ghi sẽ tạo ra một thư mục tên đúng là
`~` dưới cwd của nó. Điều này áp dụng cho mọi đường dẫn trong các unit và file
env ở đây.

## Đọc các timer

```sh
systemctl list-timers 'waxseal-*'

# lần chạy gần nhất của một instance
TRAIL=/var/lib/waxseal/chains/default/trail.jsonl
journalctl -u "waxseal-verify@$(systemd-escape "$TRAIL").service" -n 50 --no-pager

# EXIT CODE - chính nó là giao diện
systemctl show -p ExecMainStatus \
  "waxseal-verify@$(systemd-escape "$TRAIL").service"
```

### Exit code chính là giao diện

| Exit | Nghĩa | Đi tới đâu |
|---:|---|---|
| 0 | nguyên vẹn | không đâu cả |
| 1 | bị phá - điểm vỡ đầu tiên được in kèm seq và lý do | **bộ phận an ninh.** Bảo toàn. Không sửa. |
| 2 | nguyên vẹn, nhưng có hàng bản build này không kiểm được theo tên | **quản lý phát hành**, không phải SOC |
| 3 | đường dẫn trail không tồn tại | lỗi cấu hình: không đọc gì, không tạo gì |

`SuccessExitStatus` trong `waxseal-verify@.service` chỉ liệt kê **0**. Nới nó
ra để nhận cả 2 sẽ làm `systemctl status` xanh cho một trạng thái vốn không
phải ok cũng không phải broken, và việc làm phẳng ba giá trị về hai đó chính là
thất bại mà cả dự án này tồn tại để ngăn - đó là cách "Migration 060" thành một
báo động can thiệp hàng loạt sai, và cách beads v1.2.2 biến một phiên bản
schema không nhận ra thành lỗi chí tử.

Exit 2 **không phải là đạt**. Hãy cảnh báo về nó, và chuyển nó tới người phụ
trách phiên bản.

**Tuyệt đối không nối một hành động khắc phục tự động vào exit 1.** waxseal báo
cáo; nó không sửa (CLAUDE.md rule 4). Không đường code nào được viết lại, đảo
thứ tự hay "sửa" các entry, và unit `OnFailure=` của bạn cũng vậy. Hàng nào là
hàng bị can thiệp là quyết định chỉ người vận hành đưa ra được, và một automation
"phục hồi từ backup" đã xoá đúng bản duy nhất của thứ vừa bị phát hiện.

Nếu bạn thêm một drop-in `OnFailure=`, hãy làm nó *thông báo* - đừng bao giờ
để nó hành động:

```ini
# /etc/systemd/system/waxseal-verify@.service.d/notify.conf
[Unit]
OnFailure=waxseal-alert@%i.service
```

và cho `waxseal-alert@` đọc `ExecMainStatus` để nó phân biệt được 1 với 2 trước
khi quyết định gọi ai.

## File pin, và vì sao dùng `DynamicUser` + `StateDirectory`

`waxseal-verify@.service` ghi trạng thái pin của nó vào
`/var/lib/waxseal-verifier/pin` - một `StateDirectory` ở mode `0700`, thuộc
user nhất thời của unit.

`src/waxseal/adapters/pinstore.py` nêu lý do ngay trong code. Một pin **không
phải sidecar của trail**: mọi file khác mà waxseal ghi cạnh một trail
(`.attest`, `.anchors`, `.drops`) đều mô tả chính cái log và thuộc về ai sở hữu
nó, nhưng "một pin mô tả điều mà CHÍNH verifier này đã xác nhận, và toàn bộ giá
trị của nó là nó nằm ở nơi bên ghi trail không chạm tới được." Một pin mà bên
ghi sửa được là một pin bên ghi lùi lại được - và khi đó điều duy nhất một pin
bắt được, tức việc lịch sử mà verifier này đã xác nhận bị viết lại, thôi bị
bắt.

Đó cũng là lý do `waxseal preflight --pin` chỉ *đọc* trạng thái pin và chính
`--pin` trên `verify` mới là thứ đẩy pin tiến lên, và vì sao exit 2 đẩy pin
tiến (không kiểm được thì không phải bị can thiệp, SPEC.md mục 13) trong khi
exit 1 đóng băng pin.

### Một vướng mắc mà `DynamicUser` tạo ra

Một user nhất thời không thuộc group nào, nên một trail ở mode `0600` thuộc
`waxseal` là không đọc được với nó, và unit sẽ thoát khác 0 vì quyền chứ không
đưa ra được một phán quyết nào. Hãy cho trail một group mà cả hai bên cùng có,
và thêm nó vào unit như một quyền **đọc**:

```ini
# /etc/systemd/system/waxseal-verify@.service.d/group.conf
[Service]
SupplementaryGroups=waxseal-audit
```

**Đừng** giải quyết bằng cách đặt `User=waxseal` cho unit verify. Làm vậy thì
verifier ghi được cả trail lẫn pin, và sự phân tách khiến pin đáng có đã mất.

## Vì sao unit anchor *không* dùng `DynamicUser`

`waxseal anchor` có ghi: sidecar `.anchors` nằm **cạnh** trail. Nên unit đó
chạy bằng chính user của chain và có thư mục trail trong `ReadWritePaths`.

Đặt anchor **client** cạnh chain mới là topology dự kiến - mục 1 của
`deployment.vi.md` vẽ đúng mũi tên đó. Thứ phải trả lời một thẩm quyền khác là
anchor **sink**: TSA theo RFC 3161, calendar OpenTimestamps, host witness. Một
root đã công bố mà bên ghi trail viết lại được thì không chứng minh gì, và
không file unit nào kiểm được rằng URL bạn đặt trong `anchor.env` là của người
khác. `adapters/witness.py` nói đúng điều đó trong docstring của nó: chính việc
triển khai mới là luận điểm an ninh.

Hãy đặt nhịp anchor từ số đo của chính bạn, đừng lấy giá trị `hourly` tạm trong
`waxseal-anchor@.timer`. `waxseal cadence` tính khoảng thời gian tối ưu về chi
phí và trả về một **dải**, không bao giờ một điểm đơn lẻ; nó không mở trail nào
nên bạn chạy được trước khi triển khai bất cứ thứ gì.

## Trình thông dịch

`waxseal-openclaw-ingest.service` được phát hành với
`ExecStart=/usr/local/bin/python3 -m waxseal.integrations.openclaw` và đường dẫn
đó là một **giá trị tạm bạn phải sửa**:

```sh
# trong môi trường thực sự có waxseal
python3 -c 'import sys; print(sys.executable)'
sudo systemctl edit waxseal-openclaw-ingest.service
```

`waxseal install openclaw` in ra `sys.executable`, không bao giờ in `python3`
trơn, và `integrations/_install.py` ghi lý do ngay trong code: trình thông dịch
trên `PATH` không nhất thiết là trình có waxseal, và khi nó không phải, "mọi
hook event bị bỏ kèm một nhãn không ai đọc, và trail vẫn rỗng trong khi các hook
trông như đã cài." Việc đó đã xảy ra trên máy của chủ repository. Một file unit
không có cơ chế dự phòng theo `PATH`, nên đường dẫn được ghi thẳng ra - và nếu
nó sai, systemd làm unit thất bại với `203/EXEC`, tức là thất bại ồn ào.

Unit này thay cho dòng crontab mà `waxseal install openclaw` khuyến nghị:

```
*/5 * * * * <trình thông dịch> -m waxseal.integrations.openclaw
```

Không gì ở đây chạy trên đường đi của agent. Nó đọc chính ledger của OpenClaw
sau khi việc đã xảy ra - OpenClaw có giữ một ledger nhưng dọn bớt nó (30 ngày,
100k hàng) và không hash hàng nào, và đó là thứ việc này đưa vào chuỗi.

Timer của nó cố ý **không** đặt `Persistent=yes`. Bù lại một khe năm phút bị bỏ
sẽ đọc những hàng mà lần chạy sau dù sao cũng đọc; thứ một lần gián đoạn thực
sự làm mất là *độ phủ* - những hàng OpenClaw đã dọn trong lúc không có gì đưa
chúng vào chuỗi - và không thiết lập timer nào khôi phục được điều đó. Toàn vẹn
chuỗi không phải tính đầy đủ của vết: một quyết định chưa bao giờ được ghi thì
không để lại khoảng trống `seq` nào và không làm vỡ liên kết nào,
`dropped_writes` đo tính đầy đủ một cách riêng biệt, và `None` ở đó nghĩa là
*chưa đo*, chưa bao giờ nghĩa là không.

## Những gì các unit này không làm

- **Chúng không dựng host nào.** Chúng mặc định có
  `/usr/local/bin/waxseal`, một user `waxseal` cho các unit có ghi, và một
  trail đã tồn tại.
- **Chúng không cưỡng chế thời hạn lưu trữ nào.** waxseal là append-only nên
  không tự xoá gì. Hãy dự kiến quay vòng chuỗi thay vì xoá trong một chuỗi.
- **Chúng không giữ khoá niêm phong nào.** A₀ được ký gửi ở verifier và không
  bao giờ được ghi lên một host có quyền ghi. Không unit nào ở đây đặt nó lên
  một host như vậy.
- **Chúng chưa được chạy.** Các file này chưa bao giờ được một systemd nào nạp
  trên bất kỳ host nào: chúng được viết ra và chỉ được máy kiểm ở mức văn bản
  INI. Hãy coi lần `systemctl daemon-reload` đầu tiên là phép kiểm thật đầu
  tiên, và `systemd-analyze verify` là cách rẻ để thực hiện nó:

  ```sh
  systemd-analyze verify /etc/systemd/system/waxseal-verify@.service
  systemd-analyze security waxseal-openclaw-ingest.service
  ```
