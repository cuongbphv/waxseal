# `deploy/` - có gì ở đây, và thẩm quyền nào sở hữu nó

*[English](README.md)*

Luận điểm an ninh của waxseal không phải một sơ đồ. Nó là: bốn domain ở mục 1
của [`docs/architecture/deployment.vi.md`](../docs/architecture/deployment.vi.md)
là bốn **thẩm quyền quản trị** khác nhau - bốn nhóm người, không phải bốn cái
hộp. Mọi phép phát hiện sống sót được trước một kẻ tấn công có quyền ghi đều
sống sót vì một thứ chúng cần nằm dưới quyền kiểm soát của người khác.

Vì vậy bảng mục lục dưới đây có một cột thẩm quyền. Hãy đọc cột đó trước: nó
quyết định một phép phát hiện còn hiệu lực hay không.

| Đường dẫn | Đó là gì | Thẩm quyền nó thuộc về |
|---|---|---|
| `docker/` | Image runtime cho CLI | build - dùng bởi mọi domain bên dưới |
| `install.sh` | Trình cài một dòng cho một host | build |
| `compose/compose.yaml` | Ngăn xếp server cộng một `verify` chạy theo yêu cầu | **một máy, một thẩm quyền** - chỉ dành cho phát triển và một host |
| `helm/waxseal-server/` | Chain server: StatefulSet, hook seed, anchor **client** tuỳ chọn | chain |
| `helm/waxseal-verifier/` | Các CronJob `verify` và `report`, và file pin | verifier |
| `helm/tests/` | Các bộ values và snapshot `helm template` viết tay | build / CI |
| `systemd/waxseal-verify@` | Kiểm chứng theo lịch trên một host, `DynamicUser` | verifier |
| `systemd/waxseal-anchor@` | Công bố checkpoint, chạy bằng user của chain | chain -> anchor client |
| `systemd/waxseal-openclaw-ingest` | Đưa ledger của OpenClaw vào chuỗi mỗi năm phút | application -> chain |

`docker/` và `install.sh` được bảo trì cùng phần còn lại của `deploy/` nhưng
không được mô tả ở đây; xem phần header của chính chúng.

## Hai chart, và vì sao là hai

Một chart cài cả server lẫn verifier của nó sẽ đặt cả hai dưới cùng một Helm
release: một namespace, một biên RBAC, một nhóm người có quyền `helm upgrade`.
Một verifier mà chính người ghi trail cũng nâng cấp được là một writer tự kiểm
chứng chính mình, và các phép phát hiện sống sót được trước kẻ tấn công có
quyền ghi sẽ thôi sống sót.

Nên có hai chart, dành cho **ít nhất hai namespace, và tốt nhất là hai
cluster**:

```sh
helm install waxseal-server deploy/helm/waxseal-server \
  --namespace waxseal-chain --create-namespace

helm install waxseal-verifier deploy/helm/waxseal-verifier \
  --namespace waxseal-audit --create-namespace \
  --set trailUrl=http://waxseal-server.waxseal-chain.svc.cluster.local:8000
```

Không chart nào cài một witness. Đó là điều cố ý và không phải một thiếu sót
để sửa sau: một witness được cài bởi cùng release với chain thì trả lời cùng
một thẩm quyền và **không làm chứng cho điều gì**. Hãy host witness cho chuỗi
của một đội khác, và để một đội khác host witness cho chuỗi của bạn.
`src/waxseal/adapters/witness.py` nói đúng điều này trong docstring của chính
nó, và nói thêm rằng không đoạn code nào cưỡng chế được - chính việc triển khai
mới là luận điểm an ninh.

## Ba điều không gì trong đây kiểm được thay bạn

1. **Rằng hai chart thực sự nằm dưới hai thẩm quyền khác nhau.** Hai namespace
   do một người quản trị là một thẩm quyền mang hai cái tên.
2. **Rằng các *sink* anchor là của người khác.** Anchor *client* đứng cạnh
   chain mới là topology dự kiến - mục 1 của `deployment.vi.md` vẽ đúng mũi tên
   đó. Thứ không được là của bạn là TSA, calendar và URL witness. Một root đã
   công bố mà người ghi trail viết lại được thì không chứng minh gì.
3. **Rằng file pin nằm ngoài tầm với của writer.** Chart verifier đặt nó trên
   PVC riêng của namespace verifier, và `waxseal-verify@.service` đặt nó trong
   một `StateDirectory` của `DynamicUser`, cả hai đều vì lý do đó
   (`src/waxseal/adapters/pinstore.py`). Compose không có chỗ nào để đặt pin,
   nên service `verify` trong compose chạy mà không có `--pin` và nói rõ ra.

## Exit code chính là giao diện

Mọi thứ trong đây có kiểm chứng đều báo qua cùng bốn code, và mọi lớp bọc đều
giữ nguyên chúng thay vì gộp lại:

| Exit | Nghĩa | Đi tới đâu |
|---:|---|---|
| 0 | nguyên vẹn | không đâu cả |
| 1 | bị phá - điểm vỡ đầu tiên được in kèm seq và lý do | **bộ phận an ninh.** Bảo toàn, không sửa. |
| 2 | nguyên vẹn, nhưng có hàng bản build này không kiểm được theo tên | **quản lý phát hành**, không phải SOC |
| 3 | đường dẫn trail không tồn tại | lỗi cấu hình: không đọc gì, không tạo gì |

Exit 2 tồn tại vì hai sự cố ghi trong [`CLAUDE.md`](../CLAUDE.md): một lần rollback
để lại các hàng do schema mới hơn ghi thì không được gọi ai đó dậy như một báo
động can thiệp, và cũng không được âm thầm tính lại dưới bộ trường sai rồi báo
là nguyên vẹn. **Exit 2 không phải là đạt.**

Mọi CronJob và unit trong đây đều in ra `waxseal_command=` và `waxseal_exit=`
để một truy vấn log tách được 1 khỏi 2 mà không phải đọc trạng thái pod hay
unit. Nếu hệ thống cảnh báo của bạn gộp chúng thành "job thất bại" thì phán
quyết ba giá trị mà cả dự án này dựa trên đã bị làm phẳng về hai giá trị trên
đường tới màn hình - đúng thứ thất bại mà nó tồn tại để ngăn.

**Tuyệt đối không nối một hành động khắc phục tự động vào exit 1.** waxseal báo
cáo; nó không sửa (CLAUDE.md rule 4). Hàng nào là hàng bị can thiệp là quyết
định chỉ người vận hành đưa ra được, và một lần "sửa" sẽ phá đúng cái bằng
chứng mà toà án hoặc cơ quan quản lý cần.

## Trạng thái của thư mục này

Được viết trên một máy **không có `helm`, không có `kubectl`, không có `kind`
và không có `kubeconform`**, và không cài được cái nào ở đó. Do đó:

- chưa có `helm lint` hay `helm template` nào chạy trên bất kỳ chart nào, và
  chưa manifest nào ở đây được áp lên một cluster nào;
- các snapshot trong `helm/tests/snapshots/` được **viết tay** từ việc đọc
  template. Chúng là một lời tuyên bố ý định, không phải một bản ghi lại
  output. `helm/tests/README.md` nói đúng điều đó và nói phần nào dễ phải tạo
  lại nhất;
- các unit systemd chưa bao giờ được một systemd nạp. `systemd-analyze verify`
  là phép kiểm thật đầu tiên và rẻ nhất;
- thứ **đã** được máy kiểm là YAML và JSON: mọi file YAML không phải template
  đều parse được, mọi `values.schema.json` đều là JSON hợp lệ, và các bộ values
  mặc định cùng bộ values thử của từng chart đều validate được theo schema của
  chính chart đó.

Hãy coi job helm trong CI là phép kiểm thật đầu tiên trên các chart, và lần
`systemctl daemon-reload` đầu tiên là phép kiểm thật đầu tiên trên các unit.

## Đọc trước

- [`docs/architecture/deployment.vi.md`](../docs/architecture/deployment.vi.md) -
  bốn trust domain, bảng phân tách nhiệm vụ, và hợp đồng exit code ở mục 4.
- [`docs/architecture/deploy-options.vi.md`](../docs/architecture/deploy-options.vi.md) -
  chọn giữa các phương án đóng gói, và lớp lưu lượng duy nhất đi ra khỏi nơi
  triển khai.
- [`server/docs/deployment.vi.md`](../server/docs/deployment.vi.md) - sổ tay vận
  hành: các biến môi trường, bố cục dữ liệu dưới `WAXSEAL_SERVER_DATA_DIR`, vì
  sao các trail không nằm trong PostgreSQL, vì sao việc seed mới là thứ bảo vệ
  một triển khai, và quan điểm về TLS.
- [`CLAUDE.md`](../CLAUDE.md) - các invariant mà không gì trong đây được đi
  đường vòng qua.
