# Sổ đối chiếu với bài luận

*[English](conformance.md)*

Một bài phân tích độc lập kiểu arXiv về waxseal (viết trên v0.1.3) đã chứng minh một tập kết
quả về thư viện này, đề xuất một tập construction, kê một quy trình đánh giá tám mục, và báo
hai finding. Bản 0.1.4 đã xử lý một phần.

Tài liệu này nói phần nào đã làm, và — phần dễ bị bỏ qua nhất — phần nào chưa. Nó tồn tại vì
mục "Not implemented in this release" của changelog 0.1.4 chỉ nêu ba mục, mà ba không phải là
toàn bộ phần còn lại. Một release note liệt kê phần future work *đã khai báo* nhưng bỏ phần
future work *chưa khai báo* chính là đang báo cáo một khoảng trống như thể đã phủ — đúng thứ
mà thư viện này tồn tại để không làm.

Nguồn của bài luận cố ý không nằm trong repo (xem `.gitignore`: nó là đầu vào của 0.1.4, không
phải thứ waxseal phát hành). Các dòng dưới đây trích dẫn theo tên section và tên kết quả mà
bài luận đặt, để người có bài luận đối chiếu được.

## Cách đọc một dòng

Mỗi dòng mang một trạng thái, và nếu trạng thái nói về code thì kèm đường dẫn mở được.

| Trạng thái | Nghĩa |
|---|---|
| **[Shipped]** | Đã cài đặt, tới được từ một lệnh đã phát hành hoặc từ public API đã đóng băng, có test |
| **[Partial]** | Cài đặt một phần; dòng đó nêu chính xác phần thiếu |
| **[Written, unwired]** | Code có, test có, nhưng **không đường code nào đã phát hành gọi tới** |
| **[Not built]** | Chưa cài đặt |
| **[Out of scope]** | Cố ý không làm; dòng đó nêu ràng buộc quyết định điều đó |

**[Written, unwired]** không đồng nghĩa [Shipped], và đó là lý do sổ này tồn tại trong một
repo vốn đã có 100% line và branch coverage. Coverage đo một dòng có chạy dưới test hay không.
Nó **không** đo có đường code đã phát hành nào chạm tới dòng đó hay không. Một hàm có thể đạt
100% mà vẫn không operator nào cài wheel về chạm được.

## 1. Findings

| # | Finding | Trạng thái | Bằng chứng |
|---|---|---|---|
| F1 | Encoding canonical chỉ đơn ánh có điều kiện — `enc(⊥)` là `\x00NULL\x00`, bản thân nó là UTF-8 hợp lệ, nên "vắng mặt" và đúng một chuỗi cụ thể encode giống nhau | **[Shipped]** | lp64 đặt type tag *bên trong* vùng length-prefix: [`domain/hashing.py`](../../src/waxseal/domain/hashing.py), property test tại [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py) |
| F2 | Anchoring-policy downgrade — không gì trong trust domain của verifier ghi lại rằng trail này *lẽ ra* phải anchor kèm aggregate binding | **[Shipped]** | `expect_anchor_binding` trên pin state, reason `anchor_policy_downgrade` ở exit 2; SPEC section 13.1 |

Bài luận gắn nhãn F1 là **[Code]** và F2 là **[Inference]**. Tính từ 0.1.4, F2 đã được chứng minh.

## 2. Kết quả hình thức

Bài luận đã chứng minh những kết quả này; câu hỏi ở đây chỉ là repo có phát biểu chúng dưới
dạng chạy được hay không — một câu hỏi khác và yếu hơn câu hỏi chúng có đúng hay không.

| Kết quả | Phát biểu chạy được | Trạng thái |
|---|---|---|
| Định lý sụp đổ (trạng thái bằng chứng ba giá trị) | Đặt tên trong `CLAUDE.md`; các instance được test riêng lẻ, còn định lý là học thuyết chứ không phải một test | **[Shipped]** dạng học thuyết |
| Giải mã duy nhất / đơn ánh của frame | Property test trên `lp()` và frame, gồm cả trường hợp lone surrogate | **[Shipped]** — đã đóng G4 |
| Tính tất định của chain đã neo | Golden vector cùng các script cross-check độc lập trong [`tools/`](../../tools/) | **[Shipped]** |
| An toàn schema cấu trúc vs thủ tục | Cơ chế fingerprint đã có, và thí nghiệm *tách ba thiết kế verifier trên cùng dữ liệu* giờ chạy trong mọi lượt test | **[Shipped]** — xem mục 8 của quy trình |
| Đơn điệu tri thức, và tính cần thiết của mệnh đề nối chain | Ma trận rollback trên **mọi** tập con, kèm falsifiability receipt | **[Shipped]** — [`tests/domain/test_knowledge_monotonicity.py`](../../tests/domain/test_knowledge_monotonicity.py) |
| Tính cần thiết của ngoại sinh, phân tách khả quyết định | Lập luận trong [`docs/security/threat-model.vi.md`](../security/threat-model.vi.md); một kết quả phủ định không có test khẳng định | **[Shipped]** dạng văn xuôi |
| Tính chặt, và cái giá của "tuyệt đối" | τ được tính và được báo cáo (`waxseal verify`, `waxseal report`) | **[Shipped]** — đã đóng G1 |
| Truncation và phần dư của aggregate | Test sealing và anchored-aggregate | **[Shipped]** |
| Bất khả thi về coverage | `dropped_writes: int \| None` và sidecar `.drops` | **[Shipped]**; construction phát hiện dương tính (admission ticket) giờ cũng **[Shipped]** — xem mục 3 |
| Tách biệt liveness giữa contract và timestamp | `anchor_stale` cho nửa phía verifier; `AnchoringLiveness.sol` + `waxseal ledger-status` cho nửa công khai kiểm được | **[Shipped]** — xem mục 3 |
| Cadence tối ưu, độ phẳng, fleet dividend | Công thức đóng của `domain/cadence.py`, nối vào `waxseal cadence` | **[Shipped]** — xem mục 3 |

## 3. Các construction

| Construction | Section | Trạng thái | Ghi chú |
|---|---|---|---|
| Admission ticket ngoại sinh | Coverage | **[Shipped]** | Cơ chế **duy nhất** trong bài luận biến một write bị mất thành một write *bị phát hiện dương tính*. [`domain/tickets.py`](../../src/waxseal/domain/tickets.py) (`Ticket`, `scan_tickets`, `reconcile_tickets`, `render_reconciliation`) đã nối read-only vào `waxseal reconcile-tickets <trail> --issuer NAME --lease-size L [--issued SPEC]` (waxseal-sv1): một vé đã phát mà thiếu trên trail được báo *phát hiện dương tính*, không phải mức đo tối thiểu; cận vùng mù của lease window còn mở (`L-1`) luôn được nêu, không bao giờ đọc thành "sạch"; issuer không tới được (`--issued` bỏ trống) báo `measured=False`, khác với "0 drop" (rule 5). Bên phát vé vẫn là việc của operator — waxseal chỉ mang và đối soát vé, không bao giờ phát vé |
| Anchoring liveness contract | Contract layer | **[Shipped]** | `ports/ledger.py` + `domain/liveness.py` (F1, `26b074c`); `contracts/src/AnchoringLiveness.sol` — chỉ nhận head đã ký bởi writer, `seq` tăng nghiêm ngặt, đòi consistency proof RFC 9162 cho mọi submit sau lần đầu để một lịch sử bị viết lại không thể tiếp tục anchor (F2, `c21e0e6`); `adapters/evm.py::EvmLedgerReader`/`EvmLedgerSink`/`EvmAnchorSink` qua JSON-RPC thuần stdlib (F3, `20f2762`); `waxseal ledger-status --liveness`, `verify`/`report --liveness`, `anchor --evm-liveness` (F4, `26e3e91`). Một bên thứ ba KHÔNG LIÊN QUAN giờ đánh giá được delinquency mà không cần operator hợp tác — đúng nửa mà dòng này từng ghi là còn thiếu — bằng chứng end-to-end thật trên hai chain anvil sống: [`tests/adapters/test_evm_anvil.py`](../../tests/adapters/test_evm_anvil.py) (tầng adapter) và, lái đúng CLI `waxseal` như một subprocess, [`tests/test_cli_ledger_e2e_anvil.py`](../../tests/test_cli_ledger_e2e_anvil.py) (F5, bead này). **Khoảng trống nêu lúc ship, nay đã đóng** (waxseal-fg4.45, đóng bởi `b63c461` + `83d51a2`): F4 xây dimension ledger như một `_Check` độc lập — cùng hình dạng `_anchor_check`/`_receipts_check` đã có, đúng semantics exit-2 của CLI — thay vì nối vào `SeparationTopology`/`declared_topology` như văn bản gốc của plan mô tả, nên tại thời điểm F4, một `--liveness` đã cấu hình chưa nâng τ. Đã đóng: `SeparationTopology.ledger: bool | None` giờ tính vào τ và được `waxseal preflight` báo cáo, `--declare-topology` nhận subfield `ledger=`, ngữ pháp SPEC §13.1 được append trong `8acffda` |
| Bonded equivocation contract | Contract layer | **[Shipped]** | `domain/bond.py` (`EquivocationProof`, `NonExtensionProof`, `checkpoint_signing_digest` — F1); `contracts/src/BondedCheckpoints.sol` slash trên hai `ecrecover` cho equivocation (bằng chứng dương tính tự đủ) và trên một divergent leaf DƯƠNG TÍNH cho non-extension, cố ý KHÔNG BAO GIỜ trên một consistency proof chỉ đơn thuần xác minh thất bại — một khác biệt thiết kế so với chữ ký gốc của plan, được chấp nhận vì slash trên một proof thất bại sẽ cho phép bất kỳ ai rút cạn bond của một writer trung thực chỉ với giá gas (F2, `c21e0e6`); `EvmLedgerSink.submit_fraud_proof`/`submit_non_extension` (F3); `waxseal bond deposit`/`bond prove` (F4). Bằng chứng end-to-end thật: [`tests/adapters/test_evm_anvil.py::TestTheBond`](../../tests/adapters/test_evm_anvil.py) và, lái `bond deposit` rồi `bond prove` trên một equivocation dàn dựng như CLI subprocess thật đối đầu hai chain anvil sống, [`tests/test_cli_ledger_e2e_anvil.py::TestBondViaCli::test_deposit_then_prove_equivocation_slashes_the_bond`](../../tests/test_cli_ledger_e2e_anvil.py) — khẳng định cả trạng thái on-chain thô của `bondOf` (đã slash, amount về 0) lẫn cùng sự kiện đó đọc lại qua `ledger-status --bond` (exit 1, reason `bond_slashed`). Phạm vi giữ nguyên như bài luận: cơ chế này biến MỘT hành vi bất lương cụ thể thành đắt đỏ một khi bị bắt; nó không làm equivocation bất khả thi và không phát hiện một writer đơn giản không bao giờ tự mâu thuẫn |
| Registry fingerprint append-only on-chain | Contract layer | **[Shipped]** | `contracts/src/FingerprintRegistry.sol` tính `fp = sha256(descriptor)` NGAY TRÊN CHAIN và từ chối trùng lặp — không owner, không constructor, không đường update/pause/upgrade, xác minh trên chính BYTECODE ĐÃ DEPLOY (một phép đi qua opcode tìm `DELEGATECALL`/`CALLCODE`/`SELFDESTRUCT`), không chỉ trên source (F2, `c21e0e6`); `domain/registry.py::RegistryCrossCheck`/`descriptor_frame`/`decode_descriptor` (F1); `EvmLedgerReader.registry_lookup`/`registry_agreement` (F3); `waxseal registry publish`, `ledger-status --registry`, `verify`/`report --registry` (F4). Bằng chứng end-to-end thật: [`tests/adapters/test_evm_anvil.py::TestTheRegistry`](../../tests/adapters/test_evm_anvil.py) và, publish qua một CLI subprocess thật rồi tạo ra một disagreement thật hình dạng eclipse giữa hai endpoint trên hai chain anvil sống, [`tests/test_cli_ledger_e2e_anvil.py::TestRegistryPublishAndCrossCheckViaCli`](../../tests/test_cli_ledger_e2e_anvil.py). Gỡ đúng điều kiện dòng này từng nêu: đầu độc một entry giờ cần một va chạm SHA-256 hoặc quyền kiểm soát chain, không chỉ quyền ghi file cục bộ. **Khoảng trống nêu lúc ship, nay đã đóng** (waxseal-fg4.44, đóng bởi `081eab3` + `608775c`): từ vựng tại thời điểm F của `domain/registry.py` gộp "fingerprint vắng mặt trong registry" và "registry không đọc được" vào một status (`REGISTRY_UNREACHABLE`, reason `registry_absent_or_unreachable`), nên `ledger-status`/`verify --registry` khi đó không báo được hai sự kiện đó như hai sự thật tách biệt — được cả F3 lẫn F4 phát hiện độc lập, cả hai đều đúng khi từ chối tự vá trong code adapter/CLI một quyết định thuộc tầng domain. Đã đóng: domain giờ báo bốn trạng thái (`agrees`/`disagrees`/`absent`/`unreachable`) với hai reason tách biệt `registry_fingerprint_not_registered` và `registry_could_not_be_read`, gộp vào instance 13 của nguyên lý Tam trị |
| Anchoring tối ưu chi phí | Cost | **[Shipped]** | Công thức đóng, tính lồi, cận phẳng, và fleet dividend √M đều là số học trên tham số do operator cung cấp, trong [`domain/cadence.py`](../../src/waxseal/domain/cadence.py) ([`tests/domain/test_cadence.py`](../../tests/domain/test_cadence.py)), nối read-only vào `waxseal cadence` — không có tham số trail nào, không mở trail — lệnh in `N*`, `N_opt` đã clamp, cận clamp `[lam*delta, lam*t_max]`, các số hạng cân bằng, một *dải* khuyến nghị quanh `N_opt` (không phải một điểm, theo `flatness_bound`), và thông báo có nhãn "sai công nghệ anchor, không phải sai cadence" khi `delta > t_max` ([`tests/test_cli_cadence.py`](../../tests/test_cli_cadence.py), waxseal-8nw) |
| Handoff binding liên trail, anchoring bắc cầu | Multi-agent | **[Shipped]** | [`domain/handoff.py`](../../src/waxseal/domain/handoff.py) (`HandoffBinding`, `binding_holds`) và [`sources/handoff.py`](../../src/waxseal/sources/handoff.py) (`record_handoff`) đã build và test đầy đủ (waxseal-otj) — xem G5, nay đã đóng bởi waxseal-9al.2. `record_handoff` gọi `log.append`, nên theo đúng luật CLI trong CLAUDE.md ("CLI không bao giờ append entry vào chain") nó không bao giờ nối được vào CLI — cùng quy ước đã giữ `record_decision`/`record_file`/`generate_key` không nối CLI từ trước; mục "Handoff binding liên trail" trong README.md/.vi.md/.zh.md nay đã ghi tài liệu cho `record_handoff` như một lệnh gọi thư viện mà code của operator tự import trực tiếp, đúng như cách ba hàm kia đã được ghi. `binding_holds` thuần và read-only, nên CÓ THỂ nối vào CLI mà không đụng tới luật đó: `waxseal verify-handoff <delegate-trail> --origin <origin-trail>` (`tests/test_cli_verify_handoff.py`) nay quét một trail delegate tìm các entry handoff-binding và kiểm từng cái so với `entry_hashes()` hiện tại của trail origin, đúng khuôn mẫu `verify_membership`/`verify_consistency` đã thiết lập qua `waxseal consistency` |

Hai trong ba dòng [Out of scope] mà changelog 0.1.4 từng khai báo, cộng dòng [Partial] tầng contract,
nay đã **[Shipped]**: Workstream F của 0.1.5 xây cả ba construction on-chain mà bài luận gọi là
"đã thiết kế và phân tích, chưa xây" — chain-agnostic phía sau `ports/ledger.py`, EVM là adapter đầu
tiên, đường đọc thuần stdlib (`eth_call`), đường ghi qua một `Signer` do operator inject (rule 1 của
CLAUDE.md không đổi). Contract Foundry thật, bằng chứng end-to-end thật trên anvil ở cả tầng adapter
lẫn, mới trong release này, chính CLI được lái như một subprocess đối đầu hai chain sống — xem Ghi
chú của từng dòng ở trên và G6 mục 5 cho hai khác biệt mà bản ship này MANG THEO, được ghi lại chứ
không xoa nhẵn. Các dòng còn lại ra mắt sớm hơn, sau khi 0.1.4 đã phát hành, khi sổ này đã tồn tại để
ghi lại từng khoảng trống: anchoring tối ưu chi phí (waxseal-cmk, waxseal-8nw) và admission ticket
(waxseal-sv1) đều đã **[Shipped]** trọn vẹn và tới được từ một lệnh CLI thật; handoff binding liên trail
(waxseal-otj) đạt **[Shipped]** theo hai cách khác nhau cho hai nửa của nó — `record_handoff`
qua tài liệu README cho một lệnh gọi thư viện cố ý không nối CLI, `binding_holds` qua một lệnh
CLI read-only mới — đóng gap G5 (waxseal-9al.2).

## 4. Quy trình đánh giá

Bài luận nêu tám mục và nói thẳng rằng nửa thực nghiệm chưa được chạy. Cả tám mục đã xong.

| # | Mục | Trạng thái | Bằng chứng |
|---|---|---|---|
| 1 | Cài đặt lại độc lập từ văn xuôi spec, cross-check trên 10⁶ header ngẫu nhiên | **[Shipped]** | [`tests/domain/test_differential.py`](../../tests/domain/test_differential.py) chạy bản cài đặt lại độc lập của [`tools/gen_vectors.py`](../../tools/gen_vectors.py) đối chiếu với `domain/hashing.py` trên một lượt sweep có seed, tái lập được, với input `EntryHeader` ngẫu nhiên, trên mỗi push/PR, ở một N bị HẠ THẤP được ghi rõ và in ra ngay trong file — một cận bị hạ có nói ra, không phải một cận bịa (CLAUDE.md rule 6). [`.github/workflows/differential-nightly.yml`](../../.github/workflows/differential-nightly.yml) chạy đúng cùng một test function ở N=1.000.000 đầy đủ của bài luận, theo lịch hàng tuần; cả hai mức dùng chung một harness, chỉ khác N. Falsifiability receipt: sửa ad hoc một byte trong tag kiểu của bản encoder độc lập khiến lượt sweep đỏ ngay tại iteration 0; revert lại thì xanh trở lại (bead waxseal-jsk) |
| 2 | Property test cho bổ đề encoding, generator gồm chuỗi sentinel, **lone surrogate**, và null byte | **[Shipped]** | [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py)'s `test_lone_surrogate_raises_named_encoding_error` (waxseal-08c) thêm strategy lone-surrogate riêng (`_lone_surrogate_char`, `_text_with_lone_surrogate`) cạnh các generator sentinel và null byte sẵn có, và assert `lp()` raise một `LpEncodingError` có tên — đã quyết định và assert, không để không xác định. Đã đóng gap G4 |
| 3 | Ma trận rollback: không tập con registry nào chuyển thành broken | **[Shipped]** | `itertools.combinations` đầy đủ, không sampling, kèm falsifiability receipt |
| 4 | Falsifiability receipt cho concurrency và anchored aggregate | **[Shipped]** | Thực hành sẵn có của repo; bài luận coi đây là một đóng góp độc lập |
| 5 | Fault injection giữa các lần ghi sidecar phụ thuộc nhau, assert một mismatch **có nhãn** thay vì crash hay pass im lặng | **[Shipped]** | [`tests/test_sealed_log.py`](../../tests/test_sealed_log.py)'s `TestFaultInjectionBetweenDependentSidecarWrites` và [`tests/test_anchored_aggregate_log.py`](../../tests/test_anchored_aggregate_log.py)'s `TestFaultInjectionBetweenAnchorsAndSealagg` monkeypatch lệnh ghi thật để crash tại từng ranh giới giữa hai lần ghi sidecar phụ thuộc nhau, và xác nhận mọi trường hợp đều hội tụ về cùng một verdict có nhãn, không bao giờ pass im lặng, không bao giờ crash không được xử lý. Tìm ra và sửa một bug thật trong lúc làm: một `.sealagg` bị hỏng tại thời điểm anchor từng raise thẳng một `JSONDecodeError` ba tầng stack bên dưới; `AuditLog._aggregate_binding` giờ bắt lỗi đó và raise lại một `RuntimeError` có nhãn, nêu rõ `.sealagg` bị hỏng (CLAUDE.md rule 6) |
| 6 | Mutation testing đối kháng trên đột biến một record, đo **tách riêng** tỉ lệ phát hiện và độ chính xác của reason | **[Shipped]** | [`tests/domain/test_mutation_campaign.py`](../../tests/domain/test_mutation_campaign.py): 53 đột biến trong phạm vi trên 7 lớp (sửa/xoá/chèn/đảo, sửa `entry_hash`/`prev_hash`, lật một bit payload) tại nhiều vị trí, ground truth viết cứng theo phân tích thuật toán chứ không suy từ chính `verify_chain`. Tỉ lệ phát hiện và độ chính xác reason là hai `assert` TÁCH RIÊNG (100%/100%), không bao giờ gộp thành một pass/fail. 9 trường hợp giới hạn đã biết (tail truncation, whole-trail rewrite) được assert báo `ok`, có nhãn và loại khỏi mốc 100%, không bị âm thầm bỏ qua |
| 7 | Fuzzing never-raise trên **mọi** verifier entry point | **[Shipped]** | [`tests/test_never_raise_sweep.py`](../../tests/test_never_raise_sweep.py) phát hiện "verifier entry point" bằng cách quét `waxseal.domain` + `waxseal.adapters.anchors` qua `inspect`/`pkgutil` (tên có tiền tố `verify_`/`check_`/`parse_`/`decode_`/`read_`, hoặc docstring "never raise"/"fails closed") thay vì danh sách viết tay, và `TestRegistryCompleteness` assert registry đã fuzz khớp với phát hiện ở **cả hai chiều** — đã chứng minh tự-cập-nhật thật: nó đã bắt được đúng một khoảng trống thật (`domain.handoff.binding_holds`, thêm bởi một bead sau) ngay khi hàm đó xuất hiện. Tìm ra và sửa hai vi phạm never-raise thật: `verify_chain`/`verify_proof_bundle` crash trên trường header chứa lone UTF-16 surrogate, `verify_checkpoint` crash trên `entry_hash` không phải hex ở vị trí trước đó trong prefix; cả hai giờ báo đúng finding `entry_hash_mismatch`/`anchor_root_mismatch` sẵn có thay vì raise |
| 8 | Thí nghiệm tiến hoá schema: ghi dưới schema A, tiến hoá sang B, rollback binary, so ba thiết kế verifier trên cùng dữ liệu | **[Shipped]** | [`tests/domain/test_schema_evolution_experiment.py`](../../tests/domain/test_schema_evolution_experiment.py) (waxseal-4t1). Một trail trải qua cuộc tiến hoá: 4 dòng dưới schema A 6 trường đang ship, rồi 3 dòng dưới schema B 7 trường, mang đúng entry_hash mà một writer schema B thật sẽ tạo ra (frame lp64 7 trường thật, không phải hash bịa — hash bịa sẽ khiến "thiết kế 2 báo broken" đúng vì lý do tầm thường và thí nghiệm không chứng minh được gì). Rollback được dựng bằng một `VersionRegistry` mới chỉ biết A, theo đúng cách `test_knowledge_monotonicity.py` dựng các tập con, vì không có API xoá (rule 2). Bốn verdict, mỗi cái một assert riêng, không bao giờ gộp: thiết kế **theo số thứ tự** (beads v1.2.2) từ chối chạy và verify 0 dòng — kể cả 4 dòng nó vốn hiểu được; thiết kế **tính lại theo schema hiện tại** (migration 060) chế ra 3 break `entry_hash_mismatch`; **`verify_chain` thật của waxseal** báo 4 dòng checked, `unverifiable == (4, 5, 6)`, 0 broken; và một **đối chứng** mô phỏng binary biết schema B trước khi rollback verify đủ cả 7 dòng — thiếu nó thì "thiết kế 2 báo broken" chưa phải bằng chứng của một báo động *giả* thay vì một phát hiện thật. Hai phần thêm ngoài mức tối thiểu bài luận đòi: escape hatch của chính beads (`BD_IGNORE_SCHEMA_SKEW=1`) được mô phỏng và chỉ ra rằng nó verify *không gì cả* chứ không phải verify an toàn; và giới hạn trung thực được assert thay vì bỏ qua — không thiết kế rollback nào PHÁT HIỆN được một tamper payload trên dòng schema B; khác biệt của waxseal là nó không bao giờ nhận đã kiểm dòng đó. `DesignVerdict.unverifiable` là `None` với hai thiết kế bị sụp đổ và là một tuple với waxseal, nên định lý sụp đổ hiện ngay trong kiểu dữ liệu của kết quả. Falsifiability receipt, đã chạy thật chứ không phải mô tả: `VersionRegistry.encoder_for` bị sửa tạm để luôn trả frame hiện tại (tiêm migration 060 vào mã đang ship) → 5 test đỏ, trong đó `assert with_dispatch.broken == ()` fail với `((4, 'entry_hash_mismatch'),)` trên một dòng mà đối chứng chứng minh là lành lặn; hoàn nguyên đúng một dòng thì cả 10 test xanh lại |

## 5. Chi tiết các khoảng trống

### G1 — τ được tính và được báo cáo [Shipped]

[`domain/separation.py`](../../src/waxseal/domain/separation.py) định nghĩa
`separation_degree()`, `render_separation_degree()`, và (thêm mới để đóng gap này)
`counted_authorities()`/`render_counted_authorities()`. Cả bốn đều được test đầy đủ và
giờ được gọi từ `domain/report.py` và `cli.py`.

Kiểm được ngay bây giờ:

- `waxseal verify` (có hoặc không `--pin`) luôn in một dòng `τ (separation degree): ...` —
  `not declared` khi pin không có `declared_topology`, không bao giờ là `0` hay `1` trần trụi.
  Ví dụ, từ một lượt chạy thật trên trail demo có `declared_topology` trong pin:
  `τ (separation degree): 6 (writer(1) + seal_escrow(1) + anchor_sinks(2) + witness(1) +
  pin_separate(1) = 6)`.
- `waxseal report --json` mang một object `separation`: `{"tau": ..., "counted_authorities":
  [{"name": ..., "count": ...}, ...]}`, `null`/`null` khi chưa khai báo. Bản Markdown của
  `waxseal report` mang cùng thông tin đó trong mục `## Separation`.
- `SeparationTopology`, `separation_degree`, và `Verdict` giờ nằm trong public API đã đóng
  băng tại [`src/waxseal/__init__.py`](../../src/waxseal/__init__.py) — `tests/architecture/
  test_invariants.py::TestPublicApiFrozen` đã được sửa cùng commit, kèm rationale.

Bằng chứng: [`tests/domain/test_separation.py`](../../tests/domain/test_separation.py),
[`tests/domain/test_report.py`](../../tests/domain/test_report.py),
[`tests/test_cli_audit.py`](../../tests/test_cli_audit.py) (`TestReportSeparationDegree`),
[`tests/test_cli_pin.py`](../../tests/test_cli_pin.py) (các test τ trong
`TestDeclaredTopologyShortfall`) — các test CLI chạy `main()` thật và assert trên stdout/
JSON, không chỉ gọi thẳng `build_report()`.

Lập luận của bài luận: hai triển khai có mật mã giống hệt nhau nhưng τ khác nhau thì **không**
an toàn ngang nhau, nên một report bỏ τ là bỏ đúng đại lượng duy nhất thay đổi giữa chúng.
Khuyến nghị đó đã được đáp ứng kể từ waxseal-mfi. Bản thân `declared_topology` giờ cũng đã có
cờ CLI để ghi (`--declare-topology`, waxseal-ekd) — xem G2 bên dưới, đã xong.

### G2 — ba khai báo của pin không có đường ghi [Shipped]

`expect_anchor_binding`, `max_anchor_age_s`, và `declared_topology` đều được parse, được
kiểm, được giữ nguyên qua các lần pin advance, và được đặc tả tại SPEC section 13.1. `verify`
và `report` giờ mỗi lệnh đều nhận `--expect-anchor-binding` (store-true),
`--max-anchor-age-s SECONDS`, và `--declare-topology SPEC` (một spec `key=value` phân tách
bởi dấu phẩy, mang đủ 4 thành phần của `SeparationTopology` cùng lúc — ví dụ
`seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true`), cả ba chỉ có ý nghĩa khi
đi kèm `--pin` và bị chặn ở mức lỗi sử dụng CLI nếu không. Một spec `--declare-topology` chỉ
khai một phần trong 4 thành phần bị từ chối ngay ở tầng argparse (exit 2, in ra trước khi
trail được mở) — không bao giờ tự điền mặc định, khớp với quy tắc `malformed_pin` của SPEC
13.1 cho một object thiếu. Mỗi cờ chỉ được ghi vào pin state khi lượt chạy đó thực sự advance
pin (exit 0/2, không bao giờ ở lượt exit 1 đóng băng); một cờ không đưa ra sẽ giữ nguyên
những gì lượt chạy trước đã khai, y hệt trước khi các cờ này tồn tại.

Operator vẫn có thể tự sửa tay file JSON pin state — đường đó và format của nó (SPEC 13.1)
không đổi — nhưng không còn là đường duy nhất nữa, và các README giờ đã mô tả các cờ này.

Bằng chứng: [`tests/test_cli_pin.py`](../../tests/test_cli_pin.py), lớp `TestDeclareViaCLI`
— các test CLI chạy `main()` thật, đọc lại file pin state, và assert JSON khớp đúng format
SPEC 13.1, bao gồm cả lỗi sử dụng khi khai một phần topology và việc ghi tương thích ngược
lên một file pin ở dạng trước waxseal-ekd.

### G3 — một lượt anchor tới được nhiều domain độc lập [Shipped]

`--tsa-url` và `--ots-calendar` từng nằm trong một mutually exclusive group của lệnh
`anchor`, nên muốn publish **cùng một** checkpoint frame sang cả hai — authority cho cửa sổ
phát hiện cỡ phút, calendar cho non-repudiation dài hạn — phải chạy hai lượt liên tiếp.
Corollary về chọn anchor của bài luận khuyến nghị tới được cả hai chỉ trong một lượt chạy,
vì τ tăng một cho mỗi domain độc lập.

Ràng buộc loại trừ đã bỏ (waxseal-4yk): cả hai cờ được chấp nhận cùng lúc, một checkpoint
được tính đúng một lần (`AuditLog.anchor()`), và `MultiAnchorSink` mới trong
[`adapters/anchors.py`](../../src/waxseal/adapters/anchors.py) phát nó ra cho cả hai sink,
mỗi sink vẫn tự ghi record sidecar `.anchors` của riêng mình y hệt `RecordingAnchorSink`
luôn làm. Một sink không tới được không làm mất record của sink kia — lỗi được thu lại và
in ra có nhãn (`error: external anchor failed, nothing recorded for <sink>: <reason>`),
không bao giờ bị nuốt âm thầm (CLAUDE.md rule 6).

Bằng chứng: [`tests/test_cli_receipts.py`](../../tests/test_cli_receipts.py)'s
`TestAnchorSubcommandSinks` — `test_both_targets_together_write_two_records_over_the_same_checkpoint`
(cả hai cờ trong một lượt `anchor` → hai record sidecar, cùng `entry_hash`/`root`/`seq`) và
`test_tsa_unreachable_still_records_the_ots_result_and_labels_the_failure` (TSA không tới
được, calendar OTS tới được → record của OTS vẫn được ghi, exit 1, lỗi TSA được nêu tên trên
stderr) — cùng với [`tests/adapters/test_rfc3161_sink.py`](../../tests/adapters/test_rfc3161_sink.py)'s
`TestMultiAnchorSink` cho hợp đồng phát-sink độc lập.

### G4 — generator của property test loại đúng lớp ký tự bài luận nêu tên [Shipped]

`st.characters(codec="utf-8")` không thể sinh lone surrogate, vì lone surrogate không encode
được sang UTF-8. Đó từng là strategy **đúng** cho văn bản hợp lệ và **sai** cho phép thử bài
luận kê ra, mà mục đích là chốt xem `lp()` làm gì khi nhận một chuỗi Python cho phép còn
UTF-8 thì không.

Đã đóng bởi waxseal-08c: `lp()` giờ raise một `LpEncodingError` có tên — chained từ
`UnicodeEncodeError` của stdlib — cho một lone surrogate, thay vì để lộ một exception trần
trụi không nhãn. `domain/verify.py`, `domain/export.py`, và `domain/checkpoint.py` đều phải
được dạy bắt lỗi đó (tìm ra bởi never-raise sweep của waxseal-lmv, xem mục 7 ở trên) — một
header mà build này còn không encode được thì không thể nào tái tạo lại hash đã lưu, nên đây
là finding `entry_hash_mismatch`/`anchor_root_mismatch` sẵn có, không phải crash.

Bằng chứng: [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py)'s
`test_lone_surrogate_raises_named_encoding_error`,
[`tests/domain/test_verify.py`](../../tests/domain/test_verify.py)'s
`test_unencodable_header_field_reports_entry_hash_mismatch_not_a_crash`. Không byte vector
đông cứng nào đổi — fix chỉ thêm một `raise` trên input trước đây gây crash, không chạm vào
byte đầu ra của bất kỳ input hợp lệ hiện tại nào.

### G5 — handoff binding liên trail: một nửa vốn cố ý như vậy, nửa kia mới là gap thật [Shipped]

[`domain/handoff.py`](../../src/waxseal/domain/handoff.py) định nghĩa `HandoffBinding` (một
bộ ba con trỏ frozen, có validate: `chain_id`, `seq`, `head_hash`), `to_payload`/
`from_payload`, và `binding_holds()` — tất cả được test đầy đủ, gồm cả kịch bản anchoring bắc
cầu 2 tầng và nhiều tầng, cùng phép kiểm payload bị xoá phải báo unverifiable chứ không phải
broken (waxseal-otj). [`sources/handoff.py`](../../src/waxseal/sources/handoff.py) định
nghĩa `record_handoff()`, một hàm ghi tổng quát mà bất kỳ integration nào có hai trail riêng
biệt đều gọi được.

Gap này lần đầu được ghi lại (đợt kiểm toán của Z1) là "không gì trong `src/` gọi tới một
trong hai hàm này ngoài test của chính chúng" và gắn nhãn `needs-human` với lý luận rằng đóng
nó cần một quyết định kiến trúc về việc chọn điểm nối nào. Nhìn lại lần hai, sửa ngay trong
cùng ngày, phát hiện lý luận đó dựa trên một phép so sánh chưa đầy đủ: chưa từng kiểm xem
việc `record_handoff` không tới được từ CLI có thực sự mới lạ hay không. Không hề —
`record_handoff()` gọi `log.append()`, mà luật CLI của CLAUDE.md rất rõ ràng và tuyệt đối:
"CLI không bao giờ append entry vào chain." Luật đó đã giữ `record_decision`
([`sources/decisions.py`](../../src/waxseal/sources/decisions.py)), `record_file`
([`sources/files.py`](../../src/waxseal/sources/files.py)), và `generate_key`
([`domain/sealing.py`](../../src/waxseal/domain/sealing.py)) không nối CLI từ trước — cả ba
đều được ghi tài liệu trong README.md/.vi.md/.zh.md như những lệnh gọi mà *code ứng dụng của
chính operator* tự import và gọi trực tiếp, không bao giờ là subcommand. `record_handoff` chỉ
đơn giản là thiếu đúng phần tài liệu đó; nó không cần một quyết định kiến trúc nào, chỉ cần
mục README mà ba hàm anh em kia đã có sẵn (waxseal-9al.2 Part A — xem mục "Handoff binding
liên trail" mới trong cả ba bản README).

`binding_holds()`, ngược lại, thực sự khác về bản chất: nó thuần và read-only — không I/O,
chỉ là một phép so sánh trên `Sequence[str]` — đúng hình dạng `verify_membership`/
`verify_consistency` (`domain/anchoring.py`) đã có sẵn, và hai hàm đó đã được nối read-only
vào `waxseal consistency`. Không gì trong luật never-append cản việc nối một hàm read-only
vào CLI; nửa này của gap là thật, không phải cố ý. `waxseal verify-handoff <delegate-trail>
--origin <origin-trail>` (waxseal-9al.2 Part B) nay đóng nó lại: lệnh quét trail delegate tìm
các entry `HANDOFF_PAYLOAD_TYPE`, mở trail origin read-only (chỉ local path, không hỗ trợ
URL/remote), và gọi `binding_holds` so với `entry_hashes()` hiện tại của origin cho từng
binding tìm được — không append gì vào trail nào cả. Exit 0 khi không có gì để kiểm hoặc mọi
binding đều holds; exit 1 khi có ít nhất một binding không còn holds (một sai lệch thực sự
được phát hiện, không chỉ "unverifiable" — `binding_holds` là một phép so sánh xác định, không
phải một tra cứu tên); exit 3 khi một trail path được nêu tên không tồn tại.

Bằng chứng: [`tests/domain/test_handoff.py`](../../tests/domain/test_handoff.py),
[`tests/test_sources_handoff.py`](../../tests/test_sources_handoff.py) (đã có từ trước,
waxseal-otj), và [`tests/test_cli_verify_handoff.py`](../../tests/test_cli_verify_handoff.py)
(mới, waxseal-9al.2): một binding hợp lệ holds so với origin của nó (exit 0), một trail origin
bị rewrite toàn bộ khiến binding không còn holds (exit 1, nêu tên seq lỗi), không có entry
handoff-binding nào trên trail delegate (exit 0, "nothing to check" — không phải lỗi), một
delegation multi-agent 2 hop (A → B → C, cả hai hop đều được kiểm), một origin path không tồn
tại (exit 3), và payload của một header-only reader không sẵn có (bị bỏ qua, không báo là thất
bại — đúng rule 5 unmeasured-≠-absent, không phải việc của lệnh này để tự bịa ra một verdict
cho những byte nó chưa bao giờ được đưa cho).

### G6 — tầng on-chain ship kèm hai khác biệt đã biết, cố ý [Shipped — cả hai khoảng trống đã đóng]

Workstream F (F1-F4, `26b074c`/`c21e0e6`/`20f2762`/`26e3e91`) đã giao ba contract mà mục 3 ghi
**[Shipped]**. Hai chỗ code ship khác với văn bản gốc của plan được chính các agent phát hiện ra
ghi nhận công khai thay vì âm thầm nuốt, và cả hai từng mở dạng bead `needs-human` tại thời
điểm ghi mục này (nay đều đã đóng — fg4.44 bởi `081eab3`+`608775c`, fg4.45 bởi
`b63c461`+`83d51a2`) — kỷ luật của sổ này là mô tả cái ĐÃ SHIP, không phải mô tả nguyên văn chưa sửa
của plan, nên cả hai được ghi thẳng ở đây thay vì hoà vào ba dòng **[Shipped]** ở trên.

- **waxseal-fg4.44 — `registry_absent` và `registry_unreachable` là MỘT status, không phải hai.**
  `RegistryCrossCheck` trong `domain/registry.py` báo `REGISTRY_UNREACHABLE` (reason
  `registry_absent_or_unreachable`) cho CẢ HAI trường hợp "registry contract không giữ gì dưới
  fingerprint này" VÀ "không đọc được registry" — hai sự thật khác nhau một operator có lý do
  muốn tách biệt, gộp lại vì `RegistryFinding` được xây quanh input nó nhận
  (`onchain_descriptor: bytes | None`), vốn đã không tách được hai trường hợp trước khi tới kiểu
  đó. Được F3 (close-reason của `waxseal-7yf`) và F4 (close-reason của `waxseal-j7b`) phát hiện
  độc lập, cả hai đều đúng khi từ chối tự bịa ra một status thứ ba trong code adapter hoặc CLI —
  đó là quyết định thuộc tầng domain, và `domain/registry.py` là một module đã ship, đã test từ
  F1. Còn chờ quyết định của chủ repo: khác biệt này có đáng thêm một state vào một bảng ánh xạ
  mà chính dòng ở trên vừa khen là exhaustive hay không. **Nay đã đóng** (`081eab3` + `608775c`): chủ repo đã quyết —
  bảng ánh xạ nhận thêm state, và phép tách được gộp vào instance 13 của nguyên lý Tam trị.
- **waxseal-fg4.45 — dimension ledger không nâng τ.** Văn bản Workstream F4 của plan mô tả nối
  một check `--liveness`/`--registry` đã cấu hình vào `SeparationTopology` của
  `domain/separation.py` (một trường `ledger: bool`) để nó tính vào τ, con số separation-degree mà
  `waxseal preflight`/`verify --pin` báo cáo (gap G1, ở trên). F4 ship check ledger như một
  `_Check` độc lập thay vào đó — cùng hình dạng `_anchor_check`/`_receipts_check` đã có, giao đúng
  semantics exit-2 của CLI — và nêu rõ việc thu hẹp phạm vi này thay vì âm thầm làm. Một operator
  đọc `τ (separation degree): N` hôm nay nhận một con số không tính công cho một check on-chain đã
  cấu hình, dù `ledger-status`/`verify --liveness` đang thật sự kiểm tra một điều có thật; khoảng
  trống nằm ở CON SỐ ĐƯỢC BÁO CÁO, không nằm ở bản thân check. **Nay đã đóng** (`b63c461` + `83d51a2`): τ giờ tính công
  một thẩm quyền ledger đã khai báo, và `preflight` in tách bạch khai-báo với đo-được.

Không khoảng trống nào trong hai cái trên biến ba dòng **[Shipped]** của mục 3 thành một khẳng
định sai: các construction hoạt động đúng như mô tả, test trên anvil sống thật kể cả qua một CLI
subprocess thật (F5,
[`tests/test_cli_ledger_e2e_anvil.py`](../../tests/test_cli_ledger_e2e_anvil.py)). Cả hai khoảng
trống từng nằm ở RÌA của bề mặt đã ship — một state từ vựng bị gộp, một đóng góp vào τ chưa được đếm —
đúng hình dạng mà kỷ luật [Written, unwired] ≠ [Shipped] tồn tại để giữ cho nhìn thấy được, thay
vì để một sổ như thế này xoa nhẵn đi.

## 6. Cái gì không thể trở thành [Proved] ở đây, và vì sao

Một chương trình conformance có thể chuyển mọi khẳng định *về codebase này* từ "phát biểu"
sang "đã chạy". Nó **không** chuyển được những dòng dưới đây, và một kế hoạch hứa ngược lại là
đang hứa thứ công việc không giao được:

| Khẳng định | Vì sao nó đứng yên |
|---|---|
| SHA-256 kháng va chạm và kháng tiền ảnh thứ hai; HMAC-SHA-256 là MAC an toàn | Giả định của cả ngành, không phải tính chất của repo này. Không test nào ở đây động tới |
| Việc xoá khoá epoch là hiệu quả | **Đã biết là sai theo nghĩa chặt** — CPython không zeroise được. Repo đã ghi điều này. Test nó chỉ xác nhận giới hạn đã biết, không gỡ được nó |
| Anchor và witness thuộc thẩm quyền hành chính khác | Phần mềm không cưỡng chế được. Đó là nghĩa vụ của operator, và τ là một **khai báo** về nó chính vì waxseal không đo được |
| Các authority hỏng độc lập với nhau | Một lựa chọn mô hình hoá, và là lựa chọn lạc quan |
| Mọi con số tiền tệ, độ trễ, và pháp lý | Đo được cho một triển khai tại một thời điểm. Một phép đo không phải một chứng minh, và con số không chuyển sang chỗ khác được |
| Đánh giá tính mới so với prior art | Cần một lượt khảo cứu tài liệu hệ thống. Bài luận tự nói lượt tìm của nó là ba truy vấn |

Mọi thứ còn lại — mọi khẳng định mà chủ ngữ là code trong repo này — đều chạy được. Đó là mục
tiêu đạt được, và là phạm vi mà công việc conformance nên bị bó vào.
