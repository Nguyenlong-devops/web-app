# Kiểm kê tài sản

## Tem QR thiết bị trong mạng nội bộ

**In hàng loạt:** tick các thiết bị trong Quản Lý Computer (checkbox đầu bảng để
chọn tất cả dòng đang hiển thị), bấm **In QR đã chọn**. Trang xem trước chia A4
thành 3 cột × 4 hàng, mỗi QR 40 mm; có thể in giấy hoặc chọn Save as PDF.
Tối đa 500 thiết bị/lần. Dùng tỷ lệ 100%, lề 10 mm, tắt header/footer của trình
duyệt. Mỗi tem có tên máy và mã tài sản; danh sách thiếu máy đã xóa sẽ yêu cầu tải
lại thay vì tự bỏ qua. Tem QR dạng này dành cho giấy A4 thường, chưa căn theo
mẫu giấy decal có sẵn của từng hãng.

Trong **Quản Lý Computer**, mỗi dòng có nút **QR**: xem trước tem, tải SVG hoặc
in tem ngay trong pop-up của bảng, không mở tab mới khi bấm QR. Đóng pop-up sẽ
giữ vị trí cuộn và các dòng đã chọn. Trang in hàng loạt vẫn mở riêng để in A4.
QR chứa đường dẫn `/assets/ID` nên đổi tên máy không cần in lại.
Camera mặc định của điện thoại quét và mở đường dẫn sẽ hiển thị pop-up thông tin;
nếu chưa đăng nhập, portal yêu cầu đăng nhập rồi quay lại đúng thiết bị.
Nếu tài khoản là admin và thiết bị thuộc một đợt **đang mở**, pop-up có nút
**Kiểm kê tài sản**, mở đúng đợt và tự mở form của máy đã quét. Nếu có nhiều
đợt phù hợp, chọn đợt trước khi bấm. Nếu không có đợt mở chứa thiết bị, chỉ hiện
thông tin máy. Không phụ thuộc đợt đang được chọn trên một máy tính khác; trạng
thái mở/đóng được lưu trên server. Quét QR và mở form không tự đánh dấu hoàn thành:
vẫn phải đối chiếu rồi bấm **Lưu & hoàn thành**. QR đã in vẫn dùng cùng đường dẫn.
Admin xem được mọi máy, user thường chỉ xem máy được cấp cho mình. Không hiển thị
recovery key BitLocker. Quét QR không tự đánh dấu hoàn thành kiểm kê.

Mở portal bằng IP/tên miền mà điện thoại truy cập được trước khi xuất QR. Nếu
muốn URL in trên mọi tem cố định, truyền biến môi trường vào container `web-app`:

```yaml
environment:
  - ASSET_PUBLIC_BASE_URL=https://portal.tenmiennoibo
```

Giá trị chỉ gồm scheme + hostname/IP + port nếu có, không thêm đường dẫn.
Nếu không cấu hình, dùng địa chỉ đang truy cập portal. Không in tem từ localhost.
Điện thoại phải kết nối mạng nội bộ/VPN. Quét bằng camera điện thoại rồi mở link
dùng được với HTTP nội bộ; quét camera ngay trong trang kiểm kê vẫn cần HTTPS.
Trang kiểm kê nhận cả QR đường dẫn cùng origin và tem tên/mã tài sản cũ.
Sau khi cập nhật source cần `docker compose up -d --build` để cài thư viện qrcode.

Trang `/inventory`, hoặc **Kiểm Kê Tài Sản** trong sidebar. Bản đầu sử dụng quyền
quản trị AD hiện có; chưa có màn hình phân quyền nhân viên kiểm kê riêng.

## Chạy và sử dụng

1. Cập nhật source và chạy `docker compose up -d --build` trên Ubuntu.
   Khi khởi động, ứng dụng tự thêm hai cột ngày và các bảng kiểm kê.
2. Nếu chưa có dữ liệu, nhập `computers.csv` từ **Quản Lý Computer**.
3. Tạo đợt, để trống vị trí để lấy tất cả thiết bị hoặc nhập chính xác vị trí.
   Danh sách và thông tin ban đầu được chốt khi tạo. Máy thêm sau không tự vào đợt.
4. Nhập tên/mã tài sản hoặc quét QR chứa nguyên tên máy/mã tài sản. Tên trùng
   phải chọn đúng máy trong danh sách. Khuyến nghị QR dùng mã tài sản cố định.
5. Đối chiếu và sửa từng dòng. **Lưu thay đổi** cập nhật danh mục và ghi lịch sử;
   **Lưu & hoàn thành** đồng thời đánh dấu đã kiểm kê. Lưu không thay đổi vẫn ghi log.
6. Máy hoàn thành chuyển xanh, hiện **Chỉnh sửa**. Sửa tiếp giữ thời điểm hoàn
   thành đầu tiên. **Mở lại kiểm kê** cần lý do trong ghi chú.
7. Đóng đợt để khóa sửa. Đóng/mở lại đều ghi lý do và lịch sử. Có thể đóng đợt
   còn máy chưa hoàn thành; số còn lại vẫn giữ nguyên trong báo cáo.

Kết quả thực tế (bình thường/hỏng/không tìm thấy/chờ xác minh) tách khỏi trạng thái
hoàn thành. Thời gian trên giao diện hiển thị theo múi giờ Việt Nam.

## Ngày mua và bảo hành

Quản Lý Computer hiển thị hai cột **Ngày Mua**, **Hết Hạn Bảo Hành**. Form
thêm/sửa có nhóm **Mua sắm & bảo hành**. Dashboard và danh sách tài sản hiện
cảnh báo cho admin khi còn từ 0 đến 30 ngày; hết hạn được đánh dấu riêng.
Ngày hết hạn vẫn được coi là còn hạn đến hết ngày đó (múi giờ Việt Nam).
Có bộ lọc sắp hết hạn/đã hết hạn/còn hạn/chưa có ngày và nút trong cảnh báo để
mở đúng danh sách. Ngày để trống không bị tính là hết hạn. Cảnh báo được tính
lại khi tải portal/danh sách hoặc lưu thiết bị, không cần tạo đợt kiểm kê.
Đây là cảnh báo trên web, chưa gửi email hoặc thông báo khi không mở portal.

Giao diện (kể cả các ô nhập), lịch sử và file xuất dùng **DD/MM/YYYY**;
ngày giờ dùng **DD/MM/YYYY HH:mm:ss**. Ô nhập không phụ thuộc locale trình duyệt.
Dữ liệu API và bản chụp lưu trữ vẫn dùng ISO để đảm bảo tương thích.

CSV xuất thêm `Ngày Mua`, `Ngày Hết Hạn Bảo Hành`. Nhập hỗ trợ `YYYY-MM-DD`
hoặc `DD/MM/YYYY`; hết hạn không được trước ngày mua. Chưa biết ngày thì để trống.
CSV cũ thiếu hai cột này vẫn nhập được, giữ nguyên ngày đã có. Cột có mặt nhưng
ô trống nghĩa là xóa ngày đó. File `computers.csv` gốc không bị sửa/tự nhập.

## Lịch sử

Ba bảng mới: `inventory_rounds`, `inventory_items`, `inventory_events`.
Mỗi lần lưu ghi đợt, thiết bị, người thao tác, thời gian, giá trị trước/sau và ghi chú.
Cập nhật danh mục và ghi lịch sử dùng cùng transaction. Kiểm tra phiên bản kết quả
và thông tin danh mục để tránh ghi đè khi hai người sửa. Khi xung đột, mở lại máy
để lấy dữ liệu mới. Bản đầu đợt được giữ riêng, không phụ thuộc các đợt tiếp theo.

Xóa máy khỏi danh mục vẫn giữ bản chụp/lịch sử đợt để xem. Lịch sử kiểm kê không
bị xóa theo chức năng dọn Audit Log. Xuất Excel gồm kết quả, thông tin đầu đợt và
lịch sử đầy đủ; thời gian xuất có múi giờ.

Sửa từ màn hình Quản Lý Computer ngoài kiểm kê vẫn theo Audit Log hiện tại,
không tự gán vào một đợt bất kỳ.

## Điện thoại / HTTPS

Với server `192.168.99.82` không có DNS nội bộ, đã có cấu hình dùng HTTPS trực
tiếp bằng IP. Xem [HTTPS.md](HTTPS.md) để tạo chứng chỉ, chạy reverse proxy và
cài CA tin cậy trên điện thoại.

Điện thoại cần kết nối được tới server qua Wi-Fi nội bộ hoặc VPN. Quét camera
trong web cần HTTPS và chứng chỉ được điện thoại tin cậy. HTTP qua IP LAN vẫn
dùng nhập tay được nhưng không đủ để cấp quyền camera. Không cần public Internet.
Thư viện đọc QR được lưu tại `app/static/vendor`, không tải CDN khi sử dụng.

Có thể dùng Nginx trên host làm reverse proxy HTTPS tới cổng 80 của Compose:

```nginx
server {
    listen 443 ssl;
    server_name inventory.example.internal;
    ssl_certificate /etc/nginx/certs/inventory.crt;
    ssl_certificate_key /etc/nginx/certs/inventory.key;
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Thay hostname/đường dẫn bằng cấu hình thật. DNS nội bộ trỏ về Ubuntu; nếu dùng
CA nội bộ, cài tin cậy CA trên điện thoại. File `nginx.conf` cũ chưa được Compose
sử dụng; ví dụ trên dành cho Nginx chạy trên host ở cổng 443.

## Kiểm thử

Dùng PostgreSQL kiểm thử riêng, không trỏ tới DB đang sử dụng:

```sh
INVENTORY_TEST_DSN='host=127.0.0.1 dbname=inventory_test user=postgres password=...' \
  python -m unittest discover -s tests -v
```

Tests tạo schema ngẫu nhiên rồi dọn schema khi xong. Bao gồm ngày, phân quyền,
chốt danh sách, hoàn thành/mở lại, lịch sử, xung đột, đóng đợt, xuất Excel và
độc lập giữa các đợt. Thư viện test dùng chung `app/requirements.txt`.

Phạm vi bản đầu: đợt mở ngay khi tạo; chưa có bước nháp/duyệt, thêm máy vào đợt
đã tạo, ảnh đính kèm, phân quyền nhân viên kiểm kê hoặc làm việc offline.
