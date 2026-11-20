# HTTPS bằng IP nội bộ — 192.168.99.82

Không cần tên miền, sửa DNS hoặc thay đổi Domain Controller. Server dùng
`https://192.168.99.82`. Chứng chỉ có SAN là IP này, ký bằng một CA nội bộ riêng.
Mỗi điện thoại/máy tính dùng portal cần cài **CA công khai** và tin cậy nó một lần.

## 1. Chạy trên server Ubuntu

Trong thư mục dự án có `docker-compose.yml`, sau khi cập nhật các file mới:

```bash
sudo apt update
sudo apt install -y openssl
bash scripts/setup-local-https.sh 192.168.99.82
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.https.yml exec https-proxy nginx -t
```

Nếu dùng UFW, cho phép truy cập cổng 443 từ mạng LAN (đổi subnet nếu mạng khác):

```bash
sudo ufw allow from 192.168.99.0/24 to any port 443 proto tcp
```

Không chạy `ufw enable` chỉ để thực hiện bước này. Nếu cổng 443 đã có dịch vụ
khác sử dụng, cần ghép cấu hình TLS vào reverse proxy hiện có hoặc đổi port.

File Compose bổ sung tạo Nginx ở cổng 443 và trỏ đến container `web-app:5000`.
Database/volume đang có được giữ nguyên. Cổng HTTP 80 cũ vẫn hoạt động để chuyển
tiếp dần; cấu hình này chưa tự chuyển HTTP sang HTTPS. Sau khi thiết lập, dùng
HTTPS cho mọi thao tác quét và in QR. Biến `ASSET_PUBLIC_BASE_URL` của container
được đặt mặc định thành `https://192.168.99.82` để tem mới chứa đúng đường dẫn.

Nếu `.env` đã có `ASSET_PUBLIC_BASE_URL`, đổi giá trị đó sang HTTPS tương ứng.
Khi cập nhật/restart về sau, tiếp tục sử dụng **cả hai file Compose** trong lệnh.

## 2. Cài chứng chỉ trên điện thoại

Chỉ sao chép file **`certs/portal-root-ca.crt`** sang điện thoại. Không sao chép
`portal-root-ca.key` hay `server.key`. Có thể dùng SCP để lấy file về máy tính:

```powershell
scp USER_UBUNTU@192.168.99.82:/DUONG_DAN_DU_AN/certs/portal-root-ca.crt .
```

Thay username và đường dẫn thực tế. Sau đó chuyển file `.crt` sang điện thoại.

**iPhone/iPad:** cài profile chứng chỉ từ file, rồi vào
**Cài đặt → Cài đặt chung → Giới thiệu → Cài đặt tin cậy chứng nhận**, bật
**Tin cậy hoàn toàn** cho **Infrastructure Portal Local CA**. Chỉ cài profile
mà chưa bật tin cậy SSL là chưa đủ.

**Android:** trong Cài đặt, tìm **Cài chứng chỉ / Install certificate**, chọn
**Chứng chỉ CA / CA certificate** và chọn file `.crt`. Vị trí menu thay đổi theo
hãng/phiên bản; đây là CA cho trình duyệt, không phải chứng chỉ người dùng/VPN.
Thiết bị do tổ chức quản lý có thể cần quản trị viên cho phép cài CA.

Nếu dùng máy tính, cũng cài CA vào kho Trusted Root của hệ điều hành/trình duyệt.

## 3. Kiểm tra quét

1. Mở **`https://192.168.99.82/login`** trực tiếp trong Safari/Chrome.
2. Trang phải hết cảnh báo chứng chỉ. Đăng nhập lại vì HTTP/HTTPS khác origin.
3. Vào **Kiểm Kê Tài Sản → chọn đợt → Quét QR**, cho phép camera.
4. Xuất lại tem bằng HTTPS: bộ quét kiểm kê hiện nhận QR URL cùng origin.
   Tem HTTP cũ vẫn mở trang HTTP khi quét bằng camera ngoài; cần in lại để
   chuyển thẳng sang HTTPS. QR cũ chỉ chứa tên/mã tài sản vẫn được hỗ trợ.

Không mở qua trình duyệt nhúng trong ứng dụng chat nếu camera bị chặn.
Không dùng cách bỏ qua cảnh báo chứng chỉ thay cho việc cài tin cậy CA.

Kiểm tra TLS trên Ubuntu:

```bash
openssl s_client -connect 192.168.99.82:443 \
  -CAfile certs/portal-root-ca.crt -verify_ip 192.168.99.82 \
  -verify_return_error </dev/null
```

Trong console trình duyệt, `window.isSecureContext` cần là `true`, và
`navigator.mediaDevices?.getUserMedia` phải tồn tại.

## Gia hạn và IP

Chứng chỉ server có hạn 365 ngày. Trước khi hết hạn, chạy lại cùng script/cùng IP,
rồi restart Nginx:

```bash
bash scripts/setup-local-https.sh 192.168.99.82
docker compose -f docker-compose.yml -f docker-compose.https.yml restart https-proxy
```

Script giữ nguyên CA/key hiện có để không phải cài lại CA trên điện thoại.
Sao lưu thư mục `certs` an toàn; nó đã được bỏ qua bởi Git. Nginx chỉ được mount
key/cert server, không được mount private key của CA. Không xóa CA khi gia hạn.

Giữ IP server cố định. Nếu IP đổi, cấp lại chứng chỉ với IP mới, cập nhật
`ASSET_PUBLIC_BASE_URL` và in lại QR chứa IP cũ. Không cần đổi CA nếu vẫn giữ CA cũ.

Tham khảo: [Quyền camera của trình duyệt](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia),
[tin cậy chứng chỉ trên iPhone](https://support.apple.com/en-us/102390),
[cấu hình HTTPS Nginx](https://nginx.org/en/docs/http/configuring_https_servers.html).
