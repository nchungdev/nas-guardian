# NAS Guardian 🛡️ — Security Operation Center (SOC)

Dịch vụ giám sát an ninh mạng và **phòng thủ chủ động (Active Defense)** viết bằng **Go**, chạy trên máy chủ NAS (OpenMediaVault / Debian). 

Học hỏi từ kiến trúc tinh hoa của **CrowdSec** (Bouncer) và **Fail2ban** (Jail), hệ thống không chỉ báo động qua **Telegram/Zalo** mà còn trực tiếp can thiệp vào tầng nhân Linux (`iptables`) để **DROP hoàn toàn gói tin của kẻ tấn công**.

---

## 🚀 Các tính năng học hỏi từ CrowdSec & Fail2ban

1. **Active Firewall Bouncer (Tự động khóa IP tại tầng nhân Linux):**
   * Sử dụng chuỗi iptables chuyên dụng `NAS_GUARDIAN_JAIL` móc vào cả `INPUT` (bảo vệ cổng Host/SSH) và `DOCKER-USER` (bảo vệ toàn bộ Container Home Assistant, Nginx, OMV).
   * **Cơ chế Fail2ban Jail:** Khi một IP vi phạm quá số lần quy định (`max_failures: 3` lần trong `600s`), hệ thống tự động chèn rule `DROP` vào iptables. Kẻ tấn công bị ngắt kết nối ngay lập tức!
   * **Auto-Unban Timer:** Tự động mở khóa và dọn sạch rule sau thời hạn cấm (`ban_duration: 3600s` / 1 tiếng).
   * **Tuyệt đối an toàn (Whitelist Protection):** Không bao giờ khóa nhầm các dải mạng tin cậy (`127.0.0.1`, `192.168.1.0/24`, Mac mini, VPN nội bộ).

2. **Honeypot Decoy Trap (Cổng bẫy bắt kẻ rà quét ngầm):**
   * Mở cổng bẫy giả lập (mặc định Port `2222`).
   * Bất kỳ IP nào cố tình quét vào cổng bẫy (vốn người dùng thật không bao giờ đụng tới) sẽ **bị kích hoạt BẪY và KHÓA NGAY LẬP TỨC (Instant Ban 24h)** mà không cần đợi thử sai 3 lần!

3. **Giám sát thời gian thực đa tầng (Multi-Engine Log Watcher):**
   * **Home Assistant:** Theo dõi token sai, dò mật khẩu, IP bị HA cấm.
   * **SSH Daemon:** Theo dõi qua `journalctl -u ssh`, bắt brute-force hoặc đăng nhập thành công từ IP lạ ngoài Internet.
   * **Nginx / Web GUI:** Phát hiện quét lỗ hổng Web, scan file nhạy cảm (`/.env`, `/wp-admin`, `phpmyadmin`...), lỗi `401`/`403`.
   * **Tra cứu GeoIP/ISP tự động:** Tự động định danh Thành phố, Quốc gia, Nhà mạng của IP tấn công.

4. **Web GUI Dashboard tương tác 2 chiều (Port 8799):**
   * Truy cập trực tiếp: `http://<IP_NAS>:8799`
   * Bảng thống kê số lượng tấn công, Uptime thời gian thực.
   * **Quản lý danh sách cấm (Jail Manager):** Xem danh sách IP đang bị khóa, đếm ngược thời gian còn lại, và có nút **"Mở khóa (Unban)"** thủ công trực tiếp từ giao diện.
   * Nút **"⚡ Thử gửi cảnh báo"** để test chuông Telegram / Zalo.
   * Kết nối **SSE (Server-Sent Events)** tự động đẩy dữ liệu thời gian thực.

---

## 📦 Cấu trúc thư mục

```text
├── Makefile                # Lệnh build, deploy sang NAS, kiểm tra trạng thái
├── README.md               # Tài liệu dự án
├── config.example.json     # Mẫu cấu hình mẫu
├── go.mod                  # Go module definition
├── main.go                 # Toàn bộ mã nguồn Go
└── nas-guardian.service    # File service systemd
```

---

## 🛠️ Quản lý & Triển khai

Từ Mac mini:

```bash
# Biên dịch và deploy phiên bản mới lên NAS
make deploy

# Xem trạng thái service trên NAS
make status

# Xem log trực tiếp
make logs

# Khởi động lại
make restart
```
