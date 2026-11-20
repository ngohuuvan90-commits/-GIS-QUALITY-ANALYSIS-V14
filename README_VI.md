# GIS QUALITY ANALYSIS V14 – Web riêng tư

Bản này giữ giao diện phân tích từ gói V14 Web trước đó và bổ sung lớp xác thực chạy ở Cloudflare Worker + D1. APK/EXE V13.1 không bị chỉnh sửa.

## Có gì trong gói
- `public/`: giao diện phân tích hiện có và lớp đăng nhập phía trình duyệt.
- `worker.js`: xác thực phía máy chủ, session cookie HttpOnly, API quản trị.
- `schema.sql`: cấu trúc CSDL D1.
- `wrangler.toml`: cấu hình Worker/Assets/D1 (cần điền database_id).

## Triển khai (cần máy tính có Node.js và tài khoản Cloudflare)
1. Cài Wrangler: `npm install -g wrangler` rồi `wrangler login`.
2. Tạo D1: `wrangler d1 create gis-quality-analysis-v14`.
3. Copy `database_id` Cloudflare trả về vào `wrangler.toml`.
4. Tạo bảng: `wrangler d1 execute gis-quality-analysis-v14 --remote --file=./schema.sql`.
5. Tạo khóa khởi tạo Admin: `wrangler secret put ADMIN_SETUP_KEY` (tự đặt một chuỗi ngẫu nhiên dài; không gửi cho ai, không đưa vào GitHub).
6. Deploy: `wrangler deploy`.
7. Khởi tạo Admin một lần bằng máy tính cá nhân. Thay URL và giá trị khóa bằng thông tin của bạn:

```bash
curl -X POST "https://TEN-WORKER.ten-tai-khoan.workers.dev/api/setup-admin" \
  -H "Content-Type: application/json" \
  -H "X-Setup-Key: KHOA_SETUP_BAN_DA_TAO" \
  -d '{"username":"admin","password":"MAT_KHAU_RIENG_DAI_TU_12_KY_TU"}'
```

Sau khi tạo Admin thành công, endpoint tự khóa vì chỉ cho phép khi bảng users còn trống. Không lưu khóa hoặc mật khẩu trong source code. Hãy đổi ví dụ `admin` và mật khẩu thành thông tin riêng của bạn.

## Sử dụng
- Mọi đường dẫn ứng dụng và file tĩnh được Worker kiểm tra session trước khi trả về.
- Admin đăng nhập rồi bấm **Quản lý user**: `ADD` tạo tài khoản, `LOCK ID` khóa, `UNLOCK ID` mở, `RESET ID` đặt lại mật khẩu.
- User chỉ truy cập ứng dụng; không có tự đăng ký.
- Session hết hạn sau 8 giờ; đăng xuất sẽ thu hồi session.
- Dữ liệu CSV/Excel người dùng chọn vẫn được xử lý trong trình duyệt, không có API tải dữ liệu sản xuất lên máy chủ trong gói này.

## Kiểm tra và giới hạn
- Mật khẩu lưu dưới dạng PBKDF2-HMAC-SHA256 (310.000 vòng) kèm salt ngẫu nhiên; session lưu hash token, cookie HttpOnly/Secure/SameSite=Strict.
- Có giới hạn đăng nhập cơ bản 8 lần/15 phút theo IP+tài khoản. Nên bổ sung Cloudflare WAF/rate limiting ở mức zone/account nếu triển khai thực tế.
- Phải deploy qua Worker như hướng dẫn; không xuất bản thư mục `public` bằng Pages/public static hosting riêng, nếu không lớp bảo vệ Worker sẽ bị bỏ qua.
- Bản ZIP chưa được triển khai lên tài khoản Cloudflare của bạn và chưa thể xác nhận hoạt động trên Internet trước khi bạn cung cấp môi trường Cloudflare. Hãy kiểm tra API `/api/health` sau deploy.
