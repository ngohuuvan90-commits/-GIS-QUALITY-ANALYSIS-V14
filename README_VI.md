# GIS QUALITY ANALYSIS V14 – Private Web

## Kiến trúc bảo vệ
- Cloudflare Worker kiểm tra phiên đăng nhập ở phía máy chủ trước khi trả về ứng dụng và mọi tài nguyên trong `public`.
- Chỉ `login.html`, `login.js` và các API đăng nhập/khởi tạo được công khai.
- Dữ liệu CSV/Excel do người dùng chọn được xử lý trong trình duyệt; ứng dụng không gửi các tệp sản xuất lên D1.
- D1 lưu tài khoản, hash mật khẩu, phiên đăng nhập và số lần đăng nhập sai.

## Cấu hình đã điền
- Worker: `gis-quality-analysis-v14`
- D1 binding: `DB`
- D1 database: `gis_quality_analysis_db`
- Database ID: `0ed53b48-82c6-4781-b452-cba07034f0e6`

## Triển khai bằng Cloudflare Workers Builds
1. Push toàn bộ thư mục dự án lên repository GitHub V14.
2. Trong Cloudflare Workers & Pages, kết nối repository này với Worker.
3. Root directory: `/` (thư mục chứa `wrangler.toml`).
4. Build command: để trống nếu giao diện cho phép; Deploy command: `npx wrangler deploy`.
5. Đảm bảo Worker có binding D1 tên `DB` trỏ đúng database ID ở trên. `wrangler.toml` cũng khai báo binding này.
6. Không triển khai thư mục `public` như một Pages site công khai độc lập; phải đi qua Worker có `run_worker_first = true`.

## Khởi tạo Admin (chỉ làm một lần)
1. Tạo secret trong Worker:
   `npx wrangler secret put ADMIN_SETUP_KEY`
   Nhập một chuỗi bí mật ngẫu nhiên dài, không dùng lại mật khẩu Admin. Không commit secret lên GitHub.
2. Sau khi Worker đã deploy, gọi endpoint một lần từ máy tính (PowerShell):

```powershell
$setupKey = Read-Host "Nhap ADMIN_SETUP_KEY"
$body = @{ username = "admin"; password = "THAY_BANG_MAT_KHAU_RIENG_DAI_IT_NHAT_12_KY_TU" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://TEN-WORKER.workers.dev/api/setup-admin" -Headers @{ "X-Setup-Key" = $setupKey } -ContentType "application/json" -Body $body
```

Thay URL và mật khẩu bằng giá trị của bạn. Không gửi mật khẩu hoặc setup key trong chat. Endpoint tự khóa sau khi tài khoản đầu tiên được tạo vì chỉ hoạt động khi bảng `users` còn trống.

## Kiểm tra sau deploy
- Mở `/`: chưa đăng nhập phải được chuyển đến `/login.html`.
- Mở trực tiếp `/index.html`, `/assets/gis-logo.png`, `/samples/...`: chưa đăng nhập phải bị chuyển đến trang đăng nhập.
- Tạo Admin một lần, đăng nhập, kiểm tra ứng dụng và đăng xuất.
- Sau đăng xuất, tải lại `/` phải quay về trang đăng nhập.

## Lưu ý bảo mật
- D1 schema phải được chạy trước khi dùng Worker. Các bảng `users`, `sessions`, `login_attempts` đã được tạo theo thao tác xác nhận của người triển khai.
- Không bật public Pages deployment trỏ thẳng vào thư mục `public`, vì việc đó sẽ bỏ qua lớp kiểm tra của Worker.
- Đường dẫn `workers.dev` chỉ hoạt động sau khi Cloudflare deploy thành công; tên miền cụ thể do Cloudflare cấp.
