## Giới thiệu
Đây là code demo.

## Cấu trúc thư mục
```
project/
│── backend/
│   └── app.py         # Python backend (Scrapy / Flask - tuỳ cấu hình)
│── frontend/
│   └── ...            # File HTML/CSS/JS cho ElectronJS
│── package.json       # Cấu hình ElectronJS
│── README.md          # Tài liệu hướng dẫn
```

## Công nghệ sử dụng
- Frontend: ElectronJS (HTML/CSS/JavaScript)
- Backend: Python (Scrapy)

## Tính năng

### Bắt buộc
- Giao diện đồ họa (GUI)
  - Form nhập thông tin các trường header (Ethernet, IP, TCP/UDP/ICMP).
  - Cho phép người dùng chọn loại giao thức cần ghép.
- Xây dựng & Gửi gói tin
  - Tạo gói tin từ dữ liệu người dùng nhập bằng Scapy.
  - Hỗ trợ nhiều interface mạng: liệt kê toàn bộ card mạng, cho phép chọn interface để gửi.
  - Gửi gói qua interface đã chọn.
- Bắt & Hiển thị phản hồi
  - Sniff gói tin trả về.
  - Hiển thị thông tin trong GUI (Src, Dst, Protocol, Payload).

### Nâng cao
- Packet Templates (mẫu sẵn)
  - Một số mẫu định nghĩa sẵn: ICMP Echo (Ping), TCP SYN, HTTP GET.
  - Cho phép lưu/tải gói tin dưới dạng JSON để dùng lại.
- Batch sending & Stress test
  - Gửi nhiều gói liên tục (chỉnh số lượng / tốc độ).
  - Cho phép dừng, thống kê số lượng đã gửi.
- Export PCAP
  - Xuất toàn bộ gói đã gửi và phản hồi nhận được thành file .pcap.
  - Có thể mở bằng Wireshark để phân tích.
- Traceroute / Port Scan (công cụ kiểm tra mạng nhỏ)
  - Traceroute: gửi ICMP Echo với TTL tăng dần → hiển thị danh sách router trung gian đến đích.
  - Port Scan: cho phép nhập host + dải port → gửi TCP SYN, phân loại kết quả (Open / Closed / Filtered).

## Cài đặt môi trường

### 1. Cài đặt Python & Flask / Scrapy
- Cài đặt Python (phiên bản 3.8+).
- Mở terminal và cài đặt các thư viện Python cần thiết:
```bash
pip install flask flask-cors scapy
```

### 2. Cài đặt Node.js & ElectronJS
- Cài đặt Node.js (phiên bản 16+).
- Trong thư mục dự án, cài đặt dependencies:
```bash
npm install
```

## Chạy ứng dụng

### 1. Chạy backend (Python)
Mở terminal trong thư mục `backend/` và chạy:
```bash
python app.py
```

### 2. Chạy frontend (ElectronJS)
Mở terminal trong thư mục gốc dự án và chạy:
```bash
npm start
```

Ứng dụng sẽ kết nối giữa **Python backend** và **ElectronJS frontend**.