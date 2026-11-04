#BinTriage
## Tuần 1: Phân tích PE bằng dòng lệnh

Từ thư mục gốc của repo, chạy lệnh sau với đường dẫn tới một file PE mẫu.

```sh
.venv/bin/python app/analysis/analyzer.py "/đường/dẫn/tới/mau.exe"
```

Chương trình đọc file dưới dạng byte và in báo cáo JSON gồm SHA-256,
kiến trúc, loại PE, timestamp trong header, thông tin các section,
tên DLL được import và cảnh báo của parser.

| Mã thoát | Ý nghĩa |
| --- | --- |
| 0 | Đã xuất báo cáo JSON |
| 1 | Không đọc được file hoặc PE không hợp lệ |
| 2 | Sai số lượng đối số |