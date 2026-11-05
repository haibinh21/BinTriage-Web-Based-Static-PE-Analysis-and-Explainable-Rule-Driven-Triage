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

## Kiểm thử

Chạy từ thư mục gốc của repo.

```sh
.venv/bin/python -m pytest -v
```

Các bài kiểm thử hiện kiểm tra mã thoát và thông báo lỗi khi thiếu
đường dẫn, file không tồn tại và file không phải PE hợp lệ.

### File mẫu kiểm thử

`tests/fixtures/hello-pe.exe` là PE32+ tối giản, được tạo bằng
Python cho bài thực hành đọc cấu trúc PE.

File có kích thước 1024 byte, một section `.text` và không có imports.
Các bài kiểm thử chỉ đọc file để kiểm tra báo cáo JSON của analyzer.

Mẫu chứa nhiều byte đệm 0, nên pefile có thể đưa ra cảnh báo
về tỷ lệ byte 0 cao. Analyzer giữ cảnh báo này trong báo cáo.