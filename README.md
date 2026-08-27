# Bank Dev API - Render

Demo API nạp tiền dùng Flask + SQLite + Waitress.

## Endpoints

- GET `/`
- POST `/api/register`
- POST `/api/deposit`
- GET `/api/balance`
- GET `/api/transactions`

## Deploy Render

Build Command:
`pip install -r requirements.txt`

Start Command:
`waitress-serve --host=0.0.0.0 --port=$PORT server:app`

Procfile đã có sẵn.

## Lưu ý

Đây là hệ thống demo/phát triển, không phải hệ thống ngân hàng thật.
Không dùng API `/api/deposit` để ghi nhận tiền thật. Khi tích hợp thanh toán thực tế,
nên xác nhận giao dịch từ webhook/nguồn ngân hàng đáng tin cậy trước khi cập nhật số dư.
