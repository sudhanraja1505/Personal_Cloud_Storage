Personal Cloud File Storage
Run locally (Windows / Mac / Linux)
python -m venv venv
venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
python -m pip install -r requirements.txt
python app.py                  # open http://localhost:5000
Features
Register / sign in (JWT, hashed passwords); every user only sees their own files
Upload multiple files by drag-and-drop; 100 MB quota per user, 50 MB per upload
Download, rename, delete, search
Share links with optional expiry; stop sharing any time
Risky file types (exe, bat, js, sh ...) are rejected; downloads are always forced as attachments
Deploy to the cloud
 <img width="1901" height="897" alt="Screenshot 2026-10-25 224231" src="https://github.com/user-attachments/assets/19f2b6f5-8e1c-4949-bbde-73d06433b4f5" />

Set SECRET_KEY, STORE_DIR (a persistent disk), optional DB_PATH
Linux: pip install gunicorn, run gunicorn app:app. Windows: pip install waitress, run waitress-serve app:app
For real scale: swap store_file/remove_file/send for S3 (boto3) and SQLite for PostgreSQL (RDS); serve over HTTPS
