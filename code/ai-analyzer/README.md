# AI Analyzer

`ai-analyzer` adalah layanan daemon yang mengeksekusi analisis atas sesi insiden berbahaya yang sudah terkorelasi.

## Tujuan

- Memproses dokumen sesi dari koleksi MongoDB `sessions`.
- Memfilter sesi dengan level `high` atau `critical` yang belum dianalisis (`ai_analyzed != true`).
- Mengirim konteks sesi ke model LLM lewat endpoint `http://localhost:11434/v1/chat/completions`.
- Menyimpan laporan investigasi terstruktur ke koleksi `investigations`.
- Mengirim notifikasi ke Discord untuk insiden dengan confidence tinggi.

## File utama

- `main.go`: implementasi penuh daemon.
  - `SessionEvent`, `IncidentSession`, `InvestigationReport` untuk schema BSON/JSON.
  - `analyzeSessionWithLLM` membuat prompt, memanggil model, dan mem-parsing respons JSON.
  - `dispatchNotification` mengirim hasil ke webhook Discord.

## Konfigurasi

Konstanta di `main.go`:

- `MongoURI` — koneksi MongoDB.
- `LLMAPIEndpoint` — endpoint LLM.
- `LLMAPIKey` — kunci otorisasi untuk model.
- `LLMModel` — model yang digunakan.
- `DiscordWebhook` — URL webhook Discord.
- `PollingInterval` — jeda loop utama.

## Alur eksekusi

1. Koneksi MongoDB dibuka.
2. Loop kontinyu mencari sesi `high`/`critical` yang belum dianalisis.
3. Jika ditemukan, sesi dikirim ke model LLM.
4. Hasil parsing JSON disimpan ke `investigations`.
5. Dokumen sesi diperbarui menjadi `ai_analyzed = true`.
6. Bila confidence >= 80, kirim embed notifikasi Discord.

## Catatan

- Model LLM harus merespons JSON valid yang sesuai dengan schema yang diharapkan.
- Kode ini menggunakan `severity_score` dan `attack_phases` untuk analisis konteks.
- Notifikasi Discord menggunakan embed field dengan batas panjang 1024 karakter.
