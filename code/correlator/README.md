# Correlator

`correlator` adalah komponen yang mengumpulkan alert Wazuh menjadi sesi insiden berdasarkan IP sumber.

## Tujuan

- Mengambil alert yang belum dikorelasikan dari koleksi MongoDB `alerts`.
- Membentuk sesi `sessions` berdasarkan `src_ip` dan decoder.
- Mengelompokkan fase serangan: `initial_access`, `discovery`, `execution`, `persistence`.
- Menghitung `severity_score` dan menentukan tingkat `severity`.
- Menandai alert sebagai `correlated` agar tidak diproses ulang.

## File utama

- `cmd/main.go`: daemon korelasi lengkap.
- `internal/session.go`: schema data `Event` dan `Session`.

## Alur eksekusi

1. Koneksi MongoDB dibuka.
2. Loop kontinyu mencari alert dengan `correlated != true`.
3. Dokument difilter berdasarkan daftar rule penting di beberapa kategori.
4. Jika alert relevan, akan diidentifikasi berdasarkan decoder:
   - `docker_dvwa`: mengolah `srcip` dari field `data.srcip`.
   - `json`: mengolah `src_ip` dari `data.src_ip`.
   - `auditd`: menambahkan event ke sesi aktif terbaru bila ada.
5. Setiap alert yang diproses ditandai `correlated=true`.
6. Sesi diperbarui/di-upsert dengan perhitungan skor, event, dan fase serangan.
7. Jika skor tinggi, dapat memicu hook AI tambahan.

## Fitur penting

- Fase serangan diatur dari rule ID yang telah dikategorikan.
- `getSeverityTier` mengonversi skor numerik menjadi `low`, `medium`, `high`, atau `critical`.
- Sesi lama yang tidak aktif selama 10 menit ditutup (`status: closed`).
- Sesi aktif diidentifikasi berdasarkan `src_ip` dan status `active`.

## Catatan

- Konektor MongoDB menggunakan `mongodb://localhost:27017`.
- Terdapat placeholder untuk menambahkan panggilan webhook / broker saat `high` atau `critical` terdeteksi.
