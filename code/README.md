# Dokumentasi Folder `code`

Folder `code/` berisi tiga layanan Go utama yang membangun pipeline AI SOC untuk Wazuh:

- `wazuh-collector/`: kolektor Wazuh yang membaca log JSON dari file dan menyimpan ke MongoDB.
- `correlator/`: daemon korelasi yang menggabungkan alert menjadi sesi insiden berdasarkan `src_ip` dan tahap serangan.
- `ai-analyzer/`: layanan AI yang memproses sesi berbahaya, memanggil model LLM, menyimpan laporan investigasi, dan mengirim notifikasi Discord.

## Struktur

- `docker-compose.yml`: service MongoDB lokal.
- `go.mod`: modul Go root untuk `code/`.
- `ai-analyzer/main.go`: logika analisis AI dan pembuatan laporan.
- `correlator/cmd/main.go`: logika korelasi alert menjadi sesi.
- `correlator/internal/session.go`: schema data sesi dan event.
- `wazuh-collector/cmd/main.go`: pengekstrak log Wazuh ke MongoDB.
- `wazuh-collector/internal/mongo.go`: koneksi MongoDB.
- `wazuh-collector/internal/tailer.go`: helper untuk mengikuti file log secara terus-menerus.

## Alur kerja umum

1. `wazuh-collector` membaca file log Wazuh dan menyimpan data mentah ke MongoDB.
2. `correlator` memindai dokumen `alerts` yang belum dikorelasikan, mengelompokkan alert ke dalam sesi berdasarkan `src_ip`, mengisi atribut fase serangan, dan memperbarui skor serta `severity`.
3. `ai-analyzer` mengambil sesi `high`/`critical` yang belum dianalisis, memanggil model LLM untuk membuat laporan investigasi, menyimpan hasil ke koleksi `investigations`, dan mengirim notifikasi ke Discord.

## Catatan penting

- Semua layanan saat ini menggunakan `mongodb://localhost:27017`.
- `ai-analyzer` mengharapkan endpoint LLM lokal di `http://localhost:11434/v1/chat/completions`.
- `docker-compose.yml` hanya menjalankan service MongoDB.
- `correlator` memiliki placeholder AI hook untuk pemanggilan token atau webhook tambahan pada sesi `high`/`critical`.
