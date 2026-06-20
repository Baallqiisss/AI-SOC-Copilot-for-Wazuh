# Wazuh Collector

`wazuh-collector` membaca log Wazuh dari file JSON dan menyimpannya ke MongoDB.

## Tujuan

- Mengikuti file log `alerts.json` dan `archives.json`.
- Mengurai setiap baris JSON dan menyimpannya ke koleksi MongoDB yang sesuai.
- Menyediakan aliran data alert dan log mentah untuk komponen korelasi dan analisis.

## File utama

- `cmd/main.go`: program utama collector.
  - Membuka koneksi MongoDB.
  - Memulai tailing file log Wazuh.
  - Menyimpan dokumen ke koleksi `alerts` dan `raw_logs`.
- `internal/mongo.go`: helper koneksi MongoDB.
- `internal/tailer.go`: helper untuk mengikuti file log secara live.

## Alur eksekusi

1. Koneksi MongoDB dibuat.
2. Tail file `alerts.json` dan `archives.json` menggunakan `hpcloud/tail`.
3. Setiap baris JSON yang valid dimasukkan ke koleksi yang sesuai.
4. Log berhasil dicetak ke stdout.

## Catatan

- File path log adalah:
  - `/var/ossec/logs/alerts/alerts.json`
  - `/var/ossec/logs/archives/archives.json`
- MongoDB lokal yang digunakan pada `mongodb://localhost:27017`.
- Kode tidak melakukan retry agresif atau buffering jika MongoDB offline.
