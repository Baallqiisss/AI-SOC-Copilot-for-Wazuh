# Laporan Proyek Wazuh AI Attack-Chain Reconstruction

*Data per: 18 Jun 2026*

---

## 1. Apa Itu Program Ini?

Sebuah **pipeline security operations bertenaga AI** yang mengubah alert mentah dari Wazuh menjadi rekonstruksi attack chain lengkap dengan laporan insiden yang actionable — dikirim otomatis ke tim security melalui Discord.

Alih-alih analis harus menyortir manual ribuan baris log untuk mencari tahu *apa yang terjadi, dalam urutan seperti apa, dan apa yang harus dilakukan selanjutnya*, sistem ini:

1. **Mengumpulkan** setiap alert dan raw log dari Wazuh ke dalam satu data lake MongoDB terpusat.
2. **Mengorelasikan** alert dari source IP yang sama menjadi satu "sesi serangan" — menandai fase MITRE ATT&CK (Initial Access, Discovery, Execution, Persistence) seiring serangan berlangsung.
3. **Menganalisis** setiap sesi berkategori high/critical menggunakan LLM lokal yang membaca seluruh timeline event dan menulis laporan investigasi terstruktur (ringkasan, skor confidence, fase serangan, tindakan yang direkomendasikan).
4. **Mengirimkan** laporan tersebut ke Discord dengan embed berkode warna begitu confidence-nya cukup tinggi.

**Tanpa cloud API, tanpa vendor LLM eksternal, tanpa biaya per-token** — model AI berjalan sepenuhnya di VPS yang sama dengan Wazuh.

---

## 2. Tujuan Utama

**Mengurangi mean-time-to-respond (MTTR) untuk insiden keamanan dengan mengotomatisasi bagian paling memakan waktu dari pekerjaan SOC: memahami banjir alert.**

Seorang penyerang yang menyerang aplikasi web selama 10 menit bisa menghasilkan **100+ alert** (recon, SQLi, RCE, file upload, reverse shell). Analis manusia harus membaca semuanya, mencari tahu urutannya, mengidentifikasi tahapan serangan, dan memutuskan tindakan apa yang harus diambil. Itu memakan waktu 30–60 menit per insiden.

Pipeline ini melakukannya dalam **~3 menit**, tanpa pengawasan, 24/7, dan mengirim hasilnya ke channel chat tim.

---

## 3. Arsitektur — Tiga Modul Inti

```
                       Wazuh Manager (native)
                              |
                     alerts.json / archives.json
                              |
                    +---------+---------+
                    |                   |
              wazuh-collector     (raw log juga)
                    |                   |
                    v                   v
                 MongoDB (wazuh db)
                 | alerts | raw_logs |
                              |
                    +---------+---------+
                    |                   |
              wazuh-correlator          |
                    |                   |
                    v                   |
              sessions (per src_ip)     |
                    |                   |
                    +-------+-----------+
                            |
                      ai-analyzer
                            |
                    Ollama (qwen2.5:3b)
                            |
                  laporan investigasi
                            |
                    Discord webhook
```

### Modul 1 — `wazuh-collector` (Go)
- Melakukan tail pada `/var/ossec/logs/alerts/alerts.json` dan `/var/ossec/logs/archives/archives.json` secara real time.
- Menyisipkan setiap alert dan baris raw log sebagai dokumen BSON ke MongoDB.
- Saat ini sudah ter-ingest: **337 alert, 412.403 raw log**.

### Modul 2 — `wazuh-correlator` (Go)
- Melakukan polling ke MongoDB untuk alert yang belum dikorelasikan setiap 2 detik.
- Mengelompokkan alert berdasarkan `src_ip` menjadi "sesi aktif" dengan idle timeout 10 menit.
- Menandai setiap sesi dengan boolean fase MITRE ATT&CK seiring rule yang cocok masuk:
  - **Initial Access** — percobaan login, SQLi auth bypass
  - **Discovery** — recon, akses endpoint sensitif, path traversal
  - **Execution** — command injection, SSTI, RCE, reverse shell
  - **Persistence** — upload file mencurigakan (web shell)
- Menghitung skor severity dinamis (jumlah level rule) → tier (low/medium/high/critical).
- Menutup sesi setelah idle 10 menit; sesi high/critical memicu hook AI.

### Modul 3 — `ai-analyzer` (Go + Ollama)
- Melakukan polling untuk sesi high/critical yang belum dianalisis.
- Menyusun prompt terstruktur dari timeline sesi (dibatasi 25 event kunci agar layak secara CPU).
- Memanggil **model Ollama lokal** (`qwen2.5:3b`, 1.9 GB) melalui endpoint `/v1/chat/completions` yang kompatibel OpenAI, dengan `response_format: json_object` untuk menjamin output terstruktur.
- Mem-parsing JSON dari LLM ke dalam `InvestigationReport` bertipe:
  - `summary` — narasi tentang apa yang terjadi
  - `confidence` — skor 1–100
  - `attack_phases` — daftar fase MITRE yang berurutan
  - `recommended_actions` — langkah penanggulangan taktis
- Menyimpan laporan ke koleksi `investigations` di MongoDB.
- Jika `confidence >= 80`, mengirim embed Discord berkode warna (merah=critical, oranye=high).

---

## 4. Hasil Live Test

### Lingkungan pengujian
- Aplikasi web rentan di-deploy pada Wazuh agent `001` (web-public) di `http://43.159.48.191:8080`.
- 6 kelas kerentanan yang diuji: information disclosure, SQLi, OS command injection / RCE / reverse shell, SSTI, unrestricted file upload + path traversal.
- **40 rule Wazuh kustom** (12 di `vuln_lab_rules.xml` + 28 di `local_rules.xml`) men-decode dan mendeteksi sinyal serangan.

### Simulasi serangan — 112 alert dari satu sumber dalam ~3 menit

| Rule | Deteksi | Jumlah |
|------|-----------|-------|
| 100001 | Aktivitas reconnaissance | 31 |
| 100020 | Remote Code Execution terkonfirmasi | 31 |
| 100010 | Percobaan SQL Injection | 15 |
| 100011 | Percobaan Command Injection | 16 |
| 100012 | Server-Side Template Injection | 15 |
| 100005 | Login berhasil | 10 |
| 100013 | Upload file mencurigakan | 10 |
| 100014 | Percobaan path traversal | 10 |
| 100021 | Tanda tangan reverse shell | 1 |

### Rekonstruksi attack chain oleh AI (verbatim dari LLM)

**Sesi 1 — aplikasi vuln_lab (src: 127.0.0.1)**
- Severity: **CRITICAL** | Confidence: **95%**
- Fase serangan: **Initial Access → Discovery → Execution → Persistence**
- Ringkasan LLM: *menggambarkan sesi ini sebagai serangan canggih yang melibatkan berbagai tahapan termasuk reconnaissance, command injection, remote code execution, dan server-side template injection — dengan penyerang diduga telah memperoleh akses awal lewat percobaan login yang berhasil, lalu mengeksekusi perintah berbahaya untuk mendapatkan persistence dan menjalankan kode arbitrer dengan privilege yang lebih tinggi.*
- Tindakan yang direkomendasikan: segmentasi jaringan, analisis forensik, menonaktifkan layanan non-esensial, patch software, meninjau log login.

**Sesi 2 — SSH brute-force dunia nyata (src: 114.10.47.145)**
- Severity: **CRITICAL** | Confidence: **95%**
- Fase serangan: **Initial Access → Discovery → Execution → Persistence → Impact**
- Pipeline ini juga menangkap penyerang brute-force eksternal sungguhan yang menyerang server selama pengujian berlangsung — membuktikan sistem ini bekerja pada traffic nyata, bukan hanya serangan simulasi.

Kedua laporan otomatis dikirim ke Discord sebagai embed merah CRITICAL.

---

## 5. Apa Saja yang Bisa Dilakukan Proyek Ini (Kemungkinan Maksimal)

### Kemampuan saat ini (sudah berfungsi)
- **Rekonstruksi attack chain tanpa pengawasan 24/7** dari alert Wazuh.
- **Sesionisasi per-penyerang** — setiap source IP mendapat timeline serangannya sendiri.
- **Penandaan fase MITRE ATT&CK** — otomatis mengklasifikasikan setiap event masuk tahap kill-chain yang mana.
- **Inferensi AI lokal/privat** — tidak ada data yang keluar dari VPS, tanpa biaya API, ramah GDPR/kedaulatan data.
- **Alerting Discord real-time** dengan embed berkode severity, bukti, dan langkah remediasi.
- **Laporan investigasi terstruktur dan dapat di-query**, disimpan di MongoDB untuk jejak audit dan analisis tren.

### Kemampuan lanjutan (effort rendah untuk diaktifkan)
- **Korelasi multi-vektor** — perluas peta rule untuk mencakup SSH brute force, web attack, deteksi malware, lateral movement, C2 beaconing. Arsitektur correlator sudah mendukung pemetaan decoder + rule ID apa pun.
- **Pemetaan countermeasure MITRE D3FEND** — prompt LLM bisa diperluas untuk menyarankan teknik defensif per taktik yang terdeteksi.
- **Replay serangan historis** — MongoDB menyimpan setiap sesi + laporan, memungkinkan query seperti "tampilkan semua event Initial Access bulan ini".
- **Tier eskalasi berbasis confidence** — laporan confidence rendah diarahkan ke dashboard, confidence tinggi ke PagerDuty/Discord, critical ke telepon/SMS.
- **Fleet multi-agent** — Wazuh sudah mendukung ribuan agent; pipeline ini scale secara horizontal dengan men-shard MongoDB.
- **Pertukaran LLM** — Ollama mendukung model GGUF apa pun. Ganti `qwen2.5:3b` dengan `llama3.1:8b` atau model security hasil fine-tuning saat GPU tersedia.
- **Feedback loop** — menyimpan koreksi analis terhadap laporan investigasi → membangun dataset fine-tuning → meningkatkan model dari waktu ke waktu.

### Kemungkinan lanjutan (visi yang lebih besar)
- **Triase Tier-1 SOC otonom** — pipeline ini sudah melakukan pekerjaan analis junior dalam membaca alert dan menulis draf laporan pertama. Dengan persetujuan human-in-the-loop, ini bisa berkembang menjadi sistem auto-triage penuh.
- **Pengayaan threat-intelligence** — sebelum analisis LLM, perkaya setiap src_ip dengan GeoIP, ASN, reputation feed, dan riwayat insiden sebelumnya. LLM kemudian bernalar dengan konteks yang lebih kaya.
- **Deteksi kampanye serangan lintas-sesi** — mengorelasikan beberapa sesi dari IP/rentang waktu berbeda yang memiliki TTP sama (payload sama, user-agent sama) menjadi satu entitas "kampanye".
- **Skor prediktif** — dilatih dari sesi historis untuk memprediksi sesi severity rendah mana yang kemungkinan akan meningkat, memungkinkan pemblokiran proaktif sebelum serangan selesai.
- **Integrasi active response** — menghubungkan tindakan rekomendasi AI kembali ke script active-response Wazuh (misalnya, auto-block src_ip di firewall saat confidence > 90).
- **Pelaporan kepatuhan** — otomatis menghasilkan laporan insiden PCI-DSS / ISO 27001 / NIST 800-53 dari data investigasi terstruktur.

---

## 6. Seberapa Bergunanya Ini? (Value Proposition)

### Untuk tim SOC
| Tanpa pipeline ini | Dengan pipeline ini |
|---|---|
| Analis membaca 100+ alert per insiden | Analis membaca 1 laporan terstruktur |
| 30–60 menit untuk merekonstruksi attack chain | ~3 menit, sepenuhnya otomatis |
| Klasifikasi fase MITRE manual | Penandaan fase otomatis |
| Alert fatigue → insiden terlewat | Backlog tetap di 0, tidak ada yang terlewat |
| Catatan remediasi ad-hoc, tidak konsisten | Daftar tindakan terstandardisasi, dihasilkan LLM |

### Untuk organisasi
- **Biaya**: Berjalan di satu VPS 4-vCPU / 8 GB yang sudah meng-host Wazuh. **Tanpa biaya marjinal per insiden yang dianalisis** dibanding $0,01–0,05 per 1K token dengan OpenAI/Anthropic.
- **Privasi**: Data serangan tidak pernah keluar dari infrastruktur Anda. Krusial untuk industri yang diatur ketat (finansial, kesehatan, pemerintahan).
- **Reliabilitas**: Semua 5 layanan (wazuh-manager, collector, correlator, ai-analyzer, ollama) dikelola systemd dengan `Restart=always` — bertahan dari reboot dan crash secara otomatis.
- **Auditabilitas**: Setiap alert → sesi → laporan investigasi disimpan di MongoDB dengan timestamp, memungkinkan postmortem insiden penuh dan bukti kepatuhan.

---

## 7. Keterbatasan & Kendala Saat Ini

| Keterbatasan | Detail | Mitigasi |
|---|---|---|
| Inferensi CPU-only | Tidak ada GPU di VPS; qwen2.5:3b berjalan di ~1,5 tok/s | Batas event (25) menjaga prompt tetap layak (~3 menit/analisis). Tambahkan GPU untuk percepatan 10x. |
| Satu request LLM bersamaan | Ollama memproses satu sesi pada satu waktu | Memadai untuk volume alert rendah; scale dengan parallel slot Ollama atau queueing untuk throughput lebih tinggi. |
| Cakupan bergantung pada rule | Hanya alert yang cocok dengan rule yang dipetakan yang membuat sesi | Memperluas peta rule (perubahan konfigurasi, bukan kode) menambahkan kelas serangan baru dalam hitungan menit. |
| Session timeout 10 menit | Serangan panjang yang idle >10 menit terpecah jadi beberapa sesi | Dapat diatur di correlator; bisa dinaikkan atau dibuat per-rule. |
| Alerting hanya via Discord | Webhook WhatsApp telah dihapus; Discord menjadi satu-satunya channel | Abstraksi webhook adalah refactor kecil; Slack/Teams/Email adalah penambahan yang mudah. |

---

## 8. Tech Stack

| Layer | Teknologi |
|---|---|
| SIEM | Wazuh 4.14.5 (native, systemd) |
| Deteksi | 40 rule kustom (XML) + decoder JSON kustom |
| Data lake | MongoDB 8 (Docker) |
| Collection / Correlation / Analysis | Go 1.26 (3 daemon mandiri) |
| Inferensi AI | Ollama 0.30.10 + qwen2.5:3b (Q4_K_M, 1.9 GB) |
| Notifikasi | Discord webhook (embed) |
| Deployment | systemd unit (auto-start, auto-restart) |

---

## 9. Pemakaian Resource

| Resource | Pemakaian |
|---|---|
| vCPU | 4 core (dibagi antara Wazuh + MongoDB + Ollama + Go daemon) |
| RAM | ~5,7 GB terpakai / 7,8 GB total (Ollama ~2,2 GB, MongoDB ~1,4 GB, Wazuh ~1,5 GB) |
| Disk | 39 GB terpakai / 154 GB (raw_logs tumbuh paling cepat, ~400K dokumen) |
| Network | Semua inferensi berjalan localhost (127.0.0.1:11434); satu-satunya koneksi keluar adalah Discord webhook |

---
