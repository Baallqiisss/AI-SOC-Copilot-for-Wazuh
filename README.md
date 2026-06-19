# AI-SOC-COPILOT-FOR-WAZUH

## Deskripsi 

AI SOC Copilot for Wazuh merupakan sebuah sistem keamanan siber berbasis kecerdasan buatan (AI) yang mengubah data alert mentah dari Wazuh menjadi rekonstruksi rantai serangan (attack chain) yang utuh, lengkap dengan laporan investigasi yang dapat langsung ditindaklanjuti. Laporan tersebut dikirimkan secara otomatis kepada tim keamanan melalui Discord.


Alih-alih analis keamanan harus membaca ribuan baris log secara manual untuk memahami apa yang terjadi, urutan kejadiannya, dan langkah apa yang perlu diambil, sistem ini melakukan empat hal berikut secara otomatis:

•	Mengumpulkan setiap alert dan log mentah Wazuh ke dalam satu data lake MongoDB terpadu.

•	Mengorelasikan alert dari sumber IP yang sama menjadi satu “sesi serangan”, sekaligus menandai fase MITRE ATT&CK (Initial Access, Discovery, Execution, Persistence) seiring berjalannya serangan.

•	Menganalisis setiap sesi bertingkat keparahan high/critical menggunakan model AI lokal yang membaca seluruh garis waktu kejadian dan menulis laporan investigasi terstruktur (ringkasan, skor keyakinan, fase serangan, rekomendasi tindakan).

•	Mengirimkan laporan tersebut ke Discord dalam bentuk embed berwarna begitu skor keyakinan cukup tinggi.
Seluruh proses inferensi AI berjalan secara lokal pada server yang sama dengan Wazuh — tanpa API cloud, tanpa vendor LLM eksternal, dan tanpa biaya per-token.
