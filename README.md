====================
📄 Panduan Guna CsCrew Suite (cscrewtools.py)
====================

Cara jalankan tools:
--------------------
$ python3 cscrewtools.py


====================
🔹 Option 1: SQLi HS (Header Scanner)
====================
- Fungsi: Scan target URL menggunakan payload SQLi dalam header HTTP (User-Agent, X-Forwarded-For, dll)
- Sesuai untuk bypass WAF atau endpoint admin
- Guna fail berisi senarai domain/URL

Contoh penggunaan:
------------------
1. Sediakan fail bernama `target.txt` (1 URL per baris)
2. Jalankan tools dan pilih Option 1
3. Masukkan path ke `target.txt`
4. Hasil disimpan dalam `vulnerable_endpoints_<timestamp>.txt`


====================
🔹 Option 2: Vuln Finder (Scanner async)
====================
- Fungsi: Crawl satu domain dan uji SQLi, XSS, dan LFI dalam parameter URL dan form
- Gunakan secara async (laju)
- Sesuai untuk pentest menyeluruh

Contoh penggunaan:
------------------
1. Masukkan URL utama (cth: https://example.com)
2. Tools akan crawl dan test semua sub-URL dan form
3. Hasil dalam `vuln_finder_results.txt` dan versi JSON


====================
🔹 Option 3: SQLi Tester + Test hasil Option 4
====================
- Fungsi: Uji sama ada URL rentan terhadap SQLi (basic payload)
- Sesuai untuk test hasil Google Dork

Cara guna:
----------
1. Pilih Option 3
2. Pilih:
   - [1] Masukkan satu URL secara manual
   - [2] Masukkan fail senarai URL (cth: hasil_dork.txt)
3. Tools akan uji setiap URL dan tunjuk jika rentan


====================
🔹 Option 4: Google Dorking
====================
- Fungsi: Gunakan Google untuk cari target yang rentan
- Sesuai digabungkan dengan Option 3

Langkah:
--------
1. Pilih Option 4
2. Masukkan dork (cth: inurl:php?id=)
3. Masukkan jumlah hasil dork (cth: 20)
4. Hasil disimpan dalam `hasil_dork.txt`


====================
🔁 Contoh Gabungan Option 4 + 3
====================
1. Guna Option 4 untuk dork:
   - Contoh dork: inurl:product.php?id=
   - Simpan ke `hasil_dork.txt`
2. Teruskan ke Option 3
   - Pilih `2` untuk input dari file `hasil_dork.txt`
   - Uji SQLi pada semua hasil dari Google


====================
🛑 Option 5: Keluar
====================
- Keluar dari program.


====================
📦 Output Files Penting
====================
- hasil_dork.txt            ← Hasil Google Dork
- vuln_finder_results.txt   ← Hasil Vuln Finder
- vulnerable_endpoints_*.txt← Hasil Header Scanner
- *.json                    ← Laporan format JSON untuk analisis lanjutan
