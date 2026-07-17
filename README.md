# 🛡️ Blue Team Access.log Forensic Cheatsheet

Kumpulan perintah Linux CLI (`grep`, `awk`, `sort`, `uniq`) untuk analisis forensik file `access.log` (Apache/Nginx) saat terjadi insiden keamanan pada aplikasi web.

> **Asumsi Format Log Standar:**
> - `$1` = IP Address
> - `$4` = Timestamp
> - `$6` = HTTP Method (GET/POST)
> - `$7` = URL / Endpoint Target
> - `$9` = HTTP Status Code
> - `$10` = Response Size (Bytes)

---

## 🚀 1. Analisis Awal (Reconnaissance & Volume)

### Tampilkan 15 IP Teratas yang Paling Banyak Mengirim Request (Potensi DDoS/Scanning)
```bash
awk '{print \$1}' access.log | sort | uniq -c | sort -nr | head -n 15
```

### Tampilkan 15 URL/Endpoint yang Paling Sering Diakses
```bash
awk '{print \$7}' access.log | sort | uniq -c | sort -nr | head -n 15
```

### Ringkasan Statistik HTTP Status Code (Melihat Dominasi Error)
```bash
awk '{print \$9}' access.log | sort | uniq -c | sort -nr
```

---

## 🔑 2. Deteksi Brute Force & Credential Stuffing

### Cari IP yang Paling Sering Melakukan POST ke Halaman Login
```bash
grep -i "POST" access.log | grep -Ei "login|signin|auth|wp-login" | awk '{print \$1}' | sort | uniq -c | sort -nr | head -n 10
```

### Deteksi Serangan Brute Force yang BERHASIL (Status 200/302 dari Proses POST)
```bash
grep -Ei "login|signin|auth" access.log | awk '\$6 ~ /POST/ && (\$9 == 200 || \$9 == 302) {print \$1, \$4, \$7, \$9}'
```

### Analisis Perubahan Ukuran Respon pada Login (Deteksi Sukses vs Gagal)
```bash
grep -Ei "login|signin" access.log | awk '{print \$1, \$9, \$10}' | sort | uniq -c
```
*(Analisis: Jika ada satu IP memicu status 200 dengan ukuran bytes yang berbeda sendiri di akhir rentetan log, itu indikasi login sukses).*

---

## 🦟 3. Deteksi Vulnerability Scanning (Alat Otomatis)

### Filter Berdasarkan User-Agent Scanner Populer (Nikto, Sqlmap, Hydra, Nmap, dll)
```bash
awk -F'"' '\$6 ~ /sqlmap|nikto|dirbuster|gobuster|nmap|w3af|acunetix|hydra/ {print \$1, \$6}' access.log | sort -u
```

### Cari Request dengan User-Agent Kosong atau Hanya Strip `-` (Potensi Script Modifikasi)
```bash
awk -F'"' '\$6 == "-" || \$6 == "" {print \$1, \$7, \$9}' access.log
```

---

## 💉 4. Deteksi Serangan Eksploitasi Web (Web Attacks)

### SQL Injection (SQLi) - Deteksi Payload Umum (UNION, SELECT, dll)
```bash
grep -Ei "select|union|concat|order%20by|%27|%22|\-\-" access.log | awk '{print \$1, \$7}'
```

### SQLi Berhasil - Filter Request SQLi yang Menghasilkan Database Error (Status 500)
```bash
grep -Ei "select|union|concat|%27" access.log | awk '\$9 == 500 {print \$1, \$7, \$9}'
```

### Path Traversal / Local File Inclusion (LFI) - Upaya Membaca File Sistem atau Konfigurasi
```bash
grep -Ei "\.\./|etc/passwd|boot.ini|win.ini|\.env|\.git|\.sql" access.log | awk '{print \$1, \$7, \$9}'
```

### Konfirmasi Kebocoran Data LFI (Status 200 OK pada File Sensitif)
```bash
grep -Ei "\.env|etc/passwd|\.sql" access.log | awk '\$9 == 200 {print \$1, \$7, \$9, \$10}'
```

---

## 👥 5. Kasus Khusus (Data Harvesting & Kasus TryHackMe)

### Menemukan Fitur/Halaman yang Dipakai Penyerang untuk Memanen Email (Data Scraping)
```bash
grep -Ei "user|profile|member|account|review" access.log | awk '{print \$7}' | sort | uniq -c | sort -nr | head -n 15
```

### Deteksi Teknik IDOR (Memindai ID Akun/Profil Secara Berurutan)
```bash
grep -Ei "profile|user|member" access.log | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -n 10
```

---

## ⏱️ 6. Isolasi & Investigasi Lanjutan (Timeline Analysis)

### Isolasi Seluruh Aktivitas Berdasarkan IP Penyerang Tertentu (Membuat Kronologi)
```bash
grep "IP_PENYERANG_DISINI" access.log | awk '{print \$4, \$6, \$7, \$9, \$10}' > timeline_penyerang.txt
```

### Saring Log Berdasarkan Rentang Jam Tertentu (Contoh: Jam 09:00 - 09:59)
```bash
grep "11/Apr/2021:09:" access.log > log_insiden_jam_09.log
```
