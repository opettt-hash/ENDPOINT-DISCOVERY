# ENDPOINT DISCOVERY (Passive) — Dokumentasi

**Ringkasan Singkat**
Program Script Python Untuk Melakukan *passive* Discovery Endpoint Api Pada Sebuah Website Untuk Reconnaissance Awal Saat Kamu Sudah Punya Izin Pentesting, Semua Script Hanya Melakukan `GET`/`HEAD` (Optional crt.sh query)

---

## Isi Repository

* `discover_endpoints_full.py` — Crawler + JS Extractor + Probe (Hasil: `endpoints_report.json`, `burp_scan.csv`, `curl_examples.txt`).
* `parse_api.py` — Parser Yang Mengekstrak Kandidat API Dari `endpoints_report.json` → `api_candidates.txt`.
* `validate_api_candidates.py` — Melakukan HEAD (+ GET Sample) Pada `api_candidates.txt`, Menyimpan `api_validation.json` Dan `curl_checks.sh`.
* `curl_examples.txt` — Contoh `curl` Yang Dihasilkan Otomatis Dari Crawling (Form/POST Dll).
* `burp_scan.csv` — CSV Siap Import Ke Burp Suite (Target List).
* `endpoints_report.json` — Contoh Output Hasil Discovery (Jika Ada).

---

## Persiapan (Termux / Linux)

Pastikan Python 3 Terpasang, Disarankan Jalankan Di Lingkungan Yang Stabil

Install Dependensi

```bash
pip install requests beautifulsoup4
# opsional (lebih nyaman untuk parsing hasil):
# apt install jq
```

---

## Cara pakai (Urutan Workflow)

1. **Discovery (Crawl + JS Extract + Probe)**

```bash
python3 discover_endpoints_full.py https://target.example --workers 10 --max-pages 150 --timeout 8

# Output:
# - endpoints_report.json
# - burp_scan.csv
# - curl_examples.txt
```

*Flags Penting*

* `--workers N` : Concurrency (Default 8).
* `--max-pages N` : Batas Crawl Pages (Default 200).
* `--subdomains` : (Opsional) Passive Subdomain Enumeration Via crt.sh (Read-Only).

2. **Parse Kandidat API**

```bash
python3 parse_api.py
# Output: api_candidates.txt
```

`parse_api.py` Mencari Kandidat Dari Beberapa Sumber Di `endpoints_report.json` (Probe_Results, Forms, Js_Found_Urls, Subdomains_Passive).

3. **Validasi Kandidat (HEAD + GET Sample)**

```bash
python3 validate_api_candidates.py --workers 8
# Output: api_validation.json, curl_checks.sh
```

Opsi:

* `--only-head` : Hanya Lakukan HEAD (Lebih Aman & Cepat)
* `--workers N` : Concurrency

`curl_checks.sh` Berisi Perintah `curl` Otomatis Untuk Endpoint Yang Merespon OK (<400)

---

## Contoh Alur Cepat (One-Liner Yang Setara)

* Generate List URL Dari `api_candidates.txt` Dan Lakukan HEAD

```bash
awk -F'\t' 'NR>1 {print $3}' api_candidates.txt | sort -u | while read url; do
  echo "---- $url ----"
  curl -s -I -L -m 8 "$url" | sed -n '1,6p'
  # jika content-type JSON -> ambil sample body
  ct=$(curl -s -I -L -m 8 "$url" 2>/dev/null | tr -d '\r' | awk '/[Cc]ontent-[Tt]ype/ {print $2}')
  if echo "$ct" | grep -iq "json"; then
    echo "[*] JSON sample:"
    curl -s -L -m 8 "$url" | head -c 800
    echo
  fi
done
```

Tapi Lebih Rapi Pakai `validate_api_candidates.py` Karena Menangani Error Dan Concurrency

---

## Output & File Penjelasan

* `endpoints_report.json` : Laporan Lengkap Dari Discovery (Crawled Pages, Probe_Results, Forms, Js Files, Subdomains_Passive, Dsb).
* `burp_scan.csv` : CSV Berisi `method_or_probe, url, status, content_type, length` — Import Ke Burp Target
* `curl_examples.txt` : Contoh Curl Untuk Form POST/GET Otomatis
* `api_candidates.txt` : Daftar Kandidat Endpoint API (Hasil Parse)
* `api_validation.json` : hasil Validasi (HEAD & GET sample) Per URL
* `curl_checks.sh` : Skrip Curl Untuk Re-Check Endpoint Yang Merespon OK

---

## Troubleshooting Singkat

* **Error `Invalid IPv6 URL`** Saat Menjalankan cript Pastikan Menggunakan Versi Script Yang Sudah Diperbaiki (Script Saat Ini Sudah Meng-Skip Token URL Yang Tidak Valid)
* **Script Lama Lambat**: Turunkan `--max-pages`, Atau Kurangi `--workers` Jika Target Sensitif.
* **Butuh Runtime JS (SPA)**: Gunakan Browser DevTools (Network → XHR/Fetch) Pada Session Interaktif Untuk Menangkap API Runtime

---

## Etika & Legal

* Hanya Gunakan Jika Kamu **Memiliki Izin Tertulis** Dari Pemilik Sistem!
* Jika Menemukan Data Sensitif Atau Bug Kritikal, Laporkan Melalui Jalur Resmi (CSIRT / Owner) Sesuai Kebijakan
---

## Contact

Kalau Mau Tambahan Fitur (Mis Output CSV Custom Untuk Burp, Headless-Browser Extraction, Atau Parsing Otomatis Untuk Types Tertentu), Tinggal Tambahin Issue Di Repo Atau Tag Saya Di Commit Message.Terimakasih

---

*Created By Rolandino* 
