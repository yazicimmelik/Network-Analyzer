# 🛡️ DNS Tünelleme Tespit Aracı  
# 🛡️ DNS Tunneling Detection Tool

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)  
[![Scapy](https://img.shields.io/badge/Scapy-2.x-green.svg)](https://scapy.net/)  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📑 İçerik Tablosu  
## 📑 Table of Contents

1. [Giriş ve Amaç](#1-giriş-ve-amaç) / Introduction and Purpose  
2. [Özellikler](#2-özellikler) / Features  
3. [Kurulum](#3-kurulum) / Installation  
4. [Kullanım](#4-kullanım) / Usage  
5. [Tespit Mekanizmaları](#5-tespit-mekanizmaları) / Detection Mechanisms  
6. [Gelecek Geliştirmeler](#6-gelecek-geliştirmeler) / Future Developments  
7. [Katkıda Bulunma](#7-katkıda-bulunma) / Contributing  
8. [Lisans](#8-lisans) / License

---

## 1. Giriş ve Amaç  
## 1. Introduction and Purpose

(TR) Bu proje, ağ trafiğindeki DNS sorgularını analiz ederek DNS tünelleme girişimlerini tespit etmeye yönelik bir araçtır.  
(EN) This project is a tool for analyzing DNS traffic to detect DNS tunneling attempts.

---

## 2. Özellikler  
## 2. Features

- Canlı trafik yakalama / Live traffic capture  
- PCAP dosyasından analiz / Analyze from PCAP file  
- DNS sorgusu ayrıştırma / DNS query parsing  
- Entropi tabanlı tespit / Entropy-based detection  
- Domain uzunluğu kontrolü / Domain length inspection  
- Frekans analizi / Frequency analysis  
- Whitelist desteği / Whitelist support  
- Matplotlib ile görselleştirme / Visualization via Matplotlib

---

## 3. Kurulum  
## 3. Installation

**Gereksinimler / Requirements:**

- Python 3.x  
- Git  
- Npcap (Windows) / libpcap (Linux/macOS)

**Yükleme / Setup:**

```bash
git clone https://github.com/yazicimmelik/Network-Analyzer.git
cd Network-Analyzer
pip install -r requirements.txt
```

---

## 4. Kullanım  
## 4. Usage

`main.py` dosyasını açın ve aşağıdaki ayarları yapın:  
Open `main.py` and adjust the following settings:

- **INTERFACE**: Ağ arayüzü adı / Interface name  
- **LIVE_CAPTURE**: `True` (canlı) / `False` (pcap)  
- **PCAP_FILE**: PCAP dosya yolu / Path to PCAP file  
- **ENTROPY_THRESHOLD**: Varsayılan 4.0 / Default 4.0  
- **whitelist_domains**: Güvenilir domainler / Trusted domains  

**Canlı trafik için / For live capture:**

```bash
sudo python main.py
```

**PCAP dosyası için / For PCAP file:**

```bash
python main.py
```

---

## 5. Tespit Mekanizmaları  
## 5. Detection Mechanisms

- Anormal domain uzunluğu / Abnormal domain length  
- Yüksek entropi / High entropy  
- Sorgu frekansı anomalileri / Query frequency anomalies  

---

## 6. Gelecek Geliştirmeler  
## 6. Future Developments

- NXDOMAIN oranı takibi / NXDOMAIN ratio monitoring  
- Zaman serisi analizi / Time-series anomaly detection  
- SQLite veri kaydı / SQLite data persistence  
- Raporlama ve grafikler / Reporting and graphing  
- Makine öğrenimi / Machine learning detection  

---

## 7. Katkıda Bulunma  
## 7. Contributing

Pull request gönderin, issue açın, katkıda bulunun.  
Send a pull request, open an issue, contribute.

---

## Acknowledgements / *Teşekkürler*

Thanks to:  
- Keyvan Arasteh (keyvan.arasteh@istinye.edu.tr)
- Istinye University

*Teşekkürler: Harika kütüphaneler ve ilham kaynakları için.*


---

## 8. Lisans  
## 8. License

Bu proje MIT lisansı ile lisanslanmıştır. Ayrıntılar için `LICENSE` dosyasına bakınız.  
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

🧑‍💻 **Geliştirici / Developer**: Melik Yazıcı  
🔗 **GitHub**: [github.com/yazicimmelik](https://github.com/yazicimmelik)
