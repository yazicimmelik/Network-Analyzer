# ROADMAP.md: Python ile Ağ Güvenliği Trafiği Analizi Özelliklerini Geliştirme ve Test Etme

## Giriş
Bu yol haritası, ağ güvenliği trafiği analiz araçlarından esinlenerek, Python kullanılarak ağ trafiği analizi özelliklerinin nasıl geliştirileceği ve test edileceğine dair detaylı bir rehber sunar. Önemli Uyarı: Bu bilgiler yalnızca eğitim ve araştırma amaçlıdır. Yetkisiz kullanımı yasa dışı ve etik dışıdır. Herhangi bir ağda veya sistemde test yapmadan önce açık izin almanız zorunludur.

Bu rehber, ağ güvenliği trafiği analizi tekniklerini Python ile yeniden oluşturmayı, etik ve yasal sınırlar içinde kalarak kontrollü bir ortamda test etmeyi amaçlar.

## Ön Koşullar
- **Python 3.x**: Geliştirme için temel dil.
- **Kütüphaneler**:
  - **Scapy**: Paket yakalama ve ağ analizi için (`pip install scapy`).
  - **Pyshark**: Wireshark tabanlı analiz için (`pip install pyshark`).
  - **Matplotlib**: Veri görselleştirme için (`pip install matplotlib`).
  - **Pandas**: Veri işleme ve analizi için (`pip install pandas`).
- **Bilgi Gereksinimleri**:
  - Python programlama temelleri.
  - Ağ protokolleri (TCP/IP, DNS, HTTP, ARP, ICMP) hakkında temel bilgi.
  - Linux komut satırı kullanımı.
- **Araçlar**: VirtualBox veya benzeri bir sanallaştırma yazılımı.

## Test Ortamını Kurma
Güvenli bir test ortamı oluşturmak için aşağıdaki adımları izleyin:
1. **VirtualBox Kurulumu**: VirtualBox’ı indirin ve kurun.
2. **Sanal Makineler (VM) Oluşturma**:
   - **Analist VM**: Kali Linux veya herhangi bir Linux dağıtımı.
   - **Hedef VM**: Trafik üreten bir sistem (ör. Windows, Linux).
3. **Ağ Yapılandırması**: VM’leri yalnızca dahili veya host-only bir ağda çalışacak şekilde ayarlayın. Bu, testlerin üretim ağlarından izole olmasını sağlar.

## Temel Bileşenlerin Geliştirilmesi

### 1. Trafik Yakalama Betiği
Bu betik, ağ trafiğini yakalar ve analiz için kaydeder.

```python
from scapy.all import *

def capture_traffic(interface="eth0", output_file="traffic.pcap"):
    packets = sniff(iface=interface, count=100)  # 100 paket yakala
    wrpcap(output_file, packets)
    print(f"Paketler {output_file} dosyasına kaydedildi.")

# Kullanım
capture_traffic("eth0", "traffic.pcap")
```

### 2. Protokol Analizi Betiği
Bu betik, yakalanan trafikteki protokolleri (ör. DNS, HTTP, ICMP) analiz eder.

```python
from scapy.all import *

def analyze_protocols(pcap_file):
    packets = rdpcap(pcap_file)
    protocols = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            protocols[proto] = protocols.get(proto, 0) + 1
    for proto, count in protocols.items():
        print(f"Protokol {proto}: {count} paket")
        
# Kullanım
analyze_protocols("traffic.pcap")
```

### 3. Anomali Tespit Betiği
Bu betik, ağ trafiğinde anormal davranışları (ör. yüksek hacimli ICMP veya DNS sorguları) tespit eder.

```python
from scapy.all import *
import pandas as pd

def detect_anomalies(pcap_file, threshold=50):
    packets = rdpcap(pcap_file)
    dns_count = 0
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            dns_count += 1
    if dns_count > threshold:
        print(f"Uyarı: Yüksek DNS trafiği ({dns_count} sorgu) tespit edildi!")
    else:
        print("Anormal trafik tespit edilmedi.")

# Kullanım
detect_anomalies("traffic.pcap", threshold=50)
```

### 4. Trafik Görselleştirme Betiği
Bu betik, trafik verilerini görselleştirir (ör. protokol dağılımı).

```python
from scapy.all import *
import matplotlib.pyplot as plt
import pandas as pd

def visualize_traffic(pcap_file):
    packets = rdpcap(pcap_file)
    protocols = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            protocols[proto] = protocols.get(proto, 0) + 1
    df = pd.DataFrame.from_dict(protocols, orient='index', columns=['Count'])
    df.plot(kind='bar')
    plt.title("Protokol Dağılımı")
    plt.xlabel("Protokol")
    plt.ylabel("Paket Sayısı")
    plt.show()

# Kullanım
visualize_traffic("traffic.pcap")
```

## Gelişmiş Geliştirmeler

### 1. Gerçek Zamanlı Trafik Analizi
Pyshark ile gerçek zamanlı trafik analizi için bir betik oluşturun.

```python
import pyshark

def live_analysis(interface="eth0"):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter="udp port 53")
    for packet in capture.sniff_continuously(packet_count=10):
        print(f"Paket: {packet}")

# Kullanım
live_analysis("eth0")
```

### 2. Anomali Tespit için Makine Öğrenimi
Makine öğrenimi tabanlı anomali tespiti için bir model entegre edin (ör. Isolation Forest).

```python
from scapy.all import *
from sklearn.ensemble import IsolationForest
import pandas as pd

def ml_anomaly_detection(pcap_file):
    packets = rdpcap(pcap_file)
    data = []
    for pkt in packets:
        if pkt.haslayer(IP):
            data.append([len(pkt), pkt[IP].proto])
    df = pd.DataFrame(data, columns=['length', 'protocol'])
    model = IsolationForest(contamination=0.1)
    predictions = model.fit_predict(df)
    anomalies = df[predictions == -1]
    print(f"Anomaliler: {len(anomalies)} paket")

# Kullanım
ml_anomaly_detection("traffic.pcap")
```

### 3. Entegre Analiz Aracı
Tüm analiz bileşenlerini birleştiren bir betik yazın.

```python
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt

def integrated_analysis(interface="eth0", pcap_file=None, threshold=50):
    if pcap_file:
        packets = rdpcap(pcap_file)
    else:
        packets = sniff(iface=interface, count=100)
    
    # Protokol analizi
    protocols = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            proto = pkt[IP].proto
            protocols[proto] = protocols.get(proto, 0) + 1
    
    # Anomali tespiti
    dns_count = sum(1 for pkt in packets if pkt.haslayer(DNSQR))
    if dns_count > threshold:
        print(f"Uyarı: Yüksek DNS trafiği ({dns_count} sorgu)!")
    
    # Görselleştirme
    df = pd.DataFrame.from_dict(protocols, orient='index', columns=['Count'])
    df.plot(kind='bar')
    plt.title("Protokol Dağılımı")
    plt.xlabel("Protokol")
    plt.ylabel("Paket Sayısı")
    plt.show()

# Kullanım
integrated_analysis(pcap_file="traffic.pcap")
```

## Geliştirmelerin Test Edilmesi
1. **Trafik Yakalama**:
   - Betiği çalıştırın.
   - Hedef VM’de trafik üretin (ör. `ping google.com` veya `nslookup example.com`).
   - Çıktı dosyasını (`traffic.pcap`) Wireshark ile doğrulayın.
2. **Protokol Analizi**:
   - Betiği çalıştırın.
   - Çıktıda protokol dağılımını kontrol edin.
3. **Anomali Tespiti**:
   - Betiği çalıştırın.
   - Yüksek DNS trafiği simüle edin (ör. `for i in {1..100}; do nslookup example.com; done`).
   - Anomali uyarısını kontrol edin.
4. **Görselleştirme**:
   - Betiği çalıştırın.
   - Grafiğin doğru şekilde oluşturulduğunu doğrulayın.

## Karşı Önlemler ve En İyi Uygulamalar
- **IDS/IPS Kullanımı**: Snort veya Suricata gibi sistemlerle anormal trafik tespitini güçlendirin.
- **Şifreli Protokoller**: HTTPS ve DNSSEC kullanarak veri gizliliğini koruyun.
- **Ağ İzleme**: Ağ trafiğini sürekli izlemek için SIEM sistemleri kullanın.
- **İzole Test Ortamı**: Üretim ağlarında test yapmayın.
- **Loglama ve Denetim**: Tüm analiz süreçlerini loglayın ve denetleyin.

## Sonuç
Bu yol haritası, Python ile ağ güvenliği trafiği analizi özelliklerini geliştirmeyi ve test etmeyi adım adım açıklamıştır. Etik ve yasal sorumluluklara bağlı kalarak, bu bilgileri siber güvenliği güçlendirmek için kullanmaya devam edin.
