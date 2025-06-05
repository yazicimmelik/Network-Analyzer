from scapy.all import sniff, DNS, IP, UDP, DNSRR
import matplotlib.pyplot as plt
import time
import collections
import math # Yeni eklendi

# --- Parametreler ---
LIVE_CAPTURE = True  # Canlı ağdan mı yakalayalım yoksa PCAP dosyasından mı okuyalım?
PCAP_FILE = "sample_dns_traffic.pcap" # Eğer LIVE_CAPTURE = False ise okunacak dosya
INTERFACE = "eth0"  # Ağ arayüzünüzün adı (Daha önceki konuşmamızda th0 olarak belirledik)
ENTROPY_THRESHOLD = 4.0 # Yeni: Entropi eşiği

# --- Global Değişkenler ve Whitelist ---
domain_frequency = collections.defaultdict(int)
queried_domains = collections.deque(maxlen=1000)
request_times = collections.defaultdict(list)
whitelist_domains = {"google.com", "microsoft.com", "cloudflare.com", "github.com"} # Örnek beyaz liste

# --- Yardımcı Fonksiyonlar ---
def calculate_shannon_entropy(data): # Yeni fonksiyon
    """
    Shannon entropisini hesaplar.
    data: string (örneğin, domain adı)
    """
    if not data:
        return 0.0

    char_counts = collections.Counter(data)
    
    entropy = 0.0
    total_chars = len(data)

    for char_count in char_counts.values():
        probability = char_count / total_chars
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_suspicious_domain(domain):
    # Whitelist kontrolü (en başta kontrol etmek daha verimli)
    if domain.lower() in whitelist_domains:
        return False

    # Entropi kontrolü
    entropy = calculate_shannon_entropy(domain)
    if entropy > ENTROPY_THRESHOLD:
        print(f"    -> Yüksek Entropi: {entropy:.2f} (Domain: {domain})") # Domain adını da gösterelim
        return True

    # Uzunluk kontrolü
    if len(domain) > 30 and "." in domain:
        print(f"    -> Çok Uzun Domain: {len(domain)} karakter (Domain: {domain})")
        return True

    # Şifreli görünümlü (entropisi yüksek) domain kontrolü (basit bir yaklaşım)
    # Bu kısmı entropi analiziyle güçlendirdik, bu satırı kaldırabiliriz veya daha spesifik hale getirebiliriz.
    # Şimdilik tutabiliriz, belki farklı bir paterni yakalar.
    if not any(c.isalpha() for c in domain) and any(c.isdigit() or not c.isalnum() for c in domain):
         print(f"    -> Anormal Karakter Yapısı (Domain: {domain})")
         return True

    return False

def analyze_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[DNS].qr == 0: # 0 for query, 1 for response
            query_name = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            src_ip = packet[IP].src

            print(f"[{time.strftime('%H:%M:%S')}] DNS Query from {src_ip}: {query_name}")

            domain_frequency[query_name] += 1
            queried_domains.append(query_name)
            request_times[query_name].append(time.time())

            # Şüpheli domain kontrolü
            if is_suspicious_domain(query_name):
                print(f"!!! ŞÜPHELİ DOMAIN TESPİT EDİLDİ: {query_name} (Kaynak IP: {src_ip})")

            # Anormal sorgu frekansı kontrolü (çok basit bir örnek)
            # Daha gelişmiş bir frekans analizi ekleyebiliriz
            if domain_frequency[query_name] > 5 and len(request_times[query_name]) > 1:
                if time.time() - request_times[query_name][-5] < 10:
                    print(f"!!! ANORMAL SORGULAMA FREKANSI: {query_name} (Kaynak IP: {src_ip})")


# --- Ana Fonksiyon ---
def main():
    print("DNS Tünelleme Tespit Aracı Başlatılıyor...")
    print(f"Canlı Yakalama: {LIVE_CAPTURE}, PCAP Dosyası: {PCAP_FILE}, Arayüz: {INTERFACE}")
    print(f"Entropi Eşiği: {ENTROPY_THRESHOLD}")


    if LIVE_CAPTURE:
        print(f"'{INTERFACE}' arayüzünden DNS trafiği yakalanıyor. Çıkmak için Ctrl+C'ye basın.")
        try:
            sniff(filter="udp port 53", prn=analyze_packet, store=0, iface=INTERFACE)
        except Exception as e:
            print(f"Hata oluştu: {e}")
            print("Arayüz adınızı kontrol edin veya yönetici olarak çalıştırmayı deneyin.")
            print("Mevcut arayüzleri görmek için 'scapy.all.show_interfaces()' kullanabilirsiniz.")
    else:
        print(f"'{PCAP_FILE}' dosyasından DNS trafiği okunuyor...")
        try:
            packets = sniff(offline=PCAP_FILE, filter="udp port 53", store=1)
            for packet in packets:
                analyze_packet(packet)
        except Exception as e:
            print(f"PCAP dosyasını okurken hata oluştu: {e}")

    # Toplu analiz ve görselleştirme (örnek)
    print("\n--- Analiz Özeti ---")
    print("En Çok Sorgulanan Domainler:")
    for domain, count in sorted(domain_frequency.items(), key=lambda item: item[1], reverse=True)[:10]:
        print(f"- {domain}: {count} kez")

    # Grafik çizimi
    if domain_frequency:
        top_domains = dict(sorted(domain_frequency.items(), key=lambda item: item[1], reverse=True)[:15])
        plt.figure(figsize=(12, 7)) # Daha büyük bir figür boyutu
        plt.barh(list(top_domains.keys()), list(top_domains.values()), color='skyblue')
        plt.xlabel("Sorgu Sayısı", fontsize=12)
        plt.ylabel("Domain", fontsize=12)
        plt.title("En Çok Sorgulanan Domainler (Top 15)", fontsize=14)
        plt.gca().invert_yaxis()
        plt.grid(axis='x', linestyle='--', alpha=0.7) # X eksenine ızgara ekle
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    main()


