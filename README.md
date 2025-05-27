# Raw Socket Port Scanner

Bu proje, C++ ve raw socket teknolojisi kullanarak geliştirilmiş kapsamlı bir port tarama ve işletim sistemi tespit aracıdır.

## Özellikler

### 🔍 Port Tarama
- **TCP Connect Scan**: Güvenilir TCP bağlantı taraması
- **UDP Scan**: DNS, SNMP gibi UDP servisleri için özel tarama
- **Multi-threaded**: Hızlı tarama için paralel işlem
- **Esnek Port Aralığı**: Aralık (1-1024) veya virgülle ayrılmış (22,80,443) format desteği

### 🖥️ İşletim Sistemi Tespiti
- **TTL Analizi**: Ping yanıtlarından TTL değeri analizi
- **OS Fingerprinting**: Linux/Unix, Windows, Cisco/Network cihazları tespiti
- **Hostname Resolution**: IP adresi ve hostname desteği

### 🛡️ Servis Tespiti
- **Banner Grabbing**: Servislerin kendilerini tanıtması
- **Bilinen Servis Portları**: 25+ yaygın servis tanımlaması
- **Özel Protokol Desteği**: HTTP, HTTPS, SSH, FTP, DNS için özelleştirilmiş istekler

### 📊 Detaylı Raporlama
- **Tablo Formatı**: Düzenli ve okunabilir çıktı
- **Güvenlik Önerileri**: Tespit edilen güvenlik açıkları için öneriler
- **İlerleme Göstergesi**: Gerçek zamanlı tarama durumu

## Kurulum

### Gereksinimler
- C++11 veya üzeri
- macOS/Linux işletim sistemi
- GCC veya Clang derleyici

### Derleme
```bash
# Makefile kullanarak
make

# Manuel derleme
g++ -std=c++11 -Wall -Wextra -O2 -pthread -o port_scanner simple_scanner.cpp
```

## Kullanım

### Temel Kullanım
```bash
# Belirli bir IP adresinde port aralığı tarama
./port_scanner 192.168.1.1 1-1024

# Belirli portları tarama
./port_scanner 192.168.1.1 22,80,443,3389

# Karışık format
./port_scanner 192.168.1.1 1-100,443,8080-8090

# Hostname kullanımı
./port_scanner scanme.nmap.org 1-1000
```

### Örnek Çıktı
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          RAW SOCKET PORT SCANNER                            ║
║                     OS Detection & Service Discovery                        ║
║                              v1.0 - 2024                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

Hedef: 192.168.1.1
Taranacak port sayısı: 1024
Tarama başlatılıyor...

İşletim sistemi tespiti yapılıyor...
Tarama ilerlemesi: 1024/1024 port
Tarama tamamlandı! Süre: 15 saniye

╔══════════════════════════════════════════════════════════════════════════════╗
║                            PORT TARAMA SONUÇLARI                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Hedef IP: 192.168.1.1                                                       ║
║ Tespit edilen OS: Linux/Unix (TTL: 64)                                      ║
║ Açık port sayısı: 4                                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ PORT  │ DURUM │ PROTOKOL │ SERVİS                                         ║
╠═══════╪═══════╪══════════╪════════════════════════════════════════════════╣
║ 22    │ AÇIK  │ TCP      │ SSH (SSH-2.0-OpenSSH_8.9p1)                  ║
║ 80    │ AÇIK  │ TCP      │ HTTP (HTTP/1.1 200 OK)                        ║
║ 443   │ AÇIK  │ TCP      │ HTTPS (HTTPS/SSL)                             ║
║ 3306  │ AÇIK  │ TCP      │ MySQL                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════╗
║                              GÜVENLİK ÖNERİLERİ                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ • Gereksiz servisleri kapatın                                               ║
║ • Güvenlik duvarı kurallarını gözden geçirin                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Teknik Detaylar

### Tarama Yöntemleri

#### TCP Connect Scan
- Tam TCP handshake gerçekleştirir
- En güvenilir yöntem
- Non-blocking socket kullanır
- 2 saniye timeout

#### UDP Scan
- Belirli portlar için özelleştirilmiş
- DNS (53), SNMP (161), TFTP (69), NTP (123)
- DNS için özel sorgu paketi gönderir

### İşletim Sistemi Tespiti
- **TTL 60-64**: Linux/Unix sistemler
- **TTL 120-128**: Windows sistemler  
- **TTL 250-255**: Cisco/Network cihazları

### Banner Grabbing
- HTTP/HTTPS: HEAD request gönderir
- SSH/FTP/SMTP: Otomatik banner okur
- SSL/TLS: Güvenli bağlantı tespiti

## Güvenlik Notları

⚠️ **Önemli Uyarılar**:
- Bu araç sadece kendi sistemlerinizde veya izin verilen sistemlerde kullanılmalıdır
- Yetkisiz port taraması yasalara aykırı olabilir
- Ağ yöneticilerinin izni olmadan kullanmayın
- Eğitim ve güvenlik testleri için tasarlanmıştır

## Desteklenen Servisler

| Port | Servis | Açıklama |
|------|--------|----------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Telnet Protocol |
| 25 | SMTP | Simple Mail Transfer Protocol |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Hypertext Transfer Protocol |
| 110 | POP3 | Post Office Protocol v3 |
| 143 | IMAP | Internet Message Access Protocol |
| 443 | HTTPS | HTTP Secure |
| 993 | IMAPS | IMAP Secure |
| 995 | POP3S | POP3 Secure |
| 3389 | RDP | Remote Desktop Protocol |
| 5432 | PostgreSQL | PostgreSQL Database |
| 3306 | MySQL | MySQL Database |
| 1433 | MSSQL | Microsoft SQL Server |
| 139 | NetBIOS | NetBIOS Session Service |
| 445 | SMB | Server Message Block |
| 161 | SNMP | Simple Network Management Protocol |
| 389 | LDAP | Lightweight Directory Access Protocol |
| 636 | LDAPS | LDAP Secure |
| 1521 | Oracle | Oracle Database |
| 27017 | MongoDB | MongoDB Database |

## Performans

- **Multi-threading**: 100 eşzamanlı bağlantı
- **Timeout**: TCP için 2 saniye, UDP için 1 saniye
- **Hız**: ~1000 port/dakika (ağ koşullarına bağlı)

## Sorun Giderme

### Yaygın Hatalar

**"Permission denied" hatası**:
```bash
# Bazı işlemler için root yetkisi gerekebilir
sudo ./port_scanner 192.168.1.1 1-1024
```

**"Connection refused" çok fazla**:
- Hedef sistem güvenlik duvarı kullanıyor olabilir
- Port aralığını küçültün
- Thread sayısını azaltın

**Yavaş tarama**:
- Thread sayısını artırın (kod içinde max_threads değişkeni)
- Timeout değerlerini azaltın
- Daha küçük port aralıkları kullanın

## Geliştirme

### Katkıda Bulunma
1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Commit yapın (`git commit -am 'Yeni özellik eklendi'`)
4. Push yapın (`git push origin feature/yeni-ozellik`)
5. Pull Request oluşturun

### Gelecek Özellikler
- [ ] IPv6 desteği
- [ ] XML/JSON çıktı formatları
- [ ] Daha gelişmiş OS fingerprinting
- [ ] Steganografi tespiti
- [ ] Web arayüzü

## Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Sorumlu kullanım için tasarlanmıştır.

## İletişim

Sorularınız için GitHub Issues kullanabilirsiniz.

---
**Not**: Bu araç penetrasyon testleri ve güvenlik değerlendirmeleri için tasarlanmıştır. Yasal ve etik kurallara uygun şekilde kullanın. 