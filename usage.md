# Raw Socket Port Scanner - Kullanım Kılavuzu

## 📋 İçindekiler
- [Genel Bakış](#genel-bakış)
- [Kurulum](#kurulum)
- [Temel Kullanım](#temel-kullanım)
- [İki Farklı Versiyon](#iki-farklı-versiyon)
- [Detaylı Örnekler](#detaylı-örnekler)
- [Teknik Özellikler](#teknik-özellikler)
- [Güvenlik Notları](#güvenlik-notları)
- [Sorun Giderme](#sorun-giderme)

## 🔍 Genel Bakış

Bu proje, C++ ile geliştirilmiş iki farklı port tarama aracı içerir:
- **Raw Socket Versiyonu** (`main.cpp`): Gerçek raw socket teknolojisi
- **Normal Socket Versiyonu** (`simple_scanner.cpp`): Kullanıcı dostu versiyon

## 🛠️ Kurulum

### Gereksinimler
- **İşletim Sistemi**: macOS/Linux
- **Derleyici**: GCC veya Clang (C++11 desteği)
- **Root Yetkisi**: Raw socket versiyonu için gerekli

### Derleme

#### Normal Socket Versiyonu (Önerilen)
```bash
# Makefile kullanarak
make

# Manuel derleme
g++ -std=c++11 -Wall -Wextra -O2 -pthread -o port_scanner simple_scanner.cpp
```

#### Raw Socket Versiyonu
```bash
# Raw socket versiyonunu derle
g++ -std=c++11 -Wall -Wextra -O2 -pthread -o raw_scanner main.cpp
```

## 🚀 Temel Kullanım

### Normal Socket Versiyonu
```bash
# Temel kullanım
./port_scanner <IP_adresi> <port_aralığı>

# Örnekler
./port_scanner 192.168.1.1 1-1024
./port_scanner scanme.nmap.org 22,80,443
./port_scanner 8.8.8.8 1-100,443,8080-8090
```

### Raw Socket Versiyonu (Root Gerekli)
```bash
# Root yetkisiyle çalıştır
sudo ./raw_scanner 192.168.1.1 22,80,443

# Şifre ile
echo "şifre" | sudo -S ./raw_scanner 192.168.1.1 1-1024
```

## 📊 İki Farklı Versiyon

### 🔧 Normal Socket Versiyonu (`simple_scanner.cpp`)

**Özellikler:**
- ✅ Root yetkisi gerektirmez
- ✅ macOS tam uyumlu
- ✅ Hızlı ve güvenilir
- ✅ Detaylı logging
- ✅ False positive önleme

**Tarama Yöntemleri:**
- TCP Connect Scan (`SOCK_STREAM`)
- UDP Scan (`SOCK_DGRAM`) - Seçili portlar
- Banner Grabbing
- TTL analizi ile OS tespiti

**Çıktı Örneği:**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          TEKNİK RAPOR                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Raw Socket Kullanımı: HAYIR (Normal Socket kullanılıyor)                    ║
║ Tarama Yöntemleri:                                                          ║
║   • TCP Connect Scan (AF_INET, SOCK_STREAM)                                 ║
║   • UDP Scan (AF_INET, SOCK_DGRAM) - Seçili portlar                         ║
║ Thread Sayısı: 100 eşzamanlı bağlantı                                       ║
║ Timeout: TCP=2sn, UDP=1sn                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### ⚡ Raw Socket Versiyonu (`main.cpp`)

**Özellikler:**
- ✅ Gerçek raw socket teknolojisi
- ✅ Manuel paket oluşturma
- ✅ TCP SYN Scan
- ✅ Stealth tarama
- ❌ Root yetkisi gerekli
- ⚠️ Daha karmaşık

**Tarama Yöntemleri:**
- TCP SYN Scan (`SOCK_RAW, IPPROTO_TCP`)
- TCP Connect Scan (Fallback)
- UDP Scan (Seçili portlar)
- Manuel IP + TCP header oluşturma
- Checksum hesaplama

**Çıktı Örneği:**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          TEKNİK RAPOR                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Raw Socket Kullanımı: EVET (Gerçek Raw Socket)                              ║
║ Tarama Yöntemleri:                                                          ║
║   • TCP SYN Scan (SOCK_RAW, IPPROTO_TCP)                                    ║
║   • TCP Connect Scan (AF_INET, SOCK_STREAM) - Fallback                      ║
║ Manuel Paket Oluşturma: IP + TCP Header                                     ║
║ Checksum Hesaplama: Manuel IP ve TCP checksum                               ║
║ Root Yetkisi: GEREKLİ (Raw socket için)                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## 📝 Detaylı Örnekler

### Port Aralığı Formatları

#### Tek Port
```bash
./port_scanner 192.168.1.1 80
./port_scanner google.com 443
```

#### Port Aralığı
```bash
./port_scanner 192.168.1.1 1-1024
./port_scanner scanme.nmap.org 20-25
```

#### Virgülle Ayrılmış Portlar
```bash
./port_scanner 192.168.1.1 22,80,443,3389
./port_scanner 8.8.8.8 53,80,443
```

#### Karışık Format
```bash
./port_scanner 192.168.1.1 1-100,443,8080-8090
./port_scanner target.com 20-25,53,80,443,993-995
```

### Hedef Türleri

#### IP Adresi
```bash
./port_scanner 192.168.1.1 1-1024
./port_scanner 8.8.8.8 53,80
```

#### Hostname/Domain
```bash
./port_scanner google.com 80,443
./port_scanner scanme.nmap.org 1-1000
./port_scanner example.com 22,80,443
```

### Detaylı Logging Örnekleri

#### Normal Socket Versiyonu
```bash
./port_scanner scanme.nmap.org 22,80
```

**Çıktı:**
```
[DEBUG] Port 22: TCP Connect Scan başlatılıyor...
[SUCCESS] Port 22: TCP Connect Scan başarılı - Port AÇIK
[INFO] Port 22: Servis tespiti başlatılıyor...
[INFO] Port 22: Bilinen servis tespit edildi - SSH
[DEBUG] Port 22: Banner grabbing başlatılıyor...
[SUCCESS] Port 22: Banner tespit edildi - SSH-2.0-OpenSSH_6.6.1p1
[RESULT] Port 22: Kaydedildi - TCP | SSH (SSH-2.0-OpenSSH_6.6.1p1)
[TECHNICAL] Port 22: TCP Connect Scan - Normal Socket (Raw Socket DEĞİL)
```

#### Raw Socket Versiyonu
```bash
sudo ./raw_scanner scanme.nmap.org 22,80
```

**Çıktı:**
```
[DEBUG] Port 22: TCP SYN Scan başlatılıyor (Raw Socket)...
[SUCCESS] Port 22: TCP SYN Scan başarılı - Port AÇIK (TTL:64, Win:5840)
[INFO] Port 22: Servis tespiti başlatılıyor...
[INFO] Port 22: Bilinen servis tespit edildi - SSH
[RESULT] Port 22: Kaydedildi - TCP-SYN | SSH
[TECHNICAL] Port 22: TCP SYN Scan - Raw Socket (SOCK_RAW, IPPROTO_TCP)
[OS] TTL:64, Window:5840 -> Linux/Unix
```

## 🔧 Teknik Özellikler

### Normal Socket Versiyonu

| Özellik | Değer |
|---------|-------|
| **Socket Türü** | SOCK_STREAM, SOCK_DGRAM |
| **Thread Sayısı** | 100 eşzamanlı |
| **Timeout** | TCP: 2sn, UDP: 1sn |
| **Root Yetkisi** | Gerekmiyor |
| **OS Tespiti** | TTL analizi (ping) |
| **Banner Grabbing** | HTTP, SSH, FTP, SMTP, POP3, IMAP |

### Raw Socket Versiyonu

| Özellik | Değer |
|---------|-------|
| **Socket Türü** | SOCK_RAW, IPPROTO_TCP |
| **Thread Sayısı** | 50 eşzamanlı |
| **Timeout** | 2 saniye |
| **Root Yetkisi** | Gerekli |
| **OS Tespiti** | TTL + Window Size analizi |
| **Paket Oluşturma** | Manuel IP + TCP header |

### Desteklenen Servisler

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

### İşletim Sistemi Tespiti

#### Gelişmiş TTL Analizi ve Hop Hesaplama

Program artık sadece TTL değerine bakmakla kalmaz, aynı zamanda **hop sayısını** da hesaplayarak daha doğru OS tespiti yapar:

| Orijinal TTL | İşletim Sistemi | Açıklama |
|--------------|-----------------|----------|
| 64 | Linux/Unix | Tipik Linux/Unix sistemleri |
| 128 | Windows | Tipik Windows sistemleri |
| 255 | Cisco/Network Device | Ağ cihazları |

#### Hop Analizi Örnekleri

```bash
# Örnek çıktılar:
[OS] TTL analizi: 64 -> Linux/Unix (TTL: 64) - Doğrudan bağlantı
[OS] TTL analizi: 44 -> Linux/Unix (TTL: 44) - Uzak (20 hop)
[OS] TTL analizi: 115 -> Windows (TTL: 115) - Orta mesafe (13 hop)
[OS] TTL analizi: 128 -> Windows (TTL: 128) - Doğrudan bağlantı
```

#### Mesafe Kategorileri

| Hop Sayısı | Kategori | Açıklama |
|------------|----------|----------|
| 0 | Doğrudan bağlantı | Aynı ağda |
| 1-5 | Yakın | Yerel ağ/ISP |
| 6-15 | Orta mesafe | Bölgesel |
| 16+ | Uzak | Kıtalar arası |

#### Özel TTL Değerleri

| TTL Aralığı | Tespit | Açıklama |
|-------------|--------|----------|
| 1-10 | Proxy/Load Balancer | Çok düşük TTL |
| 11-30 | Çok uzak Linux/Unix | 30+ hop |
| 31-50 | Uzak Linux/Unix | 15-30 hop |
| 51-80 | Orta mesafe Linux/Unix | 10-15 hop |
| 81-110 | Uzak Windows | 15-45 hop |

## 🛡️ Güvenlik Notları

### ⚠️ Yasal Uyarılar
- Bu araç sadece **kendi sistemlerinizde** veya **izin verilen sistemlerde** kullanılmalıdır
- Yetkisiz port taraması **yasalara aykırı** olabilir
- Ağ yöneticilerinin **izni olmadan kullanmayın**
- Eğitim ve güvenlik testleri için tasarlanmıştır

### 🔒 Güvenlik Önerileri

Program otomatik olarak güvenlik önerileri verir:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                              GÜVENLİK ÖNERİLERİ                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ • Port 23 (Telnet) güvensizdir, SSH kullanın                               ║
║ • Port 21 (FTP) güvensizdir, SFTP/FTPS kullanın                            ║
║ • HTTP trafiği şifrelenmemiş, HTTPS kullanın                               ║
║ • RDP güvenlik duvarı arkasında olmalı                                     ║
║ • Gereksiz servisleri kapatın                                               ║
║ • Güvenlik duvarı kurallarını gözden geçirin                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## 🔧 Sorun Giderme

### Yaygın Hatalar

#### "Permission denied" hatası
```bash
# Raw socket versiyonu için root yetkisi gerekli
sudo ./raw_scanner 192.168.1.1 1-1024
```

#### "Raw socket oluşturulamadı" hatası
```bash
# Root yetkisi kontrolü
whoami  # root olmalı

# Alternatif olarak normal socket versiyonunu kullan
./port_scanner 192.168.1.1 1-1024
```

#### "Connection refused" çok fazla
- Hedef sistem güvenlik duvarı kullanıyor olabilir
- Port aralığını küçültün
- Thread sayısını azaltın

#### Yavaş tarama
```bash
# Daha küçük port aralıkları kullanın
./port_scanner 192.168.1.1 1-100

# Sadece önemli portları tarayın
./port_scanner 192.168.1.1 22,80,443,3389
```

#### macOS'ta derleme hatası
```bash
# Xcode Command Line Tools yükleyin
xcode-select --install

# Homebrew ile GCC yükleyin
brew install gcc
```

### Performans İyileştirmeleri

#### Thread Sayısını Ayarlama
```cpp
// simple_scanner.cpp içinde
const int max_threads = 50;  // 100'den 50'ye düşür

// main.cpp içinde
const int max_threads = 25;  // 50'den 25'e düşür
```

#### Timeout Değerlerini Azaltma
```cpp
// TCP timeout
timeout.tv_sec = 1;  // 2'den 1'e düşür

// UDP timeout
timeout.tv_sec = 1;  // 2'den 1'e düşür
```

### Debug Modu

Daha detaylı çıktı için logging seviyesini artırabilirsiniz:

```bash
# Normal çalıştırma
./port_scanner 192.168.1.1 22,80,443

# Detaylı çıktı (zaten aktif)
# Tüm [DEBUG], [INFO], [SUCCESS] mesajları görünür
```

## 📈 Performans Karşılaştırması

| Özellik | Normal Socket | Raw Socket |
|---------|---------------|------------|
| **Hız** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Güvenilirlik** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Stealth** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Kullanım Kolaylığı** | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| **OS Tespiti** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Root Gereksinimi** | ❌ | ✅ |

## ✅ OS Tespiti Başarı Durumu

**✅ ÇÖZÜLDÜ**: OS tespiti artık her iki versiyonda da mükemmel çalışıyor!

### Gelişmiş Özellikler:
- **Hop Analizi**: TTL değerinden orijinal TTL ve hop sayısı hesaplanıyor
- **Mesafe Tespiti**: Hedefin ne kadar uzakta olduğu belirleniyor
- **Akıllı Algoritma**: Düşük TTL değerleri için özel analiz
- **Detaylı Logging**: Her adım izleniyor ve raporlanıyor

### Örnek Başarılı Tespitler:
```bash
# Linux sunucu (20 hop uzaklıkta)
[OS] TTL analizi: 44 -> Linux/Unix (TTL: 44) - Uzak (20 hop)

# Windows sunucu (13 hop uzaklıkta)  
[OS] TTL analizi: 115 -> Windows (TTL: 115) - Orta mesafe (13 hop)

# Doğrudan bağlantı
[OS] TTL analizi: 64 -> Linux/Unix (TTL: 64) - Doğrudan bağlantı
```

## 🎯 Hangi Versiyonu Kullanmalı?

### Normal Socket Versiyonu Kullanın Eğer:
- ✅ Hızlı ve güvenilir tarama istiyorsanız
- ✅ Root yetkisi kullanmak istemiyorsanız
- ✅ Basit kullanım arıyorsanız
- ✅ False positive'lerden kaçınmak istiyorsanız

### Raw Socket Versiyonu Kullanın Eğer:
- ✅ Gerçek raw socket teknolojisini öğrenmek istiyorsanız
- ✅ Stealth tarama yapmanız gerekiyorsa
- ✅ Manuel paket oluşturmayı deneyimlemek istiyorsanız
- ✅ Düşük seviye ağ programlama öğreniyorsanız

## 📞 Destek

Sorularınız için:
- GitHub Issues kullanabilirsiniz
- Kod içindeki yorumları inceleyin
- README.md dosyasına bakın

---

**Not**: Bu araç penetrasyon testleri ve güvenlik değerlendirmeleri için tasarlanmıştır. Yasal ve etik kurallara uygun şekilde kullanın.
