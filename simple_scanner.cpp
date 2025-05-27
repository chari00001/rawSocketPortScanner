#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

class PortScanner {
private:
  std::string target_ip;
  std::vector<int> ports;
  std::map<int, std::string> open_ports;
  std::map<int, std::string> services;
  std::string detected_os;
  std::mutex result_mutex;
  std::map<int, std::string> known_services;

public:
  PortScanner(const std::string &ip) : target_ip(ip) {
    // Bilinen servisleri initialize et
    known_services[21] = "FTP";
    known_services[22] = "SSH";
    known_services[23] = "Telnet";
    known_services[25] = "SMTP";
    known_services[53] = "DNS";
    known_services[80] = "HTTP";
    known_services[110] = "POP3";
    known_services[143] = "IMAP";
    known_services[443] = "HTTPS";
    known_services[993] = "IMAPS";
    known_services[995] = "POP3S";
    known_services[3389] = "RDP";
    known_services[5432] = "PostgreSQL";
    known_services[3306] = "MySQL";
    known_services[1433] = "MSSQL";
    known_services[139] = "NetBIOS";
    known_services[445] = "SMB";
    known_services[161] = "SNMP";
    known_services[389] = "LDAP";
    known_services[636] = "LDAPS";
    known_services[1521] = "Oracle";
    known_services[27017] = "MongoDB";
    known_services[8080] = "HTTP-Alt";
    known_services[8443] = "HTTPS-Alt";
    known_services[1080] = "SOCKS";
    known_services[3128] = "Proxy";
  }

  // Port aralığını parse et
  void parsePortRange(const std::string &port_range) {
    std::stringstream ss(port_range);
    std::string token;

    while (std::getline(ss, token, ',')) {
      size_t dash_pos = token.find('-');
      if (dash_pos != std::string::npos) {
        // Aralık formatı (örn: 1-1024)
        int start = std::stoi(token.substr(0, dash_pos));
        int end = std::stoi(token.substr(dash_pos + 1));
        for (int i = start; i <= end; i++) {
          ports.push_back(i);
        }
      } else {
        // Tek port (örn: 80)
        ports.push_back(std::stoi(token));
      }
    }
  }

  // TCP Connect Scan
  bool tcpConnectScan(int port) {
    // Normal socket oluştur (Raw socket DEĞİL)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
      return false;

    // Non-blocking socket
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    int result = connect(sock, (struct sockaddr *)&target, sizeof(target));

    if (result < 0) {
      if (errno == EINPROGRESS) {
        fd_set writefds;
        struct timeval timeout;
        timeout.tv_sec = 1;       // Timeout'u azalttık
        timeout.tv_usec = 500000; // 1.5 saniye

        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        if (select(sock + 1, NULL, &writefds, NULL, &timeout) > 0) {
          int error;
          socklen_t len = sizeof(error);
          if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 &&
              error == 0) {
            // Bağlantı başarılı, ama gerçekten açık mı kontrol et
            char test_byte;
            int peek_result =
                recv(sock, &test_byte, 1, MSG_PEEK | MSG_DONTWAIT);
            close(sock);

            // Eğer recv hata vermiyorsa veya EAGAIN/EWOULDBLOCK dönüyorsa port
            // açık
            return (peek_result >= 0 || errno == EAGAIN ||
                    errno == EWOULDBLOCK);
          }
        }
      }
    } else {
      // Anında bağlandı, ama gerçekten açık mı kontrol et
      char test_byte;
      int peek_result = recv(sock, &test_byte, 1, MSG_PEEK | MSG_DONTWAIT);
      close(sock);

      return (peek_result >= 0 || errno == EAGAIN || errno == EWOULDBLOCK);
    }

    close(sock);
    return false;
  }

  // UDP Scan (basit)
  bool udpScan(int port) {
    // Normal UDP socket oluştur (Raw socket DEĞİL)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
      return false;

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    // DNS için özel sorgu
    if (port == 53) {
      char dns_query[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03w"
                         "ww\x06google\x03com\x00\x00\x01\x00\x01";
      sendto(sock, dns_query, sizeof(dns_query) - 1, 0,
             (struct sockaddr *)&target, sizeof(target));
    } else {
      char data[] = "test";
      sendto(sock, data, sizeof(data), 0, (struct sockaddr *)&target,
             sizeof(target));
    }

    char buffer[1024];
    bool result = (recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL) > 0);
    close(sock);
    return result;
  }

  // Banner Grabbing
  std::string grabBanner(int port) {
    // Normal TCP socket oluştur (Raw socket DEĞİL)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
      return "";

    struct timeval timeout;
    timeout.tv_sec = 2; // Timeout'u azalttık
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    if (connect(sock, (struct sockaddr *)&target, sizeof(target)) != 0) {
      close(sock);
      return "";
    }

    std::string banner = "";
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int bytes_received = 0;

    // Port'a göre özel istekler
    if (port == 80 || port == 8080) {
      send(sock, "HEAD / HTTP/1.0\r\n\r\n", 18, 0);
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    } else if (port == 443 || port == 8443) {
      // SSL/TLS portları için özel kontrol
      banner = "HTTPS/SSL";
      close(sock);
      return banner;
    } else if (port == 22) {
      // SSH banner'ı otomatik gelir
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0 && strncmp(buffer, "SSH-", 4) == 0) {
        banner = std::string(buffer);
      }
    } else if (port == 21) {
      // FTP banner'ı otomatik gelir
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0 && strncmp(buffer, "220", 3) == 0) {
        banner = std::string(buffer);
      }
    } else if (port == 25) {
      // SMTP banner'ı otomatik gelir
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0 && strncmp(buffer, "220", 3) == 0) {
        banner = std::string(buffer);
      }
    } else if (port == 110) {
      // POP3 banner'ı
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0 && strncmp(buffer, "+OK", 3) == 0) {
        banner = std::string(buffer);
      }
    } else if (port == 143) {
      // IMAP banner'ı
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0 && strstr(buffer, "IMAP") != NULL) {
        banner = std::string(buffer);
      }
    } else {
      // Diğer portlar için genel banner okuma
      bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
      if (bytes_received > 0) {
        banner = std::string(buffer);
      }
    }

    close(sock);

    if (!banner.empty() && bytes_received > 0) {
      // Sadece ilk satırı al ve temizle
      size_t newline = banner.find('\n');
      if (newline != std::string::npos) {
        banner = banner.substr(0, newline);
      }
      size_t carriage = banner.find('\r');
      if (carriage != std::string::npos) {
        banner = banner.substr(0, carriage);
      }

      // Boş karakterleri temizle
      for (auto it = banner.begin(); it != banner.end();) {
        if (*it < 32 && *it != ' ') {
          it = banner.erase(it);
        } else {
          ++it;
        }
      }

      // Çok kısa banner'ları reddet
      if (banner.length() < 3) {
        banner = "";
      }
    }

    return banner;
  }

  // TTL ile gelişmiş OS tespiti
  void detectOSByTTL() {
    // Ping ile TTL değerini al
    std::string ping_cmd = "ping -c 1 -W 2000 " + target_ip +
                           " 2>/dev/null | grep 'ttl=' | head -1";
    FILE *pipe = popen(ping_cmd.c_str(), "r");
    if (!pipe)
      return;

    char buffer[256];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
      result += buffer;
    }
    pclose(pipe);

    if (!result.empty()) {
      size_t ttl_pos = result.find("ttl=");
      if (ttl_pos != std::string::npos) {
        int ttl = std::stoi(result.substr(ttl_pos + 4, 3));

        // Gelişmiş OS tespiti - hop analizi ile
        int original_ttl = 0;
        int hops = 0;

        // Orijinal TTL değerini tahmin et
        if (ttl <= 64) {
          original_ttl = 64;
          hops = 64 - ttl;
        } else if (ttl <= 128) {
          original_ttl = 128;
          hops = 128 - ttl;
        } else if (ttl <= 255) {
          original_ttl = 255;
          hops = 255 - ttl;
        }

        if (original_ttl == 64) {
          detected_os = "Linux/Unix (TTL: " + std::to_string(ttl) + ")";
          if (hops == 0)
            detected_os += " - Doğrudan bağlantı";
          else if (hops <= 5)
            detected_os += " - Yakın (" + std::to_string(hops) + " hop)";
          else if (hops <= 15)
            detected_os += " - Orta mesafe (" + std::to_string(hops) + " hop)";
          else
            detected_os += " - Uzak (" + std::to_string(hops) + " hop)";
        } else if (original_ttl == 128) {
          detected_os = "Windows (TTL: " + std::to_string(ttl) + ")";
          if (hops == 0)
            detected_os += " - Doğrudan bağlantı";
          else if (hops <= 5)
            detected_os += " - Yakın (" + std::to_string(hops) + " hop)";
          else if (hops <= 15)
            detected_os += " - Orta mesafe (" + std::to_string(hops) + " hop)";
          else
            detected_os += " - Uzak (" + std::to_string(hops) + " hop)";
        } else if (original_ttl == 255) {
          detected_os =
              "Cisco/Network Device (TTL: " + std::to_string(ttl) + ")";
          if (hops == 0)
            detected_os += " - Doğrudan bağlantı";
          else
            detected_os += " - " + std::to_string(hops) + " hop uzaklıkta";
        } else {
          // Çok düşük TTL değerleri için özel analiz
          if (ttl >= 1 && ttl <= 10) {
            detected_os =
                "Proxy/Load Balancer (TTL: " + std::to_string(ttl) + ")";
          } else if (ttl >= 11 && ttl <= 30) {
            detected_os = "Çok uzak Linux/Unix (TTL: " + std::to_string(ttl) +
                          ") - 30+ hop";
          } else if (ttl >= 31 && ttl <= 50) {
            detected_os = "Uzak Linux/Unix (TTL: " + std::to_string(ttl) +
                          ") - 15-30 hop";
          } else if (ttl >= 51 && ttl <= 80) {
            detected_os =
                "Orta mesafe Linux/Unix (TTL: " + std::to_string(ttl) +
                ") - 10-15 hop";
          } else if (ttl >= 81 && ttl <= 110) {
            detected_os =
                "Uzak Windows (TTL: " + std::to_string(ttl) + ") - 15-45 hop";
          } else {
            detected_os = "Bilinmeyen OS (TTL: " + std::to_string(ttl) + ")";
          }
        }
      }
    }

    if (detected_os.empty()) {
      detected_os = "Unknown (No ping response)";
    }
  }

  // Port tarama
  void scanPort(int port) {
    bool is_open = false;
    std::string scan_method = "";

    // TCP Connect Scan dene
    if (tcpConnectScan(port)) {
      is_open = true;
      scan_method = "TCP";
    }

    // UDP Scan dene (sadece belirli portlar için)
    if (!is_open && (port == 53 || port == 161 || port == 123 || port == 69)) {
      if (udpScan(port)) {
        is_open = true;
        scan_method = "UDP";
      }
    }

    if (is_open) {
      // Servis tespiti
      std::string service = "";
      bool service_identified = false;

      // Önce bilinen servis portlarını kontrol et
      if (known_services.find(port) != known_services.end()) {
        service = known_services[port];
        service_identified = true;
      }

      // Banner grabbing (sadece TCP portları için)
      if (scan_method == "TCP") {
        std::string banner = grabBanner(port);
        if (!banner.empty()) {
          if (!service.empty()) {
            service += " (" + banner + ")";
          } else {
            service = banner;
          }
          service_identified = true;
        }
      }

      // Sadece servis tespit edilebildiyse kaydet
      if (service_identified) {
        std::lock_guard<std::mutex> lock(result_mutex);
        open_ports[port] = scan_method;
        services[port] = service;
        std::cout << "Port " << port << " açık: " << service << std::endl;
      }
    }
  }

  // Ana tarama fonksiyonu
  void scan() {
    std::cout << "╔════════════════════════════════════════════════════════════"
                 "══════════════════╗"
              << std::endl;
    std::cout << "║                          RAW SOCKET PORT SCANNER           "
                 "                 ║"
              << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════"
                 "══════════════════╝"
              << std::endl;
    std::cout << "Hedef: " << target_ip << std::endl;
    std::cout << "Taranacak port sayısı: " << ports.size() << std::endl;

    std::cout
        << "\n╔════════════════════════════════════════════════════════════"
           "══════════════════╗"
        << std::endl;
    std::cout << "║                          TEKNİK RAPOR                      "
                 "                 ║"
              << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════════"
                 "══════════════════╣"
              << std::endl;
    std::cout << "║ Raw Socket Kullanımı: HAYIR (Normal Socket kullanılıyor)   "
                 "                 ║"
              << std::endl;
    std::cout << "║ Tarama Yöntemleri:                                         "
                 "                 ║"
              << std::endl;
    std::cout << "║   • TCP Connect Scan (AF_INET, SOCK_STREAM)                "
                 "                 ║"
              << std::endl;
    std::cout << "║   • UDP Scan (AF_INET, SOCK_DGRAM) - Seçili portlar        "
                 "                 ║"
              << std::endl;
    std::cout << "║ Thread Sayısı: 100 eşzamanlı bağlantı                      "
                 "                 ║"
              << std::endl;
    std::cout << "║ Timeout: TCP=2sn, UDP=1sn                                  "
                 "                 ║"
              << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════"
                 "══════════════════╝"
              << std::endl;

    std::cout << "\nTarama başlatılıyor...\n" << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    // OS tespiti
    std::cout << "OS tespiti yapılıyor..." << std::endl;
    detectOSByTTL();
    std::cout << "Tespit edilen OS: " << detected_os << std::endl;

    // Multi-threaded tarama
    std::cout << "\nPort tarama başlatılıyor..." << std::endl;

    std::vector<std::thread> threads;
    const int max_threads = 100;

    for (size_t i = 0; i < ports.size(); i += max_threads) {
      threads.clear();

      for (int j = 0; j < max_threads && (i + j) < ports.size(); j++) {
        threads.emplace_back(&PortScanner::scanPort, this, ports[i + j]);
      }

      for (auto &t : threads) {
        t.join();
      }

      // İlerleme göster
      std::cout << "Tarama ilerlemesi: "
                << std::min(i + max_threads, ports.size()) << "/"
                << ports.size() << " port" << std::endl;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout
        << "\n╔════════════════════════════════════════════════════════════"
           "══════════════════╗"
        << std::endl;
    std::cout << "║                          TARAMA ÖZETI                      "
                 "                 ║"
              << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════════"
                 "══════════════════╣"
              << std::endl;
    std::cout << "║ Toplam tarama süresi: " << std::left << std::setw(48)
              << (std::to_string(duration.count()) + " saniye") << "║"
              << std::endl;
    std::cout << "║ Taranan port sayısı: " << std::left << std::setw(49)
              << ports.size() << "║" << std::endl;
    std::cout << "║ Tespit edilen açık port: " << std::left << std::setw(45)
              << open_ports.size() << "║" << std::endl;
    std::cout << "║ Kullanılan yöntem: Normal Socket (Raw Socket DEĞİL)        "
                 "                 ║"
              << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════"
                 "══════════════════╝"
              << std::endl;
  }

  // Sonuçları göster
  void displayResults() {
    std::cout << "╔════════════════════════════════════════════════════════════"
                 "══════════════════╗"
              << std::endl;
    std::cout << "║                            PORT TARAMA SONUÇLARI           "
                 "                 ║"
              << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════════"
                 "══════════════════╣"
              << std::endl;
    std::cout << "║ Hedef IP: " << std::left << std::setw(66) << target_ip
              << "║" << std::endl;
    std::cout << "║ Tespit edilen OS: " << std::left << std::setw(58)
              << detected_os << "║" << std::endl;
    std::cout << "║ Açık port sayısı: " << std::left << std::setw(57)
              << open_ports.size() << "║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════════"
                 "══════════════════╣"
              << std::endl;

    if (open_ports.empty()) {
      std::cout << "║                          Açık port bulunamadı!           "
                   "                   ║"
                << std::endl;
    } else {
      std::cout << "║ PORT  │ DURUM │ PROTOKOL │ SERVİS                        "
                   "                 ║"
                << std::endl;
      std::cout << "╠═══════╪═══════╪══════════╪═══════════════════════════════"
                   "═════════════════╣"
                << std::endl;

      for (const auto &pair : open_ports) {
        int port = pair.first;
        std::string protocol = pair.second;
        std::string service = services[port];

        // Uzun servis isimlerini kısalt
        if (service.length() > 47) {
          service = service.substr(0, 44) + "...";
        }

        std::cout << "║ " << std::left << std::setw(5) << port << " │ AÇIK  │ "
                  << std::left << std::setw(8) << protocol << " │ " << std::left
                  << std::setw(47) << service << " ║" << std::endl;
      }
    }

    std::cout << "╚════════════════════════════════════════════════════════════"
                 "══════════════════╝"
              << std::endl;

    // Güvenlik önerileri
    if (!open_ports.empty()) {
      std::cout << "\n╔════════════════════════════════════════════════════════"
                   "══════════════════════╗"
                << std::endl;
      std::cout << "║                              GÜVENLİK ÖNERİLERİ          "
                   "                  ║"
                << std::endl;
      std::cout << "╠══════════════════════════════════════════════════════════"
                   "════════════════════╣"
                << std::endl;

      for (const auto &pair : open_ports) {
        int port = pair.first;
        if (port == 23) {
          std::cout << "║ • Port 23 (Telnet) güvensizdir, SSH kullanın         "
                       "                      ║"
                    << std::endl;
        } else if (port == 21) {
          std::cout << "║ • Port 21 (FTP) güvensizdir, SFTP/FTPS kullanın      "
                       "                      ║"
                    << std::endl;
        } else if (port == 80 && open_ports.find(443) == open_ports.end()) {
          std::cout << "║ • HTTP trafiği şifrelenmemiş, HTTPS kullanın         "
                       "                      ║"
                    << std::endl;
        } else if (port == 3389) {
          std::cout << "║ • RDP güvenlik duvarı arkasında olmalı               "
                       "                      ║"
                    << std::endl;
        }
      }

      std::cout << "║ • Gereksiz servisleri kapatın                            "
                   "                   ║"
                << std::endl;
      std::cout << "║ • Güvenlik duvarı kurallarını gözden geçirin             "
                   "                  ║"
                << std::endl;
      std::cout << "╚══════════════════════════════════════════════════════════"
                   "════════════════════╝"
                << std::endl;
    }
  }
};

int main(int argc, char *argv[]) {
  std::cout << "╔══════════════════════════════════════════════════════════════"
               "════════════════╗"
            << std::endl;
  std::cout << "║                          RAW SOCKET PORT SCANNER             "
               "               ║"
            << std::endl;
  std::cout << "║                     OS Detection & Service Discovery         "
               "               ║"
            << std::endl;
  std::cout << "║                              v1.0 - 2024                     "
               "              ║"
            << std::endl;
  std::cout << "╚══════════════════════════════════════════════════════════════"
               "════════════════╝"
            << std::endl;

  if (argc != 3) {
    std::cout << "\nKullanım: " << argv[0] << " <IP_adresi> <port_aralığı>"
              << std::endl;
    std::cout << "\nÖrnekler:" << std::endl;
    std::cout << "  " << argv[0] << " 192.168.1.1 1-1024" << std::endl;
    std::cout << "  " << argv[0] << " 192.168.1.1 22,80,443,3389" << std::endl;
    std::cout << "  " << argv[0] << " 192.168.1.1 1-100,443,8080-8090"
              << std::endl;
    std::cout << "  " << argv[0] << " scanme.nmap.org 1-1000" << std::endl;
    std::cout << "\nNot: Bazı özellikler için root yetkisi gerekebilir."
              << std::endl;
    return 1;
  }

  std::string target_ip = argv[1];
  std::string port_range = argv[2];

  // IP adresini doğrula
  struct sockaddr_in sa;
  int result = inet_pton(AF_INET, target_ip.c_str(), &(sa.sin_addr));
  if (result == 0) {
    // Hostname olabilir, resolve etmeye çalış
    struct hostent *host_entry = gethostbyname(target_ip.c_str());
    if (host_entry == NULL) {
      std::cerr << "Hata: Geçersiz IP adresi veya hostname: " << target_ip
                << std::endl;
      return 1;
    }
    target_ip = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
    std::cout << "Hostname çözümlendi: " << argv[1] << " -> " << target_ip
              << std::endl;
  }

  PortScanner scanner(target_ip);

  try {
    scanner.parsePortRange(port_range);
    scanner.scan();
    scanner.displayResults();
  } catch (const std::exception &e) {
    std::cerr << "Hata: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}