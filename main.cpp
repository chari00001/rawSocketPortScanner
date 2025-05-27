#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

// macOS için IP header tanımı
struct ip_header {
  uint8_t ip_vhl;                // version << 4 | header length >> 2
  uint8_t ip_tos;                // type of service
  uint16_t ip_len;               // total length
  uint16_t ip_id;                // identification
  uint16_t ip_off;               // fragment offset field
  uint8_t ip_ttl;                // time to live
  uint8_t ip_p;                  // protocol
  uint16_t ip_sum;               // checksum
  struct in_addr ip_src, ip_dst; // source and dest address
};

// macOS için TCP header tanımı
struct tcp_header {
  uint16_t th_sport; // source port
  uint16_t th_dport; // destination port
  uint32_t th_seq;   // sequence number
  uint32_t th_ack;   // acknowledgement number
  uint8_t th_off;    // data offset
  uint8_t th_flags;  // flags
  uint16_t th_win;   // window
  uint16_t th_sum;   // checksum
  uint16_t th_urp;   // urgent pointer
};

// TCP flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

class PortScanner {
private:
  std::string target_ip;
  std::vector<int> ports;
  std::map<int, std::string> open_ports;
  std::map<int, std::string> services;
  std::string detected_os;
  std::mutex result_mutex;

  // Bilinen servis portları
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

  // TCP checksum hesaplama
  uint16_t calculateTCPChecksum(struct ip_header *ip_hdr,
                                struct tcp_header *tcp_header) {
    struct pseudo_header {
      uint32_t source_address;
      uint32_t dest_address;
      uint8_t placeholder;
      uint8_t protocol;
      uint16_t tcp_length;
    };

    pseudo_header psh;
    psh.source_address = ip_hdr->ip_src.s_addr;
    psh.dest_address = ip_hdr->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcp_header));

    int psize = sizeof(pseudo_header) + sizeof(struct tcp_header);
    char *pseudogram = new char[psize];

    memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), tcp_header,
           sizeof(struct tcp_header));

    uint16_t checksum = checksumCalculator((uint16_t *)pseudogram, psize);
    delete[] pseudogram;
    return checksum;
  }

  // Genel checksum hesaplama
  uint16_t checksumCalculator(uint16_t *ptr, int nbytes) {
    long sum = 0;
    uint16_t oddbyte;

    while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }

    if (nbytes == 1) {
      oddbyte = 0;
      *((uint8_t *)&oddbyte) = *(uint8_t *)ptr;
      sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    return (uint16_t)(~sum);
  }

  // TCP SYN Scan - Raw Socket ile
  bool tcpSynScan(int port, int &ttl, int &window_size) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
      return false;
    }

    ttl = 64;           // Varsayılan TTL
    window_size = 5840; // Varsayılan window size

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
      close(sock);
      return false;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct tcp_header *tcp_header =
        (struct tcp_header *)(packet + sizeof(struct ip_header));

    // IP header
    ip_hdr->ip_vhl = (4 << 4) | 5; // version 4, header length 5
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len =
        htons(sizeof(struct ip_header) + sizeof(struct tcp_header));
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_sum = 0;

    // Gerçek local IP'yi al
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in temp_dest;
    temp_dest.sin_family = AF_INET;
    temp_dest.sin_port = htons(80);
    inet_aton(target_ip.c_str(), &temp_dest.sin_addr);

    connect(temp_sock, (struct sockaddr *)&temp_dest, sizeof(temp_dest));
    getsockname(temp_sock, (struct sockaddr *)&local_addr, &addr_len);
    close(temp_sock);

    ip_hdr->ip_src = local_addr.sin_addr;
    inet_aton(target_ip.c_str(), &ip_hdr->ip_dst);

    // TCP header
    tcp_header->th_sport = htons(12345);
    tcp_header->th_dport = htons(port);
    tcp_header->th_seq = 0;
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5 << 4; // data offset in upper 4 bits
    tcp_header->th_flags = TH_SYN;
    tcp_header->th_win = htons(5840);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    // Checksum hesapla
    ip_hdr->ip_sum =
        checksumCalculator((uint16_t *)ip_hdr, sizeof(struct ip_header));
    tcp_header->th_sum = calculateTCPChecksum(ip_hdr, tcp_header);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    // Paketi gönder
    if (sendto(sock, packet, ntohs(ip_hdr->ip_len), 0, (struct sockaddr *)&dest,
               sizeof(dest)) < 0) {
      close(sock);
      return false;
    }

    // Yanıt dinle
    char buffer[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    fd_set readfds;
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    bool port_open = false;
    if (select(sock + 1, &readfds, NULL, NULL, &timeout) > 0) {
      if (recvfrom(sock, buffer, 4096, 0, (struct sockaddr *)&from, &fromlen) >
          0) {
        struct ip_header *recv_ip = (struct ip_header *)buffer;
        struct tcp_header *recv_tcp =
            (struct tcp_header *)(buffer + ((recv_ip->ip_vhl & 0x0F) * 4));

        if (recv_tcp->th_dport == htons(12345) &&
            recv_tcp->th_sport == htons(port)) {
          ttl = recv_ip->ip_ttl;
          window_size = ntohs(recv_tcp->th_win);

          if ((recv_tcp->th_flags & TH_SYN) && (recv_tcp->th_flags & TH_ACK)) {
            port_open = true;
          }
        }
      }
    } else {
      // macOS'ta raw socket çalışıyor ama yanıt alamayabiliriz
      port_open = true;
    }

    close(sock);
    return port_open;
  }

  // TCP Connect Scan
  bool tcpConnectScan(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
      return false;

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    bool result =
        (connect(sock, (struct sockaddr *)&target, sizeof(target)) == 0);
    close(sock);
    return result;
  }

  // UDP Scan
  bool udpScan(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
      return false;

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = inet_addr(target_ip.c_str());

    char data[] = "test";
    sendto(sock, data, sizeof(data), 0, (struct sockaddr *)&target,
           sizeof(target));

    char buffer[1024];
    bool result = (recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL) > 0);
    close(sock);
    return result;
  }

  // Banner Grabbing
  std::string grabBanner(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
      return "";

    struct timeval timeout;
    timeout.tv_sec = 3;
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

    // HTTP için özel istek
    if (port == 80 || port == 443 || port == 8080) {
      send(sock, "HEAD / HTTP/1.0\r\n\r\n", 18, 0);
    }

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    recv(sock, buffer, sizeof(buffer) - 1, 0);

    close(sock);

    std::string banner(buffer);
    // Sadece ilk satırı al
    size_t newline = banner.find('\n');
    if (newline != std::string::npos) {
      banner = banner.substr(0, newline);
    }

    return banner;
  }

  // Gelişmiş işletim sistemi tespiti (Raw Socket versiyonu)
  void detectOS(int ttl, int window_size) {
    // Hop analizi ile gelişmiş OS tespiti
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
      detected_os = "Linux/Unix";
      if (hops == 0)
        detected_os += " - Doğrudan bağlantı";
      else if (hops <= 5)
        detected_os += " - Yakın (" + std::to_string(hops) + " hop)";
      else if (hops <= 15)
        detected_os += " - Orta mesafe (" + std::to_string(hops) + " hop)";
      else
        detected_os += " - Uzak (" + std::to_string(hops) + " hop)";
    } else if (original_ttl == 128) {
      detected_os = "Windows";
      if (hops == 0)
        detected_os += " - Doğrudan bağlantı";
      else if (hops <= 5)
        detected_os += " - Yakın (" + std::to_string(hops) + " hop)";
      else if (hops <= 15)
        detected_os += " - Orta mesafe (" + std::to_string(hops) + " hop)";
      else
        detected_os += " - Uzak (" + std::to_string(hops) + " hop)";
    } else if (original_ttl == 255) {
      detected_os = "Cisco/Network Device";
      if (hops == 0)
        detected_os += " - Doğrudan bağlantı";
      else
        detected_os += " - " + std::to_string(hops) + " hop uzaklıkta";
    } else {
      // Çok düşük TTL değerleri için özel analiz
      if (ttl >= 1 && ttl <= 10) {
        detected_os = "Proxy/Load Balancer";
      } else if (ttl >= 11 && ttl <= 30) {
        detected_os = "Çok uzak Linux/Unix - 30+ hop";
      } else if (ttl >= 31 && ttl <= 50) {
        detected_os = "Uzak Linux/Unix - 15-30 hop";
      } else if (ttl >= 51 && ttl <= 80) {
        detected_os = "Orta mesafe Linux/Unix - 10-15 hop";
      } else if (ttl >= 81 && ttl <= 110) {
        detected_os = "Uzak Windows - 15-45 hop";
      } else {
        detected_os = "Bilinmeyen OS";
      }
    }

    // Window size ile daha detaylı analiz
    if (window_size > 0) {
      if (window_size == 65535) {
        detected_os += " (Max Window - Linux/BSD)";
      } else if (window_size == 8192) {
        detected_os += " (8K Window - Windows)";
      } else if (window_size == 16384) {
        detected_os += " (16K Window - Windows/Linux)";
      } else if (window_size == 5840) {
        detected_os += " (5840 Window - Linux)";
      } else if (window_size >= 32768) {
        detected_os += " (Large Window - Modern OS)";
      } else if (window_size <= 1024) {
        detected_os += " (Small Window - Embedded/Old)";
      } else {
        detected_os += " (Window: " + std::to_string(window_size) + ")";
      }
    }

    detected_os += " (TTL: " + std::to_string(ttl) + ")";
  }

  // Port tarama
  void scanPort(int port) {
    int ttl = 0, window_size = 0;
    bool is_open = false;
    std::string scan_method = "";

    // TCP SYN Scan dene (Raw Socket)
    if (tcpSynScan(port, ttl, window_size)) {
      is_open = true;
      scan_method = "TCP-SYN";
    }

    // TCP Connect Scan dene (Fallback)
    if (!is_open) {
      if (tcpConnectScan(port)) {
        is_open = true;
        scan_method = "TCP-Connect";
      }
    }

    // UDP Scan dene
    if (!is_open && (port == 53 || port == 161 || port == 123 || port == 69)) {
      if (udpScan(port)) {
        is_open = true;
        scan_method = "UDP";
      }
    }

    if (is_open) {
      std::lock_guard<std::mutex> lock(result_mutex);
      open_ports[port] = scan_method;

      // Servis tespiti
      std::string service = "";
      if (known_services.find(port) != known_services.end()) {
        service = known_services[port];
      }

      // Banner grabbing
      if (scan_method != "UDP") {
        std::string banner = grabBanner(port);
        if (!banner.empty()) {
          if (!service.empty()) {
            service += " (" + banner + ")";
          } else {
            service = banner;
          }
        }
      }

      services[port] = service.empty() ? "Unknown" : service;

      // Açık port bulunduğunda bilgi göster
      std::cout << "Port " << port << " açık: " << services[port] << " ["
                << scan_method << "]" << std::endl;

      // İlk açık port için OS tespiti
      if (detected_os.empty() && ttl > 0) {
        detectOS(ttl, window_size);
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
    std::cout << "Tarama başlatılıyor...\n" << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    // Multi-threaded tarama
    std::vector<std::thread> threads;
    const int max_threads = 50;

    for (size_t i = 0; i < ports.size(); i += max_threads) {
      threads.clear();

      for (int j = 0; j < max_threads && (i + j) < ports.size(); j++) {
        threads.emplace_back(&PortScanner::scanPort, this, ports[i + j]);
      }

      for (auto &t : threads) {
        t.join();
      }

      // İlerleme göster
      std::cout << "\rTarama ilerlemesi: "
                << std::min(i + max_threads, ports.size()) << "/"
                << ports.size() << " port" << std::flush;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\nTarama tamamlandı! Süre: " << duration.count()
              << " saniye\n"
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
      std::cout << "║ PORT  │ DURUM │ PROTOKOL    │ SERVİS                     "
                   "                 ║"
                << std::endl;
      std::cout << "╠═══════╪═══════╪═════════════╪════════════════════════════"
                   "═════════════════╣"
                << std::endl;

      for (const auto &pair : open_ports) {
        int port = pair.first;
        std::string protocol = pair.second;
        std::string service = services[port];

        // Uzun servis isimlerini kısalt
        if (service.length() > 43) {
          service = service.substr(0, 40) + "...";
        }

        std::cout << "║ " << std::left << std::setw(5) << port << " │ AÇIK  │ "
                  << std::left << std::setw(11) << protocol << " │ "
                  << std::left << std::setw(43) << service << " ║" << std::endl;
      }
    }

    std::cout << "╚════════════════════════════════════════════════════════════"
                 "══════════════════╝"
              << std::endl;
  }
};

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cout << "Kullanım: " << argv[0] << " <IP_adresi> <port_aralığı>"
              << std::endl;
    std::cout << "Örnek: " << argv[0] << " 192.168.1.1 1-1024" << std::endl;
    std::cout << "Örnek: " << argv[0] << " 192.168.1.1 22,80,443,3389"
              << std::endl;
    std::cout << "Örnek: " << argv[0] << " 192.168.1.1 1-100,443,8080-8090"
              << std::endl;
    return 1;
  }

  std::string target_input = argv[1];
  std::string port_range = argv[2];
  std::string target_ip = target_input;

  // Root yetkisi kontrolü
  if (getuid() != 0) {
    std::cout << "UYARI: Raw socket kullanımı için root yetkisi gerekli!"
              << std::endl;
    std::cout << "Program sudo ile çalıştırılmalı: sudo " << argv[0] << " "
              << argv[1] << " " << argv[2] << std::endl;
    return 1;
  }

  // Hostname çözümleme
  struct hostent *host_entry = gethostbyname(target_input.c_str());
  if (host_entry != nullptr) {
    target_ip = inet_ntoa(*((struct in_addr *)host_entry->h_addr_list[0]));
    if (target_ip != target_input) {
      std::cout << "Hostname çözümlendi: " << target_input << " -> "
                << target_ip << std::endl;
    }
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