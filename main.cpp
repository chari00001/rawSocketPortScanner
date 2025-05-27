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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <set>
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
                                struct tcphdr *tcp_header) {
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
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = new char[psize];

    memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), tcp_header,
           sizeof(struct tcphdr));

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

  // TCP SYN Scan
  bool tcpSynScan(int port, int &ttl, int &window_size) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
      std::cerr << "Raw socket oluşturulamadı. Root yetkisi gerekli!"
                << std::endl;
      return false;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
      close(sock);
      return false;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    struct ip_header *ip_hdr = (struct ip_header *)packet;
    struct tcphdr *tcp_header =
        (struct tcphdr *)(packet + sizeof(struct ip_header));

    // IP header
    ip_hdr->ip_vhl = (4 << 4) | 5; // version 4, header length 5
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip_header) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_sum = 0;
    inet_aton("127.0.0.1", &ip_hdr->ip_src);
    inet_aton(target_ip.c_str(), &ip_hdr->ip_dst);

    // TCP header
    tcp_header->source = htons(12345);
    tcp_header->dest = htons(port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    // Checksum hesapla
    ip_hdr->ip_sum =
        checksumCalculator((uint16_t *)packet, ntohs(ip_hdr->ip_len));
    tcp_header->check = calculateTCPChecksum(ip_hdr, tcp_header);

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
        struct tcphdr *recv_tcp =
            (struct tcphdr *)(buffer + ((recv_ip->ip_vhl & 0x0F) * 4));

        if (recv_tcp->source == htons(port)) {
          ttl = recv_ip->ip_ttl;
          window_size = ntohs(recv_tcp->window);

          if (recv_tcp->syn && recv_tcp->ack) {
            port_open = true;
          }
        }
      }
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

  // İşletim sistemi tespiti
  void detectOS(int ttl, int window_size) {
    if (ttl >= 60 && ttl <= 64) {
      detected_os = "Linux/Unix";
    } else if (ttl >= 120 && ttl <= 128) {
      detected_os = "Windows";
    } else if (ttl >= 250 && ttl <= 255) {
      detected_os = "Cisco/Network Device";
    } else {
      detected_os = "Unknown";
    }

    // Window size ile daha detaylı analiz
    if (window_size == 65535) {
      detected_os += " (High probability)";
    } else if (window_size == 8192) {
      detected_os += " (Windows variant)";
    }
  }

  // Port tarama
  void scanPort(int port) {
    int ttl = 0, window_size = 0;
    bool is_open = false;
    std::string scan_method = "";

    // TCP SYN Scan dene
    if (tcpSynScan(port, ttl, window_size)) {
      is_open = true;
      scan_method = "TCP-SYN";
    }
    // TCP Connect Scan dene
    else if (tcpConnectScan(port)) {
      is_open = true;
      scan_method = "TCP-Connect";
    }
    // UDP Scan dene
    else if (udpScan(port)) {
      is_open = true;
      scan_method = "UDP";
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
      std::string banner = grabBanner(port);
      if (!banner.empty()) {
        if (!service.empty()) {
          service += " (" + banner + ")";
        } else {
          service = banner;
        }
      }

      services[port] = service.empty() ? "Unknown" : service;

      // İlk açık port için OS tespiti
      if (detected_os.empty() && ttl > 0) {
        detectOS(ttl, window_size);
      }
    }
  }

  // Ana tarama fonksiyonu
  void scan() {
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

  std::string target_ip = argv[1];
  std::string port_range = argv[2];

  // Root yetkisi kontrolü
  if (getuid() != 0) {
    std::cout << "UYARI: Raw socket kullanımı için root yetkisi gerekli!"
              << std::endl;
    std::cout << "Program sudo ile çalıştırılmalı: sudo " << argv[0] << " "
              << argv[1] << " " << argv[2] << std::endl;
    return 1;
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