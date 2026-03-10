"""
Домашнее задание Д12
Тема: Python для аналитиков ИБ — форензика
Анализ сетевого дампа (pcapng) с помощью pyshark
"""

import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from datetime import datetime
import csv
import os

# путь к файлу дампа
PCAP_FILE = os.path.join(os.path.dirname(__file__), "dhcp.pcapng")


def load_packets(filepath):
    """Загружаем пакеты из pcapng файла"""
    print(f"[*] Загрузка дампа: {filepath}")
    cap = pyshark.FileCapture(filepath)
    packets = []
    for pkt in cap:
        packets.append(pkt)
    cap.close()
    print(f"[+] Загружено пакетов: {len(packets)}")
    return packets


def extract_ip_info(packets):
    """Извлекаем информацию об IP-адресах из пакетов"""
    ip_src_list = []
    ip_dst_list = []
    connections = []

    for pkt in packets:
        if hasattr(pkt, 'ip'):
            src = pkt.ip.src
            dst = pkt.ip.dst
            proto = pkt.highest_layer
            ip_src_list.append(src)
            ip_dst_list.append(dst)
            connections.append({
                'src': src,
                'dst': dst,
                'protocol': proto,
                'time': str(pkt.sniff_time)
            })

    return ip_src_list, ip_dst_list, connections


def extract_dhcp_info(packets):
    """Извлекаем DHCP-артефакты — тип сообщения, MAC, предложенный IP"""
    dhcp_events = []

    # маппинг типов DHCP-сообщений
    dhcp_types = {
        '1': 'Discover',
        '2': 'Offer',
        '3': 'Request',
        '4': 'Decline',
        '5': 'ACK',
        '6': 'NAK',
        '7': 'Release',
        '8': 'Inform'
    }

    for pkt in packets:
        if hasattr(pkt, 'dhcp'):
            event = {}
            event['time'] = str(pkt.sniff_time)

            # тип DHCP сообщения
            try:
                msg_type_num = pkt.dhcp.option_dhcp
                event['type'] = dhcp_types.get(msg_type_num, f'Unknown({msg_type_num})')
            except AttributeError:
                event['type'] = 'N/A'

            # MAC-адрес клиента
            try:
                event['client_mac'] = pkt.dhcp.hw_mac_addr
            except AttributeError:
                event['client_mac'] = 'N/A'

            # запрашиваемый/предложенный IP
            try:
                event['requested_ip'] = pkt.dhcp.option_requested_ip
            except AttributeError:
                try:
                    event['requested_ip'] = pkt.ip.dst if pkt.ip.dst != '255.255.255.255' else 'N/A'
                except:
                    event['requested_ip'] = 'N/A'

            # Transaction ID
            try:
                event['transaction_id'] = pkt.dhcp.id
            except AttributeError:
                event['transaction_id'] = 'N/A'

            dhcp_events.append(event)

    return dhcp_events


def extract_dns_queries(packets):
    """Ищем DNS-запросы (если есть в дампе)"""
    dns_queries = []

    for pkt in packets:
        if hasattr(pkt, 'dns'):
            try:
                query_name = pkt.dns.qry_name
                dns_queries.append({
                    'time': str(pkt.sniff_time),
                    'query': query_name,
                    'type': pkt.dns.qry_type if hasattr(pkt.dns, 'qry_type') else 'N/A'
                })
            except AttributeError:
                pass

    return dns_queries


def print_connections(connections):
    """Красиво выводим таблицу соединений"""
    print("\n" + "=" * 70)
    print("СЕТЕВЫЕ СОЕДИНЕНИЯ")
    print("=" * 70)
    print(f"{'Время':<28} {'Источник':<18} {'Назначение':<18} {'Протокол'}")
    print("-" * 70)
    for conn in connections:
        print(f"{conn['time']:<28} {conn['src']:<18} {conn['dst']:<18} {conn['protocol']}")


def print_dhcp_events(events):
    """Выводим DHCP-события"""
    print("\n" + "=" * 70)
    print("DHCP СОБЫТИЯ")
    print("=" * 70)
    for ev in events:
        print(f"  [{ev['time']}]")
        print(f"    Тип: {ev['type']}, MAC: {ev['client_mac']}")
        print(f"    IP: {ev['requested_ip']}, Transaction ID: {ev['transaction_id']}")
        print()


def print_dns_queries(queries):
    """Выводим DNS-запросы если они есть"""
    if not queries:
        print("\n[!] DNS-запросы в дампе не обнаружены")
        return
    print("\n" + "=" * 70)
    print("DNS ЗАПРОСЫ")
    print("=" * 70)
    for q in queries:
        print(f"  {q['time']} — {q['query']} (тип: {q['type']})")


def save_to_csv(connections, dhcp_events, dns_queries):
    """Сохраняем результаты в CSV"""
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # соединения
    conn_file = os.path.join(output_dir, "connections.csv")
    with open(conn_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['time', 'src', 'dst', 'protocol'])
        writer.writeheader()
        writer.writerows(connections)
    print(f"[+] Соединения сохранены: {conn_file}")

    # DHCP
    dhcp_file = os.path.join(output_dir, "dhcp_events.csv")
    with open(dhcp_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['time', 'type', 'client_mac', 'requested_ip', 'transaction_id'])
        writer.writeheader()
        writer.writerows(dhcp_events)
    print(f"[+] DHCP-события сохранены: {dhcp_file}")

    # DNS (если есть)
    if dns_queries:
        dns_file = os.path.join(output_dir, "dns_queries.csv")
        with open(dns_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['time', 'query', 'type'])
            writer.writeheader()
            writer.writerows(dns_queries)
        print(f"[+] DNS-запросы сохранены: {dns_file}")


def visualize(connections, dhcp_events, dns_queries):
    """Строим графики по результатам анализа"""
    sns.set_style("whitegrid")
    output_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Распределение по протоколам
    protocols = [c['protocol'] for c in connections]
    proto_counts = Counter(protocols)

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    axes[0].bar(proto_counts.keys(), proto_counts.values(), color=sns.color_palette("muted"))
    axes[0].set_title("Распределение пакетов по протоколам")
    axes[0].set_xlabel("Протокол")
    axes[0].set_ylabel("Количество")

    # 2. Типы DHCP-сообщений
    if dhcp_events:
        dhcp_type_counts = Counter([e['type'] for e in dhcp_events])
        colors = sns.color_palette("pastel", len(dhcp_type_counts))
        axes[1].pie(dhcp_type_counts.values(), labels=dhcp_type_counts.keys(),
                     autopct='%1.0f%%', colors=colors)
        axes[1].set_title("Типы DHCP-сообщений")
    else:
        axes[1].text(0.5, 0.5, "Нет DHCP данных", ha='center', va='center')
        axes[1].set_title("DHCP")

    plt.tight_layout()
    chart_path = os.path.join(output_dir, "analysis_charts.png")
    plt.savefig(chart_path, dpi=150)
    print(f"[+] Графики сохранены: {chart_path}")
    plt.show()

    # 3. Если есть DNS — отдельный график
    if dns_queries:
        domains = [q['query'] for q in dns_queries]
        domain_counts = Counter(domains).most_common(10)
        if domain_counts:
            fig2, ax2 = plt.subplots(figsize=(10, 5))
            names, counts = zip(*domain_counts)
            ax2.barh(names, counts, color=sns.color_palette("coolwarm", len(names)))
            ax2.set_title("Топ-10 DNS запросов")
            ax2.set_xlabel("Количество запросов")
            plt.tight_layout()
            dns_chart = os.path.join(output_dir, "dns_chart.png")
            plt.savefig(dns_chart, dpi=150)
            print(f"[+] DNS-график сохранён: {dns_chart}")
            plt.show()


def main():
    # загрузка
    packets = load_packets(PCAP_FILE)

    # извлечение артефактов
    ip_src, ip_dst, connections = extract_ip_info(packets)
    dhcp_events = extract_dhcp_info(packets)
    dns_queries = extract_dns_queries(packets)

    # вывод в консоль
    print_connections(connections)
    print_dhcp_events(dhcp_events)
    print_dns_queries(dns_queries)

    # уникальные IP
    all_ips = set(ip_src + ip_dst)
    print("\n" + "=" * 70)
    print("УНИКАЛЬНЫЕ IP-АДРЕСА")
    print("=" * 70)
    for ip in sorted(all_ips):
        print(f"  {ip}")

    # сохранение в csv
    print()
    save_to_csv(connections, dhcp_events, dns_queries)

    # визуализация
    visualize(connections, dhcp_events, dns_queries)

    print("\n[*] Анализ завершён.")


if __name__ == '__main__':
    main()
