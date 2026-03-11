"""
Итоговое домашнее задание
Тема: Автоматизированный мониторинг и реагирование на угрозы

Описание работы скрипта:
    Скрипт выполняет комплексный анализ угроз информационной безопасности,
    используя два источника данных:
      1) Логи Suricata (suricata_logs.json) -- события сетевой безопасности
         (алерты IDS, DNS-запросы к подозрительным доменам).
      2) API Vulners (mock) -- поиск уязвимостей по ключевым словам с
         получением CVSS-баллов.

    Этапы работы:
      - Загрузка и парсинг логов Suricata, выделение алертов и DNS-событий.
      - Имитация запроса к Vulners API для получения списка уязвимостей.
      - Анализ данных: подсчёт алертов по IP-адресам, определение
        подозрительных DNS-запросов, оценка критичности уязвимостей по CVSS.
      - Реагирование: имитация блокировки IP-адресов с наибольшим числом
        алертов, вывод предупреждений об опасных уязвимостях.
      - Сохранение результатов: сводный отчёт в формате JSON и CSV,
        график (PNG) с визуализацией угроз.

Как запустить:
    python threat_monitor.py
"""

import json
import os
import pandas as pd
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Источник 1: логи Suricata
# ---------------------------------------------------------------------------

def load_suricata_logs(path):
    """Загрузка логов Suricata из JSON-файла."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_suricata(events):
    """Разбор событий Suricata на алерты и DNS-запросы."""
    alerts = []
    dns_queries = []

    for ev in events:
        if ev["event_type"] == "alert":
            alerts.append({
                "timestamp": ev["timestamp"],
                "src_ip": ev["src_ip"],
                "dest_ip": ev["dest_ip"],
                "dest_port": ev["dest_port"],
                "proto": ev["proto"],
                "signature": ev["alert"]["signature"],
                "severity": ev["alert"]["severity"],
                "category": ev["alert"]["category"],
            })
        elif ev["event_type"] == "dns":
            dns_queries.append({
                "timestamp": ev["timestamp"],
                "src_ip": ev["src_ip"],
                "query": ev["dns"]["query"],
            })

    return pd.DataFrame(alerts), pd.DataFrame(dns_queries)


# ---------------------------------------------------------------------------
# Источник 2: API Vulners (mock)
# ---------------------------------------------------------------------------

def get_vulners_mock():
    """Имитация ответа Vulners API -- список уязвимостей."""
    return [
        {"id": "CVE-2024-3094",  "title": "XZ Utils backdoor (liblzma)",
         "cvss": 10.0, "type": "cve", "published": "2024-03-29"},
        {"id": "CVE-2024-21762", "title": "Fortinet FortiOS Out-of-Bound Write",
         "cvss": 9.8,  "type": "cve", "published": "2024-02-09"},
        {"id": "CVE-2023-44228", "title": "Apache OFBiz SSRF to RCE",
         "cvss": 9.8,  "type": "cve", "published": "2023-12-05"},
        {"id": "CVE-2023-46805", "title": "Ivanti Connect Secure Auth Bypass",
         "cvss": 8.2,  "type": "cve", "published": "2024-01-10"},
        {"id": "CVE-2024-0204",  "title": "GoAnywhere MFT Auth Bypass",
         "cvss": 9.8,  "type": "cve", "published": "2024-01-22"},
        {"id": "CVE-2023-20198", "title": "Cisco IOS XE Web UI Privilege Escalation",
         "cvss": 10.0, "type": "cve", "published": "2023-10-16"},
        {"id": "CVE-2023-4966",  "title": "Citrix NetScaler Information Disclosure",
         "cvss": 7.5,  "type": "cve", "published": "2023-10-10"},
        {"id": "CVE-2024-1709",  "title": "ConnectWise ScreenConnect Auth Bypass",
         "cvss": 10.0, "type": "cve", "published": "2024-02-19"},
        {"id": "CVE-2023-36884", "title": "Microsoft Office HTML RCE",
         "cvss": 8.8,  "type": "cve", "published": "2023-07-11"},
        {"id": "CVE-2023-22515", "title": "Atlassian Confluence Broken Access Control",
         "cvss": 9.8,  "type": "cve", "published": "2023-10-04"},
    ]


# ---------------------------------------------------------------------------
# Анализ данных
# ---------------------------------------------------------------------------

def analyze_alerts(df_alerts):
    """Анализ алертов: топ IP-источников, распределение сигнатур."""
    top_src = df_alerts["src_ip"].value_counts().reset_index()
    top_src.columns = ["ip", "alert_count"]

    sig_dist = df_alerts["signature"].value_counts().reset_index()
    sig_dist.columns = ["signature", "count"]

    severity_dist = df_alerts["severity"].value_counts().sort_index().reset_index()
    severity_dist.columns = ["severity", "count"]

    return top_src, sig_dist, severity_dist


def analyze_dns(df_dns, threshold=3):
    """Определение подозрительных DNS-запросов (частые обращения)."""
    counts = df_dns.groupby(["src_ip", "query"]).size().reset_index(name="count")
    suspicious = counts[counts["count"] >= threshold]
    return suspicious


def analyze_vulners(vulns_data):
    """Анализ уязвимостей: выделение критичных (CVSS >= 9.0)."""
    df = pd.DataFrame(vulns_data)
    df_critical = df[df["cvss"] >= 9.0].sort_values("cvss", ascending=False)
    return df, df_critical


# ---------------------------------------------------------------------------
# Реагирование на угрозы
# ---------------------------------------------------------------------------

BLOCKED_IPS = []


def respond_to_threats(top_src, suspicious_dns, df_critical_vulns):
    """Имитация реагирования: блокировка IP, предупреждения."""
    print("\n" + "=" * 60)
    print("РЕАГИРОВАНИЕ НА УГРОЗЫ")
    print("=" * 60)

    # Блокировка IP с количеством алертов >= 3
    block_threshold = 3
    ips_to_block = top_src[top_src["alert_count"] >= block_threshold]["ip"].tolist()

    if ips_to_block:
        print(f"\n[BLOCK] IP-адреса с >= {block_threshold} алертами:")
        for ip in ips_to_block:
            count = top_src[top_src["ip"] == ip]["alert_count"].values[0]
            print(f"  -> iptables -A INPUT -s {ip} -j DROP   "
                  f"({count} алертов) -- ЗАБЛОКИРОВАН")
            BLOCKED_IPS.append(ip)
    else:
        print("\n[OK] Нет IP-адресов, требующих блокировки.")

    # Уведомления о подозрительных DNS
    if not suspicious_dns.empty:
        print(f"\n[ALERT] Подозрительная DNS-активность:")
        for _, row in suspicious_dns.iterrows():
            print(f"  -> {row['src_ip']} запросил {row['query']} "
                  f"x{row['count']} раз -- УВЕДОМЛЕНИЕ ОТПРАВЛЕНО")

    # Уведомления о критичных уязвимостях
    if not df_critical_vulns.empty:
        print(f"\n[VULN] Критичные уязвимости (CVSS >= 9.0):")
        for _, row in df_critical_vulns.iterrows():
            print(f"  -> {row['id']} (CVSS {row['cvss']}) "
                  f"{row['title']} -- ТРЕБУЕТ ПАТЧА")

    return ips_to_block


# ---------------------------------------------------------------------------
# Отчёт и визуализация
# ---------------------------------------------------------------------------

def save_report(top_src, sig_dist, suspicious_dns, df_vulns, blocked_ips):
    """Сохранение отчёта в JSON и CSV."""
    report = {
        "report_date": "2026-03-11",
        "summary": {
            "total_alerts": int(sig_dist["count"].sum()),
            "unique_signatures": len(sig_dist),
            "blocked_ips": blocked_ips,
            "suspicious_dns_pairs": len(suspicious_dns),
            "total_vulnerabilities": len(df_vulns),
            "critical_vulnerabilities": int(
                (df_vulns["cvss"] >= 9.0).sum()
            ),
        },
        "top_source_ips": top_src.to_dict(orient="records"),
        "signature_distribution": sig_dist.to_dict(orient="records"),
        "suspicious_dns": suspicious_dns.to_dict(orient="records"),
        "vulnerabilities": df_vulns.to_dict(orient="records"),
    }

    json_path = os.path.join(SCRIPT_DIR, "threat_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Отчёт JSON сохранён: {json_path}")

    csv_path = os.path.join(SCRIPT_DIR, "threat_report.csv")
    rows = []
    for _, r in top_src.iterrows():
        rows.append({
            "category": "alert_source_ip",
            "item": r["ip"],
            "value": r["alert_count"],
            "blocked": r["ip"] in blocked_ips,
        })
    for _, r in sig_dist.iterrows():
        rows.append({
            "category": "signature",
            "item": r["signature"],
            "value": r["count"],
            "blocked": False,
        })
    for _, r in df_vulns.iterrows():
        rows.append({
            "category": "vulnerability",
            "item": f"{r['id']} {r['title']}",
            "value": r["cvss"],
            "blocked": False,
        })
    pd.DataFrame(rows).to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[+] Отчёт CSV сохранён: {csv_path}")

    return report


def build_chart(sig_dist, df_vulns):
    """Построение графика: топ сигнатур и распределение CVSS."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # --- Левый график: топ-5 сигнатур ---
    top5 = sig_dist.head(5).copy()
    short = top5["signature"].str.extract(r"ET \w+ (.+)", expand=False)
    short = short.fillna(top5["signature"])
    colors_left = ["#d32f2f", "#e64a19", "#f57c00", "#fbc02d", "#8bc34a"]
    axes[0].barh(short[::-1], top5["count"].values[::-1],
                 color=colors_left[:len(top5)][::-1])
    axes[0].set_xlabel("Количество алертов")
    axes[0].set_title("Топ-5 сигнатур Suricata")
    for i, v in enumerate(top5["count"].values[::-1]):
        axes[0].text(v + 0.1, i, str(v), va="center", fontweight="bold")

    # --- Правый график: CVSS уязвимостей ---
    vulns_sorted = df_vulns.sort_values("cvss", ascending=True)
    bar_colors = []
    for c in vulns_sorted["cvss"]:
        if c >= 9.0:
            bar_colors.append("#d32f2f")
        elif c >= 7.0:
            bar_colors.append("#f57c00")
        else:
            bar_colors.append("#8bc34a")
    axes[1].barh(vulns_sorted["id"], vulns_sorted["cvss"], color=bar_colors)
    axes[1].set_xlabel("CVSS Score")
    axes[1].set_title("Уязвимости по CVSS-баллу")
    axes[1].axvline(x=9.0, color="red", linestyle="--", alpha=0.5,
                    label="Critical (9.0)")
    axes[1].legend()
    for i, v in enumerate(vulns_sorted["cvss"].values):
        axes[1].text(v + 0.05, i, str(v), va="center", fontsize=8)

    fig.suptitle("Отчёт об угрозах -- мониторинг ИБ", fontsize=14,
                 fontweight="bold")
    plt.tight_layout()

    png_path = os.path.join(SCRIPT_DIR, "threat_chart.png")
    plt.savefig(png_path, dpi=150)
    plt.close()
    print(f"[+] График сохранён: {png_path}")


# ---------------------------------------------------------------------------
# Главная функция
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ УГРОЗ")
    print("=" * 60)

    # --- Этап 1: Сбор данных ---
    print("\n[1/4] Сбор данных...")

    log_path = os.path.join(SCRIPT_DIR, "suricata_logs.json")
    print(f"  Источник 1: логи Suricata ({log_path})")
    events = load_suricata_logs(log_path)
    df_alerts, df_dns = parse_suricata(events)
    print(f"    Загружено алертов: {len(df_alerts)}")
    print(f"    Загружено DNS-запросов: {len(df_dns)}")

    print("  Источник 2: API Vulners (mock)")
    vulns_data = get_vulners_mock()
    print(f"    Получено уязвимостей: {len(vulns_data)}")

    # --- Этап 2: Анализ данных ---
    print("\n[2/4] Анализ данных...")

    top_src, sig_dist, severity_dist = analyze_alerts(df_alerts)
    print(f"  Уникальных IP-источников угроз: {len(top_src)}")
    print(f"  Уникальных сигнатур: {len(sig_dist)}")

    suspicious_dns = analyze_dns(df_dns, threshold=3)
    print(f"  Подозрительных DNS-пар (IP, домен): {len(suspicious_dns)}")

    df_vulns, df_critical_vulns = analyze_vulners(vulns_data)
    print(f"  Критичных уязвимостей (CVSS >= 9.0): {len(df_critical_vulns)}")

    # --- Этап 3: Реагирование ---
    print("\n[3/4] Реагирование на угрозы...")
    blocked_ips = respond_to_threats(top_src, suspicious_dns, df_critical_vulns)

    # --- Этап 4: Отчёт и визуализация ---
    print("\n[4/4] Формирование отчёта и визуализации...")
    save_report(top_src, sig_dist, suspicious_dns, df_vulns, blocked_ips)
    build_chart(sig_dist, df_vulns)

    print("\n" + "=" * 60)
    print("МОНИТОРИНГ ЗАВЕРШЁН")
    print("=" * 60)


if __name__ == "__main__":
    main()
