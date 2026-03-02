import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

with open("botsv1.json", "r") as f:
    raw = json.load(f)

records = [r["result"] for r in raw]

# разделяем на WinEventLog и DNS
win_df = pd.DataFrame([r for r in records if r.get("LogName") == "Security"])
dns_df = pd.DataFrame([r for r in records if r.get("LogName") == "DNS"])

print(f"WinEventLog записей: {len(win_df)}")
print(f"DNS записей: {len(dns_df)}")

# подозрительные EventID:
# 4625 - неудачный вход, 4672 - спец. привилегии, 4703 - эскалация привилегий
# 4656 - доступ к объекту, 4624 - вход, 4720 - создание учётки, 4732 - добавление в группу
suspicious_event_codes = {"4625", "4672", "4703", "4656", "4624", "4720", "4732"}

win_df["suspicious"] = win_df["EventCode"].isin(suspicious_event_codes)
suspicious_win = win_df[win_df["suspicious"]].copy()

print(f"\nПодозрительных WinEventLog: {len(suspicious_win)}")
print("Распределение по EventCode:")
print(suspicious_win["EventCode"].value_counts().to_string())

event_descriptions = {
    "4624": "4624 - Вход в систему",
    "4625": "4625 - Неудачный вход",
    "4656": "4656 - Доступ к объекту",
    "4672": "4672 - Спец. привилегии",
    "4703": "4703 - Эскалация привилегий",
    "4720": "4720 - Создание учётной записи",
    "4732": "4732 - Добавление в группу",
}
suspicious_win["event_desc"] = suspicious_win["EventCode"].map(event_descriptions)

# DNS: ищем подозрительные домены (DGA-подобные, C2-паттерны)
def is_suspicious_domain(domain):
    if any(word in domain.lower() for word in ["malicious", "c2", "evil", "botnet"]):
        return True
    # DGA: рандомное имя с цифрами
    name = domain.split(".")[0]
    if len(name) > 6 and sum(c.isdigit() for c in name) >= 2:
        return True
    return False

dns_df["suspicious"] = dns_df["QueryName"].apply(is_suspicious_domain)
suspicious_dns = dns_df[dns_df["suspicious"]].copy()

print(f"\nПодозрительных DNS-запросов: {len(suspicious_dns)}")
for _, row in suspicious_dns.iterrows():
    print(f"  {row['QueryName']} (тип: {row.get('QueryType', '?')})")

# собираем всё вместе и строим топ-10
win_counts = suspicious_win["event_desc"].value_counts().reset_index()
win_counts.columns = ["event", "count"]

dns_counts = suspicious_dns["QueryName"].value_counts().reset_index()
dns_counts.columns = ["event", "count"]
dns_counts["event"] = "DNS: " + dns_counts["event"]

all_suspicious = pd.concat([win_counts, dns_counts], ignore_index=True)
all_suspicious = all_suspicious.sort_values("count", ascending=False).head(10)

print(f"\nТоп-10 подозрительных событий:")
print(all_suspicious.to_string(index=False))

fig, ax = plt.subplots(figsize=(12, 6))
sns.barplot(data=all_suspicious, x="count", y="event", hue="event",
            palette="Reds_r", legend=False, ax=ax)
ax.set_title("Топ-10 подозрительных событий (WinEventLog + DNS)")
ax.set_xlabel("Количество")
ax.set_ylabel("")

for i, v in enumerate(all_suspicious["count"]):
    ax.text(v + 0.1, i, str(v), va="center")

plt.tight_layout()
plt.savefig("suspicious_events.png", dpi=150)
plt.show()
print("\nГрафик сохранён в suspicious_events.png")
