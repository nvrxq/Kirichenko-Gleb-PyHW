import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

with open("events.json", "r") as f:
    data = json.load(f)

df = pd.DataFrame(data["events"])
df["timestamp"] = pd.to_datetime(df["timestamp"])

print(f"Всего событий: {len(df)}")
print(f"Период: {df['timestamp'].min()} — {df['timestamp'].max()}")
print(f"\nУникальных сигнатур: {df['signature'].nunique()}")
print(f"\nРаспределение по типам:")
print(df["signature"].value_counts().to_string())

# Сокращаем названия для читаемости на графике
short_names = {sig: sig.split(" ")[0] + " " + " ".join(sig.split(" ")[1:3])
               for sig in df["signature"].unique()}
df["short_sig"] = df["signature"].map(short_names)

sig_counts = df["short_sig"].value_counts()

plt.figure(figsize=(12, 6))
sns.barplot(x=sig_counts.values, y=sig_counts.index, hue=sig_counts.index,
            palette="YlOrRd_r", legend=False)
plt.title("Распределение событий ИБ по типам сигнатур")
plt.xlabel("Количество событий")
plt.ylabel("")
plt.tight_layout()
plt.savefig("events_distribution.png", dpi=150)
plt.show()
