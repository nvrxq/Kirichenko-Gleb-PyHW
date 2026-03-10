"""
Домашнее задание Д13
Тема: Управление системами и ресурсами защиты информации с помощью Python
Взаимодействие с API VirusTotal для проверки файлов/хешей (mock-режим)

Как запустить:
    python virustotal_check.py
    python virustotal_check.py <sha256_hash>
"""

import json
import sys
import os

VT_BASE_URL = "https://www.virustotal.com/api/v3"

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def get_mock_response(file_hash):
    """Имитация ответа VirusTotal API"""
    return {
        "data": {
            "id": file_hash,
            "type": "file",
            "attributes": {
                "sha256": file_hash,
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "size": 68,
                "type_description": "Text",
                "names": ["eicar.com", "eicar_test_file", "EICAR.txt"],
                "last_analysis_date": 1709500800,
                "last_analysis_stats": {
                    "malicious": 55,
                    "suspicious": 0,
                    "undetected": 6,
                    "harmless": 0,
                    "timeout": 1,
                    "type-unsupported": 7,
                    "failure": 0
                },
                "last_analysis_results": {
                    "Kaspersky": {
                        "category": "malicious",
                        "engine_name": "Kaspersky",
                        "result": "EICAR-Test-File"
                    },
                    "DrWeb": {
                        "category": "malicious",
                        "engine_name": "DrWeb",
                        "result": "EICAR Test File (NOT a Virus!)"
                    },
                    "Avast": {
                        "category": "malicious",
                        "engine_name": "Avast",
                        "result": "EICAR Test-NOT virus!!!"
                    },
                    "ESET-NOD32": {
                        "category": "malicious",
                        "engine_name": "ESET-NOD32",
                        "result": "Eicar test file"
                    },
                    "BitDefender": {
                        "category": "malicious",
                        "engine_name": "BitDefender",
                        "result": "EICAR-Test-File (not a virus)"
                    },
                    "McAfee": {
                        "category": "malicious",
                        "engine_name": "McAfee",
                        "result": "EICAR test file"
                    },
                    "Symantec": {
                        "category": "malicious",
                        "engine_name": "Symantec",
                        "result": "EICAR Test String"
                    },
                    "ClamAV": {
                        "category": "malicious",
                        "engine_name": "ClamAV",
                        "result": "Win.Test.EICAR_HDB-1"
                    }
                },
                "reputation": -962,
                "tags": ["text", "eicar"]
            }
        }
    }


def parse_results(data):
    attrs = data.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТ ПРОВЕРКИ")
    print("=" * 60)

    names = attrs.get("names", [])
    if names:
        print(f"  Имена файла: {', '.join(names[:5])}")

    print(f"  Тип: {attrs.get('type_description', 'N/A')}")
    print(f"  Размер: {attrs.get('size', 0)} байт")
    print(f"  SHA-256: {attrs.get('sha256', 'N/A')}")

    print(f"\n  Антивирусов проверило: {total}")
    print(f"  Обнаружили как вредоносный: {malicious}")
    print(f"  Подозрительный: {suspicious}")
    print(f"  Не обнаружили: {undetected}")

    if malicious > 0:
        print(f"\n  [!!!] ВЕРДИКТ: ВРЕДОНОСНЫЙ ({malicious}/{total})")
    elif suspicious > 0:
        print(f"\n  [?] ВЕРДИКТ: ПОДОЗРИТЕЛЬНЫЙ ({suspicious}/{total})")
    else:
        print(f"\n  [OK] ВЕРДИКТ: ЧИСТЫЙ")

    results = attrs.get("last_analysis_results", {})
    detections = {name: info for name, info in results.items()
                  if info.get("category") == "malicious"}

    if detections:
        print("\n  Обнаружения антивирусов:")
        print("  " + "-" * 50)
        for av_name, info in list(detections.items())[:10]:
            print(f"    {av_name:<25} {info.get('result', 'N/A')}")
        if len(detections) > 10:
            print(f"    ... и ещё {len(detections) - 10}")

    return stats


def save_json(data, filename):
    output_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(output_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n[+] JSON-ответ сохранён: {filepath}")


def main():
    if len(sys.argv) > 1:
        file_hash = sys.argv[1]
    else:
        print("[*] Хеш не указан, используем тестовый EICAR-файл")
        file_hash = EICAR_SHA256

    print(f"[*] Mock-запрос к VirusTotal API: {VT_BASE_URL}/files/{file_hash}")
    data = get_mock_response(file_hash)

    parse_results(data)
    save_json(data, "vt_response.json")

    print("\n[*] Готово.")


if __name__ == '__main__':
    main()
