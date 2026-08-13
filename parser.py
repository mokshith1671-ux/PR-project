import json

events = []

with open("output.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()

        try:
            obj = json.loads(line)
            events.append(obj)
        except:
            continue

with open("output.json", "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2)

print(f"[OK] Raw events captured: {len(events)}")