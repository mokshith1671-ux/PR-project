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

with open("output.json", "w") as f:
    json.dump(events, f, indent=2)

print(f"✅ Raw events captured: {len(events)}")