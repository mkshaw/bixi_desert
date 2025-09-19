import os, sys, csv, json, hmac, hashlib
from datetime import datetime, timezone
import requests

STATION_STATUS_URL = "https://gbfs.velobixi.com/gbfs/2-2/en/station_status.json"
OUT_CSV = "results.csv"

SECRET_SALT = os.environ.get("SECRET_SALT", "local-default-salt-change-me")

FIELDS = [
    "station_id_pseudo",  # pseudonymous id
    "num_bikes_available",
    "num_ebikes_available",
    "vehicle_types_available",
    "num_bikes_disabled",
    "num_docks_available",
    "num_docks_disabled",
    "is_installed",
    "is_renting",
    "is_returning",
    "last_reported",
    "eightd_has_available_keys",
    "is_charging",
    "eightd_active_station_services",
    "fetch_time_utc",
]

def fetch(url: str) -> dict:
    r = requests.get(url, timeout=20)
    r.raise_for_status()
    return r.json()

def get_station_id() -> str:
    sid = os.environ.get("STATION_ID", "").strip()
    if not sid:
        print("[error] STATION_ID env var is not set.")
        sys.exit(0)  # exit 0 so the workflow doesn't fail
    return sid

def to_iso_from_epoch(epoch):
    if epoch in (None, 0, "0"):
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None

def to_json_cell(value):
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return value

def pseudonymize_station_id(real_id: str) -> str:
    mac = hmac.new(SECRET_SALT.encode(), real_id.encode(), hashlib.sha256).hexdigest()
    return f"id_{mac[:12]}"

def main():
  
    station_id = get_station_id()

    station_data = fetch(STATION_STATUS_URL)
    stations = station_data["data"]["stations"]

    rec = next((s for s in stations if s.get("station_id") == station_id), None)
    if rec is None:
        print("[warn] target station not found in feed; skipping.")
        sys.exit(0)

    row = {
        "station_id_pseudo": pseudonymize_station_id(station_id),
        "num_bikes_available": rec.get("num_bikes_available"),
        "num_ebikes_available": rec.get("num_ebikes_available"),
        "vehicle_types_available": to_json_cell(rec.get("vehicle_types_available")),
        "num_bikes_disabled": rec.get("num_bikes_disabled"),
        "num_docks_available": rec.get("num_docks_available"),
        "num_docks_disabled": rec.get("num_docks_disabled"),
        "is_installed": rec.get("is_installed"),
        "is_renting": rec.get("is_renting"),
        "is_returning": rec.get("is_returning"),
        "last_reported": to_iso_from_epoch(rec.get("last_reported")),
        "eightd_has_available_keys": rec.get("eightd_has_available_keys"),
        "is_charging": rec.get("is_charging"),
        "eightd_active_station_services": to_json_cell(rec.get("eightd_active_station_services")),
        "fetch_time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    write_header = not os.path.exists(OUT_CSV) or os.path.getsize(OUT_CSV) == 0
    with open(OUT_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if write_header:
            w.writeheader()
        w.writerow({k: row.get(k) for k in FIELDS})

    print(f"[ok] wrote status for station={row['station_id_pseudo']} at {row['fetch_time_utc']}")

if __name__ == "__main__":
    main()
