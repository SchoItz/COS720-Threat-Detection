import os
import json
import random
import numpy as np
import pandas as pd

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "sample_demo_data.csv")
PROFILES_JSON = os.path.join(OUTPUT_DIR, "sample_profiles.json")

DEPARTMENTS = ["R&D", "Engineering", "Finance", "Operations", "HR", "IT", "Legal"]
CLEARANCE_LEVELS = ["Level 1", "Level 2", "Level 3", "Level 4", "Level 5"]
CONTRACTOR_STATUS = ["Permanent", "Contractor"]


# ── Sample Profiles for the Web Interface ───────────────────────────────────
SAMPLE_PROFILES = [
    {
        "id": 1,
        "name": "Francois Scholtz",
        "title": "Normal Employee – Standard Activity",
        "description": "Senior R&D researcher with 10 years tenure. Regular working hours, standard file handling.",
        "icon": "shield-check",
        "badge": "Normal",
        "data": {
            "employee_seniority_years": 10,
            "total_files_burned": 2,
            "burned_from_other": 0,
            "num_printed_pages_off_hours": 0,
            "total_printed_pages": 8,
            "num_entries": 2,
            "late_exit_flag": 0,
            "entry_during_weekend": 0,
            "trip_day_number": 0,
            "hostility_country_level": 1,
            "has_criminal_record": 0,
            "employee_department": "R&D",
            "employee_classification": "Level 3",
            "is_contractor": 0,
        },
    },
    {
        "id": 2,
        "name": "Friedrich Lauchner",
        "title": "Suspicious Activity – Borderline Case",
        "description": "Mid-level engineer recently returned from business travel. Slightly elevated printing.",
        "icon": "exclamation-triangle",
        "badge": "Borderline",
        "data": {
            "employee_seniority_years": 5,
            "total_files_burned": 3,
            "burned_from_other": 2,
            "num_printed_pages_off_hours": 3,
            "total_printed_pages": 8,
            "num_entries": 2,
            "late_exit_flag": 0,
            "entry_during_weekend": 1,
            "trip_day_number": 7,
            "hostility_country_level": 2,
            "has_criminal_record": 0,
            "employee_department": "Engineering",
            "employee_classification": "Level 2",
            "is_contractor": 0,
        },
    },
    {
        "id": 3,
        "name": "Alden Peach",
        "title": "High-Risk – Clear Malicious Indicators",
        "description": "High-clearance contractor with massive data exfiltration signals. Multiple red flags.",
        "icon": "shield-exclamation",
        "badge": "Malicious",
        "data": {
            "employee_seniority_years": 3,
            "total_files_burned": 87,
            "burned_from_other": 42,
            "num_printed_pages_off_hours": 145,
            "total_printed_pages": 320,
            "num_entries": 12,
            "late_exit_flag": 3,
            "entry_during_weekend": 2,
            "trip_day_number": 21,
            "hostility_country_level": 4,
            "has_criminal_record": 1,
            "employee_department": "Finance",
            "employee_classification": "Level 5",
            "is_contractor": 1,
        },
    },
    {
        "id": 4,
        "name": "Gelen Myburgh",
        "title": "False Positive Risk – Authorised Heavy Usage",
        "description": "Senior Finance executive preparing board materials. Moderate file and print activity flagged borderline by the model.",
        "icon": "person-badge",
        "badge": "Borderline",
        "data": {
            "employee_seniority_years": 20,
            "total_files_burned": 7,
            "burned_from_other": 1,
            "num_printed_pages_off_hours": 7,
            "total_printed_pages": 25,
            "num_entries": 2,
            "late_exit_flag": 0,
            "entry_during_weekend": 0,
            "trip_day_number": 2,
            "hostility_country_level": 1,
            "has_criminal_record": 0,

            "employee_department": "Finance",
            "employee_classification": "Level 4",
            "is_contractor": 0,
        },
    },
    {
        "id": 5,
        "name": "Hendre Beyer",
        "title": "IT Contractor – Elevated Access Flags",
        "description": "IT contractor with weekend access and off-hours system work. Pattern warrants review.",
        "icon": "laptop",
        "badge": "Suspicious",
        "data": {
            "employee_seniority_years": 2,
            "total_files_burned": 3,
            "burned_from_other": 1,
            "num_printed_pages_off_hours": 5,
            "total_printed_pages": 15,
            "num_entries": 3,
            "late_exit_flag": 1,
            "entry_during_weekend": 1,
            "trip_day_number": 0,
            "hostility_country_level": 1,
            "has_criminal_record": 0,
            "employee_department": "IT",
            "employee_classification": "Level 3",
            "is_contractor": 1,
        },
    },
]


def generate_synthetic_dataset(n_normal: int = 1000, n_malicious: int = 57) -> pd.DataFrame:
   
    records = []

    for _ in range(n_normal):
        records.append({
            "seniority_level": np.random.randint(0, 32),
            "total_files_burned": max(0, int(np.random.exponential(9))),
            "burned_from_other": max(0, int(np.random.exponential(2))),
            "num_printed_pages_off_hours": max(0, int(np.random.exponential(1.5))),
            "total_printed_pages": max(0, int(np.random.normal(13, 10))),
            "building_entries": max(1, int(np.random.normal(3, 1))),
            "late_exit": int(np.random.choice([0, 1], p=[0.85, 0.15])),
            "weekend_entry": int(np.random.choice([0, 1], p=[0.90, 0.10])),
            "trip_duration": max(0, int(np.random.exponential(1))),
            "country_risk_level": int(np.random.choice([1, 2, 3, 4], p=[0.60, 0.25, 0.10, 0.05])),
            "department": random.choice(DEPARTMENTS),
            "clearance_level": random.choice(CLEARANCE_LEVELS[:3]),
            "contractor_status": random.choice(["Permanent", "Permanent", "Contractor"]),
            "is_malicious": 0,
        })

    for _ in range(n_malicious):
        records.append({
            "seniority_level": np.random.randint(0, 20),
            "total_files_burned": max(20, int(np.random.exponential(60))),
            "burned_from_other": max(5, int(np.random.exponential(35))),
            "num_printed_pages_off_hours": max(10, int(np.random.exponential(80))),
            "total_printed_pages": max(50, int(np.random.normal(200, 80))),
            "building_entries": max(5, int(np.random.normal(10, 3))),
            "late_exit": int(np.random.choice([0, 1], p=[0.30, 0.70])),
            "weekend_entry": int(np.random.choice([0, 1], p=[0.40, 0.60])),
            "trip_duration": max(5, int(np.random.exponential(15))),
            "country_risk_level": int(np.random.choice([1, 2, 3, 4], p=[0.15, 0.25, 0.30, 0.30])),
            "department": random.choice(["Finance", "R&D", "Engineering", "IT"]),
            "clearance_level": random.choice(CLEARANCE_LEVELS[2:]),
            "contractor_status": random.choice(["Contractor", "Contractor", "Permanent"]),
            "is_malicious": 1,
        })

    df = pd.DataFrame(records).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    return df


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[INFO] Generating synthetic demo dataset...")
    df = generate_synthetic_dataset(n_normal=1000, n_malicious=57)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"[INFO] Synthetic dataset saved to {OUTPUT_CSV}")
    print(f"[INFO] Records: {len(df)} total "
          f"({df['is_malicious'].sum()} malicious, "
          f"{(df['is_malicious'] == 0).sum()} normal)")

    with open(PROFILES_JSON, "w") as f:
        json.dump(SAMPLE_PROFILES, f, indent=2)
    print(f"[INFO] Sample profiles saved to {PROFILES_JSON}")
    print("[DONE]")
