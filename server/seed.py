"""
Seed Script - Nakuru County Referral and Teaching Hospital (NCRTH)
Populates realistic hospital network devices across all key clinical and administrative subnets.
"""

import os
import sys
import logging
from datetime import datetime, timezone

# Ensure server module can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import init_db, get_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mneti.seed")

# 24 Realistic Hospital Devices across 5 Subnets
HOSPITAL_DEVICES = [
    # ── 1. Pharmacy Subnet (10.100.10.0/24) ──
    {
        "ip": "10.100.10.11",
        "mac": "00:14:22:A1:B2:C1",
        "hostname": "NCRTH-PHARM-PC01",
        "building": "Outpatient Pavilion",
        "room": "Pharm-Dispense-101",
        "subnet": "10.100.10.0/24",
        "device_type": "managed",
        "vendor": "Dell Inc.",
        "logged_in_user": "pharm_tech_otieno"
    },
    {
        "ip": "10.100.10.12",
        "mac": "00:14:22:A1:B2:C2",
        "hostname": "NCRTH-PHARM-PC02",
        "building": "Outpatient Pavilion",
        "room": "Pharm-Dispense-102",
        "subnet": "10.100.10.0/24",
        "device_type": "managed",
        "vendor": "Dell Inc.",
        "logged_in_user": "dr_wanjiku_pharm"
    },
    {
        "ip": "10.100.10.20",
        "mac": "54:EE:75:33:44:11",
        "hostname": "PHARM-INVENTORY-SRV",
        "building": "Outpatient Pavilion",
        "room": "Pharm-Store-105",
        "subnet": "10.100.10.0/24",
        "device_type": "managed",
        "vendor": "HP Enterprise",
        "logged_in_user": "srv_pharm_admin"
    },
    {
        "ip": "10.100.10.45",
        "mac": "00:07:4D:88:99:AA",
        "hostname": "ZEBRA-LABEL-PRN01",
        "building": "Outpatient Pavilion",
        "room": "Pharm-Dispense-101",
        "subnet": "10.100.10.0/24",
        "device_type": "unmanaged",
        "vendor": "Zebra Technologies",
        "logged_in_user": ""
    },

    # ── 2. Radiology & Imaging Subnet (10.100.20.0/24) ──
    {
        "ip": "10.100.20.15",
        "mac": "00:1B:78:44:55:66",
        "hostname": "NCRTH-MRI-CONSOLE",
        "building": "Imaging Center",
        "room": "MRI-Suite-B01",
        "subnet": "10.100.20.0/24",
        "device_type": "managed",
        "vendor": "Siemens Healthineers",
        "logged_in_user": "rad_operator_kamau"
    },
    {
        "ip": "10.100.20.16",
        "mac": "00:1B:78:77:88:99",
        "hostname": "NCRTH-CT-ACQUISITION",
        "building": "Imaging Center",
        "room": "CT-Scan-B02",
        "subnet": "10.100.20.0/24",
        "device_type": "managed",
        "vendor": "GE Healthcare",
        "logged_in_user": "ct_specialist_chebet"
    },
    {
        "ip": "10.100.20.25",
        "mac": "3C:D9:2B:12:34:56",
        "hostname": "PACS-DIAGNOSTIC-WS1",
        "building": "Imaging Center",
        "room": "Reading-Room-B05",
        "subnet": "10.100.20.0/24",
        "device_type": "managed",
        "vendor": "Barco / HP",
        "logged_in_user": "dr_mutua_radiology"
    },
    {
        "ip": "10.100.20.50",
        "mac": "00:50:56:AB:CD:01",
        "hostname": "DICOM-ARCHIVE-GW",
        "building": "Imaging Center",
        "room": "Server-Closet-B",
        "subnet": "10.100.20.0/24",
        "device_type": "unmanaged",
        "vendor": "VMware / Philips",
        "logged_in_user": ""
    },
    {
        "ip": "10.100.20.90",
        "mac": "B4:B5:2F:90:11:22",
        "hostname": "ULTRASOUND-PORTABLE-1",
        "building": "Imaging Center",
        "room": "US-Exam-B03",
        "subnet": "10.100.20.0/24",
        "device_type": "unmanaged",
        "vendor": "Mindray Medical",
        "logged_in_user": ""
    },

    # ── 3. Laboratory & Pathology Subnet (10.100.30.0/24) ──
    {
        "ip": "10.100.30.10",
        "mac": "00:09:0F:33:66:99",
        "hostname": "HEMATOLOGY-ANALYZER-01",
        "building": "Pathology Wing",
        "room": "Main-Lab-201",
        "subnet": "10.100.30.0/24",
        "device_type": "unmanaged",
        "vendor": "Sysmex Corporation",
        "logged_in_user": ""
    },
    {
        "ip": "10.100.30.11",
        "mac": "00:1E:67:88:12:34",
        "hostname": "NCRTH-LAB-CHEM-WS",
        "building": "Pathology Wing",
        "room": "BioChem-204",
        "subnet": "10.100.30.0/24",
        "device_type": "managed",
        "vendor": "Lenovo ThinkCentre",
        "logged_in_user": "lab_tech_kipchumba"
    },
    {
        "ip": "10.100.30.22",
        "mac": "00:1E:67:88:12:35",
        "hostname": "LAB-RESULTS-ENTRY-02",
        "building": "Pathology Wing",
        "room": "Main-Lab-202",
        "subnet": "10.100.30.0/24",
        "device_type": "managed",
        "vendor": "Lenovo ThinkCentre",
        "logged_in_user": "lab_intern_mercy"
    },
    {
        "ip": "10.100.30.33",
        "mac": "00:80:A3:AA:BB:CC",
        "hostname": "ROCHE-COBAS-INTERFACE",
        "building": "Pathology Wing",
        "room": "Immuno-Lab-206",
        "subnet": "10.100.30.0/24",
        "device_type": "unmanaged",
        "vendor": "Roche Diagnostics",
        "logged_in_user": ""
    },

    # ── 4. Triage, Casualty & ER Subnet (10.100.40.0/24) ──
    {
        "ip": "10.100.40.10",
        "mac": "00:1A:2B:3C:4D:5E",
        "hostname": "NCRTH-TRIAGE-ADMIT01",
        "building": "Casualty Block",
        "room": "ER-Triage-Desk",
        "subnet": "10.100.40.0/24",
        "device_type": "managed",
        "vendor": "HP EliteDesk",
        "logged_in_user": "nurse_officer_njeri"
    },
    {
        "ip": "10.100.40.11",
        "mac": "00:1A:2B:3C:4D:5F",
        "hostname": "NCRTH-TRIAGE-ADMIT02",
        "building": "Casualty Block",
        "room": "ER-Triage-Desk",
        "subnet": "10.100.40.0/24",
        "device_type": "managed",
        "vendor": "HP EliteDesk",
        "logged_in_user": "clerk_omondi"
    },
    {
        "ip": "10.100.40.15",
        "mac": "00:03:7F:11:22:33",
        "hostname": "VITALS-MONITOR-BED01",
        "building": "Casualty Block",
        "room": "ER-Resus-Bay1",
        "subnet": "10.100.40.0/24",
        "device_type": "unmanaged",
        "vendor": "Philips Healthcare",
        "logged_in_user": ""
    },
    {
        "ip": "10.100.40.21",
        "mac": "00:1A:2B:99:88:77",
        "hostname": "MOBILE-TRAUMA-CART",
        "building": "Casualty Block",
        "room": "ER-Trauma-Bay2",
        "subnet": "10.100.40.0/24",
        "device_type": "managed",
        "vendor": "Dell Latitude Rugged",
        "logged_in_user": "dr_korir_er"
    },
    {
        "ip": "10.100.40.88",
        "mac": "AC:CC:8E:55:66:77",
        "hostname": "ER-SECURITY-BADGE-SCAN",
        "building": "Casualty Block",
        "room": "ER-Entrance-Gate",
        "subnet": "10.100.40.0/24",
        "device_type": "unmanaged",
        "vendor": "Hikvision / Axis",
        "logged_in_user": ""
    },

    # ── 5. Administration, Billing & Records Subnet (10.100.50.0/24) ──
    {
        "ip": "10.100.50.12",
        "mac": "18:66:DA:11:22:33",
        "hostname": "NCRTH-BILLING-PC01",
        "building": "Admin Block",
        "room": "Finance-301",
        "subnet": "10.100.50.0/24",
        "device_type": "managed",
        "vendor": "Dell OptiPlex",
        "logged_in_user": "accountant_maina"
    },
    {
        "ip": "10.100.50.13",
        "mac": "18:66:DA:11:22:34",
        "hostname": "NCRTH-BILLING-PC02",
        "building": "Admin Block",
        "room": "Finance-302",
        "subnet": "10.100.50.0/24",
        "device_type": "managed",
        "vendor": "Dell OptiPlex",
        "logged_in_user": "cashier_akinyi"
    },
    {
        "ip": "10.100.50.14",
        "mac": "18:66:DA:44:55:66",
        "hostname": "RECORDS-ARCHIVAL-WS",
        "building": "Admin Block",
        "room": "Health-Records-305",
        "subnet": "10.100.50.0/24",
        "device_type": "managed",
        "vendor": "Dell OptiPlex",
        "logged_in_user": "records_officer_muthoni"
    },
    {
        "ip": "10.100.50.25",
        "mac": "A4:BB:6D:77:88:99",
        "hostname": "MED-SUPERINTENDENT-PC",
        "building": "Admin Block",
        "room": "Executive-Suite-310",
        "subnet": "10.100.50.0/24",
        "device_type": "managed",
        "vendor": "Apple Inc. (Mac mini)",
        "logged_in_user": "dr_mwangi_medsup"
    },
    {
        "ip": "10.100.50.99",
        "mac": "00:23:7D:66:55:44",
        "hostname": "HP-LASERJET-FINANCE",
        "building": "Admin Block",
        "room": "Finance-Printing-Hub",
        "subnet": "10.100.50.0/24",
        "device_type": "unmanaged",
        "vendor": "HP Inc.",
        "logged_in_user": ""
    }
]


def seed_database(db_path: str = None) -> None:
    init_db(db_path)
    conn = get_db(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    with conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM devices;")
        cursor.execute("DELETE FROM ip_history;")

        for dev in HOSPITAL_DEVICES:
            cursor.execute("""
                INSERT INTO devices (
                    ip, mac, hostname, building, room, subnet, 
                    device_type, status, vendor, logged_in_user, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?);
            """, (
                dev["ip"],
                dev["mac"],
                dev["hostname"],
                dev["building"],
                dev["room"],
                dev["subnet"],
                dev["device_type"],
                dev["vendor"],
                dev["logged_in_user"],
                now_str
            ))

            cursor.execute("""
                INSERT INTO ip_history (ip, mac, timestamp, is_conflict, details)
                VALUES (?, ?, ?, 0, 'Baseline Inventory Seed');
            """, (dev["ip"], dev["mac"], now_str))

    conn.close()
    log.info("Successfully seeded database with %d NCRTH hospital devices across 5 subnets.", len(HOSPITAL_DEVICES))


if __name__ == "__main__":
    seed_database()
