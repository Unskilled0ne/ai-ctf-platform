"""
Mock employee database used by the intentionally-vulnerable IDOR endpoint
(GET /api/employees/{id} in main.py — no auth check, no ownership check,
just an integer lookup). The intended solve path is enumerating IDs
against the *running app*, so — matching the README's note that IDOR and
WebSocket flags are left un-obfuscated — the flag base secret below is
plain text, not run through flag_crypto.shroud().

Employee IDs 1-4 are "normal" filler PII (fake, not real people) so the
IDOR bug has something mundane to find before hitting the interesting
record. Employee 1337 is the intended target.
"""

EMPLOYEES = {
    1: {"id": 1, "name": "Dana Koutris", "role": "Parts Counter", "email": "d.koutris@example-motors.test"},
    2: {"id": 2, "name": "Marios Iliou", "role": "Shop Foreman", "email": "m.iliou@example-motors.test"},
    3: {"id": 3, "name": "Elena Vardaki", "role": "Inventory Lead", "email": "e.vardaki@example-motors.test"},
    4: {"id": 4, "name": "Petros Nomikos", "role": "Sales", "email": "p.nomikos@example-motors.test"},
   
    1337: {
        "id": 1337,
        "name": "NGDSA Security Team",
        "role": "internal-debug-account",
        "email": "do-not-use@example-motors.test",
        "notes_base_secret": "idor-breach-base",
    },
}


def get_employee(employee_id: int):
    return EMPLOYEES.get(employee_id)
