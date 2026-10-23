"""
Mock parts database. Pure Python — no LLM call, no flags in here. Powers
the part cards in the UI via /api/parts/search in main.py.

NOTE: I made this data up — the original arcanumsec/AutoPartsCTF fork's
actual catalog wasn't available to me, so the specific part names/numbers
below are placeholders. Swap them for anything that fits your event's
"auto parts" framing; nothing else in the app depends on these exact
values.
"""

PARTS = [
    {"id": "BRK-2201", "name": "Ceramic Brake Pad Set", "category": "Brakes",
     "price": 42.99, "stock": 34, "notes": "Fits most compact sedans, 2015-2022."},
    {"id": "BRK-2202", "name": "Slotted Brake Rotor", "category": "Brakes",
     "price": 61.50, "stock": 12, "notes": "Pair with BRK-2201 for best bite."},
    {"id": "ENG-3110", "name": "Timing Belt Kit", "category": "Engine",
     "price": 118.00, "stock": 7, "notes": "Includes tensioner and idler pulley."},
    {"id": "ENG-3115", "name": "Spark Plug (Iridium)", "category": "Engine",
     "price": 9.75, "stock": 200, "notes": "Sold individually; most engines need 4."},
    {"id": "SUS-4402", "name": "Front Strut Assembly", "category": "Suspension",
     "price": 89.20, "stock": 18, "notes": "Pre-assembled, no spring compressor needed."},
    {"id": "ELE-5501", "name": "Alternator, 120A", "category": "Electrical",
     "price": 143.40, "stock": 9, "notes": "Remanufactured, 2yr warranty."},
    {"id": "FIL-6001", "name": "Cabin Air Filter", "category": "Filters",
     "price": 14.30, "stock": 75, "notes": "Replace every 12k miles."},
    {"id": "FIL-6002", "name": "Oil Filter, Spin-on", "category": "Filters",
     "price": 6.99, "stock": 150, "notes": "Standard 3/4-16 thread."},
]


def search_parts(query: str):
    """Simple case-insensitive substring match over name/category/id.
    Deliberately synchronous and boring — this endpoint exists purely to
    populate the UI's part cards and has nothing to do with the LLM
    vulnerability surface (see chains.py for that)."""
    q = (query or "").strip().lower()
    if not q:
        return PARTS
    return [
        p for p in PARTS
        if q in p["name"].lower() or q in p["category"].lower() or q in p["id"].lower()
    ]
