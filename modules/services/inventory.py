from __future__ import annotations
from typing import List, Tuple

def get_wargame_seed_items() -> List[Tuple[str, str, int, int]]:
    """
    Canonical Wargame baseline seed list.
    Each tuple is: (category_display_name, item_name, weight_lb, qty)
    Edit THIS list only.
    """
    return [
        ('emergency supplies', 'batteries', 10,  12),
        ('emergency supplies', 'batteries', 25,   8),
        ('food',               'beans',     25,  10),
        ('food',               'rice',      20,  10),
        ('medical supplies',   'bandages',   5,  20),
        ('water',              'water',     20,  20),
    ]
