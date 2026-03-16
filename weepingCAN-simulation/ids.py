# General dependencies 
import time
import math
from collections import defaultdict, deque, Counter

# --- Simple IDS ---
class SimpleCANIDS:

    def __init__(
        self,
        window_s: float = 120.0,
        min_collisions: int = 3,
    ):
        self.window_s = window_s
        self.min_collisions = min_collisions

# TO DO: IMPLEMENTATION #
       