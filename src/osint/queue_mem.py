from collections import deque
class MemQueue:
    def __init__(self): self.q = deque()
    def push(self, item): self.q.append(item)
    def pop(self): return self.q.popleft() if self.q else None
    def __len__(self): return len(self.q)
