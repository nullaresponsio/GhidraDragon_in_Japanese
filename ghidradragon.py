import random

random.seed(20250525)  # pseudo random seed

ghidra_variants = ["ギドラ","ギイドラ","ぎどら","ＧＨＩＤＲＡ","ghidra"]
engine_variants = ["エンジン","エンジンエンジン","機関","機構"]
dragon_variants = ["ドラゴン","どらごん","竜","龍","ＤＲＡＧＯＮ"]
connector_variants = ["・","－","／","："]

for _ in range(10):
    gh = random.choice(ghidra_variants)
    eng = random.choice(engine_variants)
    dr = random.choice(dragon_variants)
    conn1 = random.choice(connector_variants)
    conn2 = random.choice(connector_variants)
    print(f"{gh}{conn1}{eng}{conn2}{dr}")
