from database import get_all_attacks, get_all_attackers, get_total_count

print("\n" + "=" * 60)
print(f"  NEMESIS — Total Attacks: {get_total_count()}")
print("=" * 60)

print("\n--- ALL ATTACKS ---")
print(f"{'ID':<5} {'Time':<22} {'Service':<10} {'IP':<15} Data")
print("-" * 70)
for row in get_all_attacks():
    print(f"{row[0]:<5} {row[1]:<22} {row[2]:<10} {row[3]:<15} {row[4][:30]}")

print("\n--- ALL ATTACKERS ---")
print(f"{'ID':<5} {'IP':<15} {'First Seen':<22} {'Last Seen':<22} {'Total'}")
print("-" * 70)
for row in get_all_attackers():
    print(f"{row[0]:<5} {row[1]:<15} {row[2]:<22} {row[3]:<22} {row[4]}")
