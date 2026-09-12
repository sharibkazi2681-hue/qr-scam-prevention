"""
Script to view the SQLite database contents.
Run: python view_db.py
"""
import sqlite3

conn = sqlite3.connect('qr_scam.db')
c = conn.cursor()

print('=' * 60)
print('DATABASE TABLES:')
print('=' * 60)
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
for t in tables:
    print(f'  - {t[0]}')

print()
print('=' * 60)
print('TABLE: blacklisted_patterns (Known Scam Data)')
print('=' * 60)
c.execute('SELECT id, pattern_type, pattern_value, description, severity FROM blacklisted_patterns')
for row in c.fetchall():
    print(f'  ID:{row[0]} | Type:{row[1]} | Value:{row[2]} | Desc:{row[3]} | Severity:{row[4]}')

print()
print('=' * 60)
print('TABLE: whitelisted_patterns (Trusted Data)')
print('=' * 60)
c.execute('SELECT id, pattern_type, pattern_value, description FROM whitelisted_patterns')
for row in c.fetchall():
    print(f'  ID:{row[0]} | Type:{row[1]} | Value:{row[2]} | Desc:{row[3]}')

print()
print('=' * 60)
print('TABLE: scan_history (Scan Records)')
print('=' * 60)
c.execute('SELECT id, scan_date, data_type, qr_data, fraud_score, risk_level FROM scan_history')
rows = c.fetchall()
if rows:
    for row in rows:
        data_preview = row[3][:50] + '...' if len(row[3]) > 50 else row[3]
        print(f'  ID:{row[0]} | Date:{row[1]} | Type:{row[2]} | Data:{data_preview} | Score:{row[4]} | Risk:{row[5]}')
else:
    print('  (No scans yet)')

print()
print('=' * 60)
print('TABLE: scam_reports (User Reports)')
print('=' * 60)
c.execute('SELECT * FROM scam_reports')
rows = c.fetchall()
if rows:
    for row in rows:
        print(f'  {row}')
else:
    print('  (No reports yet)')

conn.close()
print()
print('Done! You can also use "DB Browser for SQLite" for a GUI view.')
