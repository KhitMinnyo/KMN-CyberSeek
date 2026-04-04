#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('kmn_cyberseek.db')
cursor = conn.cursor()

# Check sessions table schema
cursor.execute('PRAGMA table_info(sessions)')
columns = cursor.fetchall()
print('Sessions table columns:')
for col in columns:
    print(f'  {col[0]}: {col[1]} ({col[2]})')

# Check if auto_approve column exists
has_auto_approve = any(col[1] == 'auto_approve' for col in columns)
print(f'\nauto_approve column exists: {has_auto_approve}')

# Check sample data without auto_approve column
if has_auto_approve:
    cursor.execute('SELECT session_id, target_ip, status, auto_approve FROM sessions LIMIT 5')
else:
    cursor.execute('SELECT session_id, target_ip, status FROM sessions LIMIT 5')
sessions = cursor.fetchall()
print('\nFirst 5 sessions:')
for session in sessions:
    print(f'  {session}')

conn.close()