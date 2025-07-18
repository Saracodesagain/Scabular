from sus import SUSPICIOUS_RELATIONS


def analyze_process_list(df):
    alerts = []

    pid_to_name = dict(zip(df['PID'], df['Process Name']))

    df['Parent Name'] = df['PPID'].map(pid_to_name).fillna('Unknown')

    # Anomalies scan
    for _, row in df.iterrows():
        parent = row['Parent Name'].lower()
        child = row['Process Name'].lower()
        pid = row['PID']
        ppid = row['PPID']

        if parent in SUSPICIOUS_RELATIONS:
            if child in SUSPICIOUS_RELATIONS[parent]:
                alerts.append({
                    'Parent': parent,
                    'Child': child,
                    'PID': pid,
                    'PPID': ppid
                })

    return alerts, df
