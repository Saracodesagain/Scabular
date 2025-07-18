# dictionary of suspicious parent-child process relationships. Sources are ATT&CK, Sigma rules and LOLBins

SUSPICIOUS_RELATIONS = {

    # explorer.exe - GUI process spawning shell or script
    # T1059.003, T1204
    "explorer.exe": [
        "cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    ],

    # winlogon.exe - Should not spawn shells
    # T1037, T1547.002
    "winlogon.exe": [
        "cmd.exe", "powershell.exe", "regsvr32.exe", "rundll32.exe"
    ],

    # svchost.exe - Windows service host, suspicious if running shells
    # T1047, T1059
    "svchost.exe": [
        "cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe"
    ],

    # dllhost.exe - COM surrogate abuse
    # T1547.001
    "dllhost.exe": [
        "rundll32.exe", "regsvr32.exe", "powershell.exe"
    ],

    # spoolsp.exe - Print spooler abuse (e.g., PrintNightmare)
    # T1485
    "spoolsp.exe": [
        "cmd.exe", "powershell.exe", "rundll32.exe"
    ],

    # ctfmon.exe - Input method editor abuse
    # T1547.009
    "ctfmon.exe": [
        "cmd.exe", "powershell.exe", "rundll32.exe"
    ],

    # msiexec.exe - Installer abuse
    # T1218.001
    "msiexec.exe": [
        "cmd.exe", "powershell.exe", "rundll32.exe"
    ],

    # taskeng.exe - Task scheduler abuse
    # T1053
    "taskeng.exe": [
        "cmd.exe", "powershell.exe", "mshta.exe"
    ],

    # wmiprvse.exe - WMI service abuse
    # T1047, T1021.002
    "wmiprvse.exe": [
        "cmd.exe", "powershell.exe", "wscript.exe"
    ],

    # powershell.exe - Should not spawn shells often
    # T1059.001
    "powershell.exe": [
        "cmd.exe", "mshta.exe", "rundll32.exe"
    ],

    # winword.exe / excel.exe - Office macro abuse
    # T1137
    "winword.exe": [
        "cmd.exe", "powershell.exe", "rundll32.exe"
    ],
    "excel.exe": [
        "cmd.exe", "powershell.exe", "rundll32.exe"
    ],

    # mshta.exe - HTA script abuse
    # T1218.005
    "mshta.exe": [
        "rundll32.exe", "regsvr32.exe"
    ],

    # regsvr32.exe - COM scriptlet abuse
    # T1218.002
    "regsvr32.exe": [
        "powershell.exe", "cmd.exe"
    ],

    # rundll32.exe - DLL sideloading abuse
    # T1218.010
    "rundll32.exe": [
        "powershell.exe", "cmd.exe"
    ],

    # bitsadmin.exe - Background transfer abuse
    # T1197
    "bitsadmin.exe": [
        "cmd.exe", "powershell.exe"
    ]
}