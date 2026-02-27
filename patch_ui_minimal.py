import os

def patch_file(filepath, replacements):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    for target, replacement in replacements:
        if target in content:
            content = content.replace(target, replacement)
        else:
            print(f"Failed to find target in {filepath}")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Patched {filepath}")

# 1. translations.ts
t_path = "cra_auditor/translations.ts"
t_rep = [
    (
        "'deviceList.check.securityLogging': 'Security Logging',",
        "'deviceList.check.securityLogging': 'Security Logging',\n    'deviceList.check.minimalAttackSurface': 'Minimal Attack Surface',"
    ),
    (
        "'deviceList.check.securityLogging': 'Sicherheitsprotokollierung',",
        "'deviceList.check.securityLogging': 'Sicherheitsprotokollierung',\n    'deviceList.check.minimalAttackSurface': 'Minimale Angriffsfläche',"
    ),
    (
        "'dashboard.cra.req.securityLogging': 'Indicative mapping: Annex I Part I §1(3)(j) — support security-relevant event logging and evidence for incident handling.',",
        "'dashboard.cra.req.securityLogging': 'Indicative mapping: Annex I Part I §1(3)(j) — support security-relevant event logging and evidence for incident handling.',\n    'dashboard.cra.req.minimalAttackSurface': 'Indicative mapping: Annex I Part I §1(3)(e) — ensure the device minimises its own negative impact on the availability of services provided by other devices or networks.',"
    ),
    (
        "'dashboard.cra.req.securityLogging': 'Hinweis-Zuordnung: Anhang I Teil I §1(3)(j) — sicherheitsrelevante Ereignisprotokollierung und Nachvollziehbarkeit für Incident-Handling unterstützen.',",
        "'dashboard.cra.req.securityLogging': 'Hinweis-Zuordnung: Anhang I Teil I §1(3)(j) — sicherheitsrelevante Ereignisprotokollierung und Nachvollziehbarkeit für Incident-Handling unterstützen.',\n    'dashboard.cra.req.minimalAttackSurface': 'Hinweis-Zuordnung: Anhang I Teil I §1(3)(e) — Angriffsfläche minimieren und keine unnötigen Dienste (UPnP/SMB/mDNS) exponieren, die andere Netzwerke gefährden könnten.',"
    )
]
patch_file(t_path, t_rep)

# 2. types.ts
ty_path = "cra_auditor/types.ts"
ty_rep = [
    (
        "    securityLogging: {\n      passed: boolean;\n      details: string;\n      syslog_udp_514: boolean;\n      syslog_probe_state: string;\n      logging_endpoints: string[];\n    };\n  }>;",
        "    securityLogging: {\n      passed: boolean;\n      details: string;\n      syslog_udp_514: boolean;\n      syslog_probe_state: string;\n      logging_endpoints: string[];\n    };\n    minimalAttackSurface: {\n      passed: boolean;\n      details: string;\n    };\n  }>;"
    )
]
patch_file(ty_path, ty_rep)

# 3. components/Dashboard.tsx
db_path = "cra_auditor/components/Dashboard.tsx"
db_rep = [
    (
        "  | 'securityLogging';",
        "  | 'securityLogging'\n  | 'minimalAttackSurface';"
    ),
    (
        "    id: 'securityLogging',\n    labelKey: 'deviceList.check.securityLogging',\n    requirementKey: 'dashboard.cra.req.securityLogging'\n  }\n];",
        "    id: 'securityLogging',\n    labelKey: 'deviceList.check.securityLogging',\n    requirementKey: 'dashboard.cra.req.securityLogging'\n  },\n  {\n    id: 'minimalAttackSurface',\n    labelKey: 'deviceList.check.minimalAttackSurface',\n    requirementKey: 'dashboard.cra.req.minimalAttackSurface'\n  }\n];"
    )
]
patch_file(db_path, db_rep)

# 4. components/DeviceList.tsx
dl_path = "cra_auditor/components/DeviceList.tsx"
dl_rep = [
    (
        "    { key: t('deviceList.check.securityLogging'), passed: device.checks?.securityLogging?.passed, details: device.checks?.securityLogging?.details, icon: <Network size={14} />, requirement: t('dashboard.cra.req.securityLogging') },\n  ];",
        "    { key: t('deviceList.check.securityLogging'), passed: device.checks?.securityLogging?.passed, details: device.checks?.securityLogging?.details, icon: <Network size={14} />, requirement: t('dashboard.cra.req.securityLogging') },\n    { key: t('deviceList.check.minimalAttackSurface'), passed: device.checks?.minimalAttackSurface?.passed, details: device.checks?.minimalAttackSurface?.details, icon: <Router size={14} />, requirement: t('dashboard.cra.req.minimalAttackSurface') },\n  ];"
    )
]
patch_file(dl_path, dl_rep)

