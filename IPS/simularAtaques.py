import json
import os
from datetime import datetime
import random

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
carpeta_salida = os.path.join(SCRIPT_DIR, "CapturaTrafico")
archivo_json = os.path.join(carpeta_salida, "trafico.json")
archivo_alertas = os.path.join(carpeta_salida, "alertas.json")

# Tipos de ataques que se pueden simular
TIPOS_ATAQUES = [
    "Web Attack - Brute Force",
    "Web Attack - SQL Injection",
    "Web Attack - XSS",
    "DDoS",
    "Port Scan",
    "Botnet",
    "Infiltration"
]

# IPs de ejemplo para simular
IPS_ATAQUE = [
    "192.168.1.100",
    "10.0.0.50",
    "172.16.0.25",
    "203.0.113.10",
    "198.51.100.5"
]

IPS_DESTINO = [
    "192.168.1.6",
    "10.0.0.1",
    "172.16.0.1"
]

def generar_ataque_simulado(tipo_ataque, num_paquetes=5):
    """Genera paquetes simulados de un tipo de ataque específico"""
    hora_actual = datetime.now().strftime("%H:%M:%S")
    ip_atacante = random.choice(IPS_ATAQUE)
    ip_victima = random.choice(IPS_DESTINO)
    
    # Puertos típicos según el tipo de ataque
    puertos_ataque = {
        "Web Attack - Brute Force": (random.randint(40000, 50000), 80),
        "Web Attack - SQL Injection": (random.randint(40000, 50000), 80),
        "Web Attack - XSS": (random.randint(40000, 50000), 80),
        "DDoS": (random.randint(40000, 50000), random.choice([80, 443, 22])),
        "Port Scan": (random.randint(40000, 50000), random.randint(1, 1024)),
        "Botnet": (random.randint(40000, 50000), random.choice([80, 443, 53])),
        "Infiltration": (random.randint(40000, 50000), random.choice([22, 3389, 1433]))
    }
    
    puerto_origen, puerto_destino = puertos_ataque.get(tipo_ataque, (random.randint(40000, 50000), 80))
    probabilidad = round(random.uniform(0.75, 0.98), 2)
    
    paquetes = []
    alerta = None
    
    for i in range(num_paquetes):
        # Variar ligeramente la hora para simular múltiples paquetes
        hora_paquete = datetime.now().strftime("%H:%M:%S")
        
        paquete = {
            "hora": hora_paquete,
            "ip_origen": ip_atacante,
            "ip_destino": ip_victima,
            "puerto_origen": puerto_origen if puerto_origen != 0 else "-",
            "puerto_destino": puerto_destino if puerto_destino != 0 else "-",
            "protocolo": "TCP",
            "estado": tipo_ataque,
            "etiqueta": tipo_ataque,
            "alerta": True,
            "probabilidad": probabilidad
        }
        paquetes.append(paquete)
    
    # Crear alerta
    alerta = {
        "hora": hora_actual,
        "ip_origen": ip_atacante,
        "ip_destino": ip_victima,
        "puerto_origen": puerto_origen,
        "puerto_destino": puerto_destino,
        "tipo_ataque": tipo_ataque,
        "probabilidad": probabilidad
    }
    
    return paquetes, alerta

def agregar_ataques_simulados(num_ataques=3):
    """Agrega ataques simulados a los archivos JSON"""
    
    # Cargar datos existentes
    try:
        with open(archivo_json, "r") as f:
            trafico = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        trafico = []
    
    try:
        with open(archivo_alertas, "r") as f:
            alertas = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        alertas = []
    
    # Generar ataques
    print(f"Generando {num_ataques} ataques simulados...")
    
    for i in range(num_ataques):
        tipo_ataque = random.choice(TIPOS_ATAQUES)
        num_paquetes = random.randint(3, 8)
        
        paquetes, alerta = generar_ataque_simulado(tipo_ataque, num_paquetes)
        
        # Agregar paquetes al tráfico
        trafico.extend(paquetes)
        
        # Agregar alerta
        alertas.append(alerta)
        
        print(f"  ✓ {tipo_ataque} desde {alerta['ip_origen']} -> {alerta['ip_destino']} (probabilidad: {alerta['probabilidad']*100:.1f}%)")
    
    # Mantener solo los últimos 1000 paquetes y 100 alertas
    trafico = trafico[-1000:]
    alertas = alertas[-100:]
    
    # Guardar archivos
    with open(archivo_json, "w") as f:
        json.dump(trafico, f, indent=4)
    
    with open(archivo_alertas, "w") as f:
        json.dump(alertas, f, indent=4)
    
    print(f"\n✓ {len(paquetes) * num_ataques} paquetes de ataque agregados")
    print(f"✓ {num_ataques} alertas agregadas")
    print(f"\nArchivos actualizados:")
    print(f"  - {archivo_json}")
    print(f"  - {archivo_alertas}")
    print(f"\nRecarga la página IPS.html para ver los ataques simulados.")

def simular_ataque_especifico(tipo_ataque):
    """Simula un tipo de ataque específico"""
    if tipo_ataque not in TIPOS_ATAQUES:
        print(f"Error: Tipo de ataque '{tipo_ataque}' no válido.")
        print(f"Tipos disponibles: {', '.join(TIPOS_ATAQUES)}")
        return
    
    paquetes, alerta = generar_ataque_simulado(tipo_ataque, num_paquetes=5)
    
    # Cargar datos existentes
    try:
        with open(archivo_json, "r") as f:
            trafico = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        trafico = []
    
    try:
        with open(archivo_alertas, "r") as f:
            alertas = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        alertas = []
    
    # Agregar datos
    trafico.extend(paquetes)
    alertas.append(alerta)
    
    # Mantener límites
    trafico = trafico[-1000:]
    alertas = alertas[-100:]
    
    # Guardar
    with open(archivo_json, "w") as f:
        json.dump(trafico, f, indent=4)
    
    with open(archivo_alertas, "w") as f:
        json.dump(alertas, f, indent=4)
    
    print(f"✓ Ataque '{tipo_ataque}' simulado exitosamente")
    print(f"  Desde: {alerta['ip_origen']}:{alerta['puerto_origen']}")
    print(f"  Hacia: {alerta['ip_destino']}:{alerta['puerto_destino']}")
    print(f"  Probabilidad: {alerta['probabilidad']*100:.1f}%")

if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("SIMULADOR DE ATAQUES - IPS")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        # Modo: simular ataque específico
        tipo = sys.argv[1]
        simular_ataque_especifico(tipo)
    else:
        # Modo: simular múltiples ataques aleatorios
        num = 3
        if len(sys.argv) > 1:
            try:
                num = int(sys.argv[1])
            except ValueError:
                pass
        
        agregar_ataques_simulados(num)
    
    print("\n" + "=" * 60)

