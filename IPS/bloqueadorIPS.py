import subprocess
import json
import os
from datetime import datetime, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
archivo_bloqueadas = os.path.join(SCRIPT_DIR, "CapturaTrafico", "ips_bloqueadas.json")

# Tiempo de bloqueo por defecto (en horas)
TIEMPO_BLOQUEO_DEFAULT = 24

def cargar_ips_bloqueadas():
    """Carga la lista de IPs bloqueadas desde el archivo JSON"""
    try:
        if os.path.exists(archivo_bloqueadas):
            with open(archivo_bloqueadas, "r") as f:
                return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return []

def guardar_ips_bloqueadas(ips_bloqueadas):
    """Guarda la lista de IPs bloqueadas en el archivo JSON"""
    os.makedirs(os.path.dirname(archivo_bloqueadas), exist_ok=True)
    with open(archivo_bloqueadas, "w") as f:
        json.dump(ips_bloqueadas, f, indent=4)

def esta_bloqueada(ip):
    """Verifica si una IP ya está bloqueada"""
    ips_bloqueadas = cargar_ips_bloqueadas()
    for entrada in ips_bloqueadas:
        if entrada['ip'] == ip:
            # Verificar si el bloqueo aún es válido
            fecha_bloqueo = datetime.fromisoformat(entrada['fecha_bloqueo'])
            tiempo_bloqueo = timedelta(hours=entrada.get('tiempo_bloqueo', TIEMPO_BLOQUEO_DEFAULT))
            if datetime.now() < fecha_bloqueo + tiempo_bloqueo:
                return True
            else:
                # El bloqueo expiró, desbloquear
                desbloquear_ip(ip)
    return False

def bloquear_ip_windows_firewall(ip, nombre_regla=None):
    """Bloquea una IP usando Windows Firewall mediante netsh"""
    if nombre_regla is None:
        nombre_regla = f"IPS_Bloqueo_{ip.replace('.', '_')}"
    
    try:
        # Crear regla de bloqueo de salida (bloquear tráfico desde la IP atacante)
        comando = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={nombre_regla}',
            'dir=in',
            'action=block',
            f'remoteip={ip}',
            'enable=yes',
            'profile=any'
        ]
        
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if resultado.returncode == 0 or "ya existe" in resultado.stdout.lower() or "already exists" in resultado.stdout.lower():
            return True
        else:
            print(f"Advertencia: No se pudo crear regla de firewall: {resultado.stderr}")
            return False
            
    except Exception as e:
        print(f"Error al bloquear IP {ip} en firewall: {e}")
        return False

def desbloquear_ip_windows_firewall(ip):
    """Elimina la regla de firewall que bloquea una IP"""
    nombre_regla = f"IPS_Bloqueo_{ip.replace('.', '_')}"
    
    try:
        comando = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name={nombre_regla}'
        ]
        
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        return resultado.returncode == 0 or "no se encontró" in resultado.stdout.lower() or "not found" in resultado.stdout.lower()
        
    except Exception as e:
        print(f"Error al desbloquear IP {ip} en firewall: {e}")
        return False

def bloquear_ip(ip, tipo_ataque="Ataque detectado", probabilidad=0.0, tiempo_bloqueo_horas=TIEMPO_BLOQUEO_DEFAULT):
    """Bloquea una IP y la agrega al registro"""
    
    # Verificar si ya está bloqueada
    if esta_bloqueada(ip):
        return {
            'exito': False,
            'mensaje': f'La IP {ip} ya está bloqueada'
        }
    
    # Intentar bloquear en Windows Firewall
    exito_firewall = bloquear_ip_windows_firewall(ip)
    
    # Registrar el bloqueo
    ips_bloqueadas = cargar_ips_bloqueadas()
    
    entrada = {
        'ip': ip,
        'fecha_bloqueo': datetime.now().isoformat(),
        'tipo_ataque': tipo_ataque,
        'probabilidad': probabilidad,
        'tiempo_bloqueo': tiempo_bloqueo_horas,
        'regla_firewall': f"IPS_Bloqueo_{ip.replace('.', '_')}"
    }
    
    ips_bloqueadas.append(entrada)
    guardar_ips_bloqueadas(ips_bloqueadas)
    
    if exito_firewall:
        return {
            'exito': True,
            'mensaje': f'IP {ip} bloqueada exitosamente en Windows Firewall',
            'fecha_bloqueo': entrada['fecha_bloqueo'],
            'tiempo_bloqueo': tiempo_bloqueo_horas
        }
    else:
        return {
            'exito': False,
            'mensaje': f'IP {ip} registrada pero no se pudo bloquear en firewall (requiere permisos de administrador)',
            'fecha_bloqueo': entrada['fecha_bloqueo']
        }

def desbloquear_ip(ip):
    """Desbloquea una IP y elimina su registro"""
    # Eliminar regla de firewall
    desbloquear_ip_windows_firewall(ip)
    
    # Eliminar del registro
    ips_bloqueadas = cargar_ips_bloqueadas()
    ips_bloqueadas = [entrada for entrada in ips_bloqueadas if entrada['ip'] != ip]
    guardar_ips_bloqueadas(ips_bloqueadas)
    
    return {
        'exito': True,
        'mensaje': f'IP {ip} desbloqueada'
    }

def obtener_ips_bloqueadas():
    """Obtiene la lista de todas las IPs bloqueadas activas"""
    ips_bloqueadas = cargar_ips_bloqueadas()
    ips_activas = []
    
    for entrada in ips_bloqueadas:
        fecha_bloqueo = datetime.fromisoformat(entrada['fecha_bloqueo'])
        tiempo_bloqueo = timedelta(hours=entrada.get('tiempo_bloqueo', TIEMPO_BLOQUEO_DEFAULT))
        
        if datetime.now() < fecha_bloqueo + tiempo_bloqueo:
            tiempo_restante = (fecha_bloqueo + tiempo_bloqueo) - datetime.now()
            entrada['tiempo_restante_horas'] = round(tiempo_restante.total_seconds() / 3600, 2)
            ips_activas.append(entrada)
        else:
            # Bloqueo expirado, desbloquear
            desbloquear_ip(entrada['ip'])
    
    return ips_activas

def limpiar_bloqueos_expirados():
    """Elimina bloqueos que han expirado"""
    ips_bloqueadas = cargar_ips_bloqueadas()
    ips_activas = []
    ips_desbloqueadas = []
    
    for entrada in ips_bloqueadas:
        fecha_bloqueo = datetime.fromisoformat(entrada['fecha_bloqueo'])
        tiempo_bloqueo = timedelta(hours=entrada.get('tiempo_bloqueo', TIEMPO_BLOQUEO_DEFAULT))
        
        if datetime.now() < fecha_bloqueo + tiempo_bloqueo:
            ips_activas.append(entrada)
        else:
            ips_desbloqueadas.append(entrada['ip'])
            desbloquear_ip_windows_firewall(entrada['ip'])
    
    guardar_ips_bloqueadas(ips_activas)
    return len(ips_desbloqueadas)

if __name__ == "__main__":
    # Prueba del módulo
    print("=" * 60)
    print("MÓDULO DE BLOQUEO IPS")
    print("=" * 60)
    
    # Limpiar bloqueos expirados
    expirados = limpiar_bloqueos_expirados()
    if expirados > 0:
        print(f"✓ {expirados} bloqueos expirados eliminados")
    
    # Mostrar IPs bloqueadas
    ips_activas = obtener_ips_bloqueadas()
    if ips_activas:
        print(f"\nIPs bloqueadas actualmente ({len(ips_activas)}):")
        for entrada in ips_activas:
            print(f"  - {entrada['ip']} | {entrada['tipo_ataque']} | "
                  f"Bloqueada: {entrada['fecha_bloqueo']} | "
                  f"Tiempo restante: {entrada['tiempo_restante_horas']} horas")
    else:
        print("\nNo hay IPs bloqueadas actualmente")

