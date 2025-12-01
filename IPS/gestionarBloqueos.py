import sys
import os

# Agregar el directorio IPS al path para importar módulos
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bloqueadorIPS import (
    obtener_ips_bloqueadas,
    desbloquear_ip,
    bloquear_ip,
    limpiar_bloqueos_expirados
)

def mostrar_ips_bloqueadas():
    """Muestra todas las IPs bloqueadas actualmente"""
    ips_activas = obtener_ips_bloqueadas()
    limpiar_bloqueos_expirados()
    
    print("=" * 70)
    print("IPs BLOQUEADAS - SISTEMA IPS")
    print("=" * 70)
    
    if not ips_activas:
        print("\nNo hay IPs bloqueadas actualmente.")
        return
    
    print(f"\nTotal de IPs bloqueadas: {len(ips_activas)}\n")
    print(f"{'IP':<20} {'Tipo Ataque':<30} {'Probabilidad':<12} {'Tiempo Restante':<15}")
    print("-" * 70)
    
    for entrada in ips_activas:
        ip = entrada['ip']
        tipo = entrada.get('tipo_ataque', 'Desconocido')
        prob = entrada.get('probabilidad', 0.0)
        tiempo = entrada.get('tiempo_restante_horas', 0)
        
        print(f"{ip:<20} {tipo:<30} {prob*100:>6.1f}%      {tiempo:>6.1f} horas")

def desbloquear_ip_interactivo():
    """Permite desbloquear una IP específica"""
    print("\n" + "=" * 70)
    print("DESBLOQUEAR IP")
    print("=" * 70)
    
    ip = input("\nIngresa la IP a desbloquear: ").strip()
    
    if not ip:
        print("Error: IP no válida")
        return
    
    resultado = desbloquear_ip(ip)
    
    if resultado['exito']:
        print(f"\n✓ {resultado['mensaje']}")
    else:
        print(f"\n✗ Error: {resultado.get('mensaje', 'No se pudo desbloquear')}")

def bloquear_ip_interactivo():
    """Permite bloquear una IP manualmente"""
    print("\n" + "=" * 70)
    print("BLOQUEAR IP MANUALMENTE")
    print("=" * 70)
    
    ip = input("\nIngresa la IP a bloquear: ").strip()
    
    if not ip:
        print("Error: IP no válida")
        return
    
    tipo_ataque = input("Tipo de ataque (opcional, Enter para 'Bloqueo manual'): ").strip()
    if not tipo_ataque:
        tipo_ataque = "Bloqueo manual"
    
    try:
        tiempo = input("Tiempo de bloqueo en horas (Enter para 24 horas): ").strip()
        tiempo_bloqueo = int(tiempo) if tiempo else 24
    except ValueError:
        tiempo_bloqueo = 24
    
    resultado = bloquear_ip(ip, tipo_ataque, probabilidad=1.0, tiempo_bloqueo_horas=tiempo_bloqueo)
    
    if resultado['exito']:
        print(f"\n✓ {resultado['mensaje']}")
    else:
        print(f"\n⚠ {resultado['mensaje']}")

def menu_principal():
    """Menú principal de gestión de bloqueos"""
    while True:
        print("\n" + "=" * 70)
        print("GESTIÓN DE BLOQUEOS IPS")
        print("=" * 70)
        print("\n1. Ver IPs bloqueadas")
        print("2. Desbloquear una IP")
        print("3. Bloquear una IP manualmente")
        print("4. Limpiar bloqueos expirados")
        print("5. Salir")
        
        opcion = input("\nSelecciona una opción (1-5): ").strip()
        
        if opcion == "1":
            mostrar_ips_bloqueadas()
        elif opcion == "2":
            desbloquear_ip_interactivo()
        elif opcion == "3":
            bloquear_ip_interactivo()
        elif opcion == "4":
            expirados = limpiar_bloqueos_expirados()
            print(f"\n✓ {expirados} bloqueos expirados eliminados")
        elif opcion == "5":
            print("\nSaliendo...")
            break
        else:
            print("\nOpción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print("\n\nSaliendo...")
    except Exception as e:
        print(f"\nError: {e}")

