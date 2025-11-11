"""
Script para simular diferentes tipos de ataques y probar el sistema IPS
IMPORTANTE: Usar solo en entornos controlados y con autorización
"""
import socket
import time
import random
import threading
from datetime import datetime

class SimuladorAtaques:
    """Simula diferentes tipos de ataques para probar el IPS"""
    
    def __init__(self, target_ip="127.0.0.1", target_port=80):
        """
        Args:
            target_ip: IP objetivo (por defecto localhost)
            target_port: Puerto objetivo (por defecto 80 - HTTP)
        """
        self.target_ip = target_ip
        self.target_port = target_port
    
    def simular_brute_force_http(self, num_intentos=50, delay=0.1):
        """
        Simula un ataque Brute Force HTTP
        Múltiples intentos de conexión rápidos con diferentes credenciales
        """
        print(f"🚨 Iniciando simulación de Brute Force HTTP...")
        print(f"   Objetivo: {self.target_ip}:{self.target_port}")
        print(f"   Intentos: {num_intentos}")
        
        for i in range(num_intentos):
            try:
                # Crear socket y conectar
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, self.target_port))
                
                # Enviar request HTTP básico (simulando intento de login)
                request = f"GET /login HTTP/1.1\r\nHost: {self.target_ip}\r\n"
                request += f"User-Agent: Mozilla/5.0\r\n"
                request += f"Content-Length: {len(f'user=admin&pass=pass{i}')}\r\n"
                request += f"\r\nuser=admin&pass=pass{i}"
                
                sock.send(request.encode())
                sock.close()
                
                if i % 10 == 0:
                    print(f"   Intentos enviados: {i}/{num_intentos}")
                
                time.sleep(delay)
            except Exception as e:
                # Ignorar errores de conexión (es normal en la simulación)
                pass
        
        print(f"✅ Simulación de Brute Force completada")
    
    def simular_port_scan(self, puertos=[80, 443, 22, 21, 25, 3306, 5432], delay=0.05):
        """
        Simula un Port Scan
        Intenta conectar a múltiples puertos para descubrir servicios
        """
        print(f"🚨 Iniciando simulación de Port Scan...")
        print(f"   Objetivo: {self.target_ip}")
        print(f"   Puertos a escanear: {puertos}")
        
        for puerto in puertos:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                resultado = sock.connect_ex((self.target_ip, puerto))
                
                if resultado == 0:
                    print(f"   ✓ Puerto {puerto} abierto")
                else:
                    print(f"   ✗ Puerto {puerto} cerrado")
                
                sock.close()
                time.sleep(delay)
            except Exception as e:
                pass
        
        print(f"✅ Simulación de Port Scan completada")
    
    def simular_sql_injection(self, num_requests=30, delay=0.2):
        """
        Simula un ataque SQL Injection
        Envía requests HTTP con payloads SQL maliciosos
        """
        print(f"🚨 Iniciando simulación de SQL Injection...")
        print(f"   Objetivo: {self.target_ip}:{self.target_port}")
        
        # Payloads SQL Injection comunes
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "admin'/*",
            "' OR 1=1--",
            "' OR 'a'='a",
            "') OR ('1'='1",
        ]
        
        for i in range(num_requests):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, self.target_port))
                
                payload = random.choice(payloads)
                request = f"GET /search?q={payload} HTTP/1.1\r\n"
                request += f"Host: {self.target_ip}\r\n"
                request += f"User-Agent: Mozilla/5.0\r\n\r\n"
                
                sock.send(request.encode())
                sock.close()
                
                if i % 10 == 0:
                    print(f"   Requests enviados: {i}/{num_requests}")
                
                time.sleep(delay)
            except Exception as e:
                pass
        
        print(f"✅ Simulación de SQL Injection completada")
    
    def simular_xss_attack(self, num_requests=30, delay=0.2):
        """
        Simula un ataque XSS (Cross-Site Scripting)
        Envía requests con scripts maliciosos
        """
        print(f"🚨 Iniciando simulación de XSS Attack...")
        print(f"   Objetivo: {self.target_ip}:{self.target_port}")
        
        # Payloads XSS comunes
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]
        
        for i in range(num_requests):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, self.target_port))
                
                payload = random.choice(payloads)
                request = f"GET /search?q={payload} HTTP/1.1\r\n"
                request += f"Host: {self.target_ip}\r\n"
                request += f"User-Agent: Mozilla/5.0\r\n\r\n"
                
                sock.send(request.encode())
                sock.close()
                
                if i % 10 == 0:
                    print(f"   Requests enviados: {i}/{num_requests}")
                
                time.sleep(delay)
            except Exception as e:
                pass
        
        print(f"✅ Simulación de XSS Attack completada")
    
    def simular_ddos_basico(self, num_threads=10, requests_per_thread=20, delay=0.1):
        """
        Simula un ataque DDoS básico
        Múltiples threads enviando requests simultáneamente
        """
        print(f"🚨 Iniciando simulación de DDoS básico...")
        print(f"   Objetivo: {self.target_ip}:{self.target_port}")
        print(f"   Threads: {num_threads}")
        print(f"   Requests por thread: {requests_per_thread}")
        
        def enviar_requests():
            for _ in range(requests_per_thread):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect((self.target_ip, self.target_port))
                    
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                    sock.send(request.encode())
                    sock.close()
                    
                    time.sleep(delay)
                except Exception as e:
                    pass
        
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=enviar_requests)
            threads.append(t)
            t.start()
        
        # Esperar a que todos los threads terminen
        for t in threads:
            t.join()
        
        print(f"✅ Simulación de DDoS básico completada")
    
    def simular_ataque_completo(self):
        """Ejecuta una secuencia de diferentes ataques"""
        print("=" * 60)
        print("🔥 SIMULACIÓN COMPLETA DE ATAQUES")
        print("=" * 60)
        print(f"Objetivo: {self.target_ip}:{self.target_port}")
        print(f"Hora de inicio: {datetime.now().strftime('%H:%M:%S')}")
        print()
        
        # 1. Port Scan
        self.simular_port_scan()
        time.sleep(2)
        print()
        
        # 2. Brute Force
        self.simular_brute_force_http(num_intentos=50)
        time.sleep(2)
        print()
        
        # 3. SQL Injection
        self.simular_sql_injection(num_requests=30)
        time.sleep(2)
        print()
        
        # 4. XSS
        self.simular_xss_attack(num_requests=30)
        time.sleep(2)
        print()
        
        # 5. DDoS básico
        self.simular_ddos_basico(num_threads=5, requests_per_thread=20)
        print()
        
        print("=" * 60)
        print("✅ SIMULACIÓN COMPLETA FINALIZADA")
        print("=" * 60)
        print("\n💡 Revisa la interfaz del IPS para ver las alertas generadas")


def main():
    """Función principal con menú interactivo"""
    print("=" * 60)
    print("   SIMULADOR DE ATAQUES PARA PROBAR EL IPS")
    print("=" * 60)
    print("\n⚠️  ADVERTENCIA: Usar solo en entornos controlados")
    print("   Este script genera tráfico de red que puede ser detectado como ataque\n")
    
    # Configuración
    target_ip = input("IP objetivo (Enter para localhost): ").strip() or "127.0.0.1"
    target_port = input("Puerto objetivo (Enter para 80): ").strip() or "80"
    try:
        target_port = int(target_port)
    except:
        target_port = 80
    
    simulador = SimuladorAtaques(target_ip=target_ip, target_port=target_port)
    
    print("\n" + "=" * 60)
    print("   SELECCIONA EL TIPO DE ATAQUE A SIMULAR")
    print("=" * 60)
    print("1. Port Scan")
    print("2. Brute Force HTTP")
    print("3. SQL Injection")
    print("4. XSS Attack")
    print("5. DDoS Básico")
    print("6. Simulación Completa (todos los ataques)")
    print("0. Salir")
    print()
    
    opcion = input("Selecciona una opción: ").strip()
    
    if opcion == "1":
        simulador.simular_port_scan()
    elif opcion == "2":
        num = input("Número de intentos (Enter para 50): ").strip() or "50"
        simulador.simular_brute_force_http(num_intentos=int(num))
    elif opcion == "3":
        num = input("Número de requests (Enter para 30): ").strip() or "30"
        simulador.simular_sql_injection(num_requests=int(num))
    elif opcion == "4":
        num = input("Número de requests (Enter para 30): ").strip() or "30"
        simulador.simular_xss_attack(num_requests=int(num))
    elif opcion == "5":
        threads = input("Número de threads (Enter para 10): ").strip() or "10"
        reqs = input("Requests por thread (Enter para 20): ").strip() or "20"
        simulador.simular_ddos_basico(num_threads=int(threads), requests_per_thread=int(reqs))
    elif opcion == "6":
        simulador.simular_ataque_completo()
    elif opcion == "0":
        print("Saliendo...")
        return
    else:
        print("Opción no válida")
    
    print("\n💡 Tip: Ejecuta 'python IPS/capturaRed.py' en otra terminal")
    print("   para capturar el tráfico y ver las alertas en tiempo real")


if __name__ == "__main__":
    main()

