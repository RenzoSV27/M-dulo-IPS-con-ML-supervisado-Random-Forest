import json
import os
from datetime import datetime
from scapy.all import sniff

try:
    from detectorML import DetectorIPS
    from extraccionCaracteristicas import ExtractorCaracteristicas
    ML_DISPONIBLE = True
except ImportError:
    print("Modulos ML no disponibles. El sistema funcionara sin deteccion ML.")
    ML_DISPONIBLE = False

carpeta_salida = "IPS/CapturaTrafico"
archivo_json = os.path.join(carpeta_salida, "trafico.json")
archivo_alertas = os.path.join(carpeta_salida, "alertas.json")

os.makedirs(carpeta_salida, exist_ok=True)

if not os.path.exists(archivo_json):
    with open(archivo_json, "w") as f:
        json.dump([], f, indent=4)

if not os.path.exists(archivo_alertas):
    with open(archivo_alertas, "w") as f:
        json.dump([], f, indent=4)

try:
    with open(archivo_json, "r") as f:
        paquetes_capturados = json.load(f)
        if not isinstance(paquetes_capturados, list):
            paquetes_capturados = []
except (FileNotFoundError, json.JSONDecodeError):
    paquetes_capturados = []

detector = None
extractor = None
if ML_DISPONIBLE:
    try:
        detector = DetectorIPS()
        extractor = ExtractorCaracteristicas()
        if detector.esta_disponible():
            print("Sistema de deteccion ML activado")
        else:
            print("Modelo ML no entrenado. Ejecuta 'python IPS/entrenarModelo.py' primero")
    except Exception as e:
        print(f"Error al inicializar ML: {e}")
        detector = None
        extractor = None

protocolos = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF"
}

def procesarPaquete(paquete):
    hora = datetime.now().strftime("%H:%M:%S")
    timestamp = datetime.now()

    if paquete.haslayer("IP"):
        ip_origen = paquete["IP"].src
        ip_destino = paquete["IP"].dst
        protocolo_num = paquete["IP"].proto
        protocolo_nombre = protocolos.get(protocolo_num, f"Desconocido ({protocolo_num})")
        estado = "Activo"
        tamaño = len(paquete)

        puerto_origen = 0
        puerto_destino = 0
        flags_tcp = {}
        header_length = paquete["IP"].ihl * 4
        win_size = 0

        if paquete.haslayer("TCP"):
            puerto_origen = paquete["TCP"].sport
            puerto_destino = paquete["TCP"].dport
            flags_tcp = {
                'FIN': 1 if paquete["TCP"].flags.F else 0,
                'SYN': 1 if paquete["TCP"].flags.S else 0,
                'RST': 1 if paquete["TCP"].flags.R else 0,
                'PSH': 1 if paquete["TCP"].flags.P else 0,
                'ACK': 1 if paquete["TCP"].flags.A else 0,
                'URG': 1 if paquete["TCP"].flags.U else 0
            }
            header_length += paquete["TCP"].dataofs * 4
            win_size = paquete["TCP"].window
        elif paquete.haslayer("UDP"):
            puerto_origen = paquete["UDP"].sport
            puerto_destino = paquete["UDP"].dport
            header_length += 8

        etiqueta = "BENIGN"
        datos = {
            "hora": hora,
            "ip_origen": ip_origen,
            "ip_destino": ip_destino,
            "puerto_origen": puerto_origen if puerto_origen != 0 else "-",
            "puerto_destino": puerto_destino if puerto_destino != 0 else "-",
            "protocolo": protocolo_nombre,
            "estado": estado,
            "etiqueta": etiqueta
        }

        prediccion_ml = None
        if extractor and detector and detector.esta_disponible():
            try:
                info_paquete = {
                    'ip_origen': ip_origen,
                    'ip_destino': ip_destino,
                    'puerto_origen': puerto_origen,
                    'puerto_destino': puerto_destino,
                    'timestamp': timestamp,
                    'tamaño': tamaño,
                    'flags_tcp': flags_tcp,
                    'header_length': header_length,
                    'win_size': win_size
                }
                
                extractor.agregar_paquete(info_paquete)
                
                ip1, ip2 = sorted([ip_origen, ip_destino])
                port1, port2 = sorted([puerto_origen, puerto_destino])
                clave_flujo = f"{ip1}:{port1}-{ip2}:{port2}"
                
                if len(extractor.flujos_activos[clave_flujo]['paquetes_fwd']) + \
                   len(extractor.flujos_activos[clave_flujo]['paquetes_bwd']) >= 5:
                    caracteristicas = extractor.obtener_caracteristicas_flujo(clave_flujo)
                    caracteristicas[' Destination Port'] = puerto_destino
                    
                    prediccion_ml = detector.predecir(caracteristicas)
                    
                    etiqueta = prediccion_ml['prediccion']
                    datos['etiqueta'] = etiqueta
                    
                    if prediccion_ml['es_ataque']:
                        datos['estado'] = f"{prediccion_ml['prediccion']}"
                        datos['alerta'] = True
                        datos['probabilidad'] = prediccion_ml['probabilidad']
                        
                        try:
                            with open(archivo_alertas, "r") as f:
                                alertas = json.load(f)
                        except:
                            alertas = []
                        
                        alerta = {
                            "hora": hora,
                            "ip_origen": ip_origen,
                            "ip_destino": ip_destino,
                            "puerto_origen": puerto_origen,
                            "puerto_destino": puerto_destino,
                            "tipo_ataque": prediccion_ml['prediccion'],
                            "probabilidad": prediccion_ml['probabilidad']
                        }
                        alertas.append(alerta)
                        
                        with open(archivo_alertas, "w") as f:
                            json.dump(alertas[-100:], f, indent=4)
                        
                        print(f"ALERTA: {prediccion_ml['prediccion']} ({prediccion_ml['probabilidad']*100:.1f}%) | {ip_origen}:{puerto_origen} -> {ip_destino}:{puerto_destino}")
            except Exception as e:
                print(f"Error en deteccion ML: {e}")

        paquetes_capturados.append(datos)

        with open(archivo_json, "w") as f:
            json.dump(paquetes_capturados[-1000:], f, indent=4)

        if extractor:
            extractor.limpiar_flujos_antiguos()

        estado_display = datos['estado']
        print(f"[{hora}] {ip_origen}:{puerto_origen if puerto_origen != 0 else '-'} -> {ip_destino}:{puerto_destino if puerto_destino != 0 else '-'} | {protocolo_nombre} | {estado_display}")

print("Capturando trafico... (presiona Ctrl + C para detener)")
sniff(count=30, prn=procesarPaquete)
print("Captura finalizada. Datos guardados en", archivo_json)
