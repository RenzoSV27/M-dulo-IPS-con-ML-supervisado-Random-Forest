from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np

class ExtractorCaracteristicas:
    """Extrae características de flujos de red para el modelo ML"""
    
    def __init__(self, timeout_flujo=60):
        """
        Args:
            timeout_flujo: Tiempo en segundos para considerar un flujo como cerrado
        """
        self.timeout_flujo = timeout_flujo
        self.flujos_activos = defaultdict(lambda: {
            'paquetes_fwd': [],
            'paquetes_bwd': [],
            'tiempos_fwd': [],
            'tiempos_bwd': [],
            'inicio': None,
            'ultimo_paquete': None,
            'flags_fin': 0,
            'flags_syn': 0,
            'flags_rst': 0,
            'flags_psh_fwd': 0,
            'flags_psh_bwd': 0,
            'flags_urg_fwd': 0,
            'flags_urg_bwd': 0,
            'header_fwd': 0,
            'header_bwd': 0,
            'win_bytes_fwd': 0,
            'win_bytes_bwd': 0
        })
    
    def agregar_paquete(self, paquete_info):
        """
        Agrega un paquete a un flujo y actualiza las características
        
        Args:
            paquete_info: dict con información del paquete
                - ip_origen, ip_destino, puerto_origen, puerto_destino
                - protocolo, timestamp, tamaño, flags_tcp, etc.
        """
        # Crear clave única para el flujo (bidireccional)
        ip1, ip2 = sorted([paquete_info['ip_origen'], paquete_info['ip_destino']])
        port1, port2 = sorted([paquete_info.get('puerto_origen', 0), 
                               paquete_info.get('puerto_destino', 0)])
        
        # Determinar dirección (forward o backward)
        es_forward = (paquete_info['ip_origen'] == ip1)
        
        clave_flujo = f"{ip1}:{port1}-{ip2}:{port2}"
        flujo = self.flujos_activos[clave_flujo]
        
        timestamp = paquete_info.get('timestamp', datetime.now())
        tamaño = paquete_info.get('tamaño', 0)
        
        # Inicializar flujo
        if flujo['inicio'] is None:
            flujo['inicio'] = timestamp
            flujo['ultimo_paquete'] = timestamp
        
        # Actualizar según dirección
        if es_forward:
            flujo['paquetes_fwd'].append(tamaño)
            if len(flujo['tiempos_fwd']) > 0:
                iat = (timestamp - flujo['ultimo_paquete']).total_seconds() * 1000000  # microsegundos
                flujo['tiempos_fwd'].append(iat)
            else:
                flujo['tiempos_fwd'].append(0)
            flujo['header_fwd'] += paquete_info.get('header_length', 0)
        else:
            flujo['paquetes_bwd'].append(tamaño)
            if len(flujo['tiempos_bwd']) > 0:
                iat = (timestamp - flujo['ultimo_paquete']).total_seconds() * 1000000
                flujo['tiempos_bwd'].append(iat)
            else:
                flujo['tiempos_bwd'].append(0)
            flujo['header_bwd'] += paquete_info.get('header_length', 0)
        
        # Actualizar flags TCP
        flags = paquete_info.get('flags_tcp', {})
        flujo['flags_fin'] += flags.get('FIN', 0)
        flujo['flags_syn'] += flags.get('SYN', 0)
        flujo['flags_rst'] += flags.get('RST', 0)
        flujo['flags_psh_fwd'] += flags.get('PSH', 0) if es_forward else 0
        flujo['flags_psh_bwd'] += flags.get('PSH', 0) if not es_forward else 0
        flujo['flags_urg_fwd'] += flags.get('URG', 0) if es_forward else 0
        flujo['flags_urg_bwd'] += flags.get('URG', 0) if not es_forward else 0
        
        # Ventana TCP
        if 'win_size' in paquete_info:
            if es_forward:
                if flujo['win_bytes_fwd'] == 0:
                    flujo['win_bytes_fwd'] = paquete_info['win_size']
            else:
                if flujo['win_bytes_bwd'] == 0:
                    flujo['win_bytes_bwd'] = paquete_info['win_size']
        
        flujo['ultimo_paquete'] = timestamp
    
    def obtener_caracteristicas_flujo(self, clave_flujo):
        """
        Extrae todas las características de un flujo en el formato del dataset
        
        Returns:
            dict: Diccionario con todas las características necesarias
        """
        flujo = self.flujos_activos[clave_flujo]
        
        # Calcular estadísticas básicas
        total_fwd_packets = len(flujo['paquetes_fwd'])
        total_bwd_packets = len(flujo['paquetes_bwd'])
        total_fwd_bytes = sum(flujo['paquetes_fwd'])
        total_bwd_bytes = sum(flujo['paquetes_bwd'])
        
        # Duración del flujo (en microsegundos)
        if flujo['inicio'] and flujo['ultimo_paquete']:
            flow_duration = (flujo['ultimo_paquete'] - flujo['inicio']).total_seconds() * 1000000
        else:
            flow_duration = 0
        
        # Estadísticas de tamaños de paquetes
        def calcular_estadisticas(lista):
            if len(lista) == 0:
                return 0, 0, 0, 0
            return max(lista), min(lista), np.mean(lista), np.std(lista) if len(lista) > 1 else 0
        
        fwd_max, fwd_min, fwd_mean, fwd_std = calcular_estadisticas(flujo['paquetes_fwd'])
        bwd_max, bwd_min, bwd_mean, bwd_std = calcular_estadisticas(flujo['paquetes_bwd'])
        
        # Estadísticas de IAT (Inter-Arrival Time)
        def calcular_iat_estadisticas(lista):
            if len(lista) == 0:
                return 0, 0, 0, 0, 0
            total = sum(lista)
            mean = np.mean(lista) if len(lista) > 0 else 0
            std = np.std(lista) if len(lista) > 1 else 0
            max_val = max(lista) if len(lista) > 0 else 0
            min_val = min(lista) if len(lista) > 0 else 0
            return total, mean, std, max_val, min_val
        
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = calcular_iat_estadisticas(flujo['tiempos_fwd'])
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = calcular_iat_estadisticas(flujo['tiempos_bwd'])
        
        # IAT del flujo completo
        todos_tiempos = flujo['tiempos_fwd'] + flujo['tiempos_bwd']
        flow_iat_mean = np.mean(todos_tiempos) if len(todos_tiempos) > 0 else 0
        flow_iat_std = np.std(todos_tiempos) if len(todos_tiempos) > 1 else 0
        flow_iat_max = max(todos_tiempos) if len(todos_tiempos) > 0 else 0
        flow_iat_min = min(todos_tiempos) if len(todos_tiempos) > 0 else 0
        
        # Bytes y paquetes por segundo
        if flow_duration > 0:
            flow_bytes_s = ((total_fwd_bytes + total_bwd_bytes) / flow_duration) * 1000000
            flow_packets_s = ((total_fwd_packets + total_bwd_packets) / flow_duration) * 1000000
            fwd_packets_s = (total_fwd_packets / flow_duration) * 1000000 if total_fwd_packets > 0 else 0
            bwd_packets_s = (total_bwd_packets / flow_duration) * 1000000 if total_bwd_packets > 0 else 0
        else:
            flow_bytes_s = 0
            flow_packets_s = 0
            fwd_packets_s = 0
            bwd_packets_s = 0
        
        # Tamaños de paquetes combinados
        todos_paquetes = flujo['paquetes_fwd'] + flujo['paquetes_bwd']
        min_packet_length = min(todos_paquetes) if len(todos_paquetes) > 0 else 0
        max_packet_length = max(todos_paquetes) if len(todos_paquetes) > 0 else 0
        packet_length_mean = np.mean(todos_paquetes) if len(todos_paquetes) > 0 else 0
        packet_length_std = np.std(todos_paquetes) if len(todos_paquetes) > 1 else 0
        packet_length_variance = packet_length_std ** 2
        
        # Construir diccionario de características (orden según el dataset)
        # Nota: Algunas características requieren análisis más profundo que simplificamos aquí
        caracteristicas = {
            ' Destination Port': 0,  # Se debe obtener del flujo
            ' Flow Duration': flow_duration,
            ' Total Fwd Packets': total_fwd_packets,
            ' Total Backward Packets': total_bwd_packets,
            'Total Length of Fwd Packets': total_fwd_bytes,
            ' Total Length of Bwd Packets': total_bwd_bytes,
            ' Fwd Packet Length Max': fwd_max,
            ' Fwd Packet Length Min': fwd_min,
            ' Fwd Packet Length Mean': fwd_mean,
            ' Fwd Packet Length Std': fwd_std,
            'Bwd Packet Length Max': bwd_max,
            ' Bwd Packet Length Min': bwd_min,
            ' Bwd Packet Length Mean': bwd_mean,
            ' Bwd Packet Length Std': bwd_std,
            'Flow Bytes/s': flow_bytes_s,
            ' Flow Packets/s': flow_packets_s,
            ' Flow IAT Mean': flow_iat_mean,
            ' Flow IAT Std': flow_iat_std,
            ' Flow IAT Max': flow_iat_max,
            ' Flow IAT Min': flow_iat_min,
            'Fwd IAT Total': fwd_iat_total,
            ' Fwd IAT Mean': fwd_iat_mean,
            ' Fwd IAT Std': fwd_iat_std,
            ' Fwd IAT Max': fwd_iat_max,
            ' Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            ' Bwd IAT Mean': bwd_iat_mean,
            ' Bwd IAT Std': bwd_iat_std,
            ' Bwd IAT Max': bwd_iat_max,
            ' Bwd IAT Min': bwd_iat_min,
            'Fwd PSH Flags': flujo['flags_psh_fwd'],
            ' Bwd PSH Flags': flujo['flags_psh_bwd'],
            ' Fwd URG Flags': flujo['flags_urg_fwd'],
            ' Bwd URG Flags': flujo['flags_urg_bwd'],
            ' Fwd Header Length': flujo['header_fwd'],
            ' Bwd Header Length': flujo['header_bwd'],
            'Fwd Packets/s': fwd_packets_s,
            ' Bwd Packets/s': bwd_packets_s,
            'Min Packet Length': min_packet_length,
            'Max Packet Length': max_packet_length,
            'Packet Length Mean': packet_length_mean,
            'Packet Length Std': packet_length_std,
            'Packet Length Variance': packet_length_variance,
            'FIN Flag Count': flujo['flags_fin'],
            'SYN Flag Count': flujo['flags_syn'],
            'RST Flag Count': flujo['flags_rst'],
            'PSH Flag Count': flujo['flags_psh_fwd'] + flujo['flags_psh_bwd'],
            'ACK Flag Count': 0,  # Requiere análisis más profundo
            'URG Flag Count': flujo['flags_urg_fwd'] + flujo['flags_urg_bwd'],
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': total_bwd_bytes / total_fwd_bytes if total_fwd_bytes > 0 else 0,
            'Average Packet Size': packet_length_mean,
            'Avg Fwd Segment Size': fwd_mean if total_fwd_packets > 0 else 0,
            'Avg Bwd Segment Size': bwd_mean if total_bwd_packets > 0 else 0,
            'Fwd Header Length': flujo['header_fwd'],
            'Fwd Avg Bytes/Bulk': 0,
            'Fwd Avg Packets/Bulk': 0,
            'Fwd Avg Bulk Rate': 0,
            'Bwd Avg Bytes/Bulk': 0,
            'Bwd Avg Packets/Bulk': 0,
            'Bwd Avg Bulk Rate': 0,
            'Subflow Fwd Packets': total_fwd_packets,
            'Subflow Fwd Bytes': total_fwd_bytes,
            'Subflow Bwd Packets': total_bwd_packets,
            'Subflow Bwd Bytes': total_bwd_bytes,
            'Init_Win_bytes_forward': flujo['win_bytes_fwd'],
            ' Init_Win_bytes_backward': flujo['win_bytes_bwd'],
            ' act_data_pkt_fwd': 0,
            ' min_seg_size_forward': fwd_min if total_fwd_packets > 0 else 0,
            'Active Mean': 0,
            ' Active Std': 0,
            ' Active Max': 0,
            ' Active Min': 0,
            'Idle Mean': 0,
            ' Idle Std': 0,
            ' Idle Max': 0,
            ' Idle Min': 0
        }
        
        return caracteristicas
    
    def limpiar_flujos_antiguos(self):
        """Elimina flujos que han excedido el timeout"""
        ahora = datetime.now()
        flujos_a_eliminar = []
        
        for clave, flujo in self.flujos_activos.items():
            if flujo['ultimo_paquete']:
                tiempo_desde_ultimo = (ahora - flujo['ultimo_paquete']).total_seconds()
                if tiempo_desde_ultimo > self.timeout_flujo:
                    flujos_a_eliminar.append(clave)
        
        for clave in flujos_a_eliminar:
            del self.flujos_activos[clave]
        
        return len(flujos_a_eliminar)

