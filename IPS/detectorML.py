"""
Módulo de detección de intrusiones usando Machine Learning
"""
import joblib
import numpy as np
import os
import pandas as pd

class DetectorIPS:
    """Clase para detectar intrusiones usando el modelo ML entrenado"""
    
    def __init__(self):
        self.modelo = None
        self.label_encoder = None
        self.columnas_esperadas = None
        self.cargar_modelo()
    
    def cargar_modelo(self):
        """Carga el modelo y el encoder desde archivos"""
        carpeta_modelos = "IPS/Modelos"
        ruta_modelo = os.path.join(carpeta_modelos, "modelo_ips.pkl")
        ruta_encoder = os.path.join(carpeta_modelos, "label_encoder.pkl")
        
        try:
            if os.path.exists(ruta_modelo) and os.path.exists(ruta_encoder):
                self.modelo = joblib.load(ruta_modelo)
                self.label_encoder = joblib.load(ruta_encoder)
                
                # Cargar nombres de columnas desde el dataset original
                # Esto es necesario para asegurar el orden correcto
                dataset_path = "datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
                if os.path.exists(dataset_path):
                    df_sample = pd.read_csv(dataset_path, nrows=1)
                    df_sample.columns = df_sample.columns.str.strip()
                    self.columnas_esperadas = [col for col in df_sample.columns if col != 'Label']
                
                print("✅ Modelo ML cargado correctamente")
            else:
                print("⚠️  Modelo no encontrado. Ejecuta 'python IPS/entrenarModelo.py' primero")
        except Exception as e:
            print(f"❌ Error al cargar el modelo: {e}")
    
    def predecir(self, caracteristicas):
        """
        Predice si un flujo es benigno o un ataque
        
        Args:
            caracteristicas: DataFrame o diccionario con las características del flujo
            
        Returns:
            dict: {'prediccion': str, 'probabilidad': float, 'es_ataque': bool}
        """
        if self.modelo is None or self.label_encoder is None:
            return {
                'prediccion': 'Modelo no disponible',
                'probabilidad': 0.0,
                'es_ataque': False
            }
        
        try:
            # Convertir a DataFrame si es diccionario
            if isinstance(caracteristicas, dict):
                df = pd.DataFrame([caracteristicas])
            else:
                df = caracteristicas.copy()
            
            # Asegurar que las columnas estén en el orden correcto
            if self.columnas_esperadas:
                # Agregar columnas faltantes con valor 0
                for col in self.columnas_esperadas:
                    if col not in df.columns:
                        df[col] = 0
                # Reordenar columnas
                df = df[self.columnas_esperadas]
            
            # Limpiar valores infinitos y NaN
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(0)
            
            # Predecir
            prediccion_encoded = self.modelo.predict(df)[0]
            probabilidades = self.modelo.predict_proba(df)[0]
            
            # Decodificar etiqueta
            prediccion = self.label_encoder.inverse_transform([prediccion_encoded])[0]
            probabilidad = float(max(probabilidades))
            
            # Determinar si es ataque (todo lo que no sea BENIGN)
            es_ataque = prediccion != 'BENIGN'
            
            return {
                'prediccion': prediccion,
                'probabilidad': probabilidad,
                'es_ataque': es_ataque
            }
        except Exception as e:
            print(f"❌ Error en predicción: {e}")
            return {
                'prediccion': 'Error en predicción',
                'probabilidad': 0.0,
                'es_ataque': False
            }
    
    def esta_disponible(self):
        """Verifica si el modelo está cargado y listo para usar"""
        return self.modelo is not None and self.label_encoder is not None

