import joblib
import numpy as np
import os
import pandas as pd

class DetectorIPS:
    def __init__(self):
        self.modelo = None
        self.label_encoder = None
        self.columnas_esperadas = None
        self.cargar_modelo()
    
    def cargar_modelo(self):
        carpeta_modelos = "IPS/Modelos"
        ruta_modelo = os.path.join(carpeta_modelos, "modelo_ips.pkl")
        ruta_encoder = os.path.join(carpeta_modelos, "label_encoder.pkl")
        
        try:
            if os.path.exists(ruta_modelo) and os.path.exists(ruta_encoder):
                self.modelo = joblib.load(ruta_modelo)
                self.label_encoder = joblib.load(ruta_encoder)
                
                dataset_path = "datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
                if os.path.exists(dataset_path):
                    df_sample = pd.read_csv(dataset_path, nrows=1)
                    df_sample.columns = df_sample.columns.str.strip()
                    self.columnas_esperadas = [col for col in df_sample.columns if col != 'Label']
                
                print("Modelo ML cargado correctamente")
            else:
                print("Modelo no encontrado. Ejecuta 'python IPS/entrenarModelo.py' primero")
        except Exception as e:
            print(f"Error al cargar el modelo: {e}")
    
    def predecir(self, caracteristicas):
        if self.modelo is None or self.label_encoder is None:
            return {
                'prediccion': 'Modelo no disponible',
                'probabilidad': 0.0,
                'es_ataque': False
            }
        
        try:
            if isinstance(caracteristicas, dict):
                df = pd.DataFrame([caracteristicas])
            else:
                df = caracteristicas.copy()
            
            if self.columnas_esperadas:
                for col in self.columnas_esperadas:
                    if col not in df.columns:
                        df[col] = 0
                df = df[self.columnas_esperadas]
            
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(0)
            
            prediccion_encoded = self.modelo.predict(df)[0]
            probabilidades = self.modelo.predict_proba(df)[0]
            
            prediccion = self.label_encoder.inverse_transform([prediccion_encoded])[0]
            probabilidad = float(max(probabilidades))
            
            es_ataque = prediccion != 'BENIGN'
            
            return {
                'prediccion': prediccion,
                'probabilidad': probabilidad,
                'es_ataque': es_ataque
            }
        except Exception as e:
            print(f"Error en prediccion: {e}")
            return {
                'prediccion': 'Error en prediccion',
                'probabilidad': 0.0,
                'es_ataque': False
            }
    
    def esta_disponible(self):
        return self.modelo is not None and self.label_encoder is not None

