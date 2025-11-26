import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

carpeta_modelos = "IPS/Modelos"
os.makedirs(carpeta_modelos, exist_ok=True)

def cargar_y_preprocesar_datos(ruta_dataset):
    print("Cargando dataset...")
    df = pd.read_csv(ruta_dataset)
    
    print(f"  Dataset cargado: {df.shape[0]} filas, {df.shape[1]} columnas")
    
    df.columns = df.columns.str.strip()
    
    if 'Label' not in df.columns:
        print("Error: No se encontró la columna 'Label'")
        print(f"   Columnas disponibles: {list(df.columns[-5:])}")
        return None, None
    
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    print("Limpiando datos...")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    print("Codificando etiquetas...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"   Clases encontradas: {len(label_encoder.classes_)}")
    for i, clase in enumerate(label_encoder.classes_):
        count = np.sum(y_encoded == i)
        print(f"      - {clase}: {count} muestras")
    
    return X, y_encoded, label_encoder

def entrenar_modelo(X, y):
    print("\nDividiendo datos en entrenamiento y prueba...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"   Entrenamiento: {X_train.shape[0]} muestras")
    print(f"   Prueba: {X_test.shape[0]} muestras")
    
    print("\nEntrenando modelo Random Forest...")
    modelo = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    modelo.fit(X_train, y_train)
    
    print("\nEvaluando modelo...")
    y_pred = modelo.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nPrecision del modelo: {accuracy*100:.2f}%")
    print("\nReporte de clasificacion:")
    print(classification_report(y_test, y_pred))
    
    return modelo, X_test, y_test

def guardar_modelo(modelo, label_encoder, nombre_archivo="modelo_ips.pkl"):
    ruta_modelo = os.path.join(carpeta_modelos, nombre_archivo)
    ruta_encoder = os.path.join(carpeta_modelos, "label_encoder.pkl")
    
    joblib.dump(modelo, ruta_modelo)
    joblib.dump(label_encoder, ruta_encoder)
    
    print(f"\nModelo guardado en: {ruta_modelo}")
    print(f"Encoder guardado en: {ruta_encoder}")

def main():
    print("=" * 60)
    print("ENTRENAMIENTO DEL MODELO IPS - CICIDS2017")
    print("=" * 60)
    
    ruta_dataset = "datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    
    if not os.path.exists(ruta_dataset):
        print(f"Error: No se encontro el dataset en {ruta_dataset}")
        print("   Asegúrate de que el archivo CSV esté en la carpeta 'datasets'")
        return
    
    resultado = cargar_y_preprocesar_datos(ruta_dataset)
    if resultado[0] is None:
        return
    
    X, y, label_encoder = resultado
    
    modelo, X_test, y_test = entrenar_modelo(X, y)
    
    guardar_modelo(modelo, label_encoder)
    
    print("\n" + "=" * 60)
    print("ENTRENAMIENTO COMPLETADO")
    print("=" * 60)
    print("\nProximos pasos:")
    print("   1. El modelo está listo para usar en detección en tiempo real")
    print("   2. Ejecuta 'python IPS/detectorML.py' para probar el modelo")
    print("   3. El modelo se usará automáticamente en capturaRed.py")

if __name__ == "__main__":
    main()

