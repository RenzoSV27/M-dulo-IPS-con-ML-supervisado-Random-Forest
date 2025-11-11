"""
Script para entrenar el modelo de Machine Learning usando el dataset CICIDS2017
"""
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

# Rutas
carpeta_modelos = "IPS/Modelos"
os.makedirs(carpeta_modelos, exist_ok=True)

def cargar_y_preprocesar_datos(ruta_dataset):
    """Carga y preprocesa el dataset CICIDS2017"""
    print("📂 Cargando dataset...")
    df = pd.read_csv(ruta_dataset)
    
    print(f"   Dataset cargado: {df.shape[0]} filas, {df.shape[1]} columnas")
    
    # Limpiar nombres de columnas (eliminar espacios)
    df.columns = df.columns.str.strip()
    
    # Verificar que existe la columna Label
    if 'Label' not in df.columns:
        print("❌ Error: No se encontró la columna 'Label'")
        print(f"   Columnas disponibles: {list(df.columns[-5:])}")
        return None, None
    
    # Separar características y etiquetas
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Limpiar datos: eliminar valores infinitos y NaN
    print("🧹 Limpiando datos...")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    
    # Codificar etiquetas
    print("🏷️  Codificando etiquetas...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"   Clases encontradas: {len(label_encoder.classes_)}")
    for i, clase in enumerate(label_encoder.classes_):
        count = np.sum(y_encoded == i)
        print(f"      - {clase}: {count} muestras")
    
    return X, y_encoded, label_encoder

def entrenar_modelo(X, y):
    """Entrena un modelo Random Forest"""
    print("\n🔄 Dividiendo datos en entrenamiento y prueba...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"   Entrenamiento: {X_train.shape[0]} muestras")
    print(f"   Prueba: {X_test.shape[0]} muestras")
    
    print("\n🌲 Entrenando modelo Random Forest...")
    modelo = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    modelo.fit(X_train, y_train)
    
    print("\n📊 Evaluando modelo...")
    y_pred = modelo.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ Precisión del modelo: {accuracy*100:.2f}%")
    print("\n📋 Reporte de clasificación:")
    print(classification_report(y_test, y_pred))
    
    return modelo, X_test, y_test

def guardar_modelo(modelo, label_encoder, nombre_archivo="modelo_ips.pkl"):
    """Guarda el modelo y el encoder"""
    ruta_modelo = os.path.join(carpeta_modelos, nombre_archivo)
    ruta_encoder = os.path.join(carpeta_modelos, "label_encoder.pkl")
    
    joblib.dump(modelo, ruta_modelo)
    joblib.dump(label_encoder, ruta_encoder)
    
    print(f"\n💾 Modelo guardado en: {ruta_modelo}")
    print(f"💾 Encoder guardado en: {ruta_encoder}")

def main():
    """Función principal"""
    print("=" * 60)
    print("🚀 ENTRENAMIENTO DEL MODELO IPS - CICIDS2017")
    print("=" * 60)
    
    # Buscar el dataset
    ruta_dataset = "datasets/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    
    if not os.path.exists(ruta_dataset):
        print(f"❌ Error: No se encontró el dataset en {ruta_dataset}")
        print("   Asegúrate de que el archivo CSV esté en la carpeta 'datasets'")
        return
    
    # Cargar y preprocesar
    resultado = cargar_y_preprocesar_datos(ruta_dataset)
    if resultado[0] is None:
        return
    
    X, y, label_encoder = resultado
    
    # Entrenar modelo
    modelo, X_test, y_test = entrenar_modelo(X, y)
    
    # Guardar modelo
    guardar_modelo(modelo, label_encoder)
    
    print("\n" + "=" * 60)
    print("✅ ENTRENAMIENTO COMPLETADO")
    print("=" * 60)
    print("\n💡 Próximos pasos:")
    print("   1. El modelo está listo para usar en detección en tiempo real")
    print("   2. Ejecuta 'python IPS/detectorML.py' para probar el modelo")
    print("   3. El modelo se usará automáticamente en capturaRed.py")

if __name__ == "__main__":
    main()

