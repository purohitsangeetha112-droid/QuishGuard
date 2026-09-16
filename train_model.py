# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from url_features import extract_features

print("Loading dataset...")
df = pd.read_csv('phishing_urls.csv')

print("Extracting features from URLs...")
feature_list = [extract_features(url) for url in df['url']]
features_df = pd.DataFrame(feature_list)

X = features_df
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training the model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2%}")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

joblib.dump(model, 'phishing_model.pkl')
print("Model saved as 'phishing_model.pkl'")