# train_model_v2.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from url_features import extract_features

# --- Configuration ---
DATASET_PATH = 'raw_data.csv'      # ← your file name
SAMPLE_SIZE = 4000                  # 2000 legitimate + 2000 phishing

print("Loading dataset from", DATASET_PATH)
df = pd.read_csv(DATASET_PATH)

print(f"Total rows: {len(df)}")
print("Columns:", list(df.columns))
print("Label values:", df['label'].unique())

# Convert text labels to numbers
# legitimate -> 0, phishing -> 1
df['label_num'] = df['label'].apply(
    lambda x: 1 if str(x).strip().lower() == 'phishing' else 0
)

print("Label distribution after conversion:")
print(df['label_num'].value_counts())

# Sample a balanced subset (2000 of each)
legit_df = df[df['label_num'] == 0].sample(n=SAMPLE_SIZE // 2, random_state=42)
phish_df = df[df['label_num'] == 1].sample(n=SAMPLE_SIZE // 2, random_state=42)
balanced_df = pd.concat([legit_df, phish_df]).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\nTraining on a balanced subset of {len(balanced_df)} URLs.")
print("Extracting features from URLs... (this may take 1-2 minutes)")

feature_list = [extract_features(url) for url in balanced_df['url']]
features_df = pd.DataFrame(feature_list)

X = features_df
y = balanced_df['label_num']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training the upgraded model...")
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    max_depth=15,
    n_jobs=-1
)
model.fit(X_train, y_train)

print("Evaluating...")
y_pred = model.predict(X_test)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.2%}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

joblib.dump(model, 'phishing_model.pkl')
print("\n✅ Upgraded model saved as 'phishing_model.pkl'")