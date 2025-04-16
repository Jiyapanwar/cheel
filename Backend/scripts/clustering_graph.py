import json
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.manifold import TSNE
import os

# === Load JSON Data ===
with open("../data/Threats.json", encoding="utf-8") as file:
    data = json.load(file)

# === Flatten JSON into Records ===
records = []
for group, items in data.items():
    for entry in items:
        records.append({
            "id": entry["id"],
            "description": entry["description"],
            "score": entry.get("exploitabilityScore", 0.0)
        })

df = pd.DataFrame(records)

# === Vectorize Descriptions ===
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(df["description"])

# === Apply KMeans Clustering ===
k = 3
kmeans = KMeans(n_clusters=k, random_state=42)
df["cluster"] = kmeans.fit_predict(X)

# Optional Cluster Labels
cluster_keywords = {
    0: "XSS & Scripting",
    1: "Sensitive Data Exposure",
    2: "Authorization Flaws"
}
df["label"] = df["cluster"].map(cluster_keywords)

# === t-SNE for Visualization ===
tsne = TSNE(n_components=2, perplexity=30, random_state=42)
X_tsne = tsne.fit_transform(X.toarray())
df["x"] = X_tsne[:, 0]
df["y"] = X_tsne[:, 1]

# === 🔹 Interactive Plot using Plotly ===
fig = px.scatter(
    df, x="x", y="y",
    color="label",
    hover_data=["id", "description", "score"],
    title="Interactive Clustering of Cyberattacks (t-SNE + KMeans)",
    labels={"label": "Threat Cluster"},
    width=1000,
    height=600
)
fig.show()
fig.write_html("plot.html")


# === 🔹 Export Each Cluster to CSV ===
os.makedirs("clusters_csv", exist_ok=True)
for label in df["label"].unique():
    cluster_df = df[df["label"] == label]
    filename = f"clusters_csv/{label.replace(' ', '_').lower()}.csv"
    cluster_df.to_csv(filename, index=False)
    print(f"✅ Saved: {filename}")

# === 🔹 Bar Chart for Average Exploitability Score ===
avg_scores = df.groupby("label")["score"].mean().sort_values()

plt.figure(figsize=(10, 6))
sns.barplot(x=avg_scores.index, y=avg_scores.values, palette="Set2")
plt.title("Average Exploitability Score per Cluster", fontsize=14)
plt.ylabel("Average Score")
plt.xlabel("Cluster")
plt.xticks(rotation=20)
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("avg_exploitability_scores.png")
plt.show()

print("✅ Bar chart saved as 'avg_exploitability_scores.png'")


# import json
# import pandas as pd
# import plotly.express as px
# import matplotlib.pyplot as plt
# import seaborn as sns
# from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.cluster import KMeans
# from sklearn.manifold import TSNE
# import os
# import numpy as np

# # === Load JSON Data ===
# with open("data/Threats.json", "r") as file:
#     data = json.load(file)

# # === Flatten JSON into Records ===
# records = []
# for group, items in data.items():
#     for entry in items:
#         records.append({
#             "id": entry["id"],
#             "description": entry["description"],
#             "score": entry.get("exploitabilityScore", 0.0)
#         })

# df = pd.DataFrame(records)

# # === Vectorize Descriptions ===
# vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
# X = vectorizer.fit_transform(df["description"])

# # === Apply KMeans Clustering ===
# k = 3
# kmeans = KMeans(n_clusters=k, random_state=42)
# df["cluster"] = kmeans.fit_predict(X)

# # === Generate Mixed Cluster Labels (Dynamic + Manual) ===
# manual_keywords = {
#     0: "attack",
#     1: "vulnerability",
#     2: "breach"
# }

# def extract_keywords_per_cluster(X, labels, feature_names, top_n=3):
#     cluster_keywords = {}
#     for cluster_num in range(k):
#         cluster_indices = np.where(labels == cluster_num)[0]
#         cluster_matrix = X[cluster_indices].mean(axis=0)
#         cluster_array = np.asarray(cluster_matrix).flatten()
#         top_indices = cluster_array.argsort()[-top_n:][::-1]
#         tfidf_keywords = [feature_names[i] for i in top_indices]
#         final_label = ", ".join(tfidf_keywords + [manual_keywords.get(cluster_num, "")])
#         cluster_keywords[cluster_num] = final_label.strip(", ")
#     return cluster_keywords

# feature_names = vectorizer.get_feature_names_out()
# mixed_keywords = extract_keywords_per_cluster(X, df["cluster"].values, feature_names)

# df["label"] = df["cluster"].map(mixed_keywords)

# # === t-SNE for Visualization ===
# tsne = TSNE(n_components=2, perplexity=30, random_state=42)
# X_tsne = tsne.fit_transform(X.toarray())
# df["x"] = X_tsne[:, 0]
# df["y"] = X_tsne[:, 1]

# # === 🔹 Interactive Plot using Plotly ===
# fig = px.scatter(
#     df, x="x", y="y",
#     color="label",
#     hover_data=["id", "description", "score"],
#     title="Interactive Clustering of Cyberattacks (t-SNE + KMeans)",
#     labels={"label": "Threat Cluster"},
#     width=1000,
#     height=600
# )
# fig.show()
# fig.write_html("plot.html")

# # === 🔹 Export Each Cluster to CSV ===
# os.makedirs("clusters_csv", exist_ok=True)
# for label in df["label"].unique():
#     cluster_df = df[df["label"] == label]
#     filename = f"clusters_csv/{label.replace(',', '').replace(' ', '_').lower()}.csv"
#     cluster_df.to_csv(filename, index=False)
#     print(f"✅ Saved: {filename}")

# # === 🔹 Bar Chart for Average Exploitability Score ===
# avg_scores = df.groupby("label")["score"].mean().sort_values()

# plt.figure(figsize=(10, 6))
# sns.barplot(x=avg_scores.index, y=avg_scores.values, palette="Set2")
# plt.title("Average Exploitability Score per Cluster", fontsize=14)
# plt.ylabel("Average Score")
# plt.xlabel("Cluster")
# plt.xticks(rotation=20)
# plt.grid(axis="y", linestyle="--", alpha=0.7)
# plt.tight_layout()
# plt.savefig("avg_exploitability_scores.png")
# plt.show()

# print("✅ Bar chart saved as 'avg_exploitability_scores.png'")
