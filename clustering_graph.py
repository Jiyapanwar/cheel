import json
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# === Step 1: Load JSON Data ===
with open("data/Threats.json", "r") as file:
    data = json.load(file)

# === Step 2: Flatten Data ===
records = []
for group, items in data.items():
    for entry in items:
        records.append({
            "id": entry["id"],
            "description": entry["description"],
            "score": entry.get("exploitabilityScore", 0.0)
        })

df = pd.DataFrame(records)

# === Step 3: Vectorize Descriptions ===
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(df["description"])

# === Step 4: KMeans Clustering ===
k = 3  # adjust based on data
kmeans = KMeans(n_clusters=k, random_state=42)
df["cluster"] = kmeans.fit_predict(X)

# === Step 5: Optional Labeling ===
cluster_keywords = {
    0: "XSS & Scripting",
    1: "Sensitive Data Exposure",
    2: "Authorization Flaws"
}
df["label"] = df["cluster"].map(cluster_keywords)

# === Step 6: Export Grouped Data to JSON ===
grouped_json = {}

for _, row in df.iterrows():
    label = row["label"]
    if label not in grouped_json:
        grouped_json[label] = []
    grouped_json[label].append({
        "id": row["id"],
        "description": row["description"],
        "exploitabilityScore": row["score"]
    })

with open("grouped_threats.json", "w") as out_file:
    json.dump(grouped_json, out_file, indent=4)

print("✅ Exported grouped threats to 'grouped_threats.json'")

# === Step 7: Build Network Graph ===
G = nx.Graph()

# Add nodes and edges
for _, row in df.iterrows():
    G.add_node(row["id"], label=row["label"], desc=row["description"])
    same_cluster = df[df["cluster"] == row["cluster"]]
    for _, other in same_cluster.iterrows():
        if row["id"] != other["id"]:
            G.add_edge(row["id"], other["id"], cluster=row["cluster"])

# Draw the graph
plt.figure(figsize=(12, 8))
pos = nx.spring_layout(G, seed=42)

color_map = {
    0: "skyblue",
    1: "lightgreen",
    2: "lightcoral"
}
node_colors = [color_map[df[df["id"] == node]["cluster"].values[0]] for node in G.nodes]

nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.9)
nx.draw_networkx_edges(G, pos, alpha=0.5)
nx.draw_networkx_labels(G, pos, font_size=8)

plt.title("Cyberattack CVEs Grouped by Cluster Labels", fontsize=14)
plt.axis('off')
plt.tight_layout()
plt.show()