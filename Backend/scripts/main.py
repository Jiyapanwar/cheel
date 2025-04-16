from flask import Flask, jsonify
from flask_cors import CORS
import json
import os
import requests
from datetime import datetime
from collections import defaultdict, Counter
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.manifold import TSNE

app = Flask(__name__)
CORS(app)

# Load Threat JSON from remote URL or local fallback
def load_threat_data():
    try:
        url = "https://raw.githubusercontent.com/Jiyapanwar/cheel/main/data/Threats.json"
        response = requests.get(url)
        return response.json()
    except Exception:
        with open("data/Threats.json", "r", encoding="utf-8") as f:
            return json.load(f)

# 📌 Scatter Data
@app.route("/api/scatter")
def scatter():
    data = load_threat_data()
    entries = []
    for level, items in data.items():
        for entry in items:
            if "exploitabilityScore" in entry and "publishedDate" in entry:
                entries.append({
                    "Published Date": datetime.fromisoformat(entry["publishedDate"]).isoformat(),
                    "Exploitability Score": entry["exploitabilityScore"],
                    "Severity": level,
                    "Attack Vector": entry.get("attackVector", "UNKNOWN")
                })
    return jsonify(entries)

# 📌 Sankey Diagram Data
@app.route("/api/sankey")
def sankey():
    data = load_threat_data()
    nodes, node_index = [], {}
    links = []
    counts = defaultdict(int)

    def get_index(name):
        if name not in node_index:
            node_index[name] = len(nodes)
            nodes.append(name)
        return node_index[name]

    for tactic, entries in data.items():
        for entry in entries:
            src = entry.get("source", "Unknown")
            platforms = entry.get("platforms", ["Unknown"])
            i_src = get_index(src)
            i_tactic = get_index(tactic)
            counts[(i_src, i_tactic)] += 1
            for platform in platforms:
                i_plat = get_index(platform)
                counts[(i_tactic, i_plat)] += 1

    links_dict = {
        "source": [],
        "target": [],
        "value": []
    }

    for (src, tgt), val in counts.items():
        links_dict["source"].append(src)
        links_dict["target"].append(tgt)
        links_dict["value"].append(val)

    return jsonify({
        "nodes": nodes,
        "links": links_dict
    })

# 📌 Clustering (t-SNE) Data
@app.route("/api/clustering")
def clustering():
    data = load_threat_data()
    records = []
    for group, items in data.items():
        for entry in items:
            records.append({
                "id": entry["id"],
                "description": entry["description"],
                "score": entry.get("exploitabilityScore", 0.0)
            })

    df = pd.DataFrame(records)

    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(df["description"])
    kmeans = KMeans(n_clusters=3, random_state=42)
    df["cluster"] = kmeans.fit_predict(X)

    labels_map = {
        0: "XSS & Scripting",
        1: "Sensitive Data Exposure",
        2: "Authorization Flaws"
    }
    df["label"] = df["cluster"].map(labels_map)

    tsne = TSNE(n_components=2, perplexity=30, random_state=42)
    tsne_result = tsne.fit_transform(X.toarray())

    df["x"] = tsne_result[:, 0]
    df["y"] = tsne_result[:, 1]

    return jsonify(df[["x", "y", "label", "id", "description", "score"]].to_dict(orient="records"))

# 📌 Attack Vector Pie Chart
@app.route("/api/attack-vectors")
def attack_vectors():
    data = load_threat_data()
    all_items = [item for sublist in data.values() for item in sublist]
    vectors = [item.get("attackVector", "UNKNOWN") for item in all_items]
    count = Counter(vectors)

    # Adjust the response structure to match the frontend's expected format
    pie_data = [{"Attack Vector": key, "Count": value} for key, value in count.items()]

    return jsonify(pie_data)

# 📌 Combined Endpoint
@app.route("/api/visuals")
def visuals():
    scatter_data = scatter().get_json()
    sankey_data = sankey().get_json()
    tsne_data = clustering().get_json()
    pie_data = attack_vectors().get_json()

    return jsonify({
        "scatter": scatter_data,
        "sankey": {
            "labels": sankey_data["nodes"],
            "links": sankey_data["links"]
        },
        "tsne": tsne_data,
        "pie": pie_data
    })

# Run the app
if __name__ == "__main__":
    app.run(debug=True)



