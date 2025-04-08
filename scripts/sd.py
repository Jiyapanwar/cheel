import json
from collections import defaultdict
import plotly.graph_objects as go

# Load the JSON data
with open("Threats.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Prepare nodes and links for the Sankey diagram
nodes = []
node_index = {}
links = []

# Helper function to get index of node, add if doesn't exist
def get_node_index(name):
    if name not in node_index:
        node_index[name] = len(nodes)
        nodes.append(name)
    return node_index[name]

# Build links: Source -> Tactic -> Platform
link_counts = defaultdict(int)

for tactic, entries in data.items():
    for entry in entries:
        source = entry.get("source", "Unknown")
        platforms = entry.get("platforms", ["Unknown"])
        
        source_idx = get_node_index(source)
        tactic_idx = get_node_index(tactic)
        
        # Link from source to tactic
        link_counts[(source_idx, tactic_idx)] += 1
        
        for platform in platforms:
            platform_idx = get_node_index(platform)
            # Link from tactic to platform
            link_counts[(tactic_idx, platform_idx)] += 1

# Convert to Plotly Sankey format
sankey_links = {
    "source": [],
    "target": [],
    "value": []
}

for (src, tgt), val in link_counts.items():
    sankey_links["source"].append(src)
    sankey_links["target"].append(tgt)
    sankey_links["value"].append(val)

# Create Sankey diagram
fig = go.Figure(data=[go.Sankey(
    node=dict(
        pad=15,
        thickness=20,
        line=dict(color="black", width=0.5),
        label=nodes
    ),
    link=sankey_links
)])

fig.update_layout(title_text="Threat Flow: Source → Tactic → Platform", font_size=12)
fig.show()