import json
import plotly.express as px
from collections import Counter

# Load the JSON file
with open("../data/Threats.json", encoding='utf-8') as f:
    data = json.load(f)

# Flatten out all items from all keys
all_items = []
for category in data.values():
    all_items.extend(category)

# Extract attack vectors
attack_vectors = []
for item in all_items:
    attack_vectors.append(item.get("attackVector", "UNKNOWN"))

# Count attack vectors
vector_counts = Counter(attack_vectors)
labels = list(vector_counts.keys())
counts = list(vector_counts.values())

# Build a DataFrame for Plotly
import pandas as pd
df = pd.DataFrame({
    "Attack Vector": labels,
    "Count": counts
})

# Create interactive pie chart
fig = px.pie(
    df,
    names='Attack Vector',
    values='Count',
    title='Distribution of Attack Vectors in Threat Data',
    color_discrete_sequence=px.colors.qualitative.Set3,
    hover_data=["Attack Vector", "Count"]
)

fig.update_traces(textinfo='percent', pull=0.03)

fig.show()