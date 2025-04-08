import requests
import json
from datetime import datetime
import plotly.express as px

# Load the JSON file
url = "https://raw.githubusercontent.com/Jiyapanwar/cheel/main/data/Threats.json"
response = requests.get(url)
data = response.json()
# with open("Threats.json", "r", encoding="utf-8") as f:
#     data = json.load(f)

# Flatten and enrich the data
all_entries = []
for severity_level, entries in data.items():
    for entry in entries:
        entry["severity"] = severity_level  # fallback or label
        all_entries.append(entry)

# Extract data for plotting
plot_data = []
for entry in all_entries:
    if "exploitabilityScore" in entry and "publishedDate" in entry:
        plot_data.append({
            "Published Date": datetime.fromisoformat(entry["publishedDate"]),
            "Exploitability Score": entry["exploitabilityScore"],
            "Severity": entry.get("severity", "UNKNOWN"),
            "Attack Vector": entry.get("attackVector", "UNKNOWN")
        })

# Create a scatter plot with Plotly
fig = px.scatter(
    plot_data,
    x="Published Date",
    y="Exploitability Score",
    color="Attack Vector",               # Color by attack vector
    symbol="Severity",                   # Different symbol for each severity level
    title="Exploitability of Threats Over Time",
    labels={"Exploitability Score": "Exploitability Score"},
    hover_data=["Severity", "Attack Vector"]
)

fig.update_traces(marker=dict(size=8))
fig.show()