import React, { useEffect, useState } from "react";
import Plot from "react-plotly.js";
import axios from "axios";

const Dashboard: React.FC = () => {
  const [scatterData, setScatterData] = useState<any[]>([]);
  const [sankeyData, setSankeyData] = useState<any>(null);
  const [clusteringData, setClusteringData] = useState<any[]>([]);
  const [pieData, setPieData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await axios.get("/api/visuals");
        const { scatter, sankey, tsne, pie } = res.data;

        // Ensure pieData is an array and structure it correctly
        const formattedPieData = Array.isArray(pie) ? pie : [];

        setScatterData(scatter);
        setSankeyData(sankey);
        setClusteringData(tsne);
        setPieData(formattedPieData);
        setLoading(false);
      } catch (err: any) {
        console.error("Error fetching data:", err);
        setError("Failed to fetch data from backend.");
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) return <div className="text-center p-10 text-xl">Loading...</div>;
  if (error) return <div className="text-center p-10 text-xl text-red-500">Error: {error}</div>;

  return (
    <div className="flex min-h-screen bg-gray-100">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white p-6">
        <h2 className="text-3xl font-bold mb-6 text-center">Threat Dashboard</h2>
        <ul className="space-y-4">
          <li className="hover:bg-gray-700 p-2 rounded transition duration-300">
            <a href="#scatter">Exploitability Over Time</a>
          </li>
          <li className="hover:bg-gray-700 p-2 rounded transition duration-300">
            <a href="#sankey">Threat Flow</a>
          </li>
          <li className="hover:bg-gray-700 p-2 rounded transition duration-300">
            <a href="#clustering">Clustering of Cyberattacks</a>
          </li>
          <li className="hover:bg-gray-700 p-2 rounded transition duration-300">
            <a href="#pie">Attack Vector Distribution</a>
          </li>
        </ul>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 p-8">
        <div className="space-y-12">
          <h1 className="text-4xl font-bold text-center text-gray-800 mb-8">Threat Visualizations</h1>

          {/* Scatter Plot */}
          <div id="scatter" className="mb-12">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Exploitability Over Time</h2>
            <Plot
              data={[
                {
                  x: scatterData.map((item) => item["Published Date"]),
                  y: scatterData.map((item) => item["Exploitability Score"]),
                  text: scatterData.map(
                    (item) => `Severity: ${item.Severity}<br>Attack Vector: ${item["Attack Vector"]}`
                  ),
                  mode: "markers",
                  type: "scatter",
                  marker: { color: "rgb(255, 99, 132)", size: 10 },
                },
              ]}
              layout={{
                width : 1000,
                height: 500,
                title: "Exploitability of Threats Over Time",
                xaxis: { title: "Published Date" },
                yaxis: { title: "Exploitability Score" },
                paper_bgcolor: "rgb(245, 245, 245)",
                plot_bgcolor: "rgb(255, 255, 255)",
              }}
            />
          </div>

          {/* Sankey Diagram */}
          <div id="sankey" className="mb-12">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Threat Flow: Source → Tactic → Platform</h2>
            {sankeyData && sankeyData.labels ? (
              <Plot
                data={[
                  {
                    type: "sankey",
                    node: {
                      pad: 15,
                      thickness: 20,
                      line: { color: "black", width: 0.5 },
                      label: sankeyData.labels,
                    },
                    link: {
                      source: sankeyData.links.source,
                      target: sankeyData.links.target,
                      value: sankeyData.links.value,
                    },
                  },
                ]}
                layout={{
                  width : 1000,
                  height: 500,
                  title: "Threat Flow",
                  font: { size: 12 },
                  paper_bgcolor: "rgb(245, 245, 245)",
                  plot_bgcolor: "rgb(255, 255, 255)",
                }}
              />
            ) : (
              <div className="text-center text-gray-500">No Sankey data available</div>
            )}
          </div>

          {/* t-SNE Clustering */}
          <div id="clustering" className="mb-12">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Clustering of Cyberattacks (t-SNE + KMeans)</h2>
            <Plot
              data={[
                {
                  x: clusteringData.map((item) => item.x),
                  y: clusteringData.map((item) => item.y),
                  text: clusteringData.map(
                    (item) => `ID: ${item.id}<br>Label: ${item.label}<br>Score: ${item.score}`
                  ),
                  mode: "markers",
                  type: "scatter",
                  marker: {
                    size: 12,
                    color: clusteringData.map((item) => item.label),
                    colorscale: "Jet",
                  },
                },
              ]}
              layout={{
                width : 1000,
                height: 500,
                title: "Interactive Clustering of Cyberattacks",
                xaxis: { title: "TSNE X" },
                yaxis: { title: "TSNE Y" },
                paper_bgcolor: "rgb(245, 245, 245)",
                plot_bgcolor: "rgb(255, 255, 255)",
              }}
            />
          </div>

          {/* Attack Vector Pie Chart */}
          <div id="pie" className="mb-12">
            <h2 className="text-2xl font-semibold text-gray-700 mb-4">Attack Vector Distribution</h2>
            {Array.isArray(pieData) && pieData.length > 0 ? (
              <Plot
                data={[
                  {
                    type: "pie",
                    labels: pieData.map((item) => item["Attack Vector"]),
                    values: pieData.map((item) => item.Count),
                    hoverinfo: "label+percent+name",
                    textinfo: "percent",
                    pull: 0.03,
                  },
                ]}
                layout={{
                  width : 1000,
                  height: 500,
                  title: "Distribution of Attack Vectors in Threat Data",
                  paper_bgcolor: "rgb(245, 245, 245)",
                  plot_bgcolor: "rgb(255, 255, 255)",
                }}
              />
            ) : (
              <div className="text-center text-gray-500">No pie data available</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;








