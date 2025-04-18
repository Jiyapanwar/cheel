import axios from 'axios';
import Plotly from 'plotly.js-dist';
import { DateTime } from 'luxon';

// Fetch JSON data from the URL
const url = "https://raw.githubusercontent.com/Jiyapanwar/cheel/main/data/Threats.json";

async function fetchData() {
  try {
    const response = await axios.get(url);
    const data = response.data;

    // Flatten and enrich the data
    const allEntries: any[] = [];
    for (const [severityLevel, entries] of Object.entries(data)) {
      entries.forEach((entry: any) => {
        entry.severity = severityLevel; // fallback or label
        allEntries.push(entry);
      });
    }

    // Extract data for plotting
    const plotData = allEntries.map((entry: any) => {
      if ('exploitabilityScore' in entry && 'publishedDate' in entry) {
        return {
          'Published Date': DateTime.fromISO(entry.publishedDate).toJSDate(),
          'Exploitability Score': entry.exploitabilityScore,
          'Severity': entry.severity || 'UNKNOWN',
          'Attack Vector': entry.attackVector || 'UNKNOWN'
        };
      }
      return null;
    }).filter((entry: any) => entry !== null);

    // Create the scatter plot with Plotly
    const trace = {
      x: plotData.map((entry: any) => entry['Published Date']),
      y: plotData.map((entry: any) => entry['Exploitability Score']),
      mode: 'markers',
      type: 'scatter',
      marker: { size: 8 },
      text: plotData.map((entry: any) => `${entry['Severity']} | ${entry['Attack Vector']}`),
      hoverinfo: 'text',
      name: 'Exploitability'
    };

    const layout = {
      title: 'Exploitability of Threats Over Time',
      xaxis: { title: 'Published Date' },
      yaxis: { title: 'Exploitability Score' }
    };

    const plotDataForPlotly = [trace];

    Plotly.newPlot('plotly-div', plotDataForPlotly, layout);
  } catch (error) {
    console.error('Error fetching data:', error);
  }
}

// Call the function to fetch data and generate plot
fetchData();
