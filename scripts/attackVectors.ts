// @ts-ignore
import Plotly from 'plotly.js-dist';

// Mockup of loading your JSON data
// In a real scenario, you might use fetch() to load the data from a file or API
import * as fs from 'fs';

const loadJSONData = (): any => {
  const data = JSON.parse(fs.readFileSync('Threats.json', 'utf-8'));
  return data;
}

// Flatten out all items from all categories
const flattenData = (data: any): any[] => {
  let allItems: any[] = [];
  for (let category of Object.values(data)) {
    allItems = allItems.concat(category);
  }
  return allItems;
}

// Extract attack vectors and count their occurrences
const getAttackVectorCounts = (data: any[]): { [key: string]: number } => {
  let attackVectors: string[] = [];
  for (let item of data) {
    attackVectors.push(item.attackVector || 'UNKNOWN');
  }
  
  const vectorCounts: { [key: string]: number } = {};
  attackVectors.forEach((vector) => {
    vectorCounts[vector] = (vectorCounts[vector] || 0) + 1;
  });

  return vectorCounts;
}

// Prepare data for Plotly pie chart
const preparePlotlyData = (vectorCounts: { [key: string]: number }) => {
  const labels = Object.keys(vectorCounts);
  const counts = Object.values(vectorCounts);

  return {
    labels,
    values: counts
  };
}

// Create the pie chart using Plotly
const createPieChart = (data: { labels: string[], values: number[] }) => {
  const trace = {
    labels: data.labels,
    values: data.values,
    type: 'pie',
    textinfo: 'percent',
    pull: new Array(data.labels.length).fill(0.03) // Pull the slices out slightly
  };

  const layout = {
    title: 'Distribution of Attack Vectors in Threat Data',
    showlegend: true
  };

  const graphData = [trace];
  
  Plotly.newPlot('graph-container', graphData, layout);
}

// Main function to run everything
const main = () => {
  const data = loadJSONData();
  const flattenedData = flattenData(data);
  const vectorCounts = getAttackVectorCounts(flattenedData);
  const plotData = preparePlotlyData(vectorCounts);
  
  createPieChart(plotData);
}

// Run the main function
main();