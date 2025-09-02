// Threat & Phishing Counters
let threatCount = 0;
let phishingCount = 0;

function addAlert(message) {
  const list = document.getElementById("alertList");
  const item = document.createElement("li");
  item.textContent = message;
  list.prepend(item);
}

// Simulate real-time attacks
setInterval(() => {
  threatCount++;
  document.getElementById("threatCount").innerText = threatCount;
  addAlert("🚨 New ransomware attempt detected!");
}, 7000);

setInterval(() => {
  phishingCount++;
  document.getElementById("phishingCount").innerText = phishingCount;
  addAlert("⚠️ Phishing email blocked!");
}, 10000);

// Attack Chart
const ctx1 = document.getElementById('attackChart').getContext('2d');
new Chart(ctx1, {
  type: 'bar',
  data: {
    labels: ["Ransomware", "Phishing", "DDoS", "Insider Threats"],
    datasets: [{
      label: 'Detected Attacks',
      data: [12, 19, 7, 5],
      backgroundColor: ['#dc2626','#fbbf24','#3b82f6','#22c55e']
    }]
  }
});

// Network Traffic Chart
const ctx2 = document.getElementById('trafficChart').getContext('2d');
new Chart(ctx2, {
  type: 'line',
  data: {
    labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    datasets: [{
      label: 'Network Traffic (GB)',
      data: [20, 25, 18, 30, 22, 27, 35],
      borderColor: '#3b82f6',
      fill: true,
      backgroundColor: 'rgba(59, 130, 246, 0.3)'
    }]
  }
});
