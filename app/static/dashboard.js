/**
 * CVRS Dashboard — Chart.js interactive features (Phase 2).
 *
 * Renders score distribution histogram, top-N table, and asset-type breakdown.
 * Supports dark/light theme toggle persisted in localStorage.
 */

document.addEventListener("DOMContentLoaded", () => {
  loadCharts();
  initExportButton();
});

// ── chart loading ─────────────────────────────────────────────────────────

async function loadCharts() {
  try {
    const resp = await fetch("/api/stats");
    if (!resp.ok) return;
    const data = await resp.json();
    renderScoreHistogram(data.score_distribution);
    renderAssetTypeChart(data.by_asset_type);
    renderExposureChart(data.by_exposure);
  } catch (err) {
    console.warn("Dashboard stats unavailable:", err);
  }
}

function renderScoreHistogram(distribution) {
  const ctx = document.getElementById("scoreHistogram");
  if (!ctx || !distribution || distribution.length === 0) return;

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: distribution.map((d) => d.range),
      datasets: [
        {
          label: "Evaluations",
          data: distribution.map((d) => d.count),
          backgroundColor: [
            "rgba(40,167,69,0.7)",
            "rgba(255,193,7,0.7)",
            "rgba(255,193,7,0.7)",
            "rgba(220,53,69,0.7)",
            "rgba(220,53,69,0.9)",
          ],
          borderColor: [
            "rgb(40,167,69)",
            "rgb(255,193,7)",
            "rgb(255,193,7)",
            "rgb(220,53,69)",
            "rgb(220,53,69)",
          ],
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: "Risk Score Distribution" },
        legend: { display: false },
      },
      scales: {
        y: { beginAtZero: true, title: { display: true, text: "Count" } },
        x: { title: { display: true, text: "Score Range" } },
      },
    },
  });
}

function renderAssetTypeChart(data) {
  const ctx = document.getElementById("assetTypeChart");
  if (!ctx || !data || data.length === 0) return;

  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: data.map((d) => d.asset_type.replace(/_/g, " ")),
      datasets: [
        {
          data: data.map((d) => d.count),
          backgroundColor: [
            "#0d6efd", "#6610f2", "#6f42c1", "#d63384",
            "#dc3545", "#fd7e14", "#ffc107", "#198754",
          ],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: "Evaluations by Asset Type" },
      },
    },
  });
}

function renderExposureChart(data) {
  const ctx = document.getElementById("exposureChart");
  if (!ctx || !data || data.length === 0) return;

  new Chart(ctx, {
    type: "pie",
    data: {
      labels: data.map((d) => d.asset_exposure),
      datasets: [
        {
          data: data.map((d) => d.count),
          backgroundColor: ["#dc3545", "#ffc107", "#198754"],
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        title: { display: true, text: "Evaluations by Exposure" },
      },
    },
  });
}

// ── CSV export ────────────────────────────────────────────────────────────

function initExportButton() {
  const btn = document.getElementById("export-csv");
  if (!btn) return;

  btn.addEventListener("click", () => {
    const rows = [];
    const table = document.querySelector("#eval-table");
    if (!table) return;

    // Gather visible rows
    table.querySelectorAll("tbody tr").forEach((tr) => {
      const cells = tr.querySelectorAll("td");
      const row = [];
      cells.forEach((td) => {
        // Use textContent, strip badges
        row.push(`"${td.textContent.trim().replace(/"/g, '""')}"`);
      });
      rows.push(row.join(","));
    });

    const header = [
      "CVE ID,Asset,Asset Type,Exposure,Criticality,LLM Threat,Final Score,Financial Impact,Evaluated",
    ];
    const csv = header.concat(rows).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cvrs-export-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });
}
