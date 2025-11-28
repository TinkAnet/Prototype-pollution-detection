import { simulateWealth } from './simulate.js';

document.querySelectorAll('.sim-example').forEach(div => {
  const params = JSON.parse(div.dataset.params);
  const paramsDisplay = document.createElement('div');
  paramsDisplay.textContent = `Gain: ${params.gain}, Loss: ${params.loss}, ProbGain: ${params.probGain}, Years: ${params.years}, Simulations: ${params.simulations}`;
  paramsDisplay.style.marginBottom = '10px';
  div.parentNode.insertBefore(paramsDisplay, div);

  div.style.cursor = 'pointer';
  simulateWealth({ ...params, target: div });
  div.addEventListener('dblclick', () => {
    simulateWealth({ ...params, target: document.getElementById('main-sim') });
    document.getElementById('gain').value = params.gain;
    document.getElementById('loss').value = params.loss;
    document.getElementById('probGain').value = params.probGain;
    document.getElementById('years').value = params.years;
    document.getElementById('simulations').value = params.simulations;
  });
});

document.getElementById('sim-form').addEventListener('submit', e => {
  e.preventDefault();
  const gain = parseFloat(document.getElementById('gain').value);
  const loss = parseFloat(document.getElementById('loss').value);
  const probGain = parseFloat(document.getElementById('probGain').value);
  const years = parseInt(document.getElementById('years').value);
  const simulations = parseInt(document.getElementById('simulations').value);
  simulateWealth({ gain, loss, probGain, years, simulations, target: document.getElementById('main-sim') });
});

const firstParams = JSON.parse(document.querySelector('.sim-example').dataset.params);
simulateWealth({ ...firstParams, target: document.getElementById('main-sim') });

document.addEventListener("DOMContentLoaded", () => {
  const permalinkInput = document.getElementById("permalink");
  const copyButton = document.getElementById("copy-permalink");
  const openButton = document.getElementById("open-permalink");
  const simForm = document.getElementById("sim-form");

  function updatePermalink() {
    const params = new URLSearchParams();
    params.set("gain", document.getElementById("gain").value);
    params.set("loss", document.getElementById("loss").value);
    params.set("probGain", document.getElementById("probGain").value);
    params.set("years", document.getElementById("years").value);
    params.set("simulations", document.getElementById("simulations").value);

    const permalink = `${window.location.origin}${window.location.pathname.replace(/\/[^/]*$/, "/sim.html")}?${params.toString()}`;
    permalinkInput.value = permalink;
  }

  simForm.addEventListener("input", updatePermalink);
  updatePermalink();

  copyButton.addEventListener("click", () => {
    navigator.clipboard.writeText(permalinkInput.value).then(() => {
      alert("Permalink copied to clipboard!");
    });
  });

  openButton.addEventListener("click", () => {
    window.open(permalinkInput.value, "_blank");
  });
});