const buttons = document.querySelectorAll("[data-copy]");

async function copyCommand(button) {
  const command = button.dataset.copy;
  const label = button.querySelector("[data-copy-label]");

  try {
    await navigator.clipboard.writeText(command);
    label.textContent = "Copied";
  } catch {
    label.textContent = "Select";
  }

  window.setTimeout(() => {
    label.textContent = "Copy";
  }, 1800);
}

for (const button of buttons) {
  button.addEventListener("click", () => copyCommand(button));
}
