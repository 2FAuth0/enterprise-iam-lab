const feedback = document.querySelector("#feedback");

for (const form of document.querySelectorAll("form[data-method]")) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    feedback.textContent = "Working…";

    try {
      const response = await fetch(form.action, {
        method: form.dataset.method,
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content,
        },
        body: JSON.stringify(Object.fromEntries(new FormData(form))),
      });
      const result = await response.json();
      if (!response.ok) {
        feedback.textContent = typeof result.detail === "string"
          ? result.detail
          : "Check the entered values and retry.";
      } else if (form.action.endsWith("/logout")) {
        window.location.assign(result.redirect);
      } else {
        feedback.textContent = "Saved.";
        if (form.elements.title) form.elements.title.value = result.title;
      }
    } catch {
      feedback.textContent = "The request could not be completed.";
    } finally {
      button.disabled = false;
    }
  });
}
