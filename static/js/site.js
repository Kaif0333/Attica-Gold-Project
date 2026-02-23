function setupRevealAnimations() {
  const nodes = document.querySelectorAll(".reveal");
  if (!nodes.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );

  nodes.forEach((n) => observer.observe(n));
}

function setupCountUp() {
  const counters = document.querySelectorAll("[data-count]");
  counters.forEach((node) => {
    const target = Number(node.getAttribute("data-count"));
    if (!Number.isFinite(target)) return;

    const duration = 900;
    const start = performance.now();

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const value = Math.floor(target * progress);
      node.textContent = value.toLocaleString();
      if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
  });
}

function setupTableFilters() {
  const filters = document.querySelectorAll("[data-filter-target]");
  filters.forEach((input) => {
    const selector = input.getAttribute("data-filter-target");
    const table = document.querySelector(selector);
    if (!table) return;

    const rows = table.querySelectorAll("tbody tr");
    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      rows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? "" : "none";
      });
    });
  });
}

function setupFaqAccordion() {
  const items = document.querySelectorAll("[data-accordion]");
  items.forEach((item) => {
    const trigger = item.querySelector("[data-accordion-trigger]");
    if (!trigger) return;
    trigger.addEventListener("click", () => {
      item.classList.toggle("open");
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setupRevealAnimations();
  setupCountUp();
  setupTableFilters();
  setupFaqAccordion();
});
