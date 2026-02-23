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

function setupTickerLoop() {
  const tracks = document.querySelectorAll(".ticker-track");
  tracks.forEach((track) => {
    if (track.dataset.cloned === "1") return;
    track.innerHTML += track.innerHTML;
    track.dataset.cloned = "1";
  });
}

function setupTiltCards() {
  const cards = document.querySelectorAll("[data-tilt]");
  cards.forEach((card) => {
    const reset = () => {
      card.style.transform = "";
    };

    card.addEventListener("mousemove", (event) => {
      const rect = card.getBoundingClientRect();
      const px = (event.clientX - rect.left) / rect.width;
      const py = (event.clientY - rect.top) / rect.height;
      const rotateY = (px - 0.5) * 8;
      const rotateX = (0.5 - py) * 8;
      card.style.transform = `perspective(700px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-3px)`;
    });

    card.addEventListener("mouseleave", reset);
    card.addEventListener("blur", reset);
  });
}

function setupHeroParallax() {
  const hero = document.querySelector("[data-parallax]");
  if (!hero) return;
  hero.addEventListener("mousemove", (event) => {
    const rect = hero.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const y = (event.clientY - rect.top) / rect.height - 0.5;
    hero.style.transform = `translate3d(${x * 6}px, ${y * 6}px, 0)`;
  });
  hero.addEventListener("mouseleave", () => {
    hero.style.transform = "";
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setupRevealAnimations();
  setupCountUp();
  setupTableFilters();
  setupFaqAccordion();
  setupTickerLoop();
  setupTiltCards();
  setupHeroParallax();
});
