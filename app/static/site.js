/* Shared behaviour for the pages around the console.

   Every entrance animates transform only, never opacity. An opacity entrance
   that never gets its frame leaves the page permanently invisible, which is
   exactly what happened three times in the console's graph view. Elements are
   laid out correct and visible first; animation is decoration on top. */

(function () {
  "use strict";

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Who is signed in — so the nav says "Dashboard" rather than "Sign in", and
  // the page stops offering an account to someone who already has one.
  fetch("/api/auth/me", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((d) => {
      const slot = document.getElementById("navauth");
      if (slot && d.signed_in) {
        const name = (d.user.display_name || d.user.email).replace(/[<>&]/g, "");
        slot.innerHTML = `<a href="/">Dashboard</a> <a href="/settings">${name}</a>`;
      }
      const anon = document.getElementById("cta-anon");
      const user = document.getElementById("cta-user");
      if (anon && user) {
        anon.hidden = d.signed_in;
        user.hidden = !d.signed_in;
      }
    })
    .catch(() => {});

  if (reduced || typeof anime === "undefined") return;

  anime({
    targets: ".rise",
    translateY: [14, 0],
    delay: anime.stagger(70),
    duration: 620,
    easing: "easeOutCubic",
  });

  // Count-up on the landing statistics, once, when they scroll into view.
  const nums = document.querySelectorAll("[data-count]");
  if (nums.length) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting || e.target.dataset.done) return;
        e.target.dataset.done = "1";
        const to = Number(e.target.dataset.count);
        anime({
          targets: { n: 0 },
          n: to,
          duration: 1300,
          easing: "easeOutExpo",
          update(a) {
            e.target.textContent = Math.round(a.animations[0].currentValue)
              .toLocaleString();
          },
        });
      });
    }, { threshold: 0.4 });
    nums.forEach((n) => io.observe(n));
  }

  // Cards lift very slightly under the pointer. Transform only, so it cannot
  // affect layout or leave an element stranded mid-transition.
  document.querySelectorAll(".card").forEach((c) => {
    c.addEventListener("mouseenter", () =>
      anime({ targets: c, translateY: -3, duration: 200, easing: "easeOutQuad" }));
    c.addEventListener("mouseleave", () =>
      anime({ targets: c, translateY: 0, duration: 260, easing: "easeOutQuad" }));
  });
})();

/* One click into the shared demo account.

   The credentials are printed on the sign-in page anyway, so making someone
   retype a password we just showed them was friction with no security value. */
(function () {
  "use strict";
  const btn = document.getElementById("trydemo");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "Opening the demo mailbox…";
    try {
      const r = await fetch("/api/auth/demo", {
        method: "POST", credentials: "same-origin",
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        btn.textContent = d.detail || "Demo unavailable";
        btn.disabled = false;
        return;
      }
      window.location.href = "/";
    } catch (e) {
      btn.textContent = original;
      btn.disabled = false;
    }
  });
})();
