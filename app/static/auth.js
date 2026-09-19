/* Sign-in and sign-up. */
(function () {
  "use strict";
  const form = document.getElementById("form");
  if (!form) return;
  const msg = document.getElementById("msg");
  const go = document.getElementById("go");
  const isSignup = !!document.getElementById("display_name");

  function say(text, kind) {
    msg.innerHTML = `<div class="msg ${kind}">${String(text).replace(/[<>&]/g, "")}</div>`;
    if (typeof anime !== "undefined") {
      anime({ targets: msg.firstChild, translateY: [-6, 0], duration: 240,
              easing: "easeOutCubic" });
    }
  }

  const demo = document.getElementById("usedemo");
  if (demo) {
    demo.addEventListener("click", () => {
      document.getElementById("email").value = "demo@shashihook.app";
      document.getElementById("password").value = "shashihook-demo-2026";
      say("Demo details filled in — press Sign in.", "ok");
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    go.disabled = true;
    const original = go.textContent;
    go.textContent = isSignup ? "Creating…" : "Signing in…";
    const body = {
      email: document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
    };
    if (isSignup) body.display_name = document.getElementById("display_name").value;
    try {
      const r = await fetch(isSignup ? "/api/auth/signup" : "/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) {
        // The server deliberately returns the same wording for a wrong password
        // and an unknown address; do not try to be more helpful than that.
        say(d.detail || "That did not work.", "err");
        go.disabled = false;
        go.textContent = original;
        return;
      }
      say("Signed in. Taking you through…", "ok");
      window.location.href = d.user.has_mailbox ? "/" : "/settings";
    } catch (err) {
      say("Could not reach the server.", "err");
      go.disabled = false;
      go.textContent = original;
    }
  });
})();
