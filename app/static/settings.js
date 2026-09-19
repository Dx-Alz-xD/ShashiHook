/* Mailbox connection and account settings. */
(function () {
  "use strict";
  const msg = document.getElementById("msg");
  const state = document.getElementById("mbstate");

  function say(text, kind) {
    msg.innerHTML = `<div class="msg ${kind}">${String(text).replace(/[<>&]/g, "")}</div>`;
    msg.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  async function load() {
    const d = await (await fetch("/api/auth/me", { credentials: "same-origin" })).json();
    if (!d.signed_in) { window.location.href = "/login"; return; }
    const u = d.user;
    document.getElementById("host").value = u.imap_host || "imap.gmail.com";
    document.getElementById("user").value = u.imap_user || "";
    state.innerHTML = u.has_mailbox
      ? `<div class="msg ok">Connected to <strong>${u.imap_user}</strong>${
          u.imap_verified ? " — verified" : ""}</div>`
      : `<div class="msg err">No mailbox connected yet. Scanning stays disabled until there is one.</div>`;
    if (u.is_demo) {
      say("This is the shared demo account. Its mailbox and password cannot be changed.", "ok");
      document.querySelectorAll("#mbform input, #mbform button, #pwform input, #pwform button")
        .forEach((el) => { el.disabled = true; });
    }
  }

  document.getElementById("mbform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("mbgo");
    btn.disabled = true;
    btn.textContent = "Checking with the mail server…";
    try {
      const r = await fetch("/api/mailbox", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          host: document.getElementById("host").value.trim(),
          port: Number(document.getElementById("port").value),
          user: document.getElementById("user").value.trim(),
          password: document.getElementById("password").value,
        }),
      });
      const d = await r.json();
      if (!r.ok) { say(d.detail || "Could not connect.", "err"); }
      else {
        say("Mailbox verified and saved.", "ok");
        document.getElementById("password").value = "";
        await load();
      }
    } catch (err) {
      say("Could not reach the server.", "err");
    }
    btn.disabled = false;
    btn.textContent = "Verify and save";
  });

  document.getElementById("mbdel").addEventListener("click", async () => {
    if (!confirm("Disconnect this mailbox? The stored password is erased.")) return;
    await fetch("/api/mailbox", { method: "DELETE", credentials: "same-origin" });
    say("Mailbox disconnected and the stored password erased.", "ok");
    load();
  });

  document.getElementById("pwform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await fetch("/api/auth/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        current: document.getElementById("cur").value,
        new: document.getElementById("new").value,
      }),
    });
    const d = await r.json();
    say(r.ok ? "Password changed." : (d.detail || "Could not change it."),
        r.ok ? "ok" : "err");
    if (r.ok) e.target.reset();
  });

  document.getElementById("signout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.href = "/";
  });

  load();
})();
