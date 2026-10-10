(() => {
  "use strict";

  let accessToken = null;
  let resetToken = null;
  let refreshTimer = null;

  const byId = (id) => document.getElementById(id);
  const notice = byId("notice");

  function showNotice(message, isError = false) {
    notice.textContent = message;
    notice.classList.toggle("error", isError);
    notice.classList.remove("hidden");
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set("Content-Type", "application/json");
    if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
    const response = await fetch(path, { ...options, headers });
    if (response.status === 204) return null;
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Request failed.");
    return body;
  }

  function setSignedIn(email) {
    byId("auth-panel").classList.add("hidden");
    byId("dashboard").classList.remove("hidden");
    byId("logout").classList.remove("hidden");
    byId("delete-account").classList.remove("hidden");
    byId("account-email").textContent = email;
    refreshScans();
    refreshTimer = window.setInterval(refreshScans, 6000);
  }

  function setSignedOut() {
    accessToken = null;
    if (refreshTimer) window.clearInterval(refreshTimer);
    byId("auth-panel").classList.remove("hidden");
    byId("dashboard").classList.add("hidden");
    byId("logout").classList.add("hidden");
    byId("delete-account").classList.add("hidden");
  }

  function formValues(form) {
    const values = Object.fromEntries(new FormData(form).entries());
    if (form.elements.namedItem("authorized")) {
      values.authorized = form.elements.namedItem("authorized").checked;
    }
    return values;
  }

  byId("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const values = formValues(event.currentTarget);
      const result = await request("/api/auth/register", {
        method: "POST",
        body: JSON.stringify(values),
      });
      showNotice(result.message);
      event.currentTarget.reset();
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const values = formValues(event.currentTarget);
      const result = await request("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      accessToken = result.access_token;
      setSignedIn(values.email);
      showNotice("Signed in. Review scan scope and target permissions before running tests.");
      event.currentTarget.reset();
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  byId("forgot-password").addEventListener("click", async () => {
    const email = window.prompt("Enter the email address for your account:");
    if (!email) return;
    try {
      const result = await request("/api/auth/password-reset/request", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      showNotice(result.message);
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  byId("resend-verification").addEventListener("click", async () => {
    const email = byId("login-form").elements.namedItem("email").value;
    if (!email) {
      showNotice("Enter your email address first.", true);
      return;
    }
    try {
      const result = await request("/api/auth/resend-verification", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      showNotice(result.message);
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  byId("reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!resetToken) return;
    try {
      const values = formValues(event.currentTarget);
      await request("/api/auth/password-reset/confirm", {
        method: "POST",
        body: JSON.stringify({ token: resetToken, password: values.password }),
      });
      resetToken = null;
      window.history.replaceState(null, "", window.location.pathname);
      event.currentTarget.classList.add("hidden");
      byId("register-form").classList.remove("hidden");
      byId("login-form").classList.remove("hidden");
      showNotice("Password updated. You can now sign in.");
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  byId("scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const submitButton = form.querySelector("button[type=submit]");
    submitButton.disabled = true;
    try {
      const values = formValues(form);
      await request("/api/scans", { method: "POST", body: JSON.stringify(values) });
      form.reset();
      showNotice("Scan queued. You can close this page; results are saved to your workspace.");
      await refreshScans();
      if (!refreshTimer) refreshTimer = window.setInterval(refreshScans, 6000);
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      submitButton.disabled = false;
    }
  });

  byId("refresh").addEventListener("click", refreshScans);
  byId("logout").addEventListener("click", setSignedOut);
  byId("delete-account").addEventListener("click", async () => {
    if (!window.confirm("Permanently delete this account, workspace, scans, and reports?")) return;
    const password = window.prompt("Enter your password to confirm account deletion:");
    if (!password) return;
    try {
      await request("/api/account", {
        method: "DELETE",
        body: JSON.stringify({ password }),
      });
      setSignedOut();
      showNotice("The account and workspace were deleted.");
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  async function refreshScans() {
    if (!accessToken) return;
    try {
      const scans = await request("/api/scans");
      const list = byId("scan-list");
      list.replaceChildren();
      for (const scan of scans) {
        const card = document.createElement("article");
        card.className = "scan-card";
        const details = document.createElement("div");
        const title = document.createElement("h3");
        title.textContent = scan.name;
        const target = document.createElement("p");
        target.textContent = `${scan.target_url} · ${new Date(scan.created_at).toLocaleString()}`;
        details.append(title, target);
        const status = document.createElement("span");
        status.className = `status${scan.status === "failed" ? " failed" : ""}`;
        status.textContent = scan.status;
        card.append(details, status);
        if (scan.report) {
          const button = document.createElement("button");
          button.className = "button quiet";
          button.type = "button";
          button.textContent = "View report";
          button.addEventListener("click", () => {
            const report = byId("report");
            report.textContent = JSON.stringify(scan.report, null, 2);
            report.classList.remove("hidden");
            report.scrollIntoView({ behavior: "smooth", block: "start" });
          });
          card.append(button);
        }
        if (scan.error_message) {
          const error = document.createElement("p");
          error.textContent = scan.error_message;
          card.append(error);
        }
        if (scan.status === "completed" || scan.status === "incomplete" || scan.status === "failed") {
          const remove = document.createElement("button");
          remove.className = "button quiet";
          remove.type = "button";
          remove.textContent = "Delete";
          remove.addEventListener("click", async () => {
            try {
              await request(`/api/scans/${encodeURIComponent(scan.id)}`, {
                method: "DELETE",
              });
              await refreshScans();
            } catch (error) {
              showNotice(error.message, true);
            }
          });
          card.append(remove);
        }
        list.append(card);
      }
      if (scans.some((scan) => scan.status === "pending" || scan.status === "running")) return;
      if (refreshTimer) {
        window.clearInterval(refreshTimer);
        refreshTimer = null;
      }
    } catch (error) {
      showNotice(error.message, true);
      if (error.message.includes("access token")) setSignedOut();
    }
  }

  async function handleEmailAction() {
    const fragment = window.location.hash.slice(1);
    if (fragment.startsWith("verify=")) {
      const token = fragment.slice("verify=".length);
      try {
        await request("/api/auth/verify-email", {
          method: "POST",
          body: JSON.stringify({ token }),
        });
        showNotice("Email verified. You can now sign in.");
      } catch (error) {
        showNotice(error.message, true);
      } finally {
        window.history.replaceState(null, "", window.location.pathname);
      }
    } else if (fragment.startsWith("reset=")) {
      resetToken = fragment.slice("reset=".length);
      byId("reset-form").classList.remove("hidden");
      byId("register-form").classList.add("hidden");
      byId("login-form").classList.add("hidden");
    }
  }

  handleEmailAction();
})();
