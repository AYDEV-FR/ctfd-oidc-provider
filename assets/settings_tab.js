/*
 * Adds an "Authorized Apps" tab to the CTFd user settings (/settings) page,
 * alongside the built-in Profile and Access Tokens tabs. The tab lists the
 * OAuth2 applications the current user has authorized and lets them revoke
 * access. Data is loaded from the plugin's own endpoints, so this never has to
 * touch (or break) CTFd's own settings forms.
 */
(function () {
  "use strict";

  var TAB_ID = "oidc-authorized-apps";

  function onSettingsPage() {
    return window.location.pathname.replace(/\/+$/, "").endsWith("/settings");
  }

  function csrfNonce() {
    return (window.init && window.init.csrfNonce) || "";
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c];
    });
  }

  function init() {
    if (!onSettingsPage()) return;
    if (document.getElementById(TAB_ID)) return; // already injected

    var nav = document.querySelector(".nav-pills");
    var content = document.querySelector(".tab-content");
    if (!nav || !content) return;

    var button = document.createElement("button");
    button.className = "nav-link";
    button.id = "settings-oidc-tab";
    button.setAttribute("data-bs-toggle", "pill");
    button.setAttribute("data-bs-target", "#" + TAB_ID);
    button.setAttribute("role", "tab");
    button.textContent = "Authorized Apps";
    nav.appendChild(button);

    var pane = document.createElement("div");
    pane.className = "tab-pane fade";
    pane.id = TAB_ID;
    pane.setAttribute("role", "tabpanel");
    pane.innerHTML = '<div class="text-center text-muted py-3">Loading…</div>';
    content.appendChild(pane);

    loadApps(pane);
  }

  function loadApps(pane) {
    fetch("/oidc/authorizations?format=json", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        render(pane, (data && data.authorizations) || []);
      })
      .catch(function () {
        pane.innerHTML =
          '<div class="alert alert-danger">Failed to load authorized applications.</div>';
      });
  }

  function render(pane, apps) {
    var header =
      '<h4 class="mb-1">Authorized Applications</h4>' +
      '<p class="text-muted">Applications you have granted access to your account.</p>';

    if (!apps.length) {
      pane.innerHTML =
        header +
        '<div class="alert alert-info">You haven\'t authorized any applications yet.</div>';
      return;
    }

    var rows = apps
      .map(function (app) {
        return (
          "<tr>" +
          "<td>" +
          escapeHtml(app.name) +
          "</td>" +
          '<td><small class="text-muted">' +
          escapeHtml(app.scope) +
          "</small></td>" +
          '<td class="text-end">' +
          '<button class="btn btn-sm btn-outline-danger" data-revoke="' +
          escapeHtml(app.id) +
          '">Revoke</button>' +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    pane.innerHTML =
      header +
      '<table class="table table-striped align-middle"><thead><tr>' +
      "<th>Application</th><th>Scopes</th>" +
      '<th class="text-end">Access</th>' +
      "</tr></thead><tbody>" +
      rows +
      "</tbody></table>";

    pane.querySelectorAll("[data-revoke]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        if (!window.confirm("Revoke access for this application?")) return;
        btn.disabled = true;
        revoke(btn.getAttribute("data-revoke"), pane);
      });
    });
  }

  function revoke(id, pane) {
    fetch("/oidc/authorizations/" + encodeURIComponent(id) + "/revoke", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "CSRF-Token": csrfNonce(),
        Accept: "application/json",
      },
    })
      .then(function () {
        loadApps(pane);
      })
      .catch(function () {
        loadApps(pane);
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
