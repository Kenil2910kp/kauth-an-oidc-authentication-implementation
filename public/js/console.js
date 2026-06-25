async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

async function requireAuth(redirectTo = "/console/login.html") {
  const { res, data } = await api("/console/auth/me");
  if (!res.ok) {
    window.location.href = redirectTo;
    return null;
  }
  return data.user;
}

async function signOut() {
  await api("/console/auth/sign-out", { method: "POST" });
  window.location.href = "/console/login.html";
}

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}
