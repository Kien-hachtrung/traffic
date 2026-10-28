const authStorageKey = "wayfinder.local-auth.v1";
const themeStorageKey = "wayfinder.theme.v1";
const passwordIterations = 310000;
const adminUsername = "admin123";
const adminPassword = "123123ASD";
const adminAccountId = "__wayfinder_admin__";
const settingsMain = document.querySelector("#settings-main");
const settingsUserLabel = document.querySelector("#settings-user-label");
const signOutButton = document.querySelector("#settings-sign-out");
const accountManagerLink = document.querySelector("#settings-account-manager-link");
const settingsForm = document.querySelector("#settings-form");
const settingsUsername = document.querySelector("#settings-username");
const currentPasswordInput = document.querySelector("#settings-current-password");
const newPasswordInput = document.querySelector("#settings-new-password");
const confirmPasswordInput = document.querySelector("#settings-confirm-password");
const themeSelect = document.querySelector("#theme-select");
const settingsFeedback = document.querySelector("#settings-feedback");
const settingsSave = document.querySelector("#settings-save");

function getUserName(user) {
  return user.username || user.email;
}

function readAuthData() {
  let serialized;
  try {
    serialized = localStorage.getItem(authStorageKey);
  } catch {
    throw new Error("Browser storage is unavailable. Enable local storage to use accounts.");
  }
  if (!serialized) return { users: [], signedInEmail: null };

  let data;
  try {
    data = JSON.parse(serialized);
  } catch {
    throw new Error("Saved account data is unreadable. Clear this site's local storage to start over.");
  }
  const validUsers = data && Array.isArray(data.users) && data.users.every((user) =>
    user &&
    typeof user.email === "string" &&
    (user.username === undefined || typeof user.username === "string") &&
    typeof user.passwordSalt === "string" &&
    typeof user.passwordHash === "string"
  );
  const validAdmin = data?.admin === undefined || (
    data.admin &&
    typeof data.admin.username === "string" &&
    typeof data.admin.passwordSalt === "string" &&
    typeof data.admin.passwordHash === "string"
  );
  if (!validUsers || !validAdmin ||
      (data.signedInEmail !== null && typeof data.signedInEmail !== "string")) {
    throw new Error("Saved account data is invalid. Clear this site's local storage to start over.");
  }
  return data;
}

function saveAuthData(data) {
  try {
    localStorage.setItem(authStorageKey, JSON.stringify(data));
  } catch {
    throw new Error("Could not save account data. Check available browser storage.");
  }
}

function saveTheme(theme) {
  try {
    localStorage.setItem(themeStorageKey, theme);
  } catch {
    throw new Error("Could not save your theme. Check available browser storage.");
  }
  document.documentElement.dataset.theme = theme;
}

function loadTheme() {
  let theme;
  try {
    theme = localStorage.getItem(themeStorageKey) === "dark" ? "dark" : "light";
  } catch {
    throw new Error("Browser storage is unavailable. Enable local storage to save theme settings.");
  }
  document.documentElement.dataset.theme = theme;
  themeSelect.value = theme;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function derivePasswordHash(password, salt) {
  if (!crypto.subtle) {
    throw new Error("Secure password hashing is unavailable. Open this page on localhost or HTTPS.");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const hash = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: passwordIterations },
    key,
    256
  );
  return new Uint8Array(hash);
}

async function makePasswordRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passwordHash = await derivePasswordHash(password, salt);
  return {
    passwordAlgorithm: "PBKDF2-SHA-256",
    passwordIterations,
    passwordSalt: bytesToBase64(salt),
    passwordHash: bytesToBase64(passwordHash)
  };
}

async function passwordMatchesRecord(password, record) {
  if (!record || record.passwordAlgorithm !== "PBKDF2-SHA-256" ||
      record.passwordIterations !== passwordIterations) return false;
  const enteredHash = await derivePasswordHash(password, base64ToBytes(record.passwordSalt));
  const savedHash = base64ToBytes(record.passwordHash);
  if (enteredHash.length !== savedHash.length) return false;
  let difference = 0;
  for (let index = 0; index < enteredHash.length; index++) {
    difference |= enteredHash[index] ^ savedHash[index];
  }
  return difference === 0;
}

function isUsernameAvailable(username, users, excludedEmail = null) {
  const normalized = username.toLowerCase();
  return !users.some((user) =>
    user.email !== excludedEmail &&
    (getUserName(user).toLowerCase() === normalized || user.email.toLowerCase() === normalized)
  );
}

function getSignedInUser(data) {
  if (data.signedInEmail === adminAccountId || data.signedInEmail === adminUsername) {
    return {
      email: adminAccountId,
      username: data.admin?.username || adminUsername,
      isAdmin: true
    };
  }
  return data.users.find((user) => user.email === data.signedInEmail) || null;
}

async function verifyAdminPassword(data, password) {
  if (data.admin) return passwordMatchesRecord(password, data.admin);
  return password === adminPassword;
}

function renderSettings(user) {
  settingsUserLabel.textContent = getUserName(user);
  settingsUserLabel.hidden = false;
  signOutButton.hidden = false;
  accountManagerLink.hidden = !user.isAdmin;
  settingsUsername.value = getUserName(user);
  settingsMain.hidden = false;
}

function showSettingsError(error) {
  settingsFeedback.textContent = error.message || "Could not load account settings.";
  settingsFeedback.classList.add("is-error");
  settingsMain.hidden = false;
}

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  settingsSave.disabled = true;
  settingsFeedback.textContent = "";
  settingsFeedback.classList.remove("is-error");
  try {
    const data = readAuthData();
    const user = getSignedInUser(data);
    if (!user) {
      window.location.replace("index.html?auth=settings");
      return;
    }

    const username = settingsUsername.value.trim();
    const currentPassword = currentPasswordInput.value;
    const newPassword = newPasswordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    if (!/^[a-zA-Z0-9._-]{3,30}$/.test(username)) {
      throw new Error("Username must be 3–30 characters using letters, numbers, dots, underscores or hyphens.");
    }
    if (!currentPassword) throw new Error("Enter your current password to save account changes.");
    if (newPassword && newPassword !== confirmPassword) {
      throw new Error("The new passwords do not match.");
    }
    if (!newPassword && confirmPassword) {
      throw new Error("Enter a new password before confirming it.");
    }
    if (newPassword && newPassword.length < 8) {
      throw new Error("New password must be at least 8 characters.");
    }

    if (user.isAdmin) {
      const currentAdmin = data.admin || { username: adminUsername };
      if (username.toLowerCase() !== currentAdmin.username.toLowerCase() &&
          (!isUsernameAvailable(username, data.users) ||
           data.users.some((entry) => entry.email.toLowerCase() === username.toLowerCase()))) {
        throw new Error("That username is already in use.");
      }
      if (!await verifyAdminPassword(data, currentPassword)) {
        throw new Error("Current password is incorrect.");
      }
      const nextAdmin = {
        ...currentAdmin,
        username,
        ...(newPassword
          ? await makePasswordRecord(newPassword)
          : data.admin ? {} : await makePasswordRecord(currentPassword))
      };
      saveAuthData({ ...data, admin: nextAdmin, signedInEmail: adminAccountId });
      user.username = username;
    } else {
      const account = data.users.find((entry) => entry.email === user.email);
      if (!account) throw new Error("Your account could not be found.");
      if (username.toLowerCase() !== getUserName(account).toLowerCase() &&
          !isUsernameAvailable(username, data.users, account.email)) {
        throw new Error("That username is already in use.");
      }
      if (!await passwordMatchesRecord(currentPassword, account)) {
        throw new Error("Current password is incorrect.");
      }
      const updatedAccount = {
        ...account,
        username,
        ...(newPassword ? await makePasswordRecord(newPassword) : {})
      };
      saveAuthData({
        ...data,
        users: data.users.map((entry) => entry.email === account.email ? updatedAccount : entry)
      });
      user.username = username;
    }

    currentPasswordInput.value = "";
    newPasswordInput.value = "";
    confirmPasswordInput.value = "";
    settingsFeedback.textContent = "Account settings saved.";
    settingsUserLabel.textContent = username;
  } catch (error) {
    settingsFeedback.textContent = error.message || "Could not save account settings.";
    settingsFeedback.classList.add("is-error");
  } finally {
    settingsSave.disabled = false;
  }
});

themeSelect.addEventListener("change", () => {
  try {
    saveTheme(themeSelect.value);
  } catch (error) {
    showSettingsError(error);
  }
});

signOutButton.addEventListener("click", () => {
  try {
    const data = readAuthData();
    saveAuthData({ ...data, signedInEmail: null });
    window.location.replace("index.html");
  } catch (error) {
    showSettingsError(error);
  }
});

window.addEventListener("storage", (event) => {
  if (event.key === themeStorageKey) {
    try {
      loadTheme();
    } catch (error) {
      showSettingsError(error);
    }
    return;
  }
  if (event.key !== authStorageKey) return;
  try {
    const user = getSignedInUser(readAuthData());
    if (!user) {
      window.location.replace("index.html?auth=settings");
      return;
    }
    renderSettings(user);
  } catch (error) {
    showSettingsError(error);
  }
});

try {
  loadTheme();
  const data = readAuthData();
  const user = getSignedInUser(data);
  if (!user) {
    window.location.replace("index.html?auth=settings");
  } else {
    renderSettings(user);
  }
} catch (error) {
  showSettingsError(error);
}
