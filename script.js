const form = document.querySelector("#search-form");
const searchInput = document.querySelector("#location-search");
const suggestionsBox = document.querySelector("#search-suggestions");
const searchFeedback = document.querySelector("#search-feedback");
const placeTitle = document.querySelector("#place-title");
const placeSubtitle = document.querySelector("#place-subtitle");
const mapLocationLabel = document.querySelector("#map-location-label");
const mapCanvas = document.querySelector("#map-canvas");
const mapError = document.querySelector("#map-error");
const mapErrorMessage = document.querySelector("#map-error-message");
const trafficToggle = document.querySelector("#traffic-toggle");
const trafficStatus = document.querySelector("#traffic-status");
const nearbyList = document.querySelector("#nearby-list");
const authModal = document.querySelector("#auth-modal");
const authForm = document.querySelector("#auth-form");
const authFeedback = document.querySelector("#auth-feedback");
const authTitle = document.querySelector("#auth-title");
const authIntro = document.querySelector("#auth-intro");
const authSubmit = document.querySelector("#auth-submit");
const authSwitch = document.querySelector("#auth-switch");
const authPassword = document.querySelector("#auth-password");
const authConfirmField = document.querySelector("#auth-confirm-field");
const authConfirmPassword = document.querySelector("#auth-confirm-password");
const authEmail = document.querySelector("#auth-email");
const authIdentifierLabel = document.querySelector("#auth-identifier-label");
const authUsernameField = document.querySelector("#auth-signup-username-field");
const authUsername = document.querySelector("#auth-username");
const signInButtons = document.querySelectorAll(".account-actions [data-auth]");
const signedInLabel = document.querySelector("#signed-in-label");
const signOutButton = document.querySelector("#sign-out-button");
const exploreLink = document.querySelector("#explore-link");
const accountManagerLink = document.querySelector("#account-manager-link");
const accountManager = document.querySelector("#account-manager");
const accountForm = document.querySelector("#account-form");
const managedUsername = document.querySelector("#managed-username");
const managedEmail = document.querySelector("#managed-email");
const managedPassword = document.querySelector("#managed-password");
const managedPasswordHint = document.querySelector("#managed-password-hint");
const accountSubmit = document.querySelector("#account-submit");
const accountCancel = document.querySelector("#account-cancel");
const accountFeedback = document.querySelector("#account-feedback");
const accountList = document.querySelector("#account-list");
const accountSettingsLink = document.querySelector("#account-settings-link");
const toast = document.querySelector("#toast");
const apiKey = window.TOMTOM_API_KEY?.trim();
const defaultCenter = [-122.4194, 37.7749];
const authStorageKey = "wayfinder.local-auth.v1";
const savedPlacesStorageKey = "wayfinder.saved-places.v1";
const themeStorageKey = "wayfinder.theme.v1";
const passwordIterations = 310000;
const adminUsername = "admin123";
const adminPassword = "123123ASD";
const adminAccountId = "__wayfinder_admin__";

let activeSuggestion = -1;
let suggestionResults = [];
let suggestionTimer;
let searchRequestId = 0;
let isSignUp = false;
let isSaved = false;
let toastTimeout;
let authOpener;
let map;
let selectedMarker;
let trafficEnabled = true;
let mapReady = false;
let trafficLayerIds = [];
let selectedPlaceName;
let selectedPlacePosition = { lon: defaultCenter[0], lat: defaultCenter[1] };
let authData = { users: [], signedInEmail: null };
let currentUser = null;
let pendingAction = null;
let authStorageError = "";
let editingAccountEmail = null;

function setCurrentSection(section) {
  const links = [
    [exploreLink, "explore"],
    [accountManagerLink, "account-manager"]
  ];
  links.forEach(([link, name]) => {
    const active = name === section;
    link.classList.toggle("is-current", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("is-visible");
  window.clearTimeout(toastTimeout);
  toastTimeout = window.setTimeout(() => toast.classList.remove("is-visible"), 3200);
}

function getUserName(user) {
  return user.username || user.email;
}

function isUsernameAvailable(username, users, excludedEmail = null) {
  const normalized = username.trim().toLowerCase();
  return !users.some((user) =>
    user.email !== excludedEmail &&
    (getUserName(user).toLowerCase() === normalized || user.email.toLowerCase() === normalized)
  );
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
}

function readTheme() {
  try {
    const theme = localStorage.getItem(themeStorageKey);
    return theme === "dark" ? "dark" : "light";
  } catch {
    throw new Error("Browser storage is unavailable. Enable local storage to save theme settings.");
  }
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
  if (!data || !Array.isArray(data.users)) {
    throw new Error("Saved account data is invalid. Clear this site's local storage to start over.");
  }
  const validUsers = data.users.every((user) =>
    user &&
    typeof user.email === "string" &&
    (user.username === undefined || typeof user.username === "string") &&
    typeof user.passwordSalt === "string" &&
    typeof user.passwordHash === "string"
  );
  const validAdmin = data.admin === undefined || (
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
  authData = data;
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

function hashesMatch(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function passwordMatchesRecord(password, record) {
  if (!record || record.passwordAlgorithm !== "PBKDF2-SHA-256" ||
      record.passwordIterations !== passwordIterations ||
      typeof record.passwordSalt !== "string" ||
      typeof record.passwordHash !== "string") return false;
  const enteredHash = await derivePasswordHash(password, base64ToBytes(record.passwordSalt));
  return hashesMatch(enteredHash, base64ToBytes(record.passwordHash));
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

async function verifyAdminPassword(data, password) {
  if (data.admin) return passwordMatchesRecord(password, data.admin);
  return password === adminPassword;
}

function updateAccountActions() {
  signInButtons.forEach((button) => { button.hidden = Boolean(currentUser); });
  signedInLabel.hidden = !currentUser;
  signedInLabel.textContent = currentUser ? getUserName(currentUser) : "";
  signOutButton.hidden = !currentUser;
  const isAdmin = currentUser?.isAdmin === true;
  accountManagerLink.hidden = !isAdmin;
  accountManager.hidden = !isAdmin;
  accountSettingsLink.hidden = !currentUser;
  if (isAdmin && window.location.hash === "#account-manager") setCurrentSection("account-manager");
  else if (!isAdmin || window.location.hash !== "#account-manager") setCurrentSection("explore");
  if (isAdmin) renderManagedAccounts();
}

function restoreLocalSession() {
  try {
    authData = readAuthData();
    currentUser = authData.signedInEmail === adminAccountId || authData.signedInEmail === adminUsername
      ? { email: adminAccountId, username: authData.admin?.username || adminUsername, isAdmin: true }
      : authData.users.find((user) => user.email === authData.signedInEmail) || null;
    if (!currentUser && authData.signedInEmail) {
      authData = { ...authData, signedInEmail: null };
      saveAuthData(authData);
    }
  } catch (error) {
    authStorageError = error.message;
    currentUser = null;
  }
  updateAccountActions();
}

function requireAuthentication(action, intro = "Sign in to search places. New here? Create an account below.") {
  if (currentUser) return true;
  pendingAction = action;
  openAuth(false);
  authIntro.textContent = intro;
  return false;
}

function readSavedPlacesData() {
  let serialized;
  try {
    serialized = localStorage.getItem(savedPlacesStorageKey);
  } catch {
    throw new Error("Browser storage is unavailable. Enable local storage to save places.");
  }
  if (!serialized) return { placesByEmail: {} };

  let data;
  try {
    data = JSON.parse(serialized);
  } catch {
    throw new Error("Saved places data is unreadable. Clear this site's local storage to start over.");
  }
  if (!data || !data.placesByEmail || typeof data.placesByEmail !== "object" || Array.isArray(data.placesByEmail)) {
    throw new Error("Saved places data is invalid. Clear this site's local storage to start over.");
  }
  const validPlaces = Object.values(data.placesByEmail).every((places) =>
    Array.isArray(places) && places.every((place) =>
      place &&
      typeof place.id === "string" &&
      typeof place.name === "string" &&
      typeof place.address === "string" &&
      Number.isFinite(place.lat) &&
      Number.isFinite(place.lon)
    )
  );
  if (!validPlaces) {
    throw new Error("Saved places data is invalid. Clear this site's local storage to start over.");
  }
  return data;
}

function writeSavedPlacesData(data) {
  try {
    localStorage.setItem(savedPlacesStorageKey, JSON.stringify(data));
  } catch {
    throw new Error("Could not save places. Check available browser storage.");
  }
}

function updateManagedAccountData(nextAuthData, previousEmail, nextEmail) {
  if (!previousEmail) {
    saveAuthData(nextAuthData);
    return;
  }

  let savedData;
  let previousSavedData;
  try {
    previousSavedData = localStorage.getItem(savedPlacesStorageKey);
    savedData = readSavedPlacesData();
  } catch (error) {
    throw new Error(error.message || "Could not read saved-place data.");
  }

  if (previousEmail !== nextEmail && Object.hasOwn(savedData.placesByEmail, previousEmail)) {
    const previousPlaces = savedData.placesByEmail[previousEmail];
    if (nextEmail) {
      savedData.placesByEmail[nextEmail] = [
        ...(savedData.placesByEmail[nextEmail] || []),
        ...previousPlaces
      ];
    }
    delete savedData.placesByEmail[previousEmail];
  }

  try {
    writeSavedPlacesData(savedData);
    saveAuthData(nextAuthData);
  } catch (error) {
    try {
      if (previousSavedData === null) localStorage.removeItem(savedPlacesStorageKey);
      else localStorage.setItem(savedPlacesStorageKey, previousSavedData);
    } catch {
      throw new Error(`${error.message} Saved places could not be restored; check browser storage.`);
    }
    throw error;
  }
}

function renderManagedAccounts() {
  if (currentUser?.isAdmin !== true) return;
  try {
    authData = readAuthData();
    accountList.replaceChildren();
    if (!authData.users.length) {
      const empty = document.createElement("p");
      empty.className = "account-empty";
      empty.textContent = "No registered accounts yet.";
      accountList.append(empty);
      return;
    }

    authData.users.forEach((user) => {
      const row = document.createElement("article");
      row.className = "account-item";
      const identity = document.createElement("div");
      identity.className = "account-item-identity";
      const username = document.createElement("strong");
      username.textContent = getUserName(user);
      const email = document.createElement("span");
      email.textContent = user.email;
      identity.append(username, email);
      const actions = document.createElement("div");
      actions.className = "account-item-actions";
      const edit = document.createElement("button");
      edit.type = "button";
      edit.className = "account-action";
      edit.textContent = "Edit";
      edit.addEventListener("click", () => beginAccountEdit(user.email));
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "account-action account-action-danger";
      remove.textContent = "Delete";
      remove.addEventListener("click", () => deleteManagedAccount(user.email));
      actions.append(edit, remove);
      row.append(identity, actions);
      accountList.append(row);
    });
  } catch (error) {
    accountList.replaceChildren();
    accountFeedback.textContent = error.message || "Could not load registered accounts.";
    accountFeedback.classList.add("is-error");
  }
}

function resetAccountForm() {
  editingAccountEmail = null;
  accountForm.reset();
  managedUsername.disabled = false;
  managedEmail.disabled = false;
  managedPassword.required = true;
  managedPasswordHint.textContent = "Required for new accounts";
  accountSubmit.textContent = "Add account";
  accountCancel.hidden = true;
}

function beginAccountEdit(email) {
  const user = authData.users.find((entry) => entry.email === email);
  if (!user || currentUser?.isAdmin !== true) return;
  editingAccountEmail = email;
  managedUsername.value = getUserName(user);
  managedEmail.value = email;
  managedUsername.disabled = false;
  managedEmail.disabled = false;
  managedPassword.value = "";
  managedPassword.required = false;
  managedPasswordHint.textContent = "Leave blank to keep the current password";
  accountSubmit.textContent = "Save changes";
  accountCancel.hidden = false;
  accountFeedback.textContent = "";
  accountFeedback.classList.remove("is-error");
  managedEmail.focus();
}

async function deleteManagedAccount(email) {
  if (currentUser?.isAdmin !== true) return;
  if (!window.confirm(`Delete the account ${email} and its saved places?`)) return;
  try {
    const data = readAuthData();
    const user = data.users.find((entry) => entry.email === email);
    if (!user) throw new Error("That account no longer exists.");
    updateManagedAccountData({
      ...data,
      users: data.users.filter((entry) => entry.email !== email),
      signedInEmail: data.signedInEmail === email ? null : data.signedInEmail
    }, email, null);
    if (editingAccountEmail === email) resetAccountForm();
    accountFeedback.textContent = `Deleted ${email}.`;
    accountFeedback.classList.remove("is-error");
    renderManagedAccounts();
  } catch (error) {
    accountFeedback.textContent = error.message || "Could not delete the account.";
    accountFeedback.classList.add("is-error");
  }
}

function getCurrentUserSavedPlaces() {
  if (!currentUser) return [];
  const data = readSavedPlacesData();
  return data.placesByEmail[currentUser.email] ||
    (currentUser.isAdmin ? data.placesByEmail[adminUsername] : null) ||
    [];
}

function findSelectedSavedPlace(places) {
  return places.find((place) =>
    Math.abs(place.lat - selectedPlacePosition.lat) < 0.000001 &&
    Math.abs(place.lon - selectedPlacePosition.lon) < 0.000001
  );
}

function updateSavePlaceButton() {
  const button = document.querySelector("#save-place-button");
  let savedPlace = null;
  if (currentUser) {
    try {
      savedPlace = findSelectedSavedPlace(getCurrentUserSavedPlaces());
    } catch (error) {
      showToast(error.message);
    }
  }
  isSaved = Boolean(savedPlace);
  button.classList.toggle("is-saved", isSaved);
  button.querySelector("span").textContent = isSaved ? "Place saved" : "Save this place";
  button.setAttribute("aria-pressed", String(isSaved));
}

function showMapError(message) {
  mapErrorMessage.textContent = message;
  mapError.hidden = false;
}

function hideMapError() {
  mapError.hidden = true;
}

function tomtomUrl(path, params = {}) {
  const url = new URL(`https://api.tomtom.com${path}`);
  url.search = new URLSearchParams({ key: apiKey, ...params }).toString();
  return url;
}

async function tomtomRequest(path, params) {
  const response = await fetch(tomtomUrl(path, params));
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error("TomTom rejected the API key. Check that it is active and enabled for Maps and Search.");
    }
    if (response.status === 429) {
      throw new Error("TomTom request limit reached. Try again shortly.");
    }
    throw new Error(`TomTom request failed (${response.status}). Try again shortly.`);
  }
  return response.json();
}

function getResultName(result) {
  return result.poi?.name || result.address?.freeformAddress || result.address?.municipality || "Selected place";
}

function getResultAddress(result) {
  const name = result.poi?.name;
  const address = result.address?.freeformAddress;
  return address && address !== name ? address : result.address?.municipality || result.type || "Place";
}

function getResultPosition(result) {
  const position = result.position;
  if (position && Number.isFinite(position.lat) && Number.isFinite(position.lon)) return position;
  const coordinates = result.geometry?.coordinates;
  if (coordinates && Number.isFinite(coordinates[0]) && Number.isFinite(coordinates[1])) {
    return { lon: coordinates[0], lat: coordinates[1] };
  }
  return null;
}

function hideSuggestions() {
  suggestionsBox.hidden = true;
  suggestionsBox.replaceChildren();
  activeSuggestion = -1;
  suggestionResults = [];
  searchInput.setAttribute("aria-expanded", "false");
  searchInput.removeAttribute("aria-activedescendant");
}

function renderSuggestions(results, query) {
  suggestionsBox.replaceChildren();
  suggestionResults = results;
  activeSuggestion = -1;

  if (!results.length) {
    const empty = document.createElement("p");
    empty.className = "suggestion-empty";
    empty.textContent = `No places found for “${query}”.`;
    suggestionsBox.append(empty);
  } else {
    results.forEach((result, index) => {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "suggestion-option";
      option.setAttribute("role", "option");
      option.id = `search-option-${index}`;
      option.setAttribute("aria-selected", "false");
      option.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 10.2c0 5-8 11-8 11s-8-6-8-11a8 8 0 1 1 16 0Z"/><circle cx="12" cy="10" r="2.5"/></svg>';
      const copy = document.createElement("span");
      copy.className = "suggestion-copy";
      const name = document.createElement("strong");
      name.textContent = getResultName(result);
      const address = document.createElement("small");
      address.textContent = getResultAddress(result);
      copy.append(name, address);
      option.append(copy);
      option.addEventListener("click", () => selectResult(result));
      suggestionsBox.append(option);
    });
  }

  suggestionsBox.hidden = false;
  searchInput.setAttribute("aria-expanded", "true");
}

async function searchPlaces(query, { suggestions = false } = {}) {
  if (!currentUser) return null;
  const requestId = ++searchRequestId;
  const center = map?.getCenter();
  const params = { limit: suggestions ? "5" : "10" };
  if (center) {
    params.lat = String(center.lat);
    params.lon = String(center.lng);
  }
  try {
    const data = await tomtomRequest(`/search/2/search/${encodeURIComponent(query)}.json`, params);
    if (requestId !== searchRequestId) return null;
    if (suggestions) {
      renderSuggestions(data.results || [], query);
      return data.results || [];
    }
    return data.results || [];
  } catch (error) {
    if (requestId !== searchRequestId) return null;
    if (suggestions) {
      hideSuggestions();
      searchFeedback.textContent = error.message;
    } else {
      showToast(error.message);
    }
    return null;
  }
}

function renderNearby(places) {
  nearbyList.replaceChildren();
  if (!places.length) {
    const empty = document.createElement("p");
    empty.className = "nearby-message";
    empty.textContent = "No nearby places found.";
    nearbyList.append(empty);
    return;
  }
  places.slice(0, 5).forEach((result) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "nearby-item";
    const icon = document.createElement("span");
    icon.className = "place-icon nearby-result-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "⌖";
    const copy = document.createElement("span");
    copy.className = "nearby-copy";
    const name = document.createElement("strong");
    name.textContent = getResultName(result);
    const address = document.createElement("span");
    address.textContent = getResultAddress(result);
    copy.append(name, address);
    item.append(icon, copy);
    item.addEventListener("click", () => selectResult(result));
    nearbyList.append(item);
  });
}

async function loadNearbyPlaces(position = map?.getCenter()) {
  if (!position || !apiKey) return;
  nearbyList.replaceChildren();
  const loading = document.createElement("p");
  loading.className = "nearby-message";
  loading.textContent = "Finding places nearby…";
  nearbyList.append(loading);
  try {
    const data = await tomtomRequest("/search/2/nearbySearch/.json", {
      lat: String(position.lat),
      lon: String(position.lng),
      radius: "2500",
      limit: "5"
    });
    renderNearby(data.results || []);
  } catch (error) {
    nearbyList.replaceChildren();
    const message = document.createElement("p");
    message.className = "nearby-message nearby-error";
    message.textContent = error.message;
    nearbyList.append(message);
  }
}

function updateSelectedPlace(name, address, position) {
  selectedPlaceName = name;
  selectedPlacePosition = { lat: position.lat, lon: position.lon };
  placeTitle.textContent = name;
  placeSubtitle.textContent = address;
  mapLocationLabel.textContent = name;
  document.querySelector("#nearby-caption").textContent = `Places near ${name}`;
  searchInput.value = name;
  if (map && position) {
    const coordinates = [position.lon, position.lat];
    map.flyTo({ center: coordinates, zoom: Math.max(map.getZoom(), 14) });
    if (selectedMarker) selectedMarker.setLngLat(coordinates);
    else selectedMarker = new tt.Marker({ color: "#4e946a" }).setLngLat(coordinates).addTo(map);
    loadNearbyPlaces(position);
  }
  updateSavePlaceButton();
}

function selectResult(result) {
  if (!currentUser) {
    requireAuthentication(() => selectResult(result));
    return;
  }
  const position = getResultPosition(result);
  if (!position) {
    showToast("TomTom did not return coordinates for that place.");
    return;
  }
  updateSelectedPlace(getResultName(result), getResultAddress(result), position);
  searchFeedback.textContent = "";
  hideSuggestions();
}

async function submitSearch(query = searchInput.value) {
  const cleanQuery = query.trim();
  if (!cleanQuery) {
    searchFeedback.textContent = "Enter a place or address to search.";
    return;
  }
  if (!requireAuthentication(() => submitSearch(cleanQuery))) return;
  searchFeedback.textContent = "";
  hideSuggestions();
  const results = await searchPlaces(cleanQuery);
  if (results === null) return;
  if (!results.length) {
    searchFeedback.textContent = `No places found for “${cleanQuery}”.`;
    return;
  }
  selectResult(results[0]);
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  submitSearch();
});

searchInput.addEventListener("input", () => {
  window.clearTimeout(suggestionTimer);
  const query = searchInput.value.trim();
  searchFeedback.textContent = "";
  if (!query) {
    searchRequestId++;
    hideSuggestions();
    return;
  }
  if (!currentUser) {
    hideSuggestions();
    return;
  }
  suggestionTimer = window.setTimeout(() => searchPlaces(query, { suggestions: true }), 280);
});

searchInput.addEventListener("keydown", (event) => {
  const options = [...suggestionsBox.querySelectorAll('[role="option"]')];
  if ((event.key === "ArrowDown" || event.key === "ArrowUp") && options.length) {
    event.preventDefault();
    const direction = event.key === "ArrowDown" ? 1 : -1;
    activeSuggestion = (activeSuggestion + direction + options.length) % options.length;
    options.forEach((option, index) => {
      const selected = index === activeSuggestion;
      option.setAttribute("aria-selected", String(selected));
      if (selected) searchInput.setAttribute("aria-activedescendant", option.id);
    });
  } else if (event.key === "Enter" && activeSuggestion >= 0 && !suggestionsBox.hidden) {
    event.preventDefault();
    selectResult(suggestionResults[activeSuggestion]);
  } else if (event.key === "Escape") {
    hideSuggestions();
  }
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".search-wrap")) hideSuggestions();
});

document.querySelectorAll(".suggestion-chip").forEach((button) => {
  button.addEventListener("click", () => submitSearch(button.dataset.place));
});

function setTrafficEnabled(enabled) {
  trafficEnabled = enabled;
  trafficToggle.setAttribute("aria-pressed", String(enabled));
  trafficToggle.classList.toggle("is-on", enabled);
  trafficLayerIds.forEach((layerId) => {
    if (map?.getLayer(layerId)) map.setLayoutProperty(layerId, "visibility", enabled ? "visible" : "none");
  });
}

trafficToggle.addEventListener("click", () => setTrafficEnabled(!trafficEnabled));

function configureTrafficLayers() {
  trafficLayerIds = map.getStyle().layers
    .filter((layer) => /traffic.*flow/i.test(layer.id))
    .map((layer) => layer.id);
  if (!trafficLayerIds.length) {
    trafficStatus.textContent = "Traffic flow unavailable";
    return;
  }
  setTrafficEnabled(trafficEnabled);
  trafficStatus.textContent = "Live traffic flow";
}

function initializeMap() {
  if (!apiKey) {
    trafficStatus.textContent = "Map key is not set";
    showMapError("Add a TomTom browser API key to tomtom-config.js.");
    return;
  }
  if (!window.tt?.map || !window.tt?.Marker) {
    trafficStatus.textContent = "Map could not be loaded";
    showMapError("TomTom Maps could not load. Check your internet connection and reload.");
    return;
  }

  hideMapError();
  trafficStatus.textContent = "Loading live map…";
  try {
    map = tt.map({
      key: apiKey,
      container: "map-canvas",
      center: defaultCenter,
      zoom: 12,
      language: "en-US"
    });
    map.on("load", () => {
      mapReady = true;
      try {
        configureTrafficLayers();
        loadNearbyPlaces();
      } catch (error) {
        console.error("TomTom traffic display failed:", error);
        trafficStatus.textContent = "Traffic unavailable";
        showToast("The map loaded, but traffic could not be shown.");
      }
    });
    map.on("error", (event) => {
      console.error("TomTom map error:", event.error || event);
      if (!map.loaded()) {
        trafficStatus.textContent = "Map unavailable";
        showMapError("TomTom could not load map tiles. Check your API key, access and connection.");
      }
    });
    map.on("moveend", () => {
      const center = map.getCenter();
      mapLocationLabel.textContent = selectedPlaceName || `${center.lat.toFixed(4)}, ${center.lng.toFixed(4)}`;
      if (!selectedPlaceName) {
        selectedPlacePosition = { lat: center.lat, lon: center.lng };
        placeTitle.textContent = "Map location";
        placeSubtitle.textContent = `${center.lat.toFixed(4)}, ${center.lng.toFixed(4)}`;
        updateSavePlaceButton();
      }
      if (mapReady) loadNearbyPlaces(center);
    });
    map.on("dragstart", () => {
      selectedPlaceName = "";
    });
    map.on("load", restoreRequestedPlace);
  } catch (error) {
    console.error("TomTom map initialization failed:", error);
    trafficStatus.textContent = "Map unavailable";
    showMapError(error.message || "TomTom map could not be initialized.");
  }
}

document.querySelector("#zoom-in").addEventListener("click", () => map?.zoomIn());
document.querySelector("#zoom-out").addEventListener("click", () => map?.zoomOut());

function locateUser() {
  if (!requireAuthentication(locateUser)) return;
  if (!navigator.geolocation) {
    showToast("Location is not available in this browser.");
    return;
  }
  showToast("Checking your location…");
  navigator.geolocation.getCurrentPosition(
    ({ coords }) => {
      const position = { lat: coords.latitude, lon: coords.longitude };
      updateSelectedPlace("Your location", `${position.lat.toFixed(4)}, ${position.lon.toFixed(4)}`, position);
    },
    (error) => {
      const messages = {
        1: "Allow location access in your browser to use this feature.",
        2: "Your location could not be determined. Try again.",
        3: "Location lookup timed out. Try again."
      };
      showToast(messages[error.code] || "Could not get your location. Try again.");
    },
    { enableHighAccuracy: false, timeout: 10000, maximumAge: 60000 }
  );
}
document.querySelector("#locate-button").addEventListener("click", locateUser);
document.querySelector("#map-locate").addEventListener("click", locateUser);
document.querySelector("#map-retry").addEventListener("click", () => {
  if (map) {
    map.remove();
    map = null;
  }
  mapReady = false;
  mapCanvas.replaceChildren();
  initializeMap();
});

document.querySelector("#save-place-button").addEventListener("click", () => {
  if (!requireAuthentication(
    () => document.querySelector("#save-place-button").click(),
    "Sign in to save places. New here? Create an account below."
  )) return;

  try {
    const data = readSavedPlacesData();
    const places = data.placesByEmail[currentUser.email] || [];
    const existingPlace = findSelectedSavedPlace(places);
    if (existingPlace) {
      data.placesByEmail[currentUser.email] = places.filter((place) => place.id !== existingPlace.id);
      writeSavedPlacesData(data);
      showToast("Removed from saved places.");
    } else {
      const position = selectedPlacePosition;
      const name = selectedPlaceName || placeTitle.textContent;
      const address = selectedPlaceName
        ? placeSubtitle.textContent
        : `${position.lat.toFixed(4)}, ${position.lon.toFixed(4)}`;
      const place = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        name,
        address,
        lat: position.lat,
        lon: position.lon
      };
      data.placesByEmail[currentUser.email] = [place, ...places];
      writeSavedPlacesData(data);
      showToast(`${name} saved.`);
    }
    updateSavePlaceButton();
  } catch (error) {
    showToast(error.message);
  }
});

document.querySelector("#see-all-button").addEventListener("click", () => {
  showToast("Nearby places are provided by TomTom.");
});
document.querySelector("#more-button").addEventListener("click", () => {
  showToast("More place options will be available soon.");
});
document.querySelector("#share-button").addEventListener("click", async () => {
  const shareData = { title: "Wayfinder", text: `Explore ${placeTitle.textContent} with Wayfinder.` };
  if (navigator.share) {
    try {
      await navigator.share(shareData);
    } catch (error) {
      if (error.name !== "AbortError") showToast("This place could not be shared.");
    }
    return;
  }
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(`${shareData.text} ${window.location.href}`);
      showToast("Link copied to clipboard.");
    } catch {
      showToast("Clipboard access is unavailable in this browser.");
    }
    return;
  }
  showToast("Sharing is not available in this browser.");
});

function setAuthMode(signUp) {
  isSignUp = signUp;
  authTitle.textContent = signUp ? "Create your account" : "Welcome back";
  authIntro.textContent = signUp ? "Create an account to search for places." : "Log in to pick up where you left off.";
  authSubmit.textContent = signUp ? "Create account" : "Log in";
  authIdentifierLabel.textContent = signUp ? "Email address" : "Username or email address";
  authEmail.type = signUp ? "email" : "text";
  authEmail.placeholder = signUp ? "you@example.com" : "Username or email address";
  authEmail.autocomplete = signUp ? "email" : "username";
  authUsernameField.hidden = !signUp;
  authUsername.required = signUp;
  authPassword.autocomplete = signUp ? "new-password" : "current-password";
  authConfirmField.hidden = !signUp;
  authConfirmPassword.required = signUp;
  authConfirmPassword.value = "";
  authSwitch.innerHTML = signUp
    ? 'Already have an account? <button type="button" data-auth="login">Log in</button>'
    : 'New to Wayfinder? <button type="button" data-auth="signup">Create an account</button>';
  authFeedback.textContent = authStorageError;
  authFeedback.classList.toggle("is-error", Boolean(authStorageError));
}

function openAuth(signUp) {
  setAuthMode(signUp);
  authOpener = document.activeElement;
  authModal.hidden = false;
  document.body.classList.add("modal-open");
  document.querySelector("#auth-email").focus();
}

function closeAuth() {
  authModal.hidden = true;
  document.body.classList.remove("modal-open");
  pendingAction = null;
  authOpener?.focus();
}

function restoreRequestedPlace() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has("lat") || !params.has("lon") || !params.has("name")) return;
  if (!currentUser) {
    requireAuthentication(restoreRequestedPlace, "Sign in to open this saved place.");
    return;
  }
  const lat = Number(params.get("lat"));
  const lon = Number(params.get("lon"));
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180) {
    showToast("This saved place link is invalid.");
    return;
  }
  updateSelectedPlace(params.get("name"), params.get("address") || "Saved place", { lat, lon });
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-auth]");
  if (button) openAuth(button.dataset.auth === "signup");
});
document.querySelector("#modal-close").addEventListener("click", closeAuth);
authModal.addEventListener("click", (event) => {
  if (event.target === authModal) closeAuth();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !authModal.hidden) closeAuth();
});
accountForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (currentUser?.isAdmin !== true) return;
  accountSubmit.disabled = true;
  accountFeedback.textContent = "";
  accountFeedback.classList.remove("is-error");
  try {
    const username = managedUsername.value.trim();
    const email = managedEmail.value.trim().toLowerCase();
    const password = managedPassword.value;
    const data = readAuthData();
    if (!/^[a-zA-Z0-9._-]{3,30}$/.test(username)) {
      throw new Error("Username must be 3–30 characters using letters, numbers, dots, underscores or hyphens.");
    }
    const duplicate = data.users.some((user) =>
      user.email === email && user.email !== editingAccountEmail
    );
    if (duplicate) throw new Error("An account with this email already exists.");
    if (!isUsernameAvailable(username, data.users, editingAccountEmail) ||
        (data.admin?.username || adminUsername).toLowerCase() === username.toLowerCase()) {
      throw new Error("That username is already in use.");
    }

    let users;
    if (editingAccountEmail) {
      const currentAccount = data.users.find((user) => user.email === editingAccountEmail);
      if (!currentAccount) throw new Error("That account no longer exists.");
      let updatedAccount = { ...currentAccount, email, username };
      if (password) {
        updatedAccount = {
          ...updatedAccount,
          ...await makePasswordRecord(password)
        };
      }
      users = data.users.map((user) => user.email === editingAccountEmail ? updatedAccount : user);
      updateManagedAccountData({ ...data, users }, editingAccountEmail, email);
      accountFeedback.textContent = `Updated ${email}.`;
    } else {
      if (!password) throw new Error("Enter a password for the new account.");
      const user = {
        email,
        username,
        ...await makePasswordRecord(password),
        createdAt: new Date().toISOString()
      };
      saveAuthData({ ...data, users: [...data.users, user] });
      accountFeedback.textContent = `Added ${email}.`;
    }

    accountFeedback.classList.remove("is-error");
    resetAccountForm();
    renderManagedAccounts();
  } catch (error) {
    accountFeedback.textContent = error.message || "Could not save the account.";
    accountFeedback.classList.add("is-error");
  } finally {
    accountSubmit.disabled = false;
  }
});
accountCancel.addEventListener("click", () => {
  resetAccountForm();
  accountFeedback.textContent = "";
  accountFeedback.classList.remove("is-error");
});
exploreLink.addEventListener("click", () => setCurrentSection("explore"));
accountManagerLink.addEventListener("click", () => setCurrentSection("account-manager"));
window.addEventListener("hashchange", () => {
  if (currentUser?.isAdmin) {
    setCurrentSection(window.location.hash === "#account-manager" ? "account-manager" : "explore");
  }
});
authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authFeedback.classList.remove("is-error");
  authFeedback.textContent = "";
  authSubmit.disabled = true;
  try {
    const identifier = authEmail.value.trim().toLowerCase();
    const password = authPassword.value;
    const data = readAuthData();
    const existingUser = data.users.find((user) =>
      user.email.toLowerCase() === identifier || getUserName(user).toLowerCase() === identifier
    );

    if (isSignUp) {
      const username = authUsername.value.trim();
      if (existingUser || data.users.some((user) => user.email.toLowerCase() === identifier)) {
        throw new Error("An account with this email already exists. Log in instead.");
      }
      if (!/^[a-zA-Z0-9._-]{3,30}$/.test(username)) {
        throw new Error("Username must be 3–30 characters using letters, numbers, dots, underscores or hyphens.");
      }
      if (!isUsernameAvailable(username, data.users) ||
          username.toLowerCase() === (data.admin?.username || adminUsername).toLowerCase() ||
          username.toLowerCase() === identifier) {
        throw new Error("That username is already in use.");
      }
      if (password !== authConfirmPassword.value) throw new Error("The passwords do not match.");

      const user = {
        email: identifier,
        username,
        ...await makePasswordRecord(password),
        createdAt: new Date().toISOString()
      };
      const nextData = { users: [...data.users, user], signedInEmail: identifier };
      saveAuthData(nextData);
      authStorageError = "";
      currentUser = user;
    } else {
      const storedAdminUsername = data.admin?.username || adminUsername;
      if (identifier === storedAdminUsername.toLowerCase() &&
          await verifyAdminPassword(data, password)) {
        const admin = data.admin || {
          username: adminUsername,
          ...await makePasswordRecord(adminPassword)
        };
        saveAuthData({ ...data, admin, signedInEmail: adminAccountId });
        authStorageError = "";
        currentUser = { email: adminAccountId, username: admin.username, isAdmin: true };
      } else {
        if (!existingUser) throw new Error("Email or password is incorrect.");
        if (!await passwordMatchesRecord(password, existingUser)) {
          throw new Error("Email or password is incorrect.");
        }
        saveAuthData({ ...data, signedInEmail: existingUser.email });
        authStorageError = "";
        currentUser = existingUser;
      }
    }

    updateAccountActions();
    updateSavePlaceButton();
    authFeedback.classList.remove("is-error");
    authFeedback.textContent = isSignUp ? "Account created. You’re signed in." : "You’re signed in.";
    const action = pendingAction;
    pendingAction = null;
    window.setTimeout(() => {
      authModal.hidden = true;
      document.body.classList.remove("modal-open");
      authForm.reset();
      setAuthMode(false);
      authOpener?.focus();
      if (action) action();
      else showToast(`Signed in as ${getUserName(currentUser)}.`);
    }, 350);
  } catch (error) {
    authFeedback.textContent = error.message || "Could not complete sign in. Try again.";
    authFeedback.classList.add("is-error");
  } finally {
    authSubmit.disabled = false;
  }
});

signOutButton.addEventListener("click", () => {
  try {
    const data = readAuthData();
    saveAuthData({ ...data, signedInEmail: null });
    currentUser = null;
    window.clearTimeout(suggestionTimer);
    searchRequestId++;
    updateAccountActions();
    updateSavePlaceButton();
    hideSuggestions();
    searchFeedback.textContent = "";
    showToast("You’ve been logged out.");
  } catch (error) {
    showToast(error.message);
  }
});

window.addEventListener("storage", (event) => {
  if (event.key === themeStorageKey) {
    try {
      applyTheme(readTheme());
    } catch (error) {
      showToast(error.message);
    }
  } else if (event.key === authStorageKey) {
    authStorageError = "";
    restoreLocalSession();
    updateSavePlaceButton();
    if (!currentUser) {
      window.clearTimeout(suggestionTimer);
      searchRequestId++;
      hideSuggestions();
    }
  }
});

try {
  applyTheme(readTheme());
} catch (error) {
  showToast(error.message);
}
restoreLocalSession();
updateSavePlaceButton();
const authRedirect = new URLSearchParams(window.location.search).get("auth");
if (authRedirect === "saved" || authRedirect === "settings") {
  const destination = authRedirect === "saved" ? "saved.html" : "settings.html";
  if (currentUser) window.location.replace(destination);
  else {
    pendingAction = () => window.location.assign(destination);
    openAuth(false);
    authIntro.textContent = authRedirect === "saved"
      ? "Sign in to view saved places."
      : "Sign in to manage your account settings.";
  }
}
initializeMap();
