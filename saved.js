const authStorageKey = "wayfinder.local-auth.v1";
const savedPlacesStorageKey = "wayfinder.saved-places.v1";
const themeStorageKey = "wayfinder.theme.v1";
const adminUsername = "admin123";
const adminAccountId = "__wayfinder_admin__";
const savedMain = document.querySelector("#saved-main");
const savedList = document.querySelector("#saved-list");
const savedFeedback = document.querySelector("#saved-feedback");
const savedUserLabel = document.querySelector("#saved-user-label");
const signOutButton = document.querySelector("#saved-sign-out");
const accountManagerLink = document.querySelector("#saved-account-manager-link");
const accountSettingsLink = document.querySelector("#saved-account-settings-link");

function applyTheme() {
  let theme = "light";
  try {
    theme = localStorage.getItem(themeStorageKey) === "dark" ? "dark" : "light";
  } catch {
    savedFeedback.textContent = "Browser storage is unavailable. Theme could not be loaded.";
  }
  document.documentElement.dataset.theme = theme;
}

function getSignedInUser(data) {
  if (data.signedInEmail === adminAccountId || data.signedInEmail === adminUsername) {
    return {
      email: adminAccountId,
      username: data.admin?.username || adminUsername,
      isAdmin: true
    };
  }
  return data.users.find((entry) => entry.email === data.signedInEmail) || null;
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
  if (!data || !Array.isArray(data.users) ||
      (data.signedInEmail !== null && typeof data.signedInEmail !== "string")) {
    throw new Error("Saved account data is invalid. Clear this site's local storage to start over.");
  }
  const validUsers = data.users.every((user) =>
    user &&
    typeof user.email === "string" &&
    (user.username === undefined || typeof user.username === "string") &&
    typeof user.passwordSalt === "string" &&
    typeof user.passwordHash === "string"
  );
  if (!validUsers) {
    throw new Error("Saved account data is invalid. Clear this site's local storage to start over.");
  }
  return data;
}

function readSavedPlaces(email) {
  let serialized;
  try {
    serialized = localStorage.getItem(savedPlacesStorageKey);
  } catch {
    throw new Error("Browser storage is unavailable. Enable local storage to view saved places.");
  }
  if (!serialized) return [];

  let savedData;
  try {
    savedData = JSON.parse(serialized);
  } catch {
    throw new Error("Saved places data is unreadable. Clear this site's local storage to start over.");
  }
  if (!savedData || !savedData.placesByEmail ||
      typeof savedData.placesByEmail !== "object" || Array.isArray(savedData.placesByEmail)) {
    throw new Error("Saved places data is invalid. Clear this site's local storage to start over.");
  }
  const validPlaces = Object.values(savedData.placesByEmail).every((places) =>
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
  return savedData.placesByEmail[email] ||
    (email === adminAccountId ? savedData.placesByEmail[adminUsername] : null) ||
    [];
}

function mapUrl(place) {
  const params = new URLSearchParams({
    name: place.name,
    address: place.address,
    lat: String(place.lat),
    lon: String(place.lon)
  });
  return `index.html?${params}`;
}

function removePlace(email, placeId) {
  let data;
  try {
    const serialized = localStorage.getItem(savedPlacesStorageKey);
    data = serialized ? JSON.parse(serialized) : { placesByEmail: {} };
  } catch {
    savedFeedback.textContent = "Could not update saved places. Check browser storage.";
    return;
  }
  if (!data?.placesByEmail || typeof data.placesByEmail !== "object" || Array.isArray(data.placesByEmail)) {
    savedFeedback.textContent = "Saved places data is invalid. Clear this site's local storage to start over.";
    return;
  }
  const places = data.placesByEmail[email] || [];
  if (!Array.isArray(places) || !places.every((place) =>
    place &&
    typeof place.id === "string" &&
    typeof place.name === "string" &&
    typeof place.address === "string" &&
    Number.isFinite(place.lat) &&
    Number.isFinite(place.lon)
  )) {
    savedFeedback.textContent = "Saved places data is invalid. Clear this site's local storage to start over.";
    return;
  }
  data.placesByEmail[email] = places.filter((place) => place.id !== placeId);
  try {
    localStorage.setItem(savedPlacesStorageKey, JSON.stringify(data));
  } catch {
    savedFeedback.textContent = "Could not update saved places. Check available browser storage.";
    return;
  }
  renderPlaces(email);
}

function renderPlaces(email) {
  savedFeedback.textContent = "";
  savedList.replaceChildren();
  let places;
  try {
    places = readSavedPlaces(email);
  } catch (error) {
    savedFeedback.textContent = error.message;
    return;
  }

  if (!places.length) {
    const empty = document.createElement("p");
    empty.className = "saved-empty";
    empty.textContent = "No saved places.";
    savedList.append(empty);
    return;
  }

  places.forEach((place) => {
    const item = document.createElement("article");
    item.className = "saved-item";
    const link = document.createElement("a");
    link.className = "saved-item-link";
    link.href = mapUrl(place);
    const name = document.createElement("strong");
    name.textContent = place.name;
    const address = document.createElement("span");
    address.textContent = place.address;
    link.append(name, address);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "saved-remove";
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", `Remove ${place.name} from saved places`);
    remove.addEventListener("click", () => removePlace(email, place.id));
    item.append(link, remove);
    savedList.append(item);
  });
}

window.addEventListener("storage", (event) => {
  if (event.key === themeStorageKey) {
    applyTheme();
    return;
  }
  if (event.key !== authStorageKey) return;
  try {
    const authData = readAuthData();
    const user = getSignedInUser(authData);
    if (!user) {
      window.location.replace("index.html?auth=saved");
      return;
    }
    savedUserLabel.textContent = user.username || user.email;
    accountManagerLink.hidden = !user.isAdmin;
    accountSettingsLink.hidden = false;
    renderPlaces(user.email);
  } catch (error) {
    savedFeedback.textContent = error.message;
  }
});

try {
  applyTheme();
  const authData = readAuthData();
  const user = getSignedInUser(authData);
  if (!user) {
    window.location.replace("index.html?auth=saved");
  } else {
    savedUserLabel.textContent = user.username || user.email;
    savedUserLabel.hidden = false;
    accountManagerLink.hidden = !user.isAdmin;
    accountSettingsLink.hidden = false;
    signOutButton.hidden = false;
    savedMain.hidden = false;
    renderPlaces(user.email);
    signOutButton.addEventListener("click", () => {
      try {
        localStorage.setItem(authStorageKey, JSON.stringify({ ...authData, signedInEmail: null }));
        window.location.replace("index.html");
      } catch {
        savedFeedback.textContent = "Could not log out. Check available browser storage.";
      }
    });
  }
} catch (error) {
  savedMain.hidden = false;
  savedFeedback.textContent = error.message;
}
