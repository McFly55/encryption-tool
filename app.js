(() => {
  "use strict";

  // -- Format ---------------------------------------------------------------
  // Verschlüsselte Datei/Daten (Base64): "ENC1." + base64(salt) + "." + base64(iv) + "." + base64(ciphertext)
  const MAGIC = "ENC1";
  const PBKDF2_ITER = 250000;
  const SALT_LEN = 16;
  const IV_LEN = 12;
  const KEY_LEN = 256;

  // -- DOM ------------------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const form = $("crypto-form");
  const pwInput = $("password");
  const pwHint = $("pw-hint");
  const togglePw = $("toggle-pw");
  const eyeIcon = $("eye-icon");
  const textField = $("text-field");
  const textInput = $("text-input");
  const textLabel = $("text-label");
  const fileField = $("file-field");
  const fileInput = $("file-input");
  const dropzone = $("dropzone");
  const fileName = $("file-name");
  const actionBtn = $("action-btn");
  const resetBtn = $("reset-btn");
  const status = $("status");
  const result = $("result");
  const resultText = $("result-text");
  const copyBtn = $("copy-btn");
  const downloadBtn = $("download-btn");

  let mode = "encrypt";
  let inputKind = "text";
  let currentFile = null;
  let resultBlobUrl = null;

  // -- State helpers --------------------------------------------------------
  function setStatus(text, kind) {
    status.hidden = !text;
    status.textContent = text || "";
    status.className = "status" + (kind ? " is-" + kind : "");
  }

  function clearResult() {
    result.hidden = true;
    resultText.value = "";
    downloadBtn.hidden = true;
    if (resultBlobUrl) {
      URL.revokeObjectURL(resultBlobUrl);
      resultBlobUrl = null;
    }
  }

  // -- Segmented controls ---------------------------------------------------
  document.querySelectorAll('[data-mode]').forEach((btn) => {
    btn.addEventListener("click", () => {
      mode = btn.dataset.mode;
      document.querySelectorAll('[data-mode]').forEach((b) => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      actionBtn.textContent = mode === "encrypt" ? "Verschlüsseln" : "Entschlüsseln";
      updateLabels();
      clearResult();
      setStatus("", null);
    });
  });

  document.querySelectorAll('[data-input]').forEach((btn) => {
    btn.addEventListener("click", () => {
      inputKind = btn.dataset.input;
      document.querySelectorAll('[data-input]').forEach((b) => {
        b.classList.toggle("is-active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      textField.hidden = inputKind !== "text";
      fileField.hidden = inputKind !== "file";
      clearResult();
      setStatus("", null);
    });
  });

  function updateLabels() {
    if (mode === "encrypt") {
      textLabel.textContent = "Zu verschlüsselnder Text";
      textInput.placeholder = "Text hier eingeben oder einfügen…";
    } else {
      textLabel.textContent = "Verschlüsselter Text (Base64)";
      textInput.placeholder = "Verschlüsselten Text hier einfügen…";
    }
  }

  // -- Password visibility --------------------------------------------------
  togglePw.addEventListener("click", () => {
    const show = pwInput.type === "password";
    pwInput.type = show ? "text" : "password";
    togglePw.setAttribute("aria-label", show ? "Passwort verbergen" : "Passwort anzeigen");
    eyeIcon.innerHTML = show
      ? '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c6.5 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.16 13.16 0 0 0 2 12s3.5 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" y1="2" x2="22" y2="22"/>'
      : '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>';
  });

  // -- File handling --------------------------------------------------------
  function setFile(file) {
    currentFile = file;
    fileName.textContent = file ? `${file.name} (${formatBytes(file.size)})` : "";
  }

  fileInput.addEventListener("change", () => setFile(fileInput.files[0] || null));

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("is-drag");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("is-drag");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) {
      setFile(f);
      fileInput.files = e.dataTransfer.files;
    }
  });

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MB";
    return (n / (1024 * 1024 * 1024)).toFixed(1) + " GB";
  }

  // -- Reset ----------------------------------------------------------------
  resetBtn.addEventListener("click", () => {
    form.reset();
    setFile(null);
    clearResult();
    setStatus("", null);
    pwHint.hidden = true;
  });

  // -- Copy / Download ------------------------------------------------------
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(resultText.value);
      setStatus("In die Zwischenablage kopiert.", "success");
    } catch {
      resultText.select();
      document.execCommand("copy");
      setStatus("In die Zwischenablage kopiert.", "success");
    }
  });

  downloadBtn.addEventListener("click", () => {
    if (!resultBlobUrl) return;
    const a = document.createElement("a");
    a.href = resultBlobUrl;
    a.download = downloadBtn.dataset.name || "ergebnis.bin";
    document.body.appendChild(a);
    a.click();
    a.remove();
  });

  // -- Crypto helpers -------------------------------------------------------
  function toBase64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function fromBase64(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: KEY_LEN },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptBytes(password, bytes) {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt);
    const cipher = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes)
    );
    const out = `${MAGIC}.${toBase64(salt)}.${toBase64(iv)}.${toBase64(cipher)}`;
    return new TextEncoder().encode(out);
  }

  async function decryptBytes(password, bytes) {
    let text;
    try {
      text = new TextDecoder().decode(bytes);
    } catch {
      throw new Error("Datenformat nicht lesbar.");
    }
    const parts = text.split(".");
    if (parts.length !== 4 || parts[0] !== MAGIC) {
      throw new Error("Ungültiges Format. Entschlüsselter Text erwartet (beginnt mit ENC1.).");
    }
    const salt = fromBase64(parts[1]);
    const iv = fromBase64(parts[2]);
    const cipher = fromBase64(parts[3]);
    const key = await deriveKey(password, salt);
    try {
      return new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)
      );
    } catch {
      throw new Error("Entschlüsseln fehlgeschlagen. Passwort oder Daten sind falsch.");
    }
  }

  // -- Submit ---------------------------------------------------------------
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    setStatus("", null);
    clearResult();
    pwHint.hidden = true;

    const password = pwInput.value;
    if (!password) {
      setStatus("Bitte ein Passwort eingeben.", "error");
      pwHint.textContent = "Ein Passwort ist erforderlich.";
      pwHint.hidden = false;
      pwInput.focus();
      return;
    }
    if (password.length < 8) {
      setStatus("Passwort zu kurz. Mindestens 8 Zeichen.", "error");
      pwHint.textContent = "Mindestens 8 Zeichen empfohlen.";
      pwHint.hidden = false;
      pwInput.focus();
      return;
    }

    actionBtn.disabled = true;
    setStatus(mode === "encrypt" ? "Verschlüssele…" : "Entschlüssele…", "info");

    try {
      if (inputKind === "text") {
        const text = textInput.value;
        if (!text.trim()) {
          setStatus("Bitte Text eingeben.", "error");
          textInput.focus();
          return;
        }
        if (mode === "encrypt") {
          const enc = await encryptBytes(password, new TextEncoder().encode(text));
          resultText.value = new TextDecoder().decode(enc);
          downloadBtn.hidden = true;
        } else {
          const dec = await decryptBytes(password, new TextEncoder().encode(text));
          resultText.value = new TextDecoder().decode(dec);
          downloadBtn.hidden = true;
        }
        result.hidden = false;
        setStatus("Fertig.", "success");
      } else {
        if (!currentFile) {
          setStatus("Bitte eine Datei auswählen.", "error");
          return;
        }
        const buf = new Uint8Array(await currentFile.arrayBuffer());
        if (mode === "encrypt") {
          const enc = await encryptBytes(password, buf);
          const blob = new Blob([enc], { type: "application/octet-stream" });
          if (resultBlobUrl) URL.revokeObjectURL(resultBlobUrl);
          resultBlobUrl = URL.createObjectURL(blob);
          downloadBtn.dataset.name = currentFile.name + ".enc";
          downloadBtn.hidden = false;
          resultText.value = `${currentFile.name} → ${currentFile.name}.enc\nGröße: ${formatBytes(enc.length)}\n\nKlicke auf „Herunterladen", um die verschlüsselte Datei zu speichern.`;
        } else {
          const dec = await decryptBytes(password, buf);
          const blob = new Blob([dec], { type: "application/octet-stream" });
          if (resultBlobUrl) URL.revokeObjectURL(resultBlobUrl);
          resultBlobUrl = URL.createObjectURL(blob);
          const outName = currentFile.name.replace(/\.enc$/i, "") || "entschluesselt";
          downloadBtn.dataset.name = outName;
          downloadBtn.hidden = false;
          resultText.value = `Entschlüsselte Datei: ${outName}\nGröße: ${formatBytes(dec.length)}\n\nKlicke auf „Herunterladen", um die Datei zu speichern.`;
        }
        result.hidden = false;
        setStatus("Fertig.", "success");
      }
    } catch (err) {
      setStatus(err.message || "Ein Fehler ist aufgetreten.", "error");
      clearResult();
    } finally {
      actionBtn.disabled = false;
    }
  });
})();
