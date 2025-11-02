    import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

    // ========== CONFIG ==========
    const SUPABASE_URL = "https://kagkkpfmbjvdnekyffph.supabase.co";
    const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImthZ2trcGZtYmp2ZG5la3lmZnBoIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjIxMDg3MDIsImV4cCI6MjA3NzY4NDcwMn0._2Y9QF8Onid8NNs_E336nqutTBFC9OWYzglWVf81Mio";
    const APP_SALT = "mi-vault-app-salt-v1"; // público; solo para derivar el vault_id
    const db = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    // ========== UI HELPERS ==========
    const $ = s => document.querySelector(s);
    const $$ = s => Array.from(document.querySelectorAll(s));
    const set = (el, txt, cls) => { el.textContent = txt; if(cls){ el.className = cls; } };

    const ui = {
      auth: $("#auth"), app: $("#app"),
      status: $("#vaultStatus"), sync: $("#syncStatus"),
      authMsg: $("#authMsg"), formMsg: $("#formMsg"),
      list: $("#list"), empty: $("#empty"),
      form: $("#form"),
      master: $("#master"),
      q: $("#q"),
      fields: {
        title: $("#f_title"),
        username: $("#f_username"),
        password: $("#f_password"),
        notes: $("#f_notes"),
      }
    };

    // ========== CRYPTO (Web Crypto) ==========
    async function sha256(str){
      const data = new TextEncoder().encode(str);
      const hash = await crypto.subtle.digest("SHA-256", data);
      return b64(new Uint8Array(hash));
    }
    function b64(u8){ // URL-safe base64
      let s = btoa(String.fromCharCode(...u8));
      return s;
    }
    function fromB64(b){
      const bin = atob(b); const bytes = new Uint8Array(bin.length);
      for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
      return bytes;
    }
    async function deriveKey(password, saltB64){
      const pwKey = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password),
        {name:"PBKDF2"}, false, ["deriveKey"]
      );
      const key = await crypto.subtle.deriveKey(
        {name:"PBKDF2", salt: fromB64(saltB64), iterations: 200000, hash: "SHA-256"},
        pwKey,
        {name:"AES-GCM", length:256},
        false, ["encrypt","decrypt"]
      );
      return key;
    }
    async function encryptJSON(key, obj){
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = new TextEncoder().encode(JSON.stringify(obj));
      const cipher = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data);
      return { cipher: b64(new Uint8Array(cipher)), iv: b64(iv) };
    }
    async function decryptJSON(key, cipherB64, ivB64){
      const cipher = fromB64(cipherB64), iv = fromB64(ivB64);
      const plain = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, cipher);
      return JSON.parse(new TextDecoder().decode(plain));
    }

    // ========== VAULT STATE ==========
    let master = null;
    let vaultId = null;
    let encKey = null; // CryptoKey
    let encSaltB64 = null;

    async function computeVaultId(masterPassword){
      // No dependemos de la salt privada aún.
      const id = await sha256(APP_SALT + "::" + masterPassword);
      return id; // base64 de SHA-256
    }

    async function ensureVaultRecord(vaultId){
      const { data, error } = await db.from("vaults").select("*").eq("vault_id", vaultId).maybeSingle();
      if(error){ throw error; }
      if(data){ return data; }
      // Crear nuevo con salt aleatoria para cifrado
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
      const ins = await db.from("vaults").insert({ vault_id: vaultId, enc_salt: salt }).select().single();
      if(ins.error){ throw ins.error; }
      return ins.data;
    }

    // ========== DATA OPS ==========
    async function loadItems(){
      set(ui.sync, "Cargando…");
      const { data, error } = await db.from("vault_items")
        .select("*").eq("vault_id", vaultId).order("created_at", {ascending:false});
      if(error){ set(ui.sync, "Error de carga", "danger"); console.error(error); return; }
      renderList(data || []);
      set(ui.sync, "Sincronizado ✓", "ok");
    }

    async function addItem({title, username, password, notes}){
      const payload = { username, password, notes };
      const { cipher, iv } = await encryptJSON(encKey, payload);
      const { error } = await db.from("vault_items").insert({
        vault_id: vaultId, title, username, password_cipher: cipher, iv, notes_cipher: null
      });
      if(error){ throw error; }
    }

    async function deleteItem(id){
      const { error } = await db.from("vault_items").delete().eq("id", id).eq("vault_id", vaultId);
      if(error) throw error;
    }

    // ========== RENDER ==========
    function card(item){
      const el = document.createElement("div");
      el.className = "glass item";
      el.innerHTML = `
        <div class="meta">
          <span class="badge">${escapeHtml(item.title)}</span>
          <span class="hint">${new Date(item.created_at).toLocaleString()}</span>
        </div>
        <div class="grid three">
          <div><span class="hint">Usuario</span><div>${escapeHtml(item.username||"—")}</div></div>
          <div><span class="hint">Contraseña</span><div><button class="btn-ghost copy" data-id="${item.id}">Copiar</button></div></div>
          <div class="right"><button class="btn-danger" data-del="${item.id}">Eliminar</button></div>
        </div>
      `;
      // Eventos
      el.querySelector("[data-del]").addEventListener("click", async () => {
        if(!confirm("¿Eliminar este registro?")) return;
        await deleteItem(item.id);
        await loadItems();
      });
      el.querySelector(".copy").addEventListener("click", async () => {
        try{
          const data = await decryptJSON(encKey, item.password_cipher, item.iv);
          await navigator.clipboard.writeText(data.password ?? "");
          alert("Contraseña copiada al portapapeles ✅");
        }catch(e){
          console.error(e);
          alert("No pude descifrar este ítem (¿Master Password correcta?).");
        }
      });
      return el;
    }

    function renderList(items){
      const term = (ui.q.value||"").toLowerCase().trim();
      const filtered = items.filter(i =>
        (i.title||"").toLowerCase().includes(term) ||
        (i.username||"").toLowerCase().includes(term)
      );
      ui.list.innerHTML = "";
      if(filtered.length === 0){ ui.empty.style.display = "block"; return; }
      ui.empty.style.display = "none";
      filtered.forEach(i => ui.list.appendChild(card(i)));
    }

    function escapeHtml(s){ return (s??"").replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m])); }

    // ========== FLOW ==========
    async function unlock(){
      try{
        set(ui.authMsg, "");
        master = ui.master.value.trim();
        if(!master){ set(ui.authMsg, "Ingresa tu Master Password ✨"); return; }
        vaultId = await computeVaultId(master);
        const vrec = await ensureVaultRecord(vaultId);
        encSaltB64 = vrec.enc_salt;
        encKey = await deriveKey(master, encSaltB64);

        // Persistir "recordarme" local? Solo el hash del vault, no la clave ni la master.
        localStorage.setItem("mvault_id", vaultId);

        ui.auth.style.display = "none";
        ui.app.style.display = "block";
        set(ui.status, "Desbloqueado ✅", "pill");
        await loadItems();
      }catch(e){
        console.error(e);
        set(ui.authMsg, "No se pudo desbloquear. Revisa tu conexión o prueba de nuevo.", "danger");
      }
    }

    function lock(){
      master = null; vaultId = null; encKey = null;
      ui.app.style.display = "none";
      ui.auth.style.display = "block";
      set(ui.status, "Bloqueado 🔒", "pill");
      ui.master.value = "";
    }

    // ========== EVENTS ==========
    $("#unlockBtn").addEventListener("click", unlock);
    $("#lockBtn").addEventListener("click", lock);
    $("#wipeLocalBtn").addEventListener("click", () => {
      localStorage.removeItem("mvault_id");
      alert("Se olvidó este dispositivo. (No borra tus datos en Supabase).");
    });
    $("#newBtn").addEventListener("click", () => {
      ui.form.style.display = "block";
      ui.fields.title.value = "";
      ui.fields.username.value = "";
      ui.fields.password.value = "";
      ui.fields.notes.value = "";
    });
    $("#cancelBtn").addEventListener("click", ()=> ui.form.style.display="none");
    $("#saveBtn").addEventListener("click", async () => {
      ui.formMsg.textContent = "";
      const title = ui.fields.title.value.trim();
      if(!title){ ui.formMsg.textContent = "El título es obligatorio."; return; }
      try{
        await addItem({
          title,
          username: ui.fields.username.value,
          password: ui.fields.password.value,
          notes: ui.fields.notes.value
        });
        ui.form.style.display = "none";
        await loadItems();
      }catch(e){
        console.error(e);
        ui.formMsg.textContent = "Error al guardar. Intenta otra vez.";
      }
    });
    ui.q.addEventListener("input", async () => { await loadItems(); });

    // Autopista: si recuerdas el vault_id, te muestro pantalla de Master inmediatamente
    (function init(){
      const remember = localStorage.getItem("mvault_id");
      if(remember){ set(ui.authMsg, "Introduce tu Master Password para abrir tu vault guardado."); }
    })();
