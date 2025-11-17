// Private Diary - app.js
// Uses Web Crypto (PBKDF2 + AES-GCM) to encrypt diary data locally in localStorage.

const STORAGE_KEY = 'diary:v1';

let derivedKey = null;
let entries = {}; // { 'YYYY-MM-DD': {title, text, modified} }

// --- Utilities ---
function bufToBase64(buf){
	return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64){
	const bin = atob(b64);
	const len = bin.length;
	const arr = new Uint8Array(len);
	for(let i=0;i<len;i++) arr[i]=bin.charCodeAt(i);
	return arr.buffer;
}
function strToBuf(str){
	return new TextEncoder().encode(str);
}
function bufToStr(buf){
	return new TextDecoder().decode(buf);
}

// --- Crypto ---
async function deriveKey(password, salt, iterations=150000){
	const pwKey = await crypto.subtle.importKey('raw', strToBuf(password), {name:'PBKDF2'}, false, ['deriveKey']);
	return crypto.subtle.deriveKey({name:'PBKDF2', salt:salt, iterations:iterations, hash:'SHA-256'}, pwKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

async function encryptData(key, json){
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encoded = strToBuf(JSON.stringify(json));
	const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, encoded);
	return {ct:bufToBase64(ct), iv:bufToBase64(iv)};
}

async function decryptData(key, ctBase64, ivBase64){
	const ct = base64ToBuf(ctBase64);
	const iv = new Uint8Array(base64ToBuf(ivBase64));
	const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
	return JSON.parse(bufToStr(plain));
}

// --- Storage helpers ---
function saveStore(storeObj){
	localStorage.setItem(STORAGE_KEY, JSON.stringify(storeObj));
}
function readStore(){
	const raw = localStorage.getItem(STORAGE_KEY);
	return raw ? JSON.parse(raw) : null;
}

// --- App logic ---
async function tryUnlock(password){
	const store = readStore();
	if(!store){
		// no data yet, create empty store
		const salt = crypto.getRandomValues(new Uint8Array(16));
		derivedKey = await deriveKey(password, salt.buffer);
		entries = {};
		const enc = await encryptData(derivedKey, entries);
		saveStore({version:1, salt:bufToBase64(salt), iterations:150000, ct:enc.ct, iv:enc.iv});
		return true;
	}

	// try to derive key and decrypt
	try{
		const saltBuf = base64ToBuf(store.salt);
		derivedKey = await deriveKey(password, saltBuf, store.iterations || 150000);
		const data = await decryptData(derivedKey, store.ct, store.iv);
		entries = data || {};
		return true;
	}catch(err){
		derivedKey = null;
		entries = {};
		console.error('unlock failed', err);
		return false;
	}
}

async function persist(){
	if(!derivedKey) throw new Error('not unlocked');
	const enc = await encryptData(derivedKey, entries);
	const store = readStore() || {};
	store.version = 1;
	store.salt = store.salt || bufToBase64(crypto.getRandomValues(new Uint8Array(16)));
	store.iterations = store.iterations || 150000;
	store.ct = enc.ct;
	store.iv = enc.iv;
	saveStore(store);
}

// --- UI wiring ---
const overlay = document.getElementById('overlay');
const passwordInput = document.getElementById('passwordInput');
const overlayError = document.getElementById('overlayError');
const btnUnlock = document.getElementById('btnUnlock');
const btnCreate = document.getElementById('btnCreate');
const datePicker = document.getElementById('datePicker');
const entriesList = document.getElementById('entriesList');
const contentEl = document.getElementById('content');
const titleInput = document.getElementById('titleInput');
const btnSave = document.getElementById('btnSave');
const btnDelete = document.getElementById('btnDelete');
const btnLock = document.getElementById('btnLock');
const btnExport = document.getElementById('btnExport');
const btnImport = document.getElementById('btnImport');
const fileImport = document.getElementById('fileImport');
const searchInput = document.getElementById('searchInput');
const btnNewEntry = document.getElementById('btnNewEntry');
const themeSelect = document.getElementById('themeSelect');
const profileBtn = document.getElementById('profileBtn');
const overlayAvatar = document.getElementById('overlayAvatar');

let selectedDate = null;

function formatDateKey(d){
	const yyyy = d.getFullYear();
	const mm = String(d.getMonth()+1).padStart(2,'0');
	const dd = String(d.getDate()).padStart(2,'0');
	return `${yyyy}-${mm}-${dd}`;
}

function refreshList(){
	entriesList.innerHTML='';
	const q = (searchInput && searchInput.value) ? searchInput.value.trim().toLowerCase() : '';
	const keys = Object.keys(entries).sort((a,b)=>b.localeCompare(a));
	for(const k of keys){
		const e = entries[k];
		const hay = (k + ' ' + (e.title||'') + ' ' + (e.text||'')).toLowerCase();
		if(q && !hay.includes(q)) continue;

		const item = document.createElement('div');
		item.className='entry-item';
		if(k===selectedDate) item.classList.add('active');

		const meta = document.createElement('div');
		meta.className = 'entry-meta';
		const title = document.createElement('div');
		title.className='entry-title';
		title.textContent = e.title ? `${k} — ${e.title}` : k;
		const excerpt = document.createElement('div');
		excerpt.className='entry-excerpt';
		excerpt.textContent = e.text ? e.text.replace(/\s+/g,' ').slice(0,120) : '';

		const time = document.createElement('div');
		time.className='entry-time';
		time.textContent = new Date(e.modified).toLocaleString();


		meta.appendChild(title);
		meta.appendChild(excerpt);

		item.appendChild(meta);

		// emoji reaction display & quick actions
		const emojiWrap = document.createElement('div');
		emojiWrap.style.display='flex';
		emojiWrap.style.alignItems='center';
		if(e.reaction){
			const r = document.createElement('div');
			r.className='entry-emoji';
			r.textContent = e.reaction;
			emojiWrap.appendChild(r);
		}

		const quick = ['😊','❤️','😮','😢','🔥'];
		for(const em of quick){
			const b = document.createElement('div');
			b.className='entry-emoji';
			b.textContent = em;
			b.title = 'React ' + em;
			b.addEventListener('click',(ev)=>{ev.stopPropagation(); entries[k].reaction = em; persist().then(()=>refreshList());});
			emojiWrap.appendChild(b);
		}

		item.appendChild(emojiWrap);
		item.appendChild(time);
		item.addEventListener('click',()=>{selectDate(k)});
		entriesList.appendChild(item);
	}
}

// --- Theme & profile ---
function applyTheme(theme){
  document.body.classList.remove('theme-mint','theme-purple','theme-sunset','theme-forest');
  if(theme && theme !== 'default') document.body.classList.add(theme);
  try{ localStorage.setItem('diary:theme', theme); }catch(e){}
}

function initialsFor(name){
  if(!name) return 'ME';
  const parts = name.trim().split(/\s+/);
  if(parts.length===1) return parts[0].slice(0,2).toUpperCase();
  return (parts[0][0]+parts[1][0]).toUpperCase();
}

function loadProfile(){
  const name = localStorage.getItem('diary:profileName') || 'Me';
  profileBtn.textContent = initialsFor(name);
  if(overlayAvatar) overlayAvatar.textContent = initialsFor(name);
}

if(themeSelect){
  themeSelect.addEventListener('change', ()=> applyTheme(themeSelect.value));
  const saved = localStorage.getItem('diary:theme') || 'default';
  themeSelect.value = saved;
  applyTheme(saved);
}

if(profileBtn){
  profileBtn.addEventListener('click', ()=>{
    const name = prompt('Display name (used for avatar initials):', localStorage.getItem('diary:profileName')||'Me');
    if(name!==null){
      localStorage.setItem('diary:profileName', name);
      loadProfile();
    }
  });
}

loadProfile();

function makeNewEntryForToday(){
	const today = new Date();
	const key = formatDateKey(today);
	datePicker.value = key;
	selectedDate = key;
	// if entry already exists, show it; otherwise clear editor for new content
	if(!entries[key]){
		titleInput.value = '';
		contentEl.value = '';
	}else{
		showEntryForDate(key);
	}
	refreshList();
	contentEl.focus();
}

function showEntryForDate(key){
	const e = entries[key];
	if(e){
		titleInput.value = e.title || '';
		contentEl.value = e.text || '';
	}else{
		titleInput.value = '';
		contentEl.value = '';
	}
}

function selectDate(key){
	selectedDate = key;
	datePicker.value = key;
	refreshList();
	showEntryForDate(key);
}

btnUnlock.addEventListener('click', async ()=>{
	overlayError.textContent='';
	const ok = await tryUnlock(passwordInput.value);
	if(ok){
		overlay.classList.add('hidden');
		// if date picker empty, set to today
		if(!datePicker.value){
			const today = new Date();
			datePicker.value = formatDateKey(today);
		}
		selectedDate = datePicker.value;
		refreshList();
		if(selectedDate) showEntryForDate(selectedDate);
		passwordInput.value='';
	}else{
		overlayError.textContent='Incorrect password or corrupted data.';
	}
});

btnCreate.addEventListener('click', async ()=>{
	// create new store with provided password
	overlayError.textContent='';
	const ok = await tryUnlock(passwordInput.value);
	if(ok){
		overlay.classList.add('hidden');
		if(!datePicker.value){
			const today = new Date();
			datePicker.value = formatDateKey(today);
		}
		selectedDate = datePicker.value;
		refreshList();
		showEntryForDate(selectedDate);
		passwordInput.value='';
	}
});

datePicker.addEventListener('change', ()=>{
	if(!datePicker.value) return;
	selectDate(datePicker.value);
});

if(searchInput){
	searchInput.addEventListener('input', ()=>refreshList());
}

if(btnNewEntry){
	btnNewEntry.addEventListener('click', ()=> makeNewEntryForToday());
}

btnSave.addEventListener('click', async ()=>{
	if(!selectedDate) return alert('Select a date first');
	entries[selectedDate] = {title: titleInput.value.trim(), text: contentEl.value, modified: new Date().toISOString()};
	await persist();
	refreshList();
});

btnDelete.addEventListener('click', async ()=>{
	if(!selectedDate) return;
	if(!entries[selectedDate]) return;
	if(!confirm('Delete entry for ' + selectedDate + '?')) return;
	delete entries[selectedDate];
	selectedDate = null;
	contentEl.value=''; titleInput.value='';
	await persist();
	refreshList();
});

btnLock.addEventListener('click', ()=>{
	derivedKey = null; entries = {}; overlay.classList.remove('hidden');
});

btnExport.addEventListener('click', ()=>{
	const store = readStore();
	if(!store) return alert('No data to export');
	const blob = new Blob([JSON.stringify(store, null, 2)], {type:'application/json'});
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = 'diary-backup.json';
	a.click();
	URL.revokeObjectURL(url);
});

btnImport.addEventListener('click', ()=> fileImport.click());

fileImport.addEventListener('change', async (ev)=>{
	const f = ev.target.files[0];
	if(!f) return;
	const text = await f.text();
	let parsed;
	try{ parsed = JSON.parse(text);}catch(e){return alert('Invalid file');}
	// Ask for password to decrypt imported file
	const pw = prompt('Enter password for the imported backup to decrypt (the file is encrypted).');
	if(!pw) return;
	try{
		// attempt to derive key and decrypt
		const saltBuf = base64ToBuf(parsed.salt);
		const key = await deriveKey(pw, saltBuf, parsed.iterations || 150000);
		const data = await decryptData(key, parsed.ct, parsed.iv);
		// success - replace local store with imported data
		localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
		derivedKey = key; entries = data || {};
		overlay.classList.add('hidden');
		if(!datePicker.value){
			const today = new Date();
			datePicker.value = formatDateKey(today);
		}
		selectedDate = datePicker.value;
		refreshList();
		if(selectedDate) showEntryForDate(selectedDate);
		alert('Import successful');
	}catch(err){
		console.error(err);
		alert('Import failed: incorrect password or corrupted file');
	}
	fileImport.value='';
});

// On first load, show overlay
window.addEventListener('load', ()=>{
	const store = readStore();
	if(store){
		document.getElementById('overlayTitle').textContent='Unlock your diary';
		document.getElementById('overlayDesc').textContent='Enter your password to unlock local, encrypted diary.';
		overlay.classList.remove('hidden');
	}else{
		document.getElementById('overlayTitle').textContent='Create a password';
		document.getElementById('overlayDesc').textContent='Create a password to protect your diary locally. It will not be sent anywhere.';
		overlay.classList.remove('hidden');
		btnUnlock.textContent='Unlock';
		btnCreate.textContent='Create New';
	}
});

