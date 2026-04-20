/* ============================================
   UP2U Store - WhatsApp Mini Store
   Application Logic v5 - Security & Performance
   ============================================ */

// ---- Security ----
function sanitizeHTML(str) { if (!str) return ''; const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
function sanitizeForDisplay(str) { if (!str) return ''; return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;'); }

/** Validate URL - prevents javascript: and data: protocol attacks */
function isValidUrl(url) {
  if (!url) return true; // empty is ok
  try {
    const u = new URL(url);
    return ['http:', 'https:'].includes(u.protocol);
  } catch { return false; }
}

/** Validate social media URLs */
function validateSocialUrl(url, fieldName) {
  if (!url) return true;
  if (!isValidUrl(url)) {
    showToast(`رابط ${fieldName} غير صحيح - يجب أن يبدأ بـ https://`, 'error');
    return false;
  }
  return true;
}

// ---- Debounce Utility ----
function debounce(fn, delay = 300) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}

// ---- Rate Limiting ----
const RateLimiter = {
  _timestamps: {},
  canAction(key, intervalMs = 120000) {
    const now = Date.now();
    if (this._timestamps[key] && (now - this._timestamps[key]) < intervalMs) return false;
    this._timestamps[key] = now;
    return true;
  },
  getRemainingMs(key, intervalMs = 120000) {
    if (!this._timestamps[key]) return 0;
    const remaining = intervalMs - (Date.now() - this._timestamps[key]);
    return Math.max(0, remaining);
  }
};

// ---- Offline Detection ----
const NetworkStatus = {
  _listeners: [],
  init() {
    window.addEventListener('online', () => this._notify(true));
    window.addEventListener('offline', () => this._notify(false));
  },
  isOnline() { return navigator.onLine; },
  onChange(cb) { this._listeners.push(cb); },
  _notify(online) { this._listeners.forEach(cb => cb(online)); }
};

// ---- Lazy Image Loading ----
const LazyImages = {
  observer: null,
  init() {
    if (!('IntersectionObserver' in window)) return;
    this.observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.removeAttribute('data-src');
            img.classList.add('lazy-loaded');
          }
          this.observer.unobserve(img);
        }
      });
    }, { rootMargin: '100px' });
  },
  observe(selector) {
    if (!this.observer) return;
    document.querySelectorAll(selector).forEach(img => this.observer.observe(img));
  }
};

// ---- Password Strength ----
function getPasswordStrength(password) {
  let score = 0;
  if (password.length >= 6) score++;
  if (password.length >= 10) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  // 0-1: weak, 2-3: medium, 4-5: strong
  if (score <= 1) return { level: 'weak', label: 'ضعيفة', color: '#EF4444', percent: 25 };
  if (score <= 3) return { level: 'medium', label: 'متوسطة', color: '#F59E0B', percent: 60 };
  return { level: 'strong', label: 'قوية', color: '#22C55E', percent: 100 };
}

// ---- Custom Confirm Dialog ----
function showConfirm(message, onConfirm, onCancel) {
  // Remove existing
  const existing = document.getElementById('customConfirm');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'customConfirm';
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-dialog animate-in">
      <div class="confirm-icon">⚠️</div>
      <p class="confirm-message">${sanitizeForDisplay(message)}</p>
      <div class="confirm-actions">
        <button class="confirm-btn confirm-yes">نعم، متأكد</button>
        <button class="confirm-btn confirm-no">إلغاء</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  requestAnimationFrame(() => overlay.classList.add('active'));

  overlay.querySelector('.confirm-yes').onclick = () => { overlay.remove(); if (onConfirm) onConfirm(); };
  overlay.querySelector('.confirm-no').onclick = () => { overlay.remove(); if (onCancel) onCancel(); };
  overlay.addEventListener('click', (e) => { if (e.target === overlay) { overlay.remove(); if (onCancel) onCancel(); } });
}

// ---- Firebase Authentication ----
const Auth = {
  _auth: null,
  _user: null,
  _onAuthCallback: null,
  _inactivityTimer: null,
  _inactivityTimeout: 30 * 60 * 1000, // 30 minutes

  init() {
    if (typeof firebase === 'undefined' || !window.FIREBASE_CONFIG) return;
    if (!firebase.apps.length) firebase.initializeApp(window.FIREBASE_CONFIG);
    this._auth = firebase.auth();
    this._auth.languageCode = 'ar';
  },

  currentUser() { return this._user; },
  isLoggedIn() { return !!this._user; },
  getUid() { return this._user ? this._user.uid : null; },
  getEmail() { return this._user ? this._user.email : null; },

  onAuthStateChanged(callback) {
    this._onAuthCallback = callback;
    if (this._auth) {
      this._auth.onAuthStateChanged(user => {
        this._user = user;
        if (user) this._startInactivityTimer();
        if (callback) callback(user);
      });
    }
  },

  _startInactivityTimer() {
    this._resetInactivityTimer();
    const events = ['mousedown', 'keydown', 'touchstart', 'scroll'];
    events.forEach(e => document.addEventListener(e, () => this._resetInactivityTimer(), { passive: true }));
  },

  _resetInactivityTimer() {
    clearTimeout(this._inactivityTimer);
    if (this._user) {
      this._inactivityTimer = setTimeout(() => {
        showToast('تم تسجيل الخروج تلقائياً بسبب عدم النشاط', 'error');
        this.logout().then(() => location.reload());
      }, this._inactivityTimeout);
    }
  },

  async register(email, password) {
    const cred = await this._auth.createUserWithEmailAndPassword(email, password);
    this._user = cred.user;
    return cred.user;
  },

  async login(email, password) {
    const cred = await this._auth.signInWithEmailAndPassword(email, password);
    this._user = cred.user;
    return cred.user;
  },

  async resetPassword(email) {
    await this._auth.sendPasswordResetEmail(email);
  },

  async logout() {
    clearTimeout(this._inactivityTimer);
    await this._auth.signOut();
    this._user = null;
  }
};

// ---- Subscription Plans ----
const Plans = {
  tiers: {
    free: { name: 'مجاني', maxProducts: 3, maxImages: 1, coupons: false, badge: true, price: 0, priceSAR: 0 },
    pro: { name: 'احترافي', maxProducts: 20, maxImages: 4, coupons: true, badge: false, price: 5, priceSAR: 19 },
    business: { name: 'أعمال', maxProducts: 999, maxImages: 4, coupons: true, badge: false, price: 12, priceSAR: 49 }
  },
  get(id) { return this.tiers[id] || this.tiers.free; },
  canAddProduct(id, count) { return count < this.get(id).maxProducts; },
  canUseCoupons(id) { return this.get(id).coupons; },
  getMaxImages(id) { return this.get(id).maxImages; },
  showsBadge(id) { return this.get(id).badge; }
};

// ---- Cloud Database (Firebase) ----
const CloudDB = {
  initialized: false,
  db: null,

  init() {
    if (typeof firebase === 'undefined' || !window.FIREBASE_CONFIG ||
      !window.FIREBASE_CONFIG.apiKey || window.FIREBASE_CONFIG.apiKey === 'YOUR_API_KEY') {
      return false;
    }
    try {
      if (!firebase.apps.length) firebase.initializeApp(window.FIREBASE_CONFIG);
      this.db = firebase.database();
      this.initialized = true;
      return true;
    } catch (e) { console.error('Firebase init:', e); return false; }
  },

  getMyStoreId() { return localStorage.getItem('matgary_cloud_id'); },
  setMyStoreId(id) { localStorage.setItem('matgary_cloud_id', id); },

  generateId() {
    const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let id = ''; for (let i = 0; i < 8; i++) id += c[Math.floor(Math.random() * c.length)];
    return id;
  },

  async saveFullStore(storeId, data) {
    if (!this.initialized) return;
    data.updatedAt = new Date().toISOString();
    await this.db.ref(`stores/${storeId}`).set(data);
  },

  async loadStore(storeId) {
    if (!this.initialized) return null;
    const snap = await this.db.ref(`stores/${storeId}`).once('value');
    return snap.val();
  },

  async addReview(storeId, review) {
    if (!this.initialized) return;
    const ref = this.db.ref(`stores/${storeId}/reviews`);
    const snap = await ref.once('value');
    const reviews = snap.val() || [];
    reviews.push(review);
    await ref.set(reviews);
  },

  async incrementView(storeId) {
    if (!this.initialized) return;
    this.db.ref(`stores/${storeId}/views/store_view`).transaction(v => (v || 0) + 1);
  }
};

// ---- Local Storage DB ----
const DB = {
  getStore() { const d = localStorage.getItem('matgary_store'); return d ? JSON.parse(d) : null; },
  saveStore(s) { localStorage.setItem('matgary_store', JSON.stringify(s)); },
  getProducts() { const d = localStorage.getItem('matgary_products'); return d ? JSON.parse(d) : []; },
  saveProducts(p) { localStorage.setItem('matgary_products', JSON.stringify(p)); },
  addProduct(p) { const ps = this.getProducts(); p.id = Date.now().toString(); p.createdAt = new Date().toISOString(); ps.push(p); this.saveProducts(ps); return p; },
  updateProduct(id, u) { const ps = this.getProducts(); const i = ps.findIndex(p => p.id === id); if (i !== -1) { ps[i] = { ...ps[i], ...u }; this.saveProducts(ps); return ps[i]; } return null; },
  deleteProduct(id) { this.saveProducts(this.getProducts().filter(p => p.id !== id)); },
  getProduct(id) { return this.getProducts().find(p => p.id === id) || null; },
  getCoupons() { const d = localStorage.getItem('matgary_coupons'); return d ? JSON.parse(d) : []; },
  saveCoupons(c) { localStorage.setItem('matgary_coupons', JSON.stringify(c)); },
  addCoupon(c) { const cs = this.getCoupons(); c.id = Date.now().toString(); cs.push(c); this.saveCoupons(cs); return c; },
  deleteCoupon(id) { this.saveCoupons(this.getCoupons().filter(c => c.id !== id)); },
  validateCoupon(code) { const c = this.getCoupons().find(x => x.code.toUpperCase() === code.toUpperCase() && x.active); if (!c) return null; if (c.expiry && new Date(c.expiry) < new Date()) return null; return c; },
  getReviews() { const d = localStorage.getItem('matgary_reviews'); return d ? JSON.parse(d) : []; },
  saveReviews(r) { localStorage.setItem('matgary_reviews', JSON.stringify(r)); },
  addReview(r) { const rs = this.getReviews(); r.id = Date.now().toString(); r.date = new Date().toISOString(); rs.push(r); this.saveReviews(rs); return r; },
  getProductReviews(pid) { return this.getReviews().filter(r => r.productId === pid); },
  incrementView(k) { const v = JSON.parse(localStorage.getItem('matgary_views') || '{}'); v[k] = (v[k] || 0) + 1; localStorage.setItem('matgary_views', JSON.stringify(v)); return v[k]; },
  getViews() { return JSON.parse(localStorage.getItem('matgary_views') || '{}'); },
  getPlan() { return localStorage.getItem('matgary_plan') || 'free'; },
  setPlan(p) { localStorage.setItem('matgary_plan', p); }
};

// ---- Cloud Sync Helper with Retry ----
async function syncToCloud(retries = 3) {
  if (!CloudDB.initialized) return false;
  if (!NetworkStatus.isOnline()) { showToast('لا يوجد اتصال بالإنترنت', 'error'); return false; }
  const store = DB.getStore();
  if (!store) return false;
  let storeId = Auth.getUid() || CloudDB.getMyStoreId();
  if (!storeId) { storeId = CloudDB.generateId(); }
  CloudDB.setMyStoreId(storeId);
  const data = {
    settings: store,
    products: DB.getProducts(),
    coupons: DB.getCoupons(),
    reviews: DB.getReviews(),
    views: DB.getViews(),
    plan: DB.getPlan(),
    ownerEmail: Auth.getEmail() || null,
    createdAt: localStorage.getItem('matgary_created') || new Date().toISOString()
  };

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await CloudDB.saveFullStore(storeId, data);
      localStorage.setItem('matgary_created', data.createdAt);
      return true;
    } catch (e) {
      console.warn(`Sync attempt ${attempt}/${retries} failed:`, e);
      if (attempt < retries) await new Promise(r => setTimeout(r, 1000 * attempt));
    }
  }
  showToast('فشل المزامنة - حاول مرة أخرى', 'error');
  return false;
}

// ---- Audit Log ----
const AuditLog = {
  async log(action, details = {}) {
    if (!CloudDB.initialized) return;
    const entry = {
      action,
      details,
      by: Auth.getEmail() || 'unknown',
      uid: Auth.getUid() || 'unknown',
      at: new Date().toISOString()
    };
    try {
      const id = Date.now().toString();
      await CloudDB.db.ref(`audit_log/${id}`).set(entry);
    } catch (e) { console.warn('Audit log failed:', e); }
  },
  async getRecent(limit = 50) {
    if (!CloudDB.initialized) return [];
    try {
      const snap = await CloudDB.db.ref('audit_log').orderByKey().limitToLast(limit).once('value');
      const data = snap.val();
      if (!data) return [];
      return Object.entries(data).reverse().map(([id, v]) => ({ id, ...v }));
    } catch (e) { return []; }
  }
};

// ---- Admin Store Management ----
const AdminStore = {
  async updateSettings(storeId, settings) {
    if (!CloudDB.initialized) return;
    await CloudDB.db.ref(`stores/${storeId}/settings`).set(settings);
    await AuditLog.log('store_settings_update', { storeId, storeName: settings.name });
  },
  async addProduct(storeId, product) {
    if (!CloudDB.initialized) return;
    const snap = await CloudDB.db.ref(`stores/${storeId}/products`).once('value');
    const products = snap.val() || [];
    product.id = Date.now().toString();
    product.createdAt = new Date().toISOString();
    products.push(product);
    await CloudDB.db.ref(`stores/${storeId}/products`).set(products);
    await AuditLog.log('admin_product_add', { storeId, productName: product.name });
    return product;
  },
  async updateProduct(storeId, productId, updates) {
    if (!CloudDB.initialized) return;
    const snap = await CloudDB.db.ref(`stores/${storeId}/products`).once('value');
    const products = snap.val() || [];
    const idx = products.findIndex(p => p.id === productId);
    if (idx !== -1) {
      products[idx] = { ...products[idx], ...updates };
      await CloudDB.db.ref(`stores/${storeId}/products`).set(products);
      await AuditLog.log('admin_product_update', { storeId, productId, productName: updates.name });
    }
  },
  async deleteProduct(storeId, productId) {
    if (!CloudDB.initialized) return;
    const snap = await CloudDB.db.ref(`stores/${storeId}/products`).once('value');
    const products = (snap.val() || []).filter(p => p.id !== productId);
    await CloudDB.db.ref(`stores/${storeId}/products`).set(products);
    await AuditLog.log('admin_product_delete', { storeId, productId });
  },
  async deleteReview(storeId, reviewIdx) {
    if (!CloudDB.initialized) return;
    const snap = await CloudDB.db.ref(`stores/${storeId}/reviews`).once('value');
    const reviews = snap.val() || [];
    reviews.splice(reviewIdx, 1);
    await CloudDB.db.ref(`stores/${storeId}/reviews`).set(reviews);
    await AuditLog.log('admin_review_delete', { storeId });
  },
  async suspendStore(storeId, suspended) {
    if (!CloudDB.initialized) return;
    await CloudDB.db.ref(`stores/${storeId}/suspended`).set(suspended);
    await AuditLog.log(suspended ? 'store_suspend' : 'store_unsuspend', { storeId });
  },
  async deleteStore(storeId) {
    if (!CloudDB.initialized) return;
    await CloudDB.db.ref(`stores/${storeId}`).remove();
    await AuditLog.log('store_delete', { storeId });
  }
};

// ---- Shopping Cart ----
const Cart = {
  items: [],
  load() { const d = sessionStorage.getItem('matgary_cart'); this.items = d ? JSON.parse(d) : []; },
  save() { sessionStorage.setItem('matgary_cart', JSON.stringify(this.items)); },
  add(p) { const e = this.items.find(i => i.id === p.id); if (e) { e.qty += 1; } else { this.items.push({ id: p.id, name: p.name, price: p.price, qty: 1, image: p.image }); } this.save(); showToast(`تمت إضافة "${p.name}" إلى السلة`); },
  remove(id) { this.items = this.items.filter(i => i.id !== id); this.save(); },
  updateQty(id, q) { const i = this.items.find(x => x.id === id); if (i) { i.qty = Math.max(1, q); this.save(); } },
  clear() { this.items = []; this.save(); },
  getTotal() { return this.items.reduce((s, i) => s + (i.price * i.qty), 0); },
  getCount() { return this.items.reduce((s, i) => s + i.qty, 0); },
  isEmpty() { return this.items.length === 0; },
  applyDiscount(total, c) { if (!c) return total; if (c.type === 'percent') return total * (1 - c.value / 100); return Math.max(0, total - c.value); },
  generateCartWhatsAppLink(phone, storeName, currency, coupon) {
    const cp = phone.replace(/[^0-9+]/g, '');
    let list = this.items.map((item, i) => `${i + 1}. ${item.name} × ${item.qty} = ${(item.price * item.qty).toLocaleString('ar-SA')} ${currency}`).join('\n');
    let total = this.getTotal(), totalText = `${total.toLocaleString('ar-SA')} ${currency}`;
    if (coupon) { const d = this.applyDiscount(total, coupon); totalText = `${d.toLocaleString('ar-SA')} ${currency} (بعد خصم ${coupon.code})`; }
    const msg = `السلام عليكم ورحمة الله،\n\nأرغب بطلب المنتجات التالية من "${storeName}":\n\n${list}\n\nالإجمالي: ${totalText}\n\nأرجو تأكيد الطلب وتفاصيل التوصيل والدفع.\n\nشكراً لكم!`;
    return `https://api.whatsapp.com/send?phone=${cp}&text=${encodeURIComponent(msg)}`;
  }
};

// ---- WhatsApp Links ----
function generateWhatsAppLink(phone, productName, price, storeName) {
  const cp = phone.replace(/[^0-9+]/g, '');
  const msg = `السلام عليكم،\n\nرأيت لديكم "${productName}" بسعر ${price} وأرغب بمعرفة المزيد من التفاصيل.\n\nهل المنتج متوفر حالياً؟ وما هي طرق التوصيل والدفع؟\n\nشكراً لكم!`;
  return `https://api.whatsapp.com/send?phone=${cp}&text=${encodeURIComponent(msg)}`;
}
function generateWhatsAppInquiry(phone, storeName) {
  const cp = phone.replace(/[^0-9+]/g, '');
  const msg = `السلام عليكم،\n\nأرغب بالاستفسار عن منتجاتكم في "${storeName}".\n\nهل يمكنكم إفادتي بالتفاصيل؟\n\nشكراً لكم!`;
  return `https://api.whatsapp.com/send?phone=${cp}&text=${encodeURIComponent(msg)}`;
}
function generateUpgradeWhatsApp(storeId, planName) {
  const phone = (window.ADMIN_PHONE || '+96181112046').replace(/[^0-9+]/g, '');
  const msg = `السلام عليكم،\n\nأرغب بترقية متجري إلى باقة "${planName}".\n\nمعرّف المتجر: ${storeId}\n\nأرجو إفادتي بتفاصيل الدفع.\n\nشكراً!`;
  return `https://api.whatsapp.com/send?phone=${phone}&text=${encodeURIComponent(msg)}`;
}

// ---- Utilities ----
function showToast(message, type = 'success') {
  const e = document.querySelector('.toast'); if (e) e.remove();
  const t = document.createElement('div'); t.className = `toast ${type}`;
  t.innerHTML = `<span class="toast-icon">${type === 'success' ? '✅' : '❌'}</span><span class="toast-text">${sanitizeForDisplay(message)}</span><div class="toast-progress"><div class="toast-progress-bar"></div></div>`;
  document.body.appendChild(t); requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, 3500);
}
function handleImageUpload(input, callback) {
  const f = input.files[0]; if (!f) return;
  if (!f.type.startsWith('image/')) { showToast('الرجاء اختيار صورة صحيحة', 'error'); return; }
  if (f.size > 2 * 1024 * 1024) { showToast('الحد الأقصى 2 ميجابايت', 'error'); return; }
  const r = new FileReader(); r.onload = (e) => compressImage(e.target.result, 600, 0.7, callback); r.readAsDataURL(f);
}
function compressImage(dataUrl, maxW, q, cb) {
  const img = new Image(); img.onload = () => { const c = document.createElement('canvas'); let w = img.width, h = img.height; if (w > maxW) { h = (h * maxW) / w; w = maxW; } c.width = w; c.height = h; c.getContext('2d').drawImage(img, 0, 0, w, h); cb(c.toDataURL('image/jpeg', q)); }; img.src = dataUrl;
}
function formatPrice(p, c) { return `${Number(p).toLocaleString('ar-SA')} ${c || 'ر.س'}`; }
function getStoreUrl() {
  const origin = window.location.origin;
  const storeId = CloudDB.getMyStoreId();
  return storeId ? `${origin}store.html?id=${storeId}` : `${origin}store.html`;
}
function shareOnWhatsApp(url, text) { window.open(`https://api.whatsapp.com/send?text=${encodeURIComponent(`${text}\n${url}`)}`, '_blank'); }
function shareOnFacebook(url) { window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(url)}`, '_blank'); }
function shareOnTwitter(url, text) { window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, '_blank'); }
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast('تم النسخ بنجاح!')).catch(() => { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t); showToast('تم النسخ بنجاح!'); });
}

// ---- Initialize Network Status ----
// ---- Initialize Network Status ----
NetworkStatus.init();

function initStore() {
  console.log("Store initialized");
  
  // تحميل السلة
  if (typeof Cart !== "undefined") Cart.load();
  
  // تحميل المتجر (إذا موجود)
  const store = DB.getStore();
  if (store) {
    console.log("Store loaded:", store);
  }
  
  // مثال: عرض المنتجات (إذا عندك هالدوال)
  if (typeof renderProducts === "function") renderProducts();
  if (typeof updateUI === "function") updateUI();
}

// تشغيل عند فتح الصفحة
document.addEventListener('DOMContentLoaded', initStore);
