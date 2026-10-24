const $ = (id) => document.getElementById(id);
let token = localStorage.getItem('anss_admin_token') || '';

function toast(msg){ $('toast').textContent=msg; $('toast').classList.remove('hidden'); setTimeout(()=>$('toast').classList.add('hidden'),2600); }
function authHeaders(){ return {'Content-Type':'application/json','Authorization':`Bearer ${token}`}; }
async function api(path, opts={}){
  const res = await fetch(path,{...opts,headers:{...authHeaders(),...(opts.headers||{})}});
  if(res.status===401){ logout(); throw new Error('Session expirée'); }
  const data = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(data.detail || `Erreur ${res.status}`);
  return data;
}
function fmtDate(s){ if(!s) return '—'; return new Date(s).toLocaleString('fr-DZ',{dateStyle:'short',timeStyle:'short'}); }
function badge(status){ return `<span class="badge ${status.toLowerCase()}">${status==='PENDING'?'EN ATTENTE':status==='VALIDATED'?'VALIDÉ':'REJETÉ'}</span>`; }

async function login(){
  $('loginError').textContent='';
  try{
    const res=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('username').value,password:$('password').value})});
    const data=await res.json();
    if(!res.ok) throw new Error(data.detail||'Connexion impossible');
    token=data.token; localStorage.setItem('anss_admin_token',token); showApp();
  }catch(e){ $('loginError').textContent=e.message; }
}
function logout(){ token=''; localStorage.removeItem('anss_admin_token'); $('appView').classList.add('hidden'); $('loginView').classList.remove('hidden'); }
function showApp(){ $('loginView').classList.add('hidden'); $('appView').classList.remove('hidden'); showPage('dashboard'); }

async function loadDashboard(){
  const d=await api('/api/admin/dashboard');
  $('statTotal').textContent=d.total_reports;
  $('statPending').textContent=d.pending_reports;
  $('statValidated').textContent=d.validated_reports;
  $('statKeys').textContent=d.published_keys;
  $('statDiseases').textContent=d.active_diseases;

  // Stats par Wilaya
  if(d.wilaya_stats) {
      const statsHtml = Object.entries(d.wilaya_stats)
          .sort((a,b) => b[1] - a[1])
          .map(([w, c]) => `<div class="stat-item"><span>${w}</span><strong>${c}</strong></div>`)
          .join('');
      const container = $('recentReports').parentElement;
      let wilayaDiv = $('wilayaStats');
      if(!wilayaDiv) {
          wilayaDiv = document.createElement('div');
          wilayaDiv.id = 'wilayaStats';
          wilayaDiv.className = 'panel';
          container.parentElement.insertBefore(wilayaDiv, container);
      }
      wilayaDiv.innerHTML = `<div class="panel-head"><h3>Répartition par Wilaya</h3></div><div class="stats-grid">${statsHtml}</div>`;
  }

  const rows=await api('/api/admin/reports'); renderReports(rows.slice(0,8),'recentReports');
}
function renderReports(rows,target){
  if(!rows.length){ $(target).innerHTML='<p class="muted">Aucun signalement.</p>'; return; }
  $(target).innerHTML=`<table><thead><tr><th>ID</th><th>Épidémie</th><th>Type</th><th>Wilaya</th><th>Contact</th><th>Clés BLE</th><th>Date</th><th>Statut</th><th>Actions</th></tr></thead><tbody>${rows.map(r=>`<tr>
    <td>#${r.id}</td><td><strong>${r.disease_fr}</strong><br><span class="muted" dir="rtl">${r.disease_ar}</span></td><td>${r.classification}</td><td>${r.wilaya||'—'}</td><td>${r.phone||'—'}</td><td>${r.keys_count}</td><td>${fmtDate(r.created_at)}</td><td>${badge(r.status)}</td><td>${r.status==='PENDING'?`<div class="actions"><button class="approve" onclick="validateReport(${r.id})">Valider</button><button class="reject" onclick="rejectReport(${r.id})">Rejeter</button></div>`:'—'}</td>
  </tr>`).join('')}</tbody></table>`;
}
async function loadReports(){ const status=$('statusFilter').value; const rows=await api('/api/admin/reports'+(status?`?status=${status}`:'')); renderReports(rows,'reportsTable'); }
async function validateReport(id){ if(!confirm('Valider ce cas et publier ses identifiants temporaires ?')) return; const r=await api(`/api/admin/reports/${id}/validate`,{method:'POST'}); toast(`${r.published_keys||0} clé(s) publiée(s)`); await loadDashboard(); await loadReports(); }
async function rejectReport(id){ if(!confirm('Rejeter ce signalement ?')) return; await api(`/api/admin/reports/${id}/reject`,{method:'POST'}); toast('Signalement rejeté'); await loadDashboard(); await loadReports(); }
window.validateReport=validateReport; window.rejectReport=rejectReport;

async function loadDiseases(){
  const rows=await api('/api/admin/diseases');
  $('diseaseList').innerHTML=rows.map(d=>`<div class="disease"><div><strong>${d.name_fr} <span class="muted" dir="rtl">— ${d.name_ar}</span></strong><small>${d.code} · RSSI ${d.threshold_rssi} dBm · ${d.min_duration_minutes} min</small></div><div class="actions"><button class="toggle" onclick="editDisease(${d.id},${d.threshold_rssi},${d.min_duration_minutes})">Paramètres</button><button class="toggle ${d.active?'on':''}" onclick="toggleDisease(${d.id},${!d.active})">${d.active?'Active':'Inactive'}</button></div></div>`).join('');
}
async function toggleDisease(id,active){ await api(`/api/admin/diseases/${id}`,{method:'PATCH',body:JSON.stringify({active})}); toast(active?'Épidémie activée':'Épidémie désactivée'); await loadDiseases(); await loadDashboard(); }
window.toggleDisease=toggleDisease;
async function editDisease(id,rssi,duration){
  const newRssi=prompt('Seuil RSSI (ex. -72 dBm)', String(rssi)); if(newRssi===null) return;
  const newDuration=prompt('Durée minimale de contact en minutes', String(duration)); if(newDuration===null) return;
  const nr=Number(newRssi), nd=Number(newDuration);
  if(!Number.isFinite(nr)||!Number.isFinite(nd)||nd<0){toast('Valeurs invalides');return;}
  await api(`/api/admin/diseases/${id}`,{method:'PATCH',body:JSON.stringify({threshold_rssi:nr,min_duration_minutes:nd})});
  toast('Paramètres de détection mis à jour'); await loadDiseases();
}
window.editDisease=editDisease;

async function addDisease(){
  const body={code:$('dCode').value.trim(),name_fr:$('dFr').value.trim(),name_ar:$('dAr').value.trim(),advice_fr:$('dAdviceFr').value.trim(),advice_ar:$('dAdviceAr').value.trim(),threshold_rssi:Number($('dRssi').value),min_duration_minutes:Number($('dDuration').value),active:true};
  if(!body.code||!body.name_fr||!body.name_ar){toast('Code et noms obligatoires');return;}
  try{ await api('/api/admin/diseases',{method:'POST',body:JSON.stringify(body)}); ['dCode','dFr','dAr','dAdviceFr','dAdviceAr'].forEach(x=>$(x).value=''); toast('Épidémie ajoutée'); await loadDiseases(); await loadDashboard(); }catch(e){toast(e.message)}
}

async function loadUsers(){
  const users = await api('/api/admin/users');
  $('usersTable').innerHTML = `<table><thead><tr><th>Nom complet</th><th>Téléphone</th><th>Device ID</th><th>Date d'inscription</th><th>Signalements</th></tr></thead><tbody>${users.map(u=>`<tr>
    <td><strong>${u.full_name||'—'}</strong></td><td>${u.phone}</td><td><small class="muted">${u.device_id||'—'}</small></td><td>${fmtDate(u.created_at)}</td><td>${u.reports_count}</td>
  </tr>`).join('')}</tbody></table>`;
}

function showPage(page){
  document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden')); $(`page-${page}`).classList.remove('hidden');
  document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('active',x.dataset.page===page));
  $('pageTitle').textContent=page==='dashboard'?'Tableau de bord':page==='reports'?'Signalements':page==='users'?'Utilisateurs':'Épidémies';
  if(page==='dashboard') loadDashboard().catch(e=>toast(e.message));
  if(page==='reports') loadReports().catch(e=>toast(e.message));
  if(page==='users') loadUsers().catch(e=>toast(e.message));
  if(page==='diseases') loadDiseases().catch(e=>toast(e.message));
}

document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
$('loginBtn').addEventListener('click',login); $('password').addEventListener('keydown',e=>{if(e.key==='Enter')login()}); $('logoutBtn').addEventListener('click',logout); $('refreshDashboard').addEventListener('click',loadDashboard); $('statusFilter').addEventListener('change',loadReports); $('addDiseaseBtn').addEventListener('click',addDisease);
if(token) showApp();
