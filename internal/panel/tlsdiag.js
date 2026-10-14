'use strict';
/* TLS 诊断页脚本。与主面板共用同一个 localStorage 密钥（wb2api.key），
   所以从这里登录过就无需重复填。无内联脚本 —— 满足面板严格 CSP（script-src 'self'）。 */

const LS_KEY = 'wb2api.key';
const DEF_HOST = 'copilot.tencent.com';
const $ = (id) => document.getElementById(id);

/** 与主面板同口径的 API 调用（Bearer 鉴权 + JSON 错误提取）。 */
async function api(path, opts = {}) {
  const h = Object.assign({}, opts.headers || {});
  const k = (localStorage.getItem(LS_KEY) || '').trim();
  if (k) h['Authorization'] = 'Bearer ' + k;
  if (opts.body) h['Content-Type'] = 'application/json';
  const r = await fetch('/panel/api/' + path, Object.assign({}, opts, { headers: h }));
  const d = await r.json().catch(() => ({}));
  if (r.status === 401) throw new Error('密钥无效或未填写（展开下方「面板 API Key」填写）');
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function setStatus(msg, cls) {
  const s = $('status');
  s.className = cls || 'muted';
  s.textContent = msg;
}

function currentHost() {
  return ($('host').value || '').trim() || DEF_HOST;
}

/* ── 探测 ──────────────────────────────────────────────────────────── */
async function probe() {
  $('btnProbe').disabled = true;
  setStatus('正在探测 ' + currentHost() + ' …');
  try {
    const d = await api('tls/probe?host=' + encodeURIComponent(currentHost()));
    setStatus('探测完成：对端出示 ' + d.probe.chain.length + ' 张证书。');
    renderVerdict(d.probe, d.ca_path);
    renderChain(d.probe);
    $('btnTrust').disabled = false;
  } catch (e) {
    setStatus('探测失败：' + e.message, 'bad');
    $('verdict').textContent = '';
    $('chain').textContent = '';
    $('btnTrust').disabled = true;
  } finally {
    $('btnProbe').disabled = false;
  }
}

/* ── 信任并保存 ────────────────────────────────────────────────────── */
async function trust() {
  $('btnTrust').disabled = true;
  setStatus('正在保存证书并热加载 …');
  try {
    const d = await api('tls/trust', {
      method: 'POST',
      body: JSON.stringify({ host: currentHost() }),
    });
    let msg = '已写入 ' + d.ca_path + '（' + d.cert_count + ' 张证书）';
    msg += d.hot_applied ? '，已热加载生效。' : '，未热加载，需重启网关。';
    msg += d.verified ? ' 复验通过 ✓' : ' 复验未通过 ✗';
    setStatus(msg, d.verified ? 'ok' : 'warn');
    if (d.note) {
      const box = $('verdict');
      box.textContent = '';
      const card = el('div', 'card');
      card.appendChild(el('div', 'hint', d.note));
      box.appendChild(card);
    }
    // 复验结果落定后再刷一次链，展示最新状态。
    await probe();
  } catch (e) {
    setStatus('保存失败：' + e.message, 'bad');
  } finally {
    $('btnTrust').disabled = false;
  }
}

/* ── 渲染：结论 ────────────────────────────────────────────────────── */
function renderVerdict(res, caPath) {
  const box = $('verdict');
  box.textContent = '';
  const card = el('div', 'card');

  if (res.trusted_by_system) {
    card.appendChild(el('div', 'ok', '✓ 系统根证书池校验通过。'));
    card.appendChild(el('div', 'muted',
      '本机没有中间人代理 —— 若你仍在别处看到该报错，说明出问题的是另一台设备。'));
  } else {
    card.appendChild(el('div', 'bad', '✗ 系统根证书池校验失败（这就是你看到的报错）：'));
    card.appendChild(el('div', 'mono', res.verify_err || '(无详细信息)'));
    if (res.trusted_by_configured) {
      card.appendChild(el('div', 'ok', '✓ 但当前已配置的 CA 可以通过 —— tls_ca_file / ca.pem 已生效，无需再处理。'));
    } else {
      card.appendChild(el('div', 'warn', '→ 点「信任并保存」把下面这条链写入 ca.pem 即可修复。'));
    }
  }
  if (caPath) {
    const kv = el('div', 'kv');
    kv.style.marginTop = '8px';
    kv.appendChild(el('div', null, '保存位置'));
    kv.appendChild(el('div', 'mono', caPath));
    kv.appendChild(el('div', null, '连接目标'));
    kv.appendChild(el('div', 'mono', res.addr));
    card.appendChild(kv);
  }
  box.appendChild(card);
}

/* ── 渲染：证书链 ──────────────────────────────────────────────────── */
function renderChain(res) {
  const box = $('chain');
  box.textContent = '';
  const card = el('div', 'card');
  card.appendChild(el('div', 'muted', '对端出示的证书链共 ' + res.chain.length + ' 张（第 1 张为叶证书）'));

  res.chain.forEach((c) => {
    const d = el('div', 'cert');
    const h = el('h3', null, c.subject);
    if (c.is_ca) h.appendChild(el('span', 'tag ca', 'CA'));
    if (c.self_signed) h.appendChild(el('span', 'tag self', '自签'));
    d.appendChild(h);

    const kv = el('div', 'kv');
    const rows = [
      ['签发者', c.issuer],
      ['有效期', c.not_before + ' → ' + c.not_after],
      ['SHA256', c.sha256],
    ];
    if (c.dns_names && c.dns_names.length) rows.push(['适用域名', c.dns_names.join(', ')]);
    rows.forEach(([k, v]) => {
      kv.appendChild(el('div', null, k));
      kv.appendChild(el('div', 'mono', v));
    });
    d.appendChild(kv);
    card.appendChild(d);
  });
  box.appendChild(card);
}

/* ── 初始化 ────────────────────────────────────────────────────────── */
(function init() {
  $('host').value = DEF_HOST;
  $('key').value = localStorage.getItem(LS_KEY) || '';
  $('key').addEventListener('change', () => {
    localStorage.setItem(LS_KEY, $('key').value.trim());
  });
  $('btnProbe').addEventListener('click', probe);
  $('btnTrust').addEventListener('click', trust);
  $('host').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') probe();
  });
  probe(); // 进页面即自动探一次，省掉一次点击
})();
