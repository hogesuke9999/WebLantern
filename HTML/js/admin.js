let adminPollingInterval = null;
let csrfToken = '';
let currentClientId = '';
let configBaseUrl = ''; // config.php から取得するベースURL

// CSRFトークンおよび config.php の BASE_URL を取得・更新する関数
async function fetchCsrfToken() {
    try {
        const res = await fetch('api.php?action=get_csrf_token');
        const data = await res.json();
        if (data.success) {
            if (data.csrf_token) csrfToken = data.csrf_token;
            if (data.base_url) configBaseUrl = data.base_url; // config.php の BASE_URL を保持
        }
    } catch (e) {
        console.error('CSRFトークン取得エラー:', e);
    }
}

// 現在のURLからフォールバック用のベースURLを生成する関数
function getFallbackBaseUrl() {
    const path = location.pathname.substring(0, location.pathname.lastIndexOf('/') + 1);
    return location.origin + path;
}

// 有効なベースURLを取得（config.phpの設定値を優先）
function getEffectiveBaseUrl() {
    if (configBaseUrl) {
        // 末尾にスラッシュがない場合は付与
        return configBaseUrl.endsWith('/') ? configBaseUrl : configBaseUrl + '/';
    }
    return getFallbackBaseUrl();
}

// 管理者ログイン状態およびアカウント存在状態の確認
async function checkAdminStatus() {
    try {
        const statusRes = await fetch('api.php?action=get_status');
        if (statusRes.ok) {
            const statusData = await statusRes.json();
            if (statusData.success) {
                if (statusData.client_id) {
                    currentClientId = statusData.client_id;
                }
                if (statusData.base_url) {
                    configBaseUrl = statusData.base_url;
                }
                showDashboard();
                return;
            }
        }

        const checkRes = await fetch('api.php?action=admin_check');
        const checkData = await checkRes.json();
        
        const dashboard = document.getElementById('admin-dashboard');
        if (dashboard) dashboard.style.display = 'none';
        stopAdminPolling();

        const regCard = document.getElementById('admin-register-card');
        const loginCard = document.getElementById('admin-login-card');

        if (checkData.exists) {
            if (regCard) regCard.style.display = 'none';
            if (loginCard) loginCard.style.display = 'block';
        } else {
            if (regCard) regCard.style.display = 'block';
            if (loginCard) loginCard.style.display = 'none';
        }
    } catch (e) {
        console.error('初期確認エラー:', e);
    }
}

async function adminRegister() {
    const username = document.getElementById('reg-admin-name').value;
    const email = document.getElementById('reg-admin-email').value;
    const msgDiv = document.getElementById('reg-msg');
    msgDiv.innerHTML = '';

    try {
        const res = await fetch('api.php?action=admin_register', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username: username, email: email })
        });
        const data = await res.json();

        if (data.csrf_token) csrfToken = data.csrf_token;

        if (res.ok && data.success) {
            let html = `<div class="alert alert-success">${escapeHtml(data.message)}</div>`;
            if (data.dev_verify_url) {
                html += `<div style="margin-top:10px; font-size:0.8rem;"><a href="${data.dev_verify_url}" target="_blank">本登録（パスワード設定）画面を開く</a></div>`;
            }
            msgDiv.innerHTML = html;
        } else {
            msgDiv.innerHTML = `<div class="alert alert-danger">${escapeHtml(data.message)}</div>`;
        }
    } catch (e) {
        msgDiv.innerHTML = '<div class="alert alert-danger">通信エラーが発生しました</div>';
    }
}

async function adminLogin() {
    const id = document.getElementById('admin-id').value;
    const pass = document.getElementById('admin-pass').value;
    const msg = document.getElementById('login-msg');

    try {
        const res = await fetch('api.php?action=login', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ user_id: id, password: pass })
        });
        const data = await res.json();

        if (data.csrf_token) csrfToken = data.csrf_token;

        if (res.ok && data.success) {
            msg.innerText = '';
            showDashboard();
        } else {
            msg.innerText = data.message || 'ログインに失敗しました';
        }
    } catch (e) {
        msg.innerText = '通信エラーが発生しました';
    }
}

async function showDashboard() {
    const regCard = document.getElementById('admin-register-card');
    const loginCard = document.getElementById('admin-login-card');
    const dashboard = document.getElementById('admin-dashboard');

    if (regCard) regCard.style.display = 'none';
    if (loginCard) loginCard.style.display = 'none';
    if (dashboard) dashboard.style.display = 'block';
    
    await loadUsers();
    startAdminPolling();
}

function startAdminPolling() {
    if (adminPollingInterval) clearInterval(adminPollingInterval);
    adminPollingInterval = setInterval(loadUsers, 3000);
}

function stopAdminPolling() {
    if (adminPollingInterval) {
        clearInterval(adminPollingInterval);
        adminPollingInterval = null;
    }
}

async function loadUsers() {
    try {
        const res = await fetch('api.php?action=admin_get_users');
        if (res.status === 403 || res.status === 401) {
            stopAdminPolling();
            checkAdminStatus();
            return;
        }

        const data = await res.json();
        if (data.success) {
            if (data.base_url) configBaseUrl = data.base_url;

            const tbody = document.getElementById('userTableBody');
            if (!tbody) return;
            tbody.innerHTML = '';

            data.users.forEach(u => {
                const tr = document.createElement('tr');
                const enabledFlags = u.enabled_flags || [0, 0, 0, 0];

                let controlsHtml = '<div class="lantern-card-group">';

                u.flags.forEach((flagVal, idx) => {
                    const target = idx + 1;
                    const isEnabled = (enabledFlags[idx] === 1);
                    const isON = (flagVal === 1);
                    
                    const enableBtnClass = isEnabled ? 'btn-lantern-enable active' : 'btn-lantern-enable disabled';
                    const enableBtnText = isEnabled ? '🔔 有効' : '🔕 無効';
                    const nextEnableState = isEnabled ? 0 : 1;

                    let toggleBtnClass = 'btn-lantern-toggle';
                    if (!isEnabled) {
                        toggleBtnClass += ' is-disabled';
                    } else if (isON) {
                        toggleBtnClass += ' on';
                    } else {
                        toggleBtnClass += ' off';
                    }

                    const toggleBtnText = `#${target}: ${isON ? '点灯' : '消灯'}`;
                    const nextFlag = isON ? 0 : 1;
                    const disabledAttr = !isEnabled ? 'disabled' : '';

                    controlsHtml += `
                        <div class="lantern-card ${!isEnabled ? 'is-disabled' : ''}">
                            <button type="button" class="${enableBtnClass}" onclick="toggleLanternEnable(${u.id}, ${target}, ${nextEnableState})">
                                ${enableBtnText}
                            </button>
                            <button type="button" class="${toggleBtnClass}" ${disabledAttr} onclick="toggleLanternFlag(${u.id}, ${target}, ${nextFlag})">
                                ${toggleBtnText}
                            </button>
                        </div>
                    `;
                });
                controlsHtml += '</div>';

                let clientsHtml = '<div style="display:flex; flex-direction:column; gap:4px;">';
                if (u.clients && u.clients.length > 0) {
                    u.clients.forEach(c => {
                        const statusClass = c.is_alive ? 'alive' : 'dead';
                        const statusText = c.is_alive ? 'Online' : 'Offline';
                        const cidShort = escapeHtml(c.client_id.substring(0, 12));
                        
                        clientsHtml += `
                            <div style="display:flex; align-items:center; gap:6px;">
                                <span class="client-badge ${statusClass}" 
                                      style="cursor:pointer;" 
                                      title="IP: ${escapeHtml(c.ip_address || '-')} (クリックして切断)"
                                      onclick="killClientSession('${escapeHtml(u.user_id)}', '${escapeHtml(c.client_id)}')">
                                    ${cidShort}: ${statusText} ✖
                                </span>
                            </div>
                        `;
                    });
                } else {
                    clientsHtml += '<span style="font-size:0.8rem; color:#5A6E85;">未接続</span>';
                }
                clientsHtml += '</div>';

                const apiKey = u.api_key || '';
                let apiKeyBtnHtml = '<span style="font-size:0.8rem; color:#A0A0A0;">未発行</span>';
                if (apiKey) {
                    apiKeyBtnHtml = `
                        <div style="display:flex; flex-direction:column; gap:4px; align-items:flex-start;">
                            <button type="button" class="btn-copy-apikey" onclick="copyApiKey(this, '${escapeHtml(apiKey)}')">
                                📋 キーをコピー
                            </button>
                            <button type="button" class="btn-copy-curl" onclick="copyCurlExample(this, '${escapeHtml(apiKey)}')">
                                📜 cURL例
                            </button>
                        </div>
                    `;
                }

                const logBtnHtml = `
                    <button type="button" class="btn btn-info btn-sm text-white" onclick="downloadUserLog('${escapeHtml(u.user_id)}')">
                        個別CSV
                    </button>
                `;

                tr.innerHTML = `
                    <td class="ps-3">${u.id}</td>
                    <td><strong>${escapeHtml(u.username || '-')}</strong><br><span style="font-size:0.75rem; color:#5A6E85;">${escapeHtml(u.user_id)}</span></td>
                    <td>${apiKeyBtnHtml}</td>
                    <td>${clientsHtml}</td>
                    <td>${controlsHtml}</td>
                    <td>${logBtnHtml}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error('ユーザー一覧取得エラー:', e);
    }
}

async function copyApiKey(btnElement, apiKey) {
    if (!apiKey) return;
    try {
        await navigator.clipboard.writeText(apiKey);
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = '✅ コピー完了！';
        btnElement.classList.add('copied');
        setTimeout(() => {
            btnElement.innerHTML = originalText;
            btnElement.classList.remove('copied');
        }, 1500);
    } catch (e) {
        const textarea = document.createElement('textarea');
        textarea.value = apiKey;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('APIキーをコピーしました');
    }
}

async function copyCurlExample(btnElement, apiKey) {
    if (!apiKey) return;
    
    // config.php 由来の BASE_URL を使用して正しいエンドポイントURLを作成
    const baseUrl = getEffectiveBaseUrl();
    // action を set_status_cmd に修正
    const apiUrl = `${baseUrl}api.php?action=set_status_cmd`;
    const curlCmd = `curl -X POST "${apiUrl}" -H "Content-Type: application/json" -d '{"api_key":"${apiKey}","target":1,"flag":1}'`;
    
    try {
        await navigator.clipboard.writeText(curlCmd);
        const originalText = btnElement.innerHTML;
        btnElement.innerHTML = '✅ cURLコピー！';
        btnElement.classList.add('copied');
        setTimeout(() => {
            btnElement.innerHTML = originalText;
            btnElement.classList.remove('copied');
        }, 1500);
    } catch (e) {
        const textarea = document.createElement('textarea');
        textarea.value = curlCmd;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('cURLコマンドをコピーしました');
    }
}

function downloadUserLog(userId) {
    if (!userId) return alert('ユーザーIDが不正です');
    window.location.href = `api.php?action=admin_download_user_logs&user_id=${encodeURIComponent(userId)}`;
}

async function killClientSession(userId, clientId) {
    if (!confirm(`クライアント [ ${clientId.substring(0, 12)} ] のセッションを強制切断しますか？`)) return;

    try {
        const res = await fetch('api.php?action=admin_kill_session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ user_id: userId, client_id: clientId })
        });
        const data = await res.json();
        if (data.csrf_token) csrfToken = data.csrf_token;

        if (res.ok && data.success) {
            await loadUsers();
        } else {
            alert('切断エラー: ' + (data.message || ''));
        }
    } catch (e) {
        alert('通信エラーが発生しました');
    }
}

async function toggleLanternEnable(userId, target, newEnableState) {
    try {
        const res = await fetch('api.php?action=admin_set_enable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ id: userId, target: target, enable: newEnableState })
        });
        const data = await res.json();
        if (data.csrf_token) csrfToken = data.csrf_token;

        if (res.ok && data.success) {
            await loadUsers();
        } else {
            alert('更新エラー: ' + (data.message || ''));
        }
    } catch (e) {
        alert('通信エラーが発生しました');
    }
}

async function toggleLanternFlag(userId, target, newFlag) {
    try {
        const res = await fetch('api.php?action=admin_set_flag', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ id: userId, target: target, flag: newFlag })
        });
        const data = await res.json();
        if (data.csrf_token) csrfToken = data.csrf_token;

        if (res.ok && data.success) {
            await loadUsers();
        } else {
            alert('更新エラー: ' + (data.message || ''));
        }
    } catch (e) {
        alert('通信エラーが発生しました');
    }
}

async function adminLogout() {
    stopAdminPolling();
    try {
        const logoutUrl = currentClientId 
            ? `api.php?action=logout&client_id=${encodeURIComponent(currentClientId)}` 
            : 'api.php?action=logout';

        await fetch(logoutUrl, { 
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfToken }
        });
    } catch (e) {
        console.error('ログアウト通信エラー:', e);
    } finally {
        location.reload();
    }
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', async () => {
    await fetchCsrfToken();
    checkAdminStatus();

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', adminLogout);

    const downloadAllLogsBtn = document.getElementById('downloadAllLogsBtn');
    if (downloadAllLogsBtn) {
        downloadAllLogsBtn.addEventListener('click', () => {
            window.location.href = 'api.php?action=download_logs';
        });
    }
});