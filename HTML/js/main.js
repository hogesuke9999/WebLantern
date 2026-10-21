// js/main.js - フロントエンド制御スクリプト

let currentApiKey = null;
let currentCsrfToken = null;
let pollingInterval = null;
let currentFlags = [0, 0, 0, 0];
let activeLanterns = [false, false, false, false]; // 各ランタンの有効/無効状態
let pipWindow = null; // Picture-in-Pictureのウィンドウインスタンス

// CSRFトークンを取得・初期化する関数
async function initCsrfToken() {
    try {
        const res = await fetch('api.php?action=get_csrf_token');
        const data = await res.json();
        if (data.success && data.csrf_token) {
            currentCsrfToken = data.csrf_token;
        }
    } catch (err) {
        console.error('CSRFトークン取得エラー:', err);
    }
}

// クライアント固有の識別子(UUID/ランダム文字列)を取得または生成
function getClientId() {
    let clientId = localStorage.getItem('lantern_client_id');
    if (!clientId) {
        clientId = 'client_' + Math.random().toString(36).substring(2, 10) + '_' + Date.now();
        localStorage.setItem('lantern_client_id', clientId);
    }
    return clientId;
}

// ボタンの有効/無効表示を更新する関数
function updateToggleButtonUI(target, isEnabled) {
    const btn = document.getElementById(`btn-toggle-${target}`);
    const icon = document.getElementById(`btn-icon-${target}`);
    const text = document.getElementById(`btn-text-${target}`);

    if (!btn) return;

    if (isEnabled) {
        btn.className = 'btn-toggle-icon'; // 有効（グラデーション/アクティブ風）
        if (icon) icon.innerText = '🔔';
        if (text) text.innerText = '有効';
        btn.title = 'クリックして無効化';
    } else {
        btn.className = 'btn-toggle-icon off'; // 無効（グレーアウト）
        if (icon) icon.innerText = '🔕';
        if (text) text.innerText = '無効';
        btn.title = 'クリックして有効化';
    }
}

// ユーザー自身によるランタンの有効/無効切り替え処理
async function toggleLanternEnable(target) {
    const currentEnable = activeLanterns[target - 1] ? 1 : 0;
    const newEnable = currentEnable === 1 ? 0 : 1;

    try {
        const res = await fetch('api.php?action=user_set_enable', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ target: target, enable: newEnable })
        });
        const data = await res.json();
        if (data.success) {
            await fetchStatus(false);
        } else {
            alert('設定変更に失敗しました: ' + (data.message || ''));
        }
    } catch (err) {
        console.error('有効/無効切り替えエラー:', err);
    }
}

// フォーム切り替え制御
function toggleForm(type) {
    document.getElementById('login-card').style.display = 'none';
    document.getElementById('register-card').style.display = 'none';
    document.getElementById('reset-card').style.display = 'none';
    document.getElementById('main-card').style.display = 'none';
    document.getElementById('register-result').innerHTML = '';
    document.getElementById('reset-result').innerHTML = '';

    if (type === 'register') {
        document.getElementById('register-card').style.display = 'block';
    } else if (type === 'reset') {
        document.getElementById('reset-card').style.display = 'block';
    } else {
        document.getElementById('login-card').style.display = 'block';
    }
}

// ログイン処理
async function handleLogin(e) {
    e.preventDefault();
    const userIdInput = document.getElementById('user_id').value;
    const passwordInput = document.getElementById('password').value;

    try {
        const cid = getClientId();
        const res = await fetch('api.php?action=login', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ user_id: userIdInput, password: passwordInput, client_id: cid })
        });

        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || 'ログインに失敗しました');

        if (data.csrf_token) currentCsrfToken = data.csrf_token;
        showMainCard(data.username, data.user_id);
        currentApiKey = data.api_key;

        await fetchStatus();
        startPolling();
        showPiPModal();
    } catch (err) {
        alert('ログインエラー: ' + err.message);
    }
}

// 新規仮登録処理
async function handleRegister(e) {
    e.preventDefault();
    const usernameInput = document.getElementById('reg_username').value;
    const emailInput = document.getElementById('reg_email').value;
    const resultDiv = document.getElementById('register-result');

    try {
        const res = await fetch('api.php?action=register', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ username: usernameInput, email: emailInput })
        });

        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || '仮登録に失敗しました');

        let html = `<div style="color: #00B894; font-weight: bold;">${data.message}</div>`;
        if (data.dev_verify_url) {
            html += `<div class="dev-link"><a href="${data.dev_verify_url}" target="_blank">【開発用】本登録URLを開く</a></div>`;
        }
        resultDiv.innerHTML = html;
    } catch (err) {
        resultDiv.innerHTML = `<div style="color: #E74C3C;">${err.message}</div>`;
    }
}

// パスワード再設定リクエスト処理
async function handlePasswordResetRequest(e) {
    e.preventDefault();
    const emailInput = document.getElementById('reset_email').value;
    const resultDiv = document.getElementById('reset-result');

    try {
        const res = await fetch('api.php?action=reset_password_request', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ email: emailInput })
        });

        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || '送信に失敗しました');

        let html = `<div style="color: #00B894; font-weight: bold;">${data.message}</div>`;
        if (data.dev_verify_url) {
            html += `<div class="dev-link"><a href="${data.dev_verify_url}" target="_blank">【開発用】再設定URLを開く</a></div>`;
        }
        resultDiv.innerHTML = html;
    } catch (err) {
        resultDiv.innerHTML = `<div style="color: #E74C3C;">${err.message}</div>`;
    }
}

// メイン画面の表示
function showMainCard(username, userId) {
    document.getElementById('login-card').style.display = 'none';
    document.getElementById('register-card').style.display = 'none';
    document.getElementById('reset-card').style.display = 'none';
    document.getElementById('main-card').style.display = 'block';
    document.getElementById('display-user-name').innerText = username || '-';
    document.getElementById('display-user-id').innerText = userId || '-';
    document.getElementById('display-client-id').innerText = getClientId();
}

// モーダルダイアログの制御
function showPiPModal() {
    if (!pipWindow) {
        document.getElementById('pip-modal').style.display = 'flex';
    }
}

function closePiPModal() {
    document.getElementById('pip-modal').style.display = 'none';
}

async function confirmOpenPiP() {
    closePiPModal();
    await openPiP();
}

// ステータス取得＆死活チェック
async function fetchStatus(isInitialCheck = false) {
    try {
        const cid = getClientId();
        const res = await fetch(`api.php?action=get_status&client_id=${encodeURIComponent(cid)}`);

        // 管理者による強制キック(401)を検知した場合
        if (res.status === 401) {
            if (pollingInterval) clearInterval(pollingInterval);
            if (pipWindow) pipWindow.close();
            closePiPModal();

            currentApiKey = null;
            currentFlags = [0, 0, 0, 0];
            activeLanterns = [false, false, false, false];

            toggleForm('login');
            return;
        }

        const data = await res.json();

        if (data.success) {
            if (data.csrf_token) currentCsrfToken = data.csrf_token;

            if (isInitialCheck) {
                showMainCard(data.username, data.user_id);
                startPolling();
                showPiPModal();
            }

            let enabledChanged = false;

            // 有効/無効状態の更新
            if (Array.isArray(data.enabled_flags)) {
                data.enabled_flags.forEach((val, idx) => {
                    const isEnabled = (val === 1);
                    if (activeLanterns[idx] !== isEnabled) {
                        activeLanterns[idx] = isEnabled;
                        enabledChanged = true;
                    }
                    updateToggleButtonUI(idx + 1, isEnabled);
                });
            }

            // フラグ（点灯状態）の更新
            if (Array.isArray(data.flags)) {
                const hasFlagsChanged = data.flags.some((val, idx) => val !== currentFlags[idx]);
                currentFlags = [...data.flags];

                if (enabledChanged || hasFlagsChanged || isInitialCheck) {
                    updateUI(currentFlags, true);
                }
            }

            // 有効なランタン数が変わった場合はPiPウィンドウを再構築
            if (enabledChanged && pipWindow) {
                rebuildPiPWindow();
            }

            if (data.api_key) currentApiKey = data.api_key;
        } else {
            if (pollingInterval) clearInterval(pollingInterval);
            if (pipWindow) pipWindow.close();
            closePiPModal();
            toggleForm('login');
        }
    } catch (err) {
        if (!isInitialCheck) console.error('ステータス取得エラー:', err);
    }
}

// 消灯処理（一般ユーザー画面からの操作として user_set_flag を使用）
async function turnOffLantern(target) {
    if (!activeLanterns[target - 1]) return; // 無効化されていれば処理しない
    if (currentFlags[target - 1] === 0) return; // 既に消灯していれば処理しない

    try {
        const res = await fetch('api.php?action=user_set_flag', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ target: target, flag: 0 })
        });
        const data = await res.json();
        if (data.success) {
            currentFlags[target - 1] = 0;
            updateUI(currentFlags);
            await fetchStatus(false);
        }
    } catch (err) {
        console.error('消灯エラー:', err);
    }
}

// ポーリング開始（3秒間隔）
function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(() => fetchStatus(false), 3000);
}

// UI描画更新関数
function updateUI(flags, isForceUpdate = false) {
    let anyOn = false;

    flags.forEach((flag, idx) => {
        const target = idx + 1;
        const card = document.getElementById(`lantern-card-${target}`);
        const img = document.getElementById(`lantern-img-${target}`);
        const badge = document.getElementById(`lantern-badge-${target}`);

        const isEnabled = activeLanterns[idx];

        // カード全体の有効/無効スタイル切り替え
        if (card) {
            if (isEnabled) {
                card.classList.remove('disabled');
            } else {
                card.classList.add('disabled');
            }
        }

        if (isEnabled && flag === 1) {
            anyOn = true;
        }

        // 有効なランタン、または初回・強制更新時のみ画像を更新
        if (isEnabled || isForceUpdate) {
            if (flag === 1) {
                if (img) img.src = 'lanthan_on.svg';
                if (badge) {
                    badge.innerText = '点灯 (1)';
                    badge.className = 'lantern-badge on';
                }
                if (card) card.classList.add('active');
            } else {
                if (img) img.src = 'lanthan_off.svg';
                if (badge) {
                    badge.innerText = '消灯 (0)';
                    badge.className = 'lantern-badge';
                }
                if (card) card.classList.remove('active');
            }
        }
    });

    // 1つでも点灯していれば背景アニメーションなどのクラスを付与
    if (anyOn) {
        document.body.classList.add('any-lantern-on');
    } else {
        document.body.classList.remove('any-lantern-on');
    }

    updatePiPUI(flags);
}

// APIキーのクリップボードコピー
function copyApiKey() {
    if (!currentApiKey) return alert('APIキーが取得できていません');
    navigator.clipboard.writeText(currentApiKey);
    alert('APIキーをコピーしました');
}

// cURL例のコピー（CSRFトークンおよび PHPSESSID を含めるように修正済み）
function copyCurlCommand() {
    const baseUrl = window.location.origin + window.location.pathname.replace(/\/[^\/]*$/, '/');
    const cid = getClientId();

    // Cookieから PHPSESSID を取得
    const phpSessId = document.cookie
        .split('; ')
        .find(row => row.startsWith('PHPSESSID='))
        ?.split('=')[1] || '';

    let curlCmd = `curl -X POST "${baseUrl}api.php?action=user_set_enable" \\\n`;
    curlCmd += `  -H "Content-Type: application/json" \\\n`;

    if (currentCsrfToken) {
        curlCmd += `  -H "X-CSRF-Token: ${currentCsrfToken}" \\\n`;
    }

    if (phpSessId) {
        curlCmd += `  -b "PHPSESSID=${phpSessId}" \\\n`;
    }

    curlCmd += `  -d '{"target": 1, "enable": 1}'`;

    navigator.clipboard.writeText(curlCmd);
    alert('cURLコマンドをコピーしました');
}

// Picture-in-Picture (PiP) ウィンドウを開く
async function openPiP() {
    if (!('documentPictureInPicture' in window)) {
        alert('お使いのブラウザは Picture-in-Picture API に対応していません。Google Chrome または Microsoft Edge 最新版をご利用ください。');
        return;
    }

    try {
        pipWindow = await window.documentPictureInPicture.requestWindow({
            width: 400,
            height: 160,
        });

        rebuildPiPWindow();
        pipWindow.addEventListener('pagehide', () => { pipWindow = null; });
    } catch (e) {
        console.error('PiP表示失敗:', e);
    }
}

// PiPウィンドウ内部のDOM構造を有効なランタン数に応じて再構築
function rebuildPiPWindow() {
    if (!pipWindow || !pipWindow.document) return;

    const doc = pipWindow.document;
    doc.body.innerHTML = '';
    doc.head.innerHTML = '';

    // 有効(active)なランタンのリストを抽出
    const enabledIndices = [];
    activeLanterns.forEach((active, idx) => {
        if (active) enabledIndices.push(idx + 1);
    });

    const colCount = enabledIndices.length > 0 ? enabledIndices.length : 1;

    // スタイルの注入
    const style = doc.createElement('style');
    style.textContent = `
        body {
            margin: 0; padding: 4px; height: 100vh; box-sizing: border-box;
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            font-family: -apple-system, sans-serif; color: #1C2A3A; background-color: #F0F8FF;
            transition: background-color 0.3s ease; overflow: hidden;
        }
        .pip-title { font-size: clamp(10px, 3.2vw, 14px); color: #5A6E85; margin-bottom: 2px; white-space: nowrap; font-weight: bold; }
        .pip-grid { display: grid; grid-template-columns: repeat(${colCount}, 1fr); gap: 0.5vw; width: 100%; height: 85%; align-items: center; }
        .pip-item {
            background: #FFFFFF; border-radius: 6px; border: 1px solid #D0E3F0; padding: 2px; text-align: center;
            font-size: clamp(9px, 2.8vw, 13px); display: flex; flex-direction: column;
            justify-content: space-between; align-items: center; height: 100%; box-sizing: border-box;
            transition: all 0.3s ease;
        }
        .pip-item.active {
            background: radial-gradient(circle at center, #FFFDF9 0%, #FFF3E0 100%);
            border-color: #FFC078;
            box-shadow: 0 0 12px rgba(255, 159, 67, 0.4);
        }
        .pip-img { width: 100%; max-width: 140px; height: auto; max-height: 65vh; object-fit: contain; margin: auto 0; cursor: pointer; transition: filter 0.3s ease; }
        .pip-item.active .pip-img {
            filter: drop-shadow(0 0 6px rgba(255, 159, 67, 0.7));
        }
        .empty-msg { font-size: 0.9rem; color: #5A6E85; }
        @keyframes flash { 0% { background-color: #1E88E5; } 100% { background-color: #F0F8FF; } }
        .flash-effect { animation: flash 0.8s ease-in-out; }
    `;
    doc.head.appendChild(style);

    let gridHtml = '<div class="pip-title">ランタン状態モニター</div>';

    if (enabledIndices.length === 0) {
        gridHtml += '<div class="empty-msg">有効なランタンがありません</div>';
    } else {
        gridHtml += '<div class="pip-grid">';
        enabledIndices.forEach(i => {
            gridHtml += `
                <div class="pip-item" id="pip-card-${i}">
                    <div>#${i}</div>
                    <img id="pip-img-${i}" class="pip-img" src="lanthan_off.svg" alt="L${i}">
                    <div id="pip-txt-${i}">消灯</div>
                </div>
            `;
        });
        gridHtml += '</div>';
    }

    doc.body.innerHTML = gridHtml;

    // 各画像に消灯クリックイベントを付与
    enabledIndices.forEach(i => {
        const pipImg = doc.getElementById(`pip-img-${i}`);
        if (pipImg) {
            pipImg.onclick = () => turnOffLantern(i);
        }
    });

    updatePiPUI(currentFlags);
}

// PiP表示の更新
function updatePiPUI(flags) {
    if (!pipWindow || !pipWindow.document) return;

    flags.forEach((flag, idx) => {
        const target = idx + 1;
        if (!activeLanterns[idx]) return; // 無効なランタンは描画更新スキップ

        const card = pipWindow.document.getElementById(`pip-card-${target}`);
        const img = pipWindow.document.getElementById(`pip-img-${target}`);
        const txt = pipWindow.document.getElementById(`pip-txt-${target}`);

        if (img && txt) {
            if (flag === 1) {
                img.src = 'lanthan_on.svg';
                txt.innerText = '点灯';
                txt.style.color = '#FF9F43';
                if (card) card.classList.add('active');
            } else {
                img.src = 'lanthan_off.svg';
                txt.innerText = '消灯';
                txt.style.color = '#5A6E85';
                if (card) card.classList.remove('active');
            }
        }
    });

    // 点灯通知フラッシュアニメーションとウィンドウフォーカス
    const hasActiveChange = flags.some((val, idx) => activeLanterns[idx] && val === 1);
    if (hasActiveChange) {
        try { pipWindow.focus(); } catch(e) {}
        const body = pipWindow.document.body;
        body.classList.remove('flash-effect');
        void body.offsetWidth; // リフロー発生
        body.classList.add('flash-effect');
    }
}

// ログアウト
async function logout() {
    try {
        const cid = getClientId();
        await fetch(`api.php?action=logout&client_id=${encodeURIComponent(cid)}`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ client_id: cid })
        });
    } catch (e) {
        console.error('ログアウト通信エラー:', e);
    }

    if (pollingInterval) clearInterval(pollingInterval);
    if (pipWindow) pipWindow.close();

    closePiPModal();
    currentApiKey = null;
    currentFlags = [0, 0, 0, 0];
    activeLanterns = [false, false, false, false];

    toggleForm('login');
    document.getElementById('user_id').value = '';
    document.getElementById('password').value = '';
}

// 初期化
document.addEventListener('DOMContentLoaded', async () => {
    await initCsrfToken();
    await fetchStatus(true);
});