export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);
    const db = env.DB;
    const kv = env.KV_CONNECTIONS; 

    // ==========================================
    // CRITICAL SECURITY PARAMETERS
    // Change these values to secure your admin panel
    // ==========================================
    const ADMIN_USER = "admin";
    const ADMIN_PASS = "SecretPassword123";

    const hostUrl = new URL(request.url).origin;

    // Helper logic to check if a user record has expired
    const isAccountExpired = (expDateStr) => {
      if (!expDateStr || expDateStr === "Never" || expDateStr.trim() === "") return false;
      const parsedExpiry = Date.parse(expDateStr);
      if (isNaN(parsedExpiry)) return false; // Graceful fallback if format is broken
      
      // Compare calendar expiration end with current server epoch time
      return Date.now() > parsedExpiry;
    };

    // 1. PUBLIC ENDPOINTS (Exempt from Admin Login Challenge)
    if (pathname === "/proxy") {
      const streamUrl = searchParams.get("url");
      const user = searchParams.get("user");
      const pass = searchParams.get("pass");

      if (!streamUrl) return new Response("Missing Stream URL", { status: 400 });
      if (!user || !pass) return new Response("Missing Credentials", { status: 401 });

      const userCheck = await db.prepare("SELECT * FROM users WHERE username = ? AND password = ? AND status = 'active'").bind(user, pass).first();
      if (!userCheck) return new Response("Unauthorized Line", { status: 401 });

      // STRICT EXPIRATION ENFORCEMENT: Block stream if timeline threshold crossed
      if (isAccountExpired(userCheck.exp_date)) {
        return new Response("Subscription Expired. Access Denied.", { 
          status: 403, 
          headers: { "Access-Control-Allow-Origin": "*" } 
        });
      }

      const maxAllowed = parseInt(userCheck.max_connections) || 1;
      const kvKey = `active_conn:${user}`;
      let currentConns = 0;

      if (kv) {
        const stored = await kv.get(kvKey);
        currentConns = stored ? parseInt(stored) : 0;
        if (currentConns >= maxAllowed) {
          return new Response(`Connection Limit Reached (${currentConns}/${maxAllowed}). Close existing stream first.`, { 
            status: 403,
            headers: { "Access-Control-Allow-Origin": "*" }
          });
        }
        await kv.put(kvKey, (currentConns + 1).toString(), { expirationTtl: 14400 });
      }

      try {
        const response = await fetch(streamUrl);
        const newHeaders = new Headers(response.headers);
        newHeaders.set("Access-Control-Allow-Origin", "*");

        const originalBody = response.body;
        const transformStream = new TransformStream({
          flush(controller) {
            if (kv) {
              ctx.waitUntil((async () => {
                const freshCount = await kv.get(kvKey);
                const currentVal = freshCount ? parseInt(freshCount) : 1;
                await kv.put(kvKey, Math.max(0, currentVal - 1).toString(), { expirationTtl: 14400 });
              })());
            }
          }
        });

        const modifiedBody = originalBody.pipeThrough(transformStream);
        return new Response(modifiedBody, { status: response.status, headers: newHeaders });

      } catch (e) {
        if (kv) {
          const freshCount = await kv.get(kvKey);
          const currentVal = freshCount ? parseInt(freshCount) : 1;
          await kv.put(kvKey, Math.max(0, currentVal - 1).toString(), { expirationTtl: 14400 });
        }
        return new Response("Proxy Playback Error: " + e.message, { status: 500 });
      }
    }

    if (pathname === "/get_playlist") {
      const user = searchParams.get("user");
      const pass = searchParams.get("pass");
      const proxyId = searchParams.get("proxy");

      const userCheck = await db.prepare("SELECT * FROM users WHERE username = ? AND password = ? AND status = 'active'").bind(user, pass).first();
      if (!userCheck) return new Response("Unauthorized Account", { status: 401 });

      // Block playlist download entirely if account date threshold crossed
      if (isAccountExpired(userCheck.exp_date)) {
        return new Response("Subscription Expired. Playlist generation locked.", { status: 403 });
      }

      let baseProxyString = "";
      let isBuiltIn = false;

      if (proxyId === 'default' || !proxyId) {
        baseProxyString = `${hostUrl}/proxy?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&url=`;
        isBuiltIn = true;
      } else {
        const proxy = await db.prepare("SELECT url FROM proxies WHERE id = ?").bind(proxyId).first();
        if (proxy) baseProxyString = proxy.url;
      }

      const streams = await db.prepare("SELECT * FROM streams").all();
      let m3u = "#EXTM3U\n";
      
      for (const stream of streams.results) {
        let targetUrl = stream.url;
        
        if (isBuiltIn) {
          targetUrl = `${baseProxyString}${encodeURIComponent(stream.url)}`;
        } else if (baseProxyString) {
          let computedProxy = baseProxyString
            .replace(/{user}/g, encodeURIComponent(user))
            .replace(/{pass}/g, encodeURIComponent(pass));
            
          targetUrl = `${computedProxy}${encodeURIComponent(stream.url)}`;
        }
        
        m3u += `#EXTINF:-1 tvg-name="${stream.name}" group-title="${stream.category}",${stream.name}\n${targetUrl}\n`;
      }

      return new Response(m3u, {
        headers: {
          "Content-Type": "application/mpegurl",
          "Content-Disposition": `attachment; filename="${user}_playlist.m3u"`,
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    // ==========================================
    // 2. ADMIN WALL SECURITY LAYER CHALLENGES
    // ==========================================
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      return new Response("Access Denied: Admin Authorization Required.", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="Admin IPTV Dashboard"' }
      });
    }

    try {
      const [type, credentials] = authHeader.split(" ");
      if (type.toLowerCase() !== "basic" || !credentials) throw new Error();
      const decoded = atob(credentials);
      const [inputUser, inputPass] = decoded.split(":");
      if (inputUser !== ADMIN_USER || inputPass !== ADMIN_PASS) throw new Error();
    } catch (e) {
      return new Response("Invalid Admin Credentials. Please try again.", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="Admin IPTV Dashboard"' }
      });
    }

    // ADMINISTRATIVE POST APIs ROUTERS
    if (request.method === "POST" && pathname.startsWith("/api/")) {
      const body = await request.json();
      
      if (pathname === "/api/users/add") {
        await db.prepare("INSERT INTO users (username, password, exp_date, max_connections) VALUES (?, ?, ?, ?)")
          .bind(body.username, body.password, body.exp_date || "Never", parseInt(body.max_connections) || 1).run();
        return Response.json({ success: true });
      }
      
      if (pathname === "/api/users/edit") {
        await db.prepare("UPDATE users SET password = ?, status = ?, exp_date = ?, max_connections = ? WHERE id = ?")
          .bind(body.password, body.status, body.exp_date, parseInt(body.max_connections) || 1, body.id).run();
        return Response.json({ success: true });
      }
      
      if (pathname === "/api/users/delete") {
        await db.prepare("DELETE FROM users WHERE id = ?").bind(body.id).run();
        return Response.json({ success: true });
      }
      
      if (pathname === "/api/streams/add") {
        await db.prepare("INSERT INTO streams (name, url, category) VALUES (?, ?, ?)")
          .bind(body.name, body.url, body.category || "Live").run();
        return Response.json({ success: true });
      }

      if (pathname === "/api/streams/mass_import") {
        const lines = body.m3u.split("\n");
        let currentName = "Unknown Stream";
        let currentCategory = "Imported";
        
        for (let line of lines) {
          line = line.trim();
          if (line.startsWith("#EXTINF:")) {
            const nameMatch = line.match(/,(.*)$/);
            if (nameMatch) currentName = nameMatch;
            const catMatch = line.match(/group-title="([^"]+)"/);
            if (catMatch) currentCategory = catMatch;
          } else if (line.startsWith("http")) {
            await db.prepare("INSERT INTO streams (name, url, category) VALUES (?, ?, ?)")
              .bind(currentName, line, currentCategory).run();
          }
        }
        return Response.json({ success: true });
      }
      
      if (pathname === "/api/streams/edit") {
        await db.prepare("UPDATE streams SET name = ?, url = ?, category = ? WHERE id = ?")
          .bind(body.name, body.url, body.category, body.id).run();
        return Response.json({ success: true });
      }
      
      if (pathname === "/api/streams/delete") {
        await db.prepare("DELETE FROM streams WHERE id = ?").bind(body.id).run();
        return Response.json({ success: true });
      }

      if (pathname === "/api/streams/mass_delete") {
        if (body.scope === "all") {
          await db.prepare("DELETE FROM streams").run();
        } else if (body.scope === "category" && body.category) {
          await db.prepare("DELETE FROM streams WHERE category = ?").bind(body.category).run();
        }
        return Response.json({ success: true });
      }

      if (pathname === "/api/proxies/add") {
        await db.prepare("INSERT INTO proxies (name, url) VALUES (?, ?)")
          .bind(body.name, body.url).run();
        return Response.json({ success: true });
      }

      if (pathname === "/api/proxies/delete") {
        await db.prepare("DELETE FROM proxies WHERE id = ?").bind(body.id).run();
        return Response.json({ success: true });
      }
    }

    if (pathname === "/api/data") {
      const users = await db.prepare("SELECT * FROM users").all();
      const streams = await db.prepare("SELECT * FROM streams").all();
      const proxies = await db.prepare("SELECT * FROM proxies").all();
      
      const mappedUsers = await Promise.all(users.results.map(async (u) => {
        let activeNow = 0;
        if (kv) {
          const count = await kv.get(`active_conn:${u.username}`);
          activeNow = count ? parseInt(count) : 0;
        }
        // Calculate expiration states and send them downstream to browser client
        const expired = isAccountExpired(u.exp_date);
        return { ...u, active_connections: activeNow, is_expired: expired };
      }));

      return Response.json({ users: mappedUsers, streams: streams.results, proxies: proxies.results });
    }

    // 3. DASHBOARD UI LAYOUT GENERATION
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>TFMS IPTV Panel</title>
      <style>
        body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { background: #1a1f2c; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        h1, h2, h3 { margin: 0; }
        h3 { font-size: 16px; margin-top: 15px; margin-bottom: 5px; color: #475569; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
        th { background: #edf2f7; }
        input, select, textarea { width: 100%; padding: 8px; margin: 4px 0 10px 0; border: 1px solid #cbd5e1; border-radius: 4px; box-sizing: border-box; }
        button { background: #2563eb; color: white; border: none; padding: 8px 14px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #1d4ed8; }
        .btn-danger { background: #dc2626; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-success { background: #16a34a; }
        .action-btns button { padding: 4px 8px; font-size: 12px; margin-right: 4px; }
        .flex-actions { display: flex; align-items: center; gap: 4px; }
        .proxy-list { margin-top: 15px; background: #f8fafc; padding: 10px; border-radius: 6px; }
        .proxy-item { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
        .proxy-item:last-child { border-bottom: none; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; background: #64748b; }
        .badge-alert { background: #dc2626; }
        .badge-ok { background: #16a34a; }
        .badge-expired { background: #64748b; text-decoration: line-through; }
        .mass-delete-box { margin-top: 15px; padding: 15px; border: 1px solid #fee2e2; background: #fef2f2; border-radius: 6px; display: flex; gap: 10px; align-items: center; }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>TFMS IPTV Panel v4.0.0</h1><a href="https://www.tfms.xyz/firestick/sites/links.html" target="_blank"><button>Get Streams</button></a><a href="https://tfms.xyz/firestick/sites/proxies.html" target="_blank"><button>Get Proxies</button></a>
          <div>
            <label style="color:white; font-size:12px;">Change Proxy Server: </label>
            <select id="globalProxySelect" style="width:auto; display:inline-block; margin:0; padding:4px; font-size:12px;"></select>
          </div>
        </header>

        <div class="card">
          <h2>Add A New Proxy Routing URL</h2>
          <div style="display:flex; gap:10px; margin-top:10px;">
            <input type="text" id="proxyName" placeholder="New Proxy Name">
            <input type="text" id="proxyUrl" placeholder="New Proxy Url, Must Include the trialing / Can Include /?url= or /proxy?url= etc.">
            <button style="white-space: nowrap;" onclick="addProxy()">Add Proxy Server</button>
          </div>
          <div class="proxy-list">
            <strong>Configured Proxies:</strong>
            <div id="proxyContainer"></div>
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <h2>User Line Registry</h2>
            <hr>
            <h3>Create & Edit Account</h3>
            <input type="hidden" id="userId">
            <input type="text" id="username" placeholder="New Account Username">
            <input type="text" id="password" placeholder="New Account Password">
            <input type="number" id="maxConnections" placeholder="Max Allowed Simultaneous Connections" min="1" value="1">
            <input type="text" id="userExp" placeholder="Expiry Date (YYYY-MM-DD)">
            <select id="userStatus">
              <option value="active">Active Entry Line</option>
              <option value="disabled">Suspended / Deactivated Entry</option>
            </select>
            <button id="userBtn" onclick="saveUser()">Create New User</button>
            <button id="cancelUserBtn" style="display:none; background:#64748b" onclick="resetUserForm()">Cancel</button>

            <h3>Registered Users Lines</h3>
            <table>
              <thead>
                <tr><th>Subscriber</th><th>Conns (Live/Max)</th><th>Status</th><th>Actions</th></tr>
              </thead>
              <tbody id="userTable"></tbody>
            </table>
          </div>

          <div class="card">
            <h2>Add Streams</h2>
            <hr>
            <h3>Create & Edit Streams</h3>
            <input type="hidden" id="streamId">
            <input type="text" id="streamName" placeholder="Stream Name">
            <input type="text" id="streamUrlInput" placeholder="Stream Source URL">
            <input type="text" id="streamCategory" placeholder="Target Listing Category Group">
            <button id="streamBtn" onclick="saveStream()">Add New Stream</button>
            <button id="cancelStreamBtn" style="display:none; background:#64748b" onclick="resetStreamForm()">Cancel</button>

            <h3>M3U Bulk Import (.m3u parsing)</h3>
            <textarea id="massM3u" rows="4" placeholder="Drop full playlist rows here..."></textarea>
            <button class="btn-success" onclick="massImport()">Mass Import Streams</button>

            <h3>Parsed Live Output Feeds</h3>
            <table>
              <thead>
                <tr><th>Channel Identifier</th><th>Group Tag</th><th>Actions</th></tr>
              </thead>
              <tbody id="streamTable"></tbody>
            </table>

            <div class="mass-delete-box">
              <strong style="color: #991b1b; font-size: 14px; white-space: nowrap;">Mass Delete:</strong>
              <select id="massDeleteSelect" style="margin: 0; padding: 6px; font-size: 13px;">
                <option value="all">Wipe All Streams Completely</option>
              </select>
              <button class="btn-danger" style="white-space: nowrap;" onclick="executeMassDelete()">Clear Streams</button>
            </div>
          </div>
        </div>
      </div>

      <script>
        const builtInProxy = { id: 'default', name: 'Standard Worker Core Proxy', url: '' };

        async function loadData() {
          const res = await fetch('/api/data');
          if (res.status === 401) return window.location.reload();
          const data = await res.json();
          
          const proxySelect = document.getElementById('globalProxySelect');
          const lastSelected = proxySelect.value || 'default';
          proxySelect.innerHTML = '';
          
          const allProxies = [builtInProxy, ...data.proxies];
          allProxies.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.id;
            opt.textContent = p.name;
            proxySelect.appendChild(opt);
          });
          proxySelect.value = lastSelected;

          const proxyContainer = document.getElementById('proxyContainer');
          proxyContainer.innerHTML = '';

          data.proxies.forEach(p => {
            const div = document.createElement('div');
            div.className = 'proxy-item';
            div.innerHTML = \`
              <span><strong>\${p.name}</strong> - <small style="color:#2563eb">\${p.url}</small></span>
              <button class="btn-danger" style="padding: 2px 6px; font-size: 11px;" onclick="deleteProxy(\${p.id})">Remove Proxy</button>
            \`;
            proxyContainer.appendChild(div);
          });

          const userTable = document.getElementById('userTable');
          userTable.innerHTML = '';
          data.users.forEach(u => {
            let badgeClass = 'badge badge-ok';
            let connLabel = \`\${u.active_connections} / \${u.max_connections || 1}\`;
            let isExpired = u.is_expired;
            
            if (u.active_connections >= (u.max_connections || 1)) {
              badgeClass = 'badge badge-alert';
            }
            
            // Visual override if timeline constraints are violated
            if (isExpired) {
              badgeClass = 'badge badge-expired';
              connLabel = 'EXPIRED';
            }
            
            const tr = document.createElement('tr');
            tr.innerHTML = \`
              <td style="\${isExpired ? 'color:#94a3b8; text-decoration:line-through;' : ''}">
                <b>\${u.username}</b> <br>
                <small style="font-size:10px; color:#64748b;">Expires: \${u.exp_date || 'Never'}</small>
              </td>
              <td><span class="\${badgeClass}">\${connLabel}</span></td>
              <td>\${u.status}</td>
              <td class="action-btns">
                <div class="flex-actions">
                  <button onclick="editUser(\${u.id}, '\${u.username}', '\${u.password}', '\${u.exp_date}', '\${u.status}', \${u.max_connections || 1})">Edit</button>
                  <button class="btn-danger" onclick="deleteUser(\${u.id})">Delete</button>
                  <button class="btn-success" \${isExpired ? 'disabled style="opacity:0.4; cursor:not-allowed;"' : ''} onclick="downloadPlaylist('\${u.username}', '\${u.password}')">Playlist</button>
                </div>
              </td>
            \`;
            userTable.appendChild(tr);
          });

          const streamTable = document.getElementById('streamTable');
          const massDeleteSelect = document.getElementById('massDeleteSelect');
          
          streamTable.innerHTML = '';
          massDeleteSelect.innerHTML = '<option value="all">Wipe All Streams Completely</option>';
          
          const uniqueCategories = new Set();

          data.streams.forEach(s => {
            if (s.category) uniqueCategories.add(s.category);
            const tr = document.createElement('tr');
            tr.innerHTML = \`
              <td>\${s.name}</td>
              <td>\${s.category}</td>
              <td class="action-btns">
                <button onclick="editStream(\${s.id}, '\${s.name}', '\${s.url}', '\${s.category}')">Edit</button>
                <button class="btn-danger" onclick="deleteStream(\${s.id})">Delete</button>
              </td>
            \`;
            streamTable.appendChild(tr);
          });

          uniqueCategories.forEach(cat => {
            const opt = document.createElement('option');
            opt.value = \`category:\${cat}\`;
            opt.textContent = \`Clear Category: "\${cat}"\`;
            massDeleteSelect.appendChild(opt);
          });
        }

        async function postData(url, data) {
          const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
          if (res.status === 401) return window.location.reload();
          loadData();
        }

        function saveUser() {
          const id = document.getElementById('userId').value;
          const data = {
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
            exp_date: document.getElementById('userExp').value,
            status: document.getElementById('userStatus').value,
            max_connections: parseInt(document.getElementById('maxConnections').value) || 1
          };
          if (id) {
            postData('/api/users/edit', { id: parseInt(id), ...data });
          } else {
            postData('/api/users/add', data);
          }
          resetUserForm();
        }

        // Populates parameters during editing sessions
        function editUser(id, user, pass, exp, status, maxConn) {
          document.getElementById('userId').value = id;
          document.getElementById('username').value = user;
          document.getElementById('username').disabled = true;
          document.getElementById('password').value = pass;
          document.getElementById('userExp').value = exp === 'Never' ? '' : exp;
          document.getElementById('userStatus').value = status;
          document.getElementById('maxConnections').value = maxConn;
          document.getElementById('userBtn').textContent = "Update Account Parameters";
          document.getElementById('cancelUserBtn').style.display = "inline-block";
        }

        function deleteUser(id) { if(confirm('Delete user line entirely?')) postData('/api/users/delete', { id }); }
        
        function resetUserForm() {
          document.getElementById('userId').value = '';
          document.getElementById('username').value = '';
          document.getElementById('username').disabled = false;
          document.getElementById('password').value = '';
          document.getElementById('userExp').value = '';
          document.getElementById('maxConnections').value = 1;
          document.getElementById('userBtn').textContent = "Create New User";
          document.getElementById('cancelUserBtn').style.display = "none";
        }

        function saveStream() {
          const id = document.getElementById('streamId').value;
          const data = {
            name: document.getElementById('streamName').value,
            url: document.getElementById('streamUrlInput').value,
            category: document.getElementById('streamCategory').value
          };
          if (id) {
            postData('/api/streams/edit', { id: parseInt(id), ...data });
          } else {
            postData('/api/streams/add', data);
          }
          resetStreamForm();
        }

        function editStream(id, name, url, category) {
          document.getElementById('streamId').value = id;
          document.getElementById('streamName').value = name;
          document.getElementById('streamUrlInput').value = url;
          document.getElementById('streamCategory').value = category;
          document.getElementById('streamBtn').textContent = "Update Stream Entry";
          document.getElementById('cancelStreamBtn').style.display = "inline-block";
        }

        function deleteStream(id) { if(confirm('Delete target broadcast stream?')) postData('/api/streams/delete', { id }); }
        
        function massImport() {
          const m3u = document.getElementById('massM3u').value;
          postData('/api/streams/mass_import', { m3u });
          document.getElementById('massM3u').value = '';
        }

        function executeMassDelete() {
          const selection = document.getElementById('massDeleteSelect').value;
          let confirmationMsg = "Are you absolutely sure you want to delete all streams completely?";
          let payload = { scope: "all" };

          if (selection.startsWith("category:")) {
            const categoryName = selection.substring(9);
            confirmationMsg = \`Are you sure you want to delete all streams inside the category: "\${categoryName}"?\`;
            payload = { scope: "category", category: categoryName };
          }

          if (confirm(confirmationMsg)) {
            postData('/api/streams/mass_delete', payload);
          }
        }

        function resetStreamForm() {
          document.getElementById('streamId').value = '';
          document.getElementById('streamName').value = '';
          document.getElementById('streamUrlInput').value = '';
          document.getElementById('streamCategory').value = '';
          document.getElementById('streamBtn').textContent = "Add New Stream";
          document.getElementById('cancelStreamBtn').style.display = "none";
        }

        function addProxy() {
          const name = document.getElementById('proxyName').value;
          const url = document.getElementById('proxyUrl').value;
          if(!name || !url) return alert('Fill out proxy parameters.');
          postData('/api/proxies/add', { name, url });
          document.getElementById('proxyName').value = '';
          document.getElementById('proxyUrl').value = '';
        }

        function deleteProxy(id) { if(confirm('Delete this proxy server reference?')) postData('/api/proxies/delete', { id }); }

        function downloadPlaylist(user, pass) {
          const select = document.getElementById('globalProxySelect');
          const proxyId = select.value;
          let downloadUrl = \`/get_playlist?user=\${encodeURIComponent(user)}&pass=\${encodeURIComponent(pass)}&proxy=\${proxyId}\`;
          window.open(downloadUrl, '_blank');
        }

        setInterval(loadData, 10000);
        loadData();
      </script>
    </body>
    </html>
    `;

    return new Response(html, { headers: { "Content-Type": "text/html" } });
  }
};
