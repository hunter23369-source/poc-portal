using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// Serve wwwroot static files (bg.jpg, logo, site.css)
builder.Environment.WebRootPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");

var app = builder.Build();
app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = new FileExtensionContentTypeProvider()
});

// -------------------- ENV --------------------
string Env(string key, string fallback) => Environment.GetEnvironmentVariable(key) ?? fallback;

var PORTAL_DB = Env("PORTAL_DB", "");
if (string.IsNullOrWhiteSpace(PORTAL_DB))
{
    Console.WriteLine("FATAL: PORTAL_DB env var missing.");
    Environment.Exit(1);
}

var SETUP_ENABLED = Env("PORTAL_SETUP_ENABLED", "true").Trim().ToLowerInvariant() == "true";
var SETUP_TOKEN = Env("PORTAL_SETUP_TOKEN", "4321");

// Must be set in compose for real use
var AUTH_KEY = Env("PORTAL_AUTH_KEY", "CHANGE_ME__set_PORTAL_AUTH_KEY_in_compose");

// Upload dir (for contractor docs etc.)
var uploadDir = Env("PORTAL_UPLOAD_DIR", "/data/uploads");
Directory.CreateDirectory(uploadDir);

// Branding assets
const string LOGO_PATH = "/logo.jpg"; // change to "/logo.png" if needed

// -------------------- BASIC ROUTES --------------------
app.MapGet("/health", () => Results.Ok("ok"));

// Public homepage
app.MapGet("/", (HttpContext ctx) =>
{
    var body = $@"
<div class='mv-panel'>
  <div class='h1'>TN Election Portal</div>
  <div class='mv-subtle'>Select your portal.</div>

  <div style='height:14px'></div>

  <div class='card'>
    <div class='grid'>
      <a class='btn btn-primary' style='padding:14px 16px; font-size:16px;' href='/login?role=aoe'>AOE / Client</a>

      <div class='grid grid-2'>
        <a class='btn btn-secondary' href='/login?role=contractor'>MV Contractor</a>
        <a class='btn btn-secondary' href='/login?role=machinetech'>Machine Tech</a>
      </div>
    </div>

    <div class='mv-footer'>
      <div style='margin-bottom:8px; font-weight:800; color: rgba(255,255,255,0.0)'></div>
      <div class='grid grid-3'>
        <a href='https://microvote.com' target='_blank'>Link for white boarddsfgdfgsgdfsg</a>
        <a href='https://microvote.com' target='_blank'>Link 2</a>
        <a href='https://microvote.com' target='_blank'>Link 3</a>
        <a href='https://microvote.com' target='_blank'>Link 4</a>
        <a href='https://microvote.com' target='_blank'>Link 5</a>
        <a href='https://microvote.com' target='_blank'>Link 6</a>
      </div>
    </div>
  </div>
</div>";

    return Html(Layout("Home", Topbar(ctx, "TN Election Portal (POC)", showLogoLinkToAdminLogin: true) + Container(body)));
});

// Logo should take you to Admin login
app.MapGet("/admin/login", (HttpContext ctx) => Results.Redirect("/login?role=admin"));

// After login, route based on actual role
app.MapGet("/app", (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    return auth.Role switch
    {
        "admin" => Results.Redirect("/admin"),
        "aoe" => Results.Redirect("/aoe"),
        "contractor" => Results.Redirect("/contractor"),
        "machinetech" => Results.Redirect("/machinetech"),
        _ => Results.Redirect("/")
    };
});

// -------------------- AUTH --------------------
app.MapGet("/login", (HttpContext ctx) =>
{
    var requestedRole = (ctx.Request.Query["role"].ToString() ?? "").Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(requestedRole)) requestedRole = "aoe";

    var auth = GetAuth(ctx);
    if (auth != null) return Results.Redirect("/app");

    return Html(LoginPage(requestedRole));
});

app.MapPost("/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var requestedRole = (form["requested_role"].ToString() ?? "aoe").Trim().ToLowerInvariant();

    var email = (form["email"].ToString() ?? "").Trim().ToLowerInvariant();
    var password = form["password"].ToString() ?? "";

    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        return Html(LoginPage(requestedRole, "Email and password are required.", email));

    await using var conn = new NpgsqlConnection(PORTAL_DB);
    await conn.OpenAsync();

    long id;
    string role;
    string hash;
    bool deleted;

    await using (var cmd = new NpgsqlCommand(@"
        SELECT id, role, COALESCE(password_hash,''), COALESCE(is_deleted,false)
        FROM users
        WHERE lower(email)=@e
        LIMIT 1
    ", conn))
    {
        cmd.Parameters.AddWithValue("e", email);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync())
            return Html(LoginPage(requestedRole, "Invalid login.", email));

        id = r.GetInt64(0);
        role = (r.IsDBNull(1) ? "" : r.GetString(1)).Trim().ToLowerInvariant();
        hash = r.IsDBNull(2) ? "" : r.GetString(2);
        deleted = !r.IsDBNull(3) && r.GetBoolean(3);
    }

    if (deleted) return Html(LoginPage(requestedRole, "Account is disabled.", email));
    if (string.IsNullOrWhiteSpace(hash) || !BCrypt.Net.BCrypt.Verify(password, hash))
        return Html(LoginPage(requestedRole, "Invalid login.", email));

    // Optional: If user clicked a role button, but their actual role doesn't match,
    // we still allow login but route them to their real portal.
    SetAuth(ctx, new Auth(id, email, role));

    return Results.Redirect("/app");
});

app.MapGet("/logout", (HttpContext ctx) =>
{
    ClearAuth(ctx);
    return Results.Redirect("/");
});

// -------------------- SETUP (admin bootstrap) --------------------
app.MapGet("/setup", () =>
{
    if (!SETUP_ENABLED) return Results.NotFound("Setup disabled.");
    return Html(SetupPage(SETUP_TOKEN));
});

app.MapPost("/setup", async (HttpContext ctx) =>
{
    if (!SETUP_ENABLED) return Results.NotFound("Setup disabled.");

    var form = await ctx.Request.ReadFormAsync();
    var token = form["token"].ToString() ?? "";
    var email = (form["email"].ToString() ?? "").Trim().ToLowerInvariant();
    var password = form["password"].ToString() ?? "";

    if (token != SETUP_TOKEN)
        return Html(SetupPage(SETUP_TOKEN, "Invalid setup token.", email));

    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        return Html(SetupPage(SETUP_TOKEN, "Email and password are required.", email));

    var hash = BCrypt.Net.BCrypt.HashPassword(password);

    await using var conn = new NpgsqlConnection(PORTAL_DB);
    await conn.OpenAsync();

    long id;
    await using (var cmd = new NpgsqlCommand(@"
        INSERT INTO users (email, role, display_name, password_hash, is_deleted)
        VALUES (@e, 'admin', 'Admin', @h, FALSE)
        ON CONFLICT (email) DO UPDATE SET
            role='admin',
            password_hash=EXCLUDED.password_hash,
            is_deleted=FALSE
        RETURNING id
    ", conn))
    {
        cmd.Parameters.AddWithValue("e", email);
        cmd.Parameters.AddWithValue("h", hash);
        id = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    SetAuth(ctx, new Auth(id, email, "admin"));
    return Results.Redirect("/admin");
});

// -------------------- HTML + UI HELPERS --------------------
static IResult Html(string s) => Results.Content(s, "text/html");

static string H(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");

static string Layout(string title, string body) => $@"
<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>{H(title)}</title>
  <link rel='stylesheet' href='/site.css' />
</head>
<body>
  <div class='mv-bg-overlay'>
    {body}
  </div>
</body>
</html>";

static string Container(string inner) => $@"<div class='mv-container'>{inner}</div>";

string Topbar(HttpContext ctx, string subtitle, bool showLogoLinkToAdminLogin)
{
    var auth = GetAuth(ctx);

    // Logo must be clickable and should go to Admin login
    var logoHref = showLogoLinkToAdminLogin ? "/admin/login" : "/";

    var right = "";
    if (auth != null)
    {
        right = $@"<a class='btn btn-ghost' href='/logout'>Logout</a>";
    }

    return $@"
<div class='mv-topbar'>
  <div class='mv-topbar-inner'>
    <a class='mv-brand' href='{logoHref}'>
      <img src='{LOGO_PATH}' alt='MicroVote' />
      <div class='mv-title'>
        <strong>MicroVote</strong>
        <span>{H(subtitle)}</span>
      </div>
    </a>
    <div class='btn-row'>{right}</div>
  </div>
</div>";
}

string Nav(HttpContext ctx, string active)
{
    var auth = GetAuth(ctx);
    if (auth == null) return "";

    if (auth.Role == "admin")
    {
        return $@"
<div class='mv-panel' style='margin-top:14px; padding:12px 14px;'>
  <div class='mv-nav'>
    <a class='{(active=="dashboard"?"active":"")}' href='/admin'>Dashboard</a>
    <a class='{(active=="elections"?"active":"")}' href='/admin/elections'>Elections</a>
    <a class='{(active=="counties"?"active":"")}' href='/admin/counties'>Counties</a>
    <a class='{(active=="contractors"?"active":"")}' href='/admin/contractors'>Contractors</a>
    <a class='{(active=="users"?"active":"")}' href='/admin/users'>Users</a>
  </div>
</div>";
    }

    // Non-admin nav (kept minimal for now)
    var roleTitle = auth.Role switch
    {
        "aoe" => "AOE",
        "contractor" => "Contractor",
        "machinetech" => "Machine Tech",
        _ => "User"
    };

    return $@"
<div class='mv-panel' style='margin-top:14px; padding:12px 14px;'>
  <div class='mv-nav'>
    <a class='{(active=="dashboard"?"active":"")}' href='/{auth.Role}'>Dashboard</a>
    <span style='color:rgba(255,255,255,0.65); font-weight:800; padding:8px 10px;'>{H(roleTitle)}</span>
  </div>
</div>";
}

// Login page (role-aware label only)
string LoginPage(string requestedRole, string? err = null, string email = "")
{
    string roleLabel = requestedRole switch
    {
        "admin" => "Administrator Login",
        "contractor" => "MV Contractor Login",
        "machinetech" => "Machine Tech Login",
        _ => "AOE / Client Login"
    };

    var alert = string.IsNullOrWhiteSpace(err) ? "" : $@"<div class='alert err'><strong>Error:</strong> {H(err!)}</div>";

    var body = $@"
<div class='mv-panel'>
  <div class='h1'>{H(roleLabel)}</div>
  <div class='mv-subtle'>Use your portal credentials to sign in.</div>

  <div style='height:14px'></div>

  {alert}

  <div class='card'>
    <form method='post' action='/login'>
      <input type='hidden' name='requested_role' value='{H(requestedRole)}' />
      <div class='grid grid-2'>
        <div>
          <label>Email</label>
          <input type='email' name='email' value='{H(email)}' autocomplete='username' />
        </div>
        <div>
          <label>Password</label>
          <input type='password' name='password' autocomplete='current-password' />
        </div>
      </div>

      <div style='height:12px'></div>
      <div class='btn-row'>
        <button class='btn btn-primary' type='submit'>Sign in</button>
        <a class='btn btn-secondary' href='/'>Back</a>
      </div>
    </form>
  </div>
</div>";

    return Layout("Login", Topbar(new DefaultHttpContext(), "TN Election Portal (POC)", showLogoLinkToAdminLogin: true) + Container(body));
}

string SetupPage(string token, string? err = null, string email = "")
{
    var alert = string.IsNullOrWhiteSpace(err) ? "" : $@"<div class='alert err'><strong>Error:</strong> {H(err!)}</div>";

    var body = $@"
<div class='mv-panel'>
  <div class='h1'>Admin Setup</div>
  <div class='mv-subtle'>POC-only bootstrap. Sets admin password and signs you in.</div>

  <div style='height:14px'></div>
  {alert}

  <div class='card'>
    <form method='post' action='/setup'>
      <div class='grid grid-2'>
        <div>
          <label>Setup token</label>
          <input type='text' name='token' value='{H(token)}' />
        </div>
        <div>
          <label>Admin email</label>
          <input type='email' name='email' value='{H(email)}' />
        </div>
      </div>

      <div style='height:10px'></div>

      <div>
        <label>New password</label>
        <input type='password' name='password' />
      </div>

      <div style='height:12px'></div>
      <div class='btn-row'>
        <button class='btn btn-primary' type='submit'>Set admin password</button>
        <a class='btn btn-secondary' href='/'>Back</a>
      </div>
    </form>
  </div>
</div>";

    return Layout("Setup", Topbar(new DefaultHttpContext(), "TN Election Portal (POC)", showLogoLinkToAdminLogin: true) + Container(body));
}

// -------------------- COOKIE AUTH --------------------
void SetAuth(HttpContext ctx, Auth auth)
{
    var payload = JsonSerializer.Serialize(auth);
    var payloadB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
    var sig = HmacHex(AUTH_KEY, payloadB64);
    var value = payloadB64 + "." + sig;

    ctx.Response.Cookies.Append("mv_auth", value, new CookieOptions
    {
        HttpOnly = true,
        Secure = false, // true behind HTTPS
        SameSite = SameSiteMode.Lax,
        Expires = DateTimeOffset.UtcNow.AddDays(7)
    });
}

void ClearAuth(HttpContext ctx) => ctx.Response.Cookies.Delete("mv_auth");

Auth? GetAuth(HttpContext ctx)
{
    if (!ctx.Request.Cookies.TryGetValue("mv_auth", out var value)) return null;
    if (string.IsNullOrWhiteSpace(value)) return null;

    var parts = value.Split('.', 2);
    if (parts.Length != 2) return null;

    var payloadB64 = parts[0];
    var sig = parts[1];

    var expected = HmacHex(AUTH_KEY, payloadB64);
    if (!FixedTimeEquals(sig, expected)) return null;

    try
    {
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payloadB64));
        return JsonSerializer.Deserialize<Auth>(json);
    }
    catch { return null; }
}

bool RequireRole(HttpContext ctx, string role, out IResult? fail)
{
    fail = null;
    var a = GetAuth(ctx);
    if (a == null) { fail = Results.Redirect("/login"); return false; }
    if ((a.Role ?? "").Trim().ToLowerInvariant() != role)
    {
        // If admin tries to visit non-admin portal, route them properly, and vice versa.
        fail = Results.Redirect("/app");
        return false;
    }
    return true;
}

static string HmacHex(string key, string message)
{
    var k = Encoding.UTF8.GetBytes(key);
    var m = Encoding.UTF8.GetBytes(message);
    using var h = new HMACSHA256(k);
    return Convert.ToHexString(h.ComputeHash(m)).ToLowerInvariant();
}

static bool FixedTimeEquals(string aHex, string bHex)
{
    try
    {
        var a = Convert.FromHexString(aHex);
        var b = Convert.FromHexString(bHex);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
    catch { return false; }
}

// record

// constants
var InventoryTypes = new[]
{
    "Rev-E",
    "VVPAT",
    "Booth",
    "High Speed Printer",
    "ABS Scanner"
};



var ProgressChoices = new[]
{
    "started",
    "sent_for_approval",
    "revision",
    "approved_awaiting_programming",
    "finished"
};

static string ProgressLabel(string s) => s switch
{
    "started" => "Started",
    "sent_for_approval" => "Sent for approval",
    "revision" => "Revision",
    "approved_awaiting_programming" => "Approved awaiting programming",
    "finished" => "Finished",
    _ => s
};
// NOTE: DB helpers and the rest of routes come in next sections.


// NOTE: DB helpers and the rest of routes come in next sections.
// =========================
// DB helpers + schema ensure
// =========================
async Task<NpgsqlConnection> OpenConnAsync()
{
    var conn = new NpgsqlConnection(PORTAL_DB);
    await conn.OpenAsync();
    return conn;
}

static string ReadTextOrFirstArray(NpgsqlDataReader rd, int ordinal)
{
    if (rd.IsDBNull(ordinal)) return "";
    // Some of your earlier attempts ended up with array-ish values; this keeps UI resilient
    var obj = rd.GetValue(ordinal);
    if (obj is string s) return s;
    if (obj is string[] arr) return arr.Length > 0 ? (arr[0] ?? "") : "";
    return obj?.ToString() ?? "";
}

static string Alert(string kind, string msg)
{
    // kind: ok / warn / err
    var k = (kind ?? "ok").Trim().ToLowerInvariant();
    if (k != "ok" && k != "warn" && k != "err") k = "ok";
    return $@"<div class='alert {H(k)}'><strong>{(k == "ok" ? "OK" : k == "warn" ? "Warning" : "Error")}:</strong> {H(msg)}</div>";
}

static string ConfirmJs(string message) => $"return confirm('{H(message).Replace("'", "\\'")}');";

// Ensure schema on startup
// await EnsureSchemaAsync();

// =========================
// Admin area
// =========================
app.MapGet("/admin", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;

    // Admin Dashboard: upcoming elections, open issues, quick counts
    await using var conn = await OpenConnAsync();

    // Count open inventory issues
    int openIssues = 0;
    await using (var cmd = new NpgsqlCommand(@"
SELECT COUNT(*)
FROM inventory_issues i
JOIN inventory inv ON inv.id=i.inventory_id
WHERE COALESCE(i.is_resolved,false)=false AND COALESCE(inv.is_deleted,false)=false
", conn))
    {
        openIssues = Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    // Count unassigned contractors
    int unassigned = 0;
    await using (var cmd = new NpgsqlCommand(@"
SELECT COUNT(*)
FROM users u
LEFT JOIN contractor_assignments a ON a.contractor_user_id=u.id AND COALESCE(a.is_active,true)=true
WHERE u.role='contractor' AND COALESCE(u.is_deleted,false)=false AND a.contractor_user_id IS NULL
", conn))
    {
        unassigned = Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    // Upcoming elections (next 60 days, not archived)
    var upcomingRows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT e.id, e.election_name, e.election_date, e.progress_status,
       c.county_name
FROM elections e
JOIN counties c ON c.id=e.county_id
WHERE COALESCE(e.is_deleted,false)=false
  AND COALESCE(e.is_archived,false)=false
  AND e.election_date >= CURRENT_DATE
  AND e.election_date <= (CURRENT_DATE + INTERVAL '60 days')
ORDER BY e.election_date ASC
LIMIT 20
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var date = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
            var status = ReadTextOrFirstArray(r, 3);
            var county = ReadTextOrFirstArray(r, 4);

            upcomingRows.Append($@"
<tr>
  <td><a href='/admin/elections/{id}'>{H(name)}</a></td>
  <td>{H(county)}</td>
  <td>{H(date)}</td>
  <td>{H(status)}</td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", showLogoLinkToAdminLogin: false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Administrator Dashboard</div>
    <div class='mv-subtle'>Summary and quick access.</div>

    <div style='height:14px'></div>

    <div class='grid grid-3'>
      <div class='card'>
        <div style='font-weight:900; font-size:26px;'>{openIssues}</div>
        <div style='font-weight:800;'>Open Inventory Issues</div>
        <div class='mv-subtle'>Reported issues not yet resolved.</div>
        <div style='height:10px'></div>
        <a class='btn btn-secondary' href='/admin/issues'>View Issues</a>
      </div>

      <div class='card'>
        <div style='font-weight:900; font-size:26px;'>{unassigned}</div>
        <div style='font-weight:800;'>Unassigned Contractors</div>
        <div class='mv-subtle'>Contractors not assigned to a county/election.</div>
        <div style='height:10px'></div>
        <a class='btn btn-secondary' href='/admin/contractors'>Manage Contractors</a>
      </div>

      <div class='card'>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>
        <div style='font-weight:800;'>Admin Profile</div>
        <div class='mv-subtle'>Placeholder only.</div>
      </div>
    </div>

    <div style='height:16px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Upcoming Elections (next 60 days)</div>
      <table class='table'>
        <thead><tr><th>Election</th><th>County</th><th>Date</th><th>Status</th></tr></thead>
        <tbody>
          {(upcomingRows.Length == 0 ? "<tr><td colspan='4'>No upcoming elections in the next 60 days.</td></tr>" : upcomingRows.ToString())}
        </tbody>
      </table>
    </div>
  </div>
")}
";

    return Html(Layout("Admin Dashboard", body));
});

app.MapGet("/admin/counties", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    var rows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, county_name, county_code,
       COALESCE(aoe_name,''), COALESCE(deputy_name,''),
       COALESCE(email,''), COALESCE(phone,''),
       COALESCE(uses_mv_support,false)
FROM counties
WHERE COALESCE(is_deleted,false)=false
ORDER BY county_name ASC
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var code = ReadTextOrFirstArray(r, 2);
            var aoe = ReadTextOrFirstArray(r, 3);
            var dep = ReadTextOrFirstArray(r, 4);
            var email = ReadTextOrFirstArray(r, 5);
            var phone = ReadTextOrFirstArray(r, 6);
            var support = r.GetBoolean(7) ? "Yes" : "No";

            rows.Append($@"
<tr>
  <td><a href='/admin/counties/{id}'>{H(name)}</a></td>
  <td>{H(code)}</td>
  <td>{H(aoe)}</td>
  <td>{H(dep)}</td>
  <td>{H(email)}</td>
  <td>{H(phone)}</td>
  <td>{support}</td>
  <td class='right'>
    <form method='post' action='/admin/counties/delete' style='display:inline' onsubmit=""{ConfirmJs("Delete this county? This will also hide its elections and inventory from view.").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}' />
      <button class='btn btn-danger' type='submit'>Delete</button>
    </form>
  </td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "counties")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Counties / Clients</div>
    <div class='mv-subtle'>Create and manage county profiles. County names are clickable.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Add County</div>
      <form method='post' action='/admin/counties/create'>
        <div class='grid grid-3'>
          <div>
            <label>County name</label>
            <input name='county_name' placeholder='Morgan' required />
          </div>
          <div>
            <label>County code</label>
            <input name='county_code' placeholder='065' required />
            <div class='mv-subtle'>Supports 000–999.</div>
          </div>
          <div>
            <label>Uses MV Election-Day Support?</label>
            <select name='uses_mv_support'>
              <option value='false' selected>No</option>
              <option value='true'>Yes</option>
            </select>
          </div>
        </div>

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Add county</button>
        </div>
      </form>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>County List</div>
      <table class='table'>
        <thead>
          <tr>
            <th>County</th><th>Code</th><th>AOE</th><th>Deputy</th><th>Email</th><th>Phone</th><th>MV Support</th><th class='right'>Actions</th>
          </tr>
        </thead>
        <tbody>
          {(rows.Length==0 ? "<tr><td colspan='8'>No counties added yet.</td></tr>" : rows.ToString())}
        </tbody>
      </table>
    </div>

  </div>
")}
";
    return Html(Layout("Counties", body));
});

app.MapPost("/admin/counties/create", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    var name = (form["county_name"].ToString() ?? "").Trim();
    var code = (form["county_code"].ToString() ?? "").Trim();
    var support = (form["uses_mv_support"].ToString() ?? "false").Trim().ToLowerInvariant() == "true";

    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(code))
        return Results.Redirect("/admin/counties");

    // Normalize code to 3 digits if numeric
    if (int.TryParse(code, out var n) && n >= 0 && n <= 999)
        code = n.ToString("000");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO counties(county_code, county_name, uses_mv_support, is_deleted, created_at)
VALUES (@code, @name, @support, FALSE, NOW())
", conn))
    {
        cmd.Parameters.AddWithValue("@code", code);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@support", support);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/admin/counties");
});

app.MapPost("/admin/counties/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE counties SET is_deleted=TRUE, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    // Soft-delete county inventory too
    await using (var cmd = new NpgsqlCommand(@"
UPDATE inventory SET is_deleted=TRUE, updated_at=NOW()
WHERE county_id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    // Soft-delete elections too
    await using (var cmd = new NpgsqlCommand(@"
UPDATE elections SET is_deleted=TRUE, deleted_at=NOW()
WHERE county_id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/admin/counties");
});

// =========================
// County Profile page
// =========================
app.MapGet("/admin/counties/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    string countyName = "", countyCode = "";
    string aoe = "", deputy = "", email = "", phone = "";
    string officeAddr = "", storageAddr = "", website = "";
    bool usesSupport = false;

    await using (var cmd = new NpgsqlCommand(@"
SELECT county_name, county_code,
       COALESCE(aoe_name,''), COALESCE(deputy_name,''),
       COALESCE(email,''), COALESCE(phone,''),
       COALESCE(office_address,''), COALESCE(storage_address,''),
       COALESCE(website,''), COALESCE(uses_mv_support,false)
FROM counties
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);

        countyName = ReadTextOrFirstArray(r, 0);
        countyCode = ReadTextOrFirstArray(r, 1);
        aoe = ReadTextOrFirstArray(r, 2);
        deputy = ReadTextOrFirstArray(r, 3);
        email = ReadTextOrFirstArray(r, 4);
        phone = ReadTextOrFirstArray(r, 5);
        officeAddr = ReadTextOrFirstArray(r, 6);
        storageAddr = ReadTextOrFirstArray(r, 7);
        website = ReadTextOrFirstArray(r, 8);
        usesSupport = r.GetBoolean(9);
    }

    // Elections list for this county
    var electionRows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, election_name, election_date, COALESCE(progress_status,''), COALESCE(is_archived,false)
FROM elections
WHERE county_id=@cid AND COALESCE(is_deleted,false)=false
ORDER BY election_date DESC, id DESC
LIMIT 100
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", id);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var eid = r.GetInt64(0);
            var en = ReadTextOrFirstArray(r, 1);
            var ed = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
            var st = ReadTextOrFirstArray(r, 3);
            var arch = r.GetBoolean(4) ? "Archived" : "Active";

            electionRows.Append($@"
<tr>
  <td><a href='/admin/elections/{eid}'>{H(en)}</a></td>
  <td>{H(ed)}</td>
  <td>{H(st)}</td>
  <td>{H(arch)}</td>
</tr>");
        }
    }

    // Commissioners
    var commissionerRows = await RenderCommissionersAsync(conn, id, adminView: true);

    // Precincts
    var precinctRows = await RenderPrecinctsAsync(conn, id, adminView: true);

    // Machine tech assignments for this county
    var techRows = await RenderCountyMachineTechsAsync(conn, id);

    // Inventory list + issues indicator
    var inventoryRows = await RenderInventoryAsync(conn, id, viewerUserId: null, canReportIssue: true, adminView: true);

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "counties")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>{H(countyName)} <span class='mv-subtle'>({H(countyCode)})</span></div>

    <div style='height:10px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>County Profile</div>

        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>

        <form method='post' action='/admin/counties/update'>
          <input type='hidden' name='id' value='{id}' />

          <label>AOE name</label>
          <input name='aoe_name' value='{H(aoe)}' />

          <label>Deputy name</label>
          <input name='deputy_name' value='{H(deputy)}' />

          <div class='grid grid-2'>
            <div>
              <label>Email</label>
              <input name='email' value='{H(email)}' />
            </div>
            <div>
              <label>Phone</label>
              <input name='phone' value='{H(phone)}' />
            </div>
          </div>

          <label>Office address</label>
          <textarea name='office_address' rows='2'>{H(officeAddr)}</textarea>

          <label>Machine storage address</label>
          <textarea name='storage_address' rows='2'>{H(storageAddr)}</textarea>

          <label>County website</label>
          <input name='website' value='{H(website)}' />

          <label>Uses MV election-day support?</label>
          <select name='uses_mv_support'>
            <option value='false' {(usesSupport ? "" : "selected")}>No</option>
            <option value='true' {(usesSupport ? "selected" : "")}>Yes</option>
          </select>

          <div style='height:12px'></div>
          <div class='btn-row'>
            <button class='btn btn-primary' type='submit'>Save county</button>
            {(string.IsNullOrWhiteSpace(website) ? "" : $"<a class='btn btn-secondary' href='{H(website)}' target='_blank'>Open website</a>")}
          </div>
        </form>
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Elections for this County</div>
        <div class='mv-subtle'>Shows active + archived (soft deleted hidden).</div>
        <table class='table'>
          <thead><tr><th>Election</th><th>Date</th><th>Status</th><th>State</th></tr></thead>
          <tbody>{(electionRows.Length==0 ? "<tr><td colspan='4'>No elections for this county.</td></tr>" : electionRows.ToString())}</tbody>
        </table>
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Commissioners</div>
        {commissionerRows}
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Machine Techs</div>
        {techRows}
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Precincts</div>
        {precinctRows}
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Inventory</div>
        {inventoryRows}
      </div>
    </div>

  </div>
")}
";
    return Html(Layout("County", body));
});

app.MapPost("/admin/counties/update", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");

    var aoe = (form["aoe_name"].ToString() ?? "").Trim();
    var deputy = (form["deputy_name"].ToString() ?? "").Trim();
    var email = (form["email"].ToString() ?? "").Trim();
    var phone = (form["phone"].ToString() ?? "").Trim();
    var office = (form["office_address"].ToString() ?? "").Trim();
    var storage = (form["storage_address"].ToString() ?? "").Trim();
    var web = (form["website"].ToString() ?? "").Trim();
    var support = (form["uses_mv_support"].ToString() ?? "false").Trim().ToLowerInvariant() == "true";

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE counties
SET aoe_name=@aoe,
    deputy_name=@dep,
    email=@email,
    phone=@phone,
    office_address=@office,
    storage_address=@storage,
    website=@web,
    uses_mv_support=@support,
    updated_at=NOW()
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@aoe", aoe);
        cmd.Parameters.AddWithValue("@dep", deputy);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@phone", phone);
        cmd.Parameters.AddWithValue("@office", office);
        cmd.Parameters.AddWithValue("@storage", storage);
        cmd.Parameters.AddWithValue("@web", web);
        cmd.Parameters.AddWithValue("@support", support);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{id}");
});

// =========================
// Commissioners (simple one-row per county)
// =========================
async Task<string> RenderCommissionersAsync(NpgsqlConnection conn, long countyId, bool adminView)
{
    // Ensure table exists (already done in EnsureSchemaAsync in Part 2, but safe)
    await using (var cmd = new NpgsqlCommand(@"
CREATE TABLE IF NOT EXISTS county_commissioners (
  id BIGSERIAL PRIMARY KEY,
  county_id BIGINT NOT NULL REFERENCES counties(id),
  chair_name TEXT DEFAULT '',
  secretary_name TEXT DEFAULT '',
  member1_name TEXT DEFAULT '',
  member2_name TEXT DEFAULT '',
  member3_name TEXT DEFAULT '',
  updated_at TIMESTAMPTZ
);
", conn)) await cmd.ExecuteNonQueryAsync();

    // Fetch / create row
    long rowId = 0;
    string chair="", sec="", m1="", m2="", m3="";

    await using (var cmd = new NpgsqlCommand(@"
SELECT id, COALESCE(chair_name,''), COALESCE(secretary_name,''),
       COALESCE(member1_name,''), COALESCE(member2_name,''), COALESCE(member3_name,'')
FROM county_commissioners
WHERE county_id=@cid
LIMIT 1
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync())
        {
            rowId = r.GetInt64(0);
            chair = ReadTextOrFirstArray(r, 1);
            sec = ReadTextOrFirstArray(r, 2);
            m1 = ReadTextOrFirstArray(r, 3);
            m2 = ReadTextOrFirstArray(r, 4);
            m3 = ReadTextOrFirstArray(r, 5);
        }
    }

    if (rowId == 0)
    {
        await using var ins = new NpgsqlCommand(@"
INSERT INTO county_commissioners(county_id) VALUES (@cid)
RETURNING id
", conn);
        ins.Parameters.AddWithValue("@cid", countyId);
        rowId = Convert.ToInt64(await ins.ExecuteScalarAsync());
    }

    var form = $@"
<form method='post' action='/admin/counties/commissioners/save'>
  <input type='hidden' name='county_id' value='{countyId}' />

  <label>Chairman</label>
  <input name='chair_name' value='{H(chair)}' />

  <label>Secretary</label>
  <input name='secretary_name' value='{H(sec)}' />

  <div class='grid grid-3'>
    <div>
      <label>Member 1</label>
      <input name='member1_name' value='{H(m1)}' />
    </div>
    <div>
      <label>Member 2</label>
      <input name='member2_name' value='{H(m2)}' />
    </div>
    <div>
      <label>Member 3</label>
      <input name='member3_name' value='{H(m3)}' />
    </div>
  </div>

  <div style='height:10px'></div>
  <button class='btn btn-primary' type='submit'>Save commissioners</button>
</form>";

    return form;
}

app.MapPost("/admin/counties/commissioners/save", async (HttpContext ctx) =>
{
    // Admin only (AOE will get a parallel route later in Section 5)
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");

    var chair = (form["chair_name"].ToString() ?? "").Trim();
    var sec = (form["secretary_name"].ToString() ?? "").Trim();
    var m1 = (form["member1_name"].ToString() ?? "").Trim();
    var m2 = (form["member2_name"].ToString() ?? "").Trim();
    var m3 = (form["member3_name"].ToString() ?? "").Trim();

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE county_commissioners
SET chair_name=@c,
    secretary_name=@s,
    member1_name=@m1,
    member2_name=@m2,
    member3_name=@m3,
    updated_at=NOW()
WHERE county_id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@c", chair);
        cmd.Parameters.AddWithValue("@s", sec);
        cmd.Parameters.AddWithValue("@m1", m1);
        cmd.Parameters.AddWithValue("@m2", m2);
        cmd.Parameters.AddWithValue("@m3", m3);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

// =========================
// Precincts (CRUD)
// =========================
async Task<string> RenderPrecinctsAsync(NpgsqlConnection conn, long countyId, bool adminView)
{
    await using (var cmd = new NpgsqlCommand(@"
CREATE TABLE IF NOT EXISTS precincts (
  id BIGSERIAL PRIMARY KEY,
  county_id BIGINT NOT NULL REFERENCES counties(id),
  precinct_name TEXT NOT NULL,
  precinct_address TEXT DEFAULT '',
  registered_voters INT NOT NULL DEFAULT 0,
  is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);
", conn)) await cmd.ExecuteNonQueryAsync();

    var rows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, precinct_name, COALESCE(precinct_address,''), COALESCE(registered_voters,0)
FROM precincts
WHERE county_id=@cid AND COALESCE(is_deleted,false)=false
ORDER BY precinct_name ASC, id ASC
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var addr = ReadTextOrFirstArray(r, 2);
            var voters = r.GetInt32(3);

            rows.Append($@"
<tr>
  <td>{H(name)}</td>
  <td>{H(addr)}</td>
  <td class='right'>{voters}</td>
  <td class='right'>
    <a class='btn btn-secondary' href='/admin/precincts/edit/{id}'>Edit</a>
    <form method='post' action='/admin/precincts/delete' style='display:inline' onsubmit=""{ConfirmJs("Delete this precinct?").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}'/>
      <input type='hidden' name='county_id' value='{countyId}'/>
      <button class='btn btn-danger' type='submit'>Delete</button>
    </form>
  </td>
</tr>");
        }
    }

    var html = $@"
<form method='post' action='/admin/precincts/create'>
  <input type='hidden' name='county_id' value='{countyId}' />
  <div class='grid grid-3'>
    <div>
      <label>Name</label>
      <input name='precinct_name' placeholder='Precinct 1' required />
    </div>
    <div>
      <label>Address</label>
      <input name='precinct_address' placeholder='123 Main St' />
    </div>
    <div>
      <label>Registered voters</label>
      <input name='registered_voters' type='number' min='0' value='0' />
    </div>
  </div>
  <div style='height:10px'></div>
  <button class='btn btn-primary' type='submit'>Add precinct</button>
</form>

<div style='height:12px'></div>
<table class='table'>
  <thead><tr><th>Name</th><th>Address</th><th class='right'>Voters</th><th class='right'>Actions</th></tr></thead>
  <tbody>{(rows.Length==0 ? "<tr><td colspan='4'>No precincts added.</td></tr>" : rows.ToString())}</tbody>
</table>";

    return html;
}

app.MapPost("/admin/precincts/create", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");
    var name = (form["precinct_name"].ToString() ?? "").Trim();
    var addr = (form["precinct_address"].ToString() ?? "").Trim();
    var votersStr = (form["registered_voters"].ToString() ?? "0").Trim();
    if (!int.TryParse(votersStr, out var voters)) voters = 0;
    voters = Math.Max(0, voters);

    if (string.IsNullOrWhiteSpace(name)) return Results.Redirect($"/admin/counties/{countyId}");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO precincts(county_id, precinct_name, precinct_address, registered_voters, is_deleted)
VALUES (@cid, @n, @a, @v, FALSE)
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@a", addr);
        cmd.Parameters.AddWithValue("@v", voters);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapGet("/admin/precincts/edit/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    long countyId;
    string name="", addr="";
    int voters=0;

    await using (var cmd = new NpgsqlCommand(@"
SELECT county_id, precinct_name, COALESCE(precinct_address,''), COALESCE(registered_voters,0)
FROM precincts
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);
        countyId = r.GetInt64(0);
        name = ReadTextOrFirstArray(r, 1);
        addr = ReadTextOrFirstArray(r, 2);
        voters = r.GetInt32(3);
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "counties")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Edit Precinct</div>
    <div class='card'>
      <form method='post' action='/admin/precincts/edit'>
        <input type='hidden' name='id' value='{id}'/>
        <input type='hidden' name='county_id' value='{countyId}'/>

        <label>Name</label>
        <input name='precinct_name' value='{H(name)}' required />

        <label>Address</label>
        <input name='precinct_address' value='{H(addr)}' />

        <label>Registered voters</label>
        <input name='registered_voters' type='number' min='0' value='{voters}' />

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Save</button>
          <a class='btn btn-secondary' href='/admin/counties/{countyId}'>Back</a>
        </div>
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Edit Precinct", body));
});

app.MapPost("/admin/precincts/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");

    var name = (form["precinct_name"].ToString() ?? "").Trim();
    var addr = (form["precinct_address"].ToString() ?? "").Trim();
    var votersStr = (form["registered_voters"].ToString() ?? "0").Trim();
    if (!int.TryParse(votersStr, out var voters)) voters = 0;
    voters = Math.Max(0, voters);

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE precincts
SET precinct_name=@n, precinct_address=@a, registered_voters=@v, updated_at=NOW()
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@a", addr);
        cmd.Parameters.AddWithValue("@v", voters);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapPost("/aoe/precincts/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/aoe/county");
    long.TryParse(form["county_id"].ToString(), out var countyId);

    var name = (form["precinct_name"].ToString() ?? "").Trim();
    var addr = (form["precinct_address"].ToString() ?? "").Trim();
    var votersStr = (form["registered_voters"].ToString() ?? "0").Trim();
    if (!int.TryParse(votersStr, out var voters)) voters = 0;
    voters = Math.Max(0, voters);

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE precincts
SET precinct_name=@n, precinct_address=@a, registered_voters=@v, updated_at=NOW()
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@a", addr);
        cmd.Parameters.AddWithValue("@v", voters);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});


app.MapPost("/admin/precincts/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE precincts SET is_deleted=TRUE, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapPost("/aoe/precincts/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/aoe/county");
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/aoe/county");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE precincts SET is_deleted=TRUE, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    // If your AOE county page is /aoe/county (single county), redirect there.
    // If you later add /aoe/county/{id}, change this redirect to match.
    return Results.Redirect("/aoe/county");
});


// =========================
// Machine Tech assignment (admin)
// =========================
async Task<string> RenderCountyMachineTechsAsync(NpgsqlConnection conn, long countyId)
{
    // assigned techs
    var assigned = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.id, u.email, COALESCE(u.display_name,'')
FROM machine_tech_assignments a
JOIN users u ON u.id=a.tech_user_id
WHERE a.county_id=@cid AND COALESCE(a.is_active,true)=true AND COALESCE(u.is_deleted,false)=false
ORDER BY u.email ASC
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var uid = r.GetInt64(0);
            var email = ReadTextOrFirstArray(r, 1);
            var dn = ReadTextOrFirstArray(r, 2);

            assigned.Append($@"
<tr>
  <td>{H(string.IsNullOrWhiteSpace(dn) ? email : dn)}</td>
  <td>{H(email)}</td>
  <td class='right'>
    <form method='post' action='/admin/machinetechs/unassign' style='display:inline' onsubmit=""{ConfirmJs("Unassign this machine tech from the county?").Replace("\"","&quot;")}"">
      <input type='hidden' name='county_id' value='{countyId}'/>
      <input type='hidden' name='tech_user_id' value='{uid}'/>
      <button class='btn btn-danger' type='submit'>Unassign</button>
    </form>
  </td>
</tr>");
        }
    }

    // available tech users (role = machinetech)
    var options = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, email, COALESCE(display_name,'')
FROM users
WHERE role='machinetech' AND COALESCE(is_deleted,false)=false
ORDER BY email ASC
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var uid = r.GetInt64(0);
            var email = ReadTextOrFirstArray(r, 1);
            var dn = ReadTextOrFirstArray(r, 2);
            var label = string.IsNullOrWhiteSpace(dn) ? email : $"{dn} ({email})";
            options.Append($@"<option value='{uid}'>{H(label)}</option>");
        }
    }

    return $@"
<div class='mv-subtle'>Assign existing Machine Tech users to this county (invites are added later).</div>

<div style='height:10px'></div>

<form method='post' action='/admin/machinetechs/assign'>
  <input type='hidden' name='county_id' value='{countyId}' />
  <label>Select Machine Tech</label>
  <select name='tech_user_id' required>
    <option value=''>-- Select --</option>
    {options}
  </select>
  <div style='height:10px'></div>
  <button class='btn btn-primary' type='submit'>Assign</button>
</form>

<div style='height:12px'></div>

<table class='table'>
  <thead><tr><th>Name</th><th>Email</th><th class='right'>Actions</th></tr></thead>
  <tbody>{(assigned.Length==0 ? "<tr><td colspan='3'>No machine techs assigned.</td></tr>" : assigned.ToString())}</tbody>
</table>";
}

app.MapPost("/admin/machinetechs/assign", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["tech_user_id"].ToString(), out var techUserId)) return Results.Redirect($"/admin/counties/{countyId}");

    await using var conn = await OpenConnAsync();

    // Deactivate any existing assignment for this tech
    await using (var cmd = new NpgsqlCommand(@"
UPDATE machine_tech_assignments
SET is_active=false
WHERE tech_user_id=@uid
", conn))
    {
        cmd.Parameters.AddWithValue("@uid", techUserId);
        await cmd.ExecuteNonQueryAsync();
    }

    // Create new assignment
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO machine_tech_assignments(tech_user_id, county_id, is_active, created_at)
VALUES (@uid, @cid, true, NOW())
", conn))
    {
        cmd.Parameters.AddWithValue("@uid", techUserId);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapPost("/admin/machinetechs/unassign", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["tech_user_id"].ToString(), out var techUserId)) return Results.Redirect($"/admin/counties/{countyId}");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE machine_tech_assignments
SET is_active=false
WHERE tech_user_id=@uid AND county_id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@uid", techUserId);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

// =========================
// Inventory (CRUD + issues) - admin view
// =========================


async Task<string> RenderInventoryAsync(NpgsqlConnection conn, long countyId, long? viewerUserId, bool canReportIssue, bool adminView)
{
    var rows = new StringBuilder();

    await using (var cmd = new NpgsqlCommand(@"
SELECT inv.id, inv.item_type, inv.serial_number,
       EXISTS (
         SELECT 1 FROM inventory_issues i
         WHERE i.inventory_id=inv.id AND COALESCE(i.is_resolved,false)=false
       ) AS has_open_issue
FROM inventory inv
WHERE inv.county_id=@cid AND COALESCE(inv.is_deleted,false)=false
ORDER BY inv.item_type ASC, inv.serial_number ASC, inv.id ASC
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var type = ReadTextOrFirstArray(r, 1);
            var sn = ReadTextOrFirstArray(r, 2);
            var hasIssue = r.GetBoolean(3);

            var issueBadge = hasIssue ? "<span class='badge badge-warn'>Issue</span>" : "<span class='badge badge-ok'>OK</span>";

            rows.Append($@"
<tr>
  <td>{H(type)} {issueBadge}</td>
  <td>{H(sn)}</td>
  <td class='right'>
    <a class='btn btn-secondary' href='/admin/inventory/edit/{id}'>Edit</a>
    <form method='post' action='/admin/inventory/delete' style='display:inline' onsubmit=""{ConfirmJs("Delete this inventory item?").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}'/>
      <input type='hidden' name='county_id' value='{countyId}'/>
      <button class='btn btn-danger' type='submit'>Delete</button>
    </form>
  </td>
</tr>

<tr>
  <td colspan='3' style='padding-top:0;'>
    <form method='post' action='/inventory/issues/report' style='margin:0;'>
      <input type='hidden' name='inventory_id' value='{id}'/>
      <input type='hidden' name='return_to' value='/admin/counties/{countyId}'/>
      <div class='grid grid-2' style='align-items:end;'>
        <div>
          <label style='font-weight:700;'>Report issue for this item</label>
          <input name='issue_text' placeholder='Describe the problem...' />
        </div>
        <div class='right'>
          <button class='btn btn-primary' type='submit'>Report issue</button>
        </div>
      </div>
    </form>
  </td>
</tr>
");
        }
    }

    var typeOptions = new StringBuilder();
    foreach (var t in InventoryTypes) typeOptions.Append($@"<option value='{H(t)}'>{H(t)}</option>");

    var html = $@"
<form method='post' action='/admin/inventory/create'>
  <input type='hidden' name='county_id' value='{countyId}' />
  <div class='grid grid-2'>
    <div>
      <label>Item type</label>
      <select name='item_type' required>
        {typeOptions}
      </select>
    </div>
    <div>
      <label>Serial number</label>
      <input name='serial_number' placeholder='SN12345' required />
    </div>
  </div>
  <div style='height:10px'></div>
  <button class='btn btn-primary' type='submit'>Add item</button>
</form>

<div style='height:12px'></div>
<table class='table'>
  <thead><tr><th>Item</th><th>Serial</th><th class='right'>Actions</th></tr></thead>
  <tbody>{(rows.Length==0 ? "<tr><td colspan='3'>No inventory items added.</td></tr>" : rows.ToString())}</tbody>
</table>";

    return html;
}

app.MapPost("/admin/inventory/create", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");
    var type = (form["item_type"].ToString() ?? "").Trim();
    var sn = (form["serial_number"].ToString() ?? "").Trim();

    if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(sn))
        return Results.Redirect($"/admin/counties/{countyId}");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO inventory(county_id, item_type, serial_number, is_deleted, created_at)
VALUES (@cid, @t, @sn, false, NOW())
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        cmd.Parameters.AddWithValue("@t", type);
        cmd.Parameters.AddWithValue("@sn", sn);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapGet("/admin/inventory/edit/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    long countyId;
    string type="", sn="";

    await using (var cmd = new NpgsqlCommand(@"
SELECT county_id, item_type, serial_number
FROM inventory
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);
        countyId = r.GetInt64(0);
        type = ReadTextOrFirstArray(r, 1);
        sn = ReadTextOrFirstArray(r, 2);
    }

    var typeOptions = new StringBuilder();
    foreach (var t in InventoryTypes)
    {
        var sel = string.Equals(t, type, StringComparison.OrdinalIgnoreCase) ? "selected" : "";
        typeOptions.Append($@"<option value='{H(t)}' {sel}>{H(t)}</option>");
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "counties")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Edit Inventory Item</div>
    <div class='card'>
      <form method='post' action='/admin/inventory/edit'>
        <input type='hidden' name='id' value='{id}'/>
        <input type='hidden' name='county_id' value='{countyId}'/>

        <label>Item type</label>
        <select name='item_type' required>{typeOptions}</select>

        <label>Serial number</label>
        <input name='serial_number' value='{H(sn)}' required />

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Save</button>
          <a class='btn btn-secondary' href='/admin/counties/{countyId}'>Back</a>
        </div>
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Edit Inventory", body));
});

app.MapPost("/admin/inventory/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");

    var type = (form["item_type"].ToString() ?? "").Trim();
    var sn = (form["serial_number"].ToString() ?? "").Trim();

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE inventory
SET item_type=@t, serial_number=@sn, updated_at=NOW()
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@t", type);
        cmd.Parameters.AddWithValue("@sn", sn);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapPost("/admin/inventory/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/counties");
    if (!long.TryParse(form["county_id"].ToString(), out var countyId)) return Results.Redirect("/admin/counties");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE inventory SET is_deleted=true, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/counties/{countyId}");
});

app.MapPost("/aoe/inventory/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    // The AOE page uses /aoe/county, so redirect there if the form is missing values.
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/aoe/county");

    // county_id might be present, but AOE doesn't use /aoe/counties/{id} like admin.
    // We can still read it if you want it later:
    long.TryParse(form["county_id"].ToString(), out var countyId);

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE inventory SET is_deleted=true, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});


// =========================
// Issue Reporting (shared route used by admin/AOE/contractor/machinetech later)
// =========================
app.MapPost("/inventory/issues/report", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx); // can be null, but normally should not be
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["inventory_id"].ToString(), out var invId))
        return Results.Text("Bad inventory_id", "text/plain", statusCode: 400);

    var text = (form["issue_text"].ToString() ?? "").Trim();
    var returnTo = (form["return_to"].ToString() ?? "/").Trim();
    if (string.IsNullOrWhiteSpace(text))
        return Results.Redirect(returnTo);

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO inventory_issues(inventory_id, reported_by_user_id, issue_text, reported_at, is_resolved)
VALUES (@iid, @uid, @txt, NOW(), false)
", conn))
    {
        cmd.Parameters.AddWithValue("@iid", invId);
        cmd.Parameters.AddWithValue("@uid", auth == null ? (object)DBNull.Value : auth.UserId);
        cmd.Parameters.AddWithValue("@txt", text);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect(returnTo);
});
// =========================
// Invites (Admin) + Accept Invite
// =========================

// Helper: nice "email already exists" message placeholder (we show on create user/invite)
static string FriendlyEmailExists(string email) =>
    $"That email is already in use: {H(email)}. Try a different email or remove the old user first.";

// Admin: Invites page
app.MapGet("/admin/invites", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    // Recent invites
    var rows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, email, role, COALESCE(display_name,''), COALESCE(county_id,0),
       token, expires_at, COALESCE(used_at,null)
FROM invites
ORDER BY id DESC
LIMIT 50
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var email = ReadTextOrFirstArray(r, 1);
            var role = ReadTextOrFirstArray(r, 2);
            var dn = ReadTextOrFirstArray(r, 3);
            var countyId = r.IsDBNull(4) ? 0 : r.GetInt64(4);
            var token = ReadTextOrFirstArray(r, 5);
            var expires = r.GetFieldValue<DateTimeOffset>(6).ToString("yyyy-MM-dd HH:mm");
            var used = r.IsDBNull(7) ? "" : r.GetFieldValue<DateTimeOffset>(7).ToString("yyyy-MM-dd HH:mm");

            var link = $"/invite/{token}";
            rows.Append($@"
<tr>
  <td>{id}</td>
  <td>{H(email)}</td>
  <td>{H(role)}</td>
  <td>{H(dn)}</td>
  <td>{(countyId==0 ? "" : countyId.ToString())}</td>
  <td><a href='{H(link)}'>{H(link)}</a></td>
  <td>{H(expires)}</td>
  <td>{H(used)}</td>
</tr>");
        }
    }

    // Counties for dropdown (used when role=aoe, role=machinetech assignment handled separately)
    var countyOptions = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, county_name, county_code
FROM counties
WHERE COALESCE(is_deleted,false)=false
ORDER BY county_name ASC
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var code = ReadTextOrFirstArray(r, 2);
            countyOptions.Append($@"<option value='{id}'>{H(name)} ({H(code)})</option>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "users")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Invites</div>
    <div class='mv-subtle'>Create an invite link. Users set password on first use.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Create Invite</div>
      <form method='post' action='/admin/invites/create'>
        <div class='grid grid-3'>
          <div>
            <label>Email</label>
            <input name='email' type='email' required />
          </div>
          <div>
            <label>Display name</label>
            <input name='display_name' />
          </div>
          <div>
            <label>Role</label>
            <select name='role' required>
              <option value='aoe' selected>AOE / Client</option>
              <option value='contractor'>MV Contractor</option>
              <option value='machinetech'>Machine Tech</option>
            </select>
          </div>
        </div>

        <div style='height:10px'></div>

        <div class='grid grid-2'>
          <div>
            <label>County (only needed for AOE)</label>
            <select name='county_id'>
              <option value=''>-- None --</option>
              {countyOptions}
            </select>
            <div class='mv-subtle'>AOE users must be tied to a county for isolation.</div>
          </div>
          <div>
            <label>Expires in (hours)</label>
            <input name='expires_hours' type='number' min='1' value='72' />
          </div>
        </div>

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Create invite</button>
        </div>
      </form>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Recent Invites</div>
      <table class='table'>
        <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Name</th><th>CountyId</th><th>Link</th><th>Expires</th><th>Used</th></tr></thead>
        <tbody>{(rows.Length==0 ? "<tr><td colspan='8'>No invites yet.</td></tr>" : rows.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("Invites", body));
});

app.MapPost("/admin/invites/create", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    var email = (form["email"].ToString() ?? "").Trim().ToLowerInvariant();
    var dn = (form["display_name"].ToString() ?? "").Trim();
    var role = (form["role"].ToString() ?? "aoe").Trim().ToLowerInvariant();
    var countyStr = (form["county_id"].ToString() ?? "").Trim();
    var expStr = (form["expires_hours"].ToString() ?? "72").Trim();

    long? countyId = null;
    if (long.TryParse(countyStr, out var cid)) countyId = cid;

    if (!int.TryParse(expStr, out var expHours)) expHours = 72;
    expHours = Math.Clamp(expHours, 1, 720);

    if (string.IsNullOrWhiteSpace(email)) return Results.Redirect("/admin/invites");

    // If role is aoe, county is required
    if (role == "aoe" && (countyId == null || countyId <= 0))
    {
        return Html(Layout("Invites", Topbar(ctx, "MV Election Portal (POC)", false) + Nav(ctx, "users") + Container($@"
<div class='mv-panel'>
  <div class='alert err'><strong>Error:</strong> AOE invites must include a county.</div>
  <a class='btn btn-secondary' href='/admin/invites'>Back</a>
</div>")));
    }

    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    var expiresAt = DateTimeOffset.UtcNow.AddHours(expHours);

    await using var conn = await OpenConnAsync();

    // Email already exists? warn but still allow invite if user is deleted? For now: block if active.
    await using (var chk = new NpgsqlCommand(@"
SELECT COUNT(*) FROM users WHERE lower(email)=@e AND COALESCE(is_deleted,false)=false
", conn))
    {
        chk.Parameters.AddWithValue("@e", email);
        var count = Convert.ToInt64(await chk.ExecuteScalarAsync());
        if (count > 0)
        {
            return Html(Layout("Invites", Topbar(ctx, "MV Election Portal (POC)", false) + Nav(ctx, "users") + Container($@"
<div class='mv-panel'>
  <div class='alert err'><strong>Error:</strong> {FriendlyEmailExists(email)}</div>
  <a class='btn btn-secondary' href='/admin/invites'>Back</a>
</div>")));
        }
    }

    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO invites(email, display_name, role, county_id, token, expires_at)
VALUES (@e, @dn, @role, @cid, @t, @exp)
", conn))
    {
        cmd.Parameters.AddWithValue("@e", email);
        cmd.Parameters.AddWithValue("@dn", dn);
        cmd.Parameters.AddWithValue("@role", role);
        cmd.Parameters.AddWithValue("@cid", (object?)countyId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@t", token);
        cmd.Parameters.AddWithValue("@exp", expiresAt);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/admin/invites");
});

// Accept invite: show set-password page
app.MapGet("/invite/{token}", async (HttpContext ctx, string token) =>
{
    token = (token ?? "").Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(token)) return Results.Redirect("/");

    await using var conn = await OpenConnAsync();
    string email="", dn="", role="";
    long? countyId = null;
    DateTimeOffset exp;
    DateTimeOffset? used = null;

    await using (var cmd = new NpgsqlCommand(@"
SELECT email, COALESCE(display_name,''), role, county_id, expires_at, used_at
FROM invites
WHERE token=@t
LIMIT 1
", conn))
    {
        cmd.Parameters.AddWithValue("@t", token);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Invalid invite.", "text/plain", statusCode: 404);

        email = ReadTextOrFirstArray(r, 0);
        dn = ReadTextOrFirstArray(r, 1);
        role = ReadTextOrFirstArray(r, 2);
        countyId = r.IsDBNull(3) ? null : r.GetInt64(3);
        exp = r.GetFieldValue<DateTimeOffset>(4);
        used = r.IsDBNull(5) ? null : r.GetFieldValue<DateTimeOffset>(5);
    }

    if (DateTimeOffset.UtcNow > exp) return Results.Text("Invite expired.", "text/plain", statusCode: 400);
    if (used != null) return Results.Text("Invite already used.", "text/plain", statusCode: 400);

    var body = $@"
{Topbar(ctx, "TN Election Portal (POC)", true)}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Accept Invite</div>
    <div class='mv-subtle'>You are creating your portal password.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div><strong>Email:</strong> {H(email)}</div>
      <div><strong>Role:</strong> {H(role)}</div>
      <div style='height:12px'></div>

      <form method='post' action='/invite/{H(token)}'>
        <label>New password</label>
        <input type='password' name='password' required />

        <label>Confirm password</label>
        <input type='password' name='password2' required />

        <div style='height:12px'></div>
        <button class='btn btn-primary' type='submit'>Set password</button>
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Accept Invite", body));
});

// Accept invite POST: create user
app.MapPost("/invite/{token}", async (HttpContext ctx, string token) =>
{
    token = (token ?? "").Trim().ToLowerInvariant();
    var form = await ctx.Request.ReadFormAsync();

    var pw1 = form["password"].ToString() ?? "";
    var pw2 = form["password2"].ToString() ?? "";

    if (pw1.Length < 6) return Results.Text("Password must be at least 6 characters.", "text/plain", statusCode: 400);
    if (pw1 != pw2) return Results.Text("Passwords do not match.", "text/plain", statusCode: 400);

    await using var conn = await OpenConnAsync();

    // Lock invite row
    string email="", dn="", role="";
    long? countyId = null;
    DateTimeOffset exp;
    DateTimeOffset? used = null;
    long inviteId;

    await using (var cmd = new NpgsqlCommand(@"
SELECT id, email, COALESCE(display_name,''), role, county_id, expires_at, used_at
FROM invites
WHERE token=@t
LIMIT 1
FOR UPDATE
", conn))
    {
        cmd.Parameters.AddWithValue("@t", token);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Invalid invite.", "text/plain", statusCode: 404);

        inviteId = r.GetInt64(0);
        email = ReadTextOrFirstArray(r, 1);
        dn = ReadTextOrFirstArray(r, 2);
        role = ReadTextOrFirstArray(r, 3);
        countyId = r.IsDBNull(4) ? null : r.GetInt64(4);
        exp = r.GetFieldValue<DateTimeOffset>(5);
        used = r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6);
    }

    if (DateTimeOffset.UtcNow > exp) return Results.Text("Invite expired.", "text/plain", statusCode: 400);
    if (used != null) return Results.Text("Invite already used.", "text/plain", statusCode: 400);

    if (role == "aoe" && (countyId == null || countyId <= 0))
        return Results.Text("AOE invites must be tied to a county.", "text/plain", statusCode: 400);

    // Email already exists?
    await using (var chk = new NpgsqlCommand(@"
SELECT COUNT(*) FROM users WHERE lower(email)=@e AND COALESCE(is_deleted,false)=false
", conn))
    {
        chk.Parameters.AddWithValue("@e", email);
        var count = Convert.ToInt64(await chk.ExecuteScalarAsync());
        if (count > 0) return Results.Text("Email already exists.", "text/plain", statusCode: 400);
    }

    var hash = BCrypt.Net.BCrypt.HashPassword(pw1);

    long userId;
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO users(email, role, display_name, password_hash, county_id, is_deleted)
VALUES (@e, @role, @dn, @h, @cid, false)
RETURNING id
", conn))
    {
        cmd.Parameters.AddWithValue("@e", email);
        cmd.Parameters.AddWithValue("@role", role);
        cmd.Parameters.AddWithValue("@dn", dn);
        cmd.Parameters.AddWithValue("@h", hash);
        cmd.Parameters.AddWithValue("@cid", (object?)countyId ?? DBNull.Value);
        userId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    // Mark invite used
    await using (var cmd = new NpgsqlCommand(@"
UPDATE invites SET used_at=NOW() WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", inviteId);
        await cmd.ExecuteNonQueryAsync();
    }

    // Create blank profile rows if needed
    if (role == "contractor")
    {
        await using var cmd = new NpgsqlCommand(@"
INSERT INTO contractor_profiles(user_id, full_name, phone, address, dob, updated_at)
VALUES (@uid, '', '', '', '', NOW())
ON CONFLICT (user_id) DO NOTHING
", conn);
        cmd.Parameters.AddWithValue("@uid", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    SetAuth(ctx, new Auth(userId, email, role));

    // Contractors + machine techs go to their dashboards
    return Results.Redirect("/app");
});

// =========================
// Admin Users (list + remove)
// =========================
app.MapGet("/admin/users", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    var rows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.id, u.email, u.role, COALESCE(u.display_name,''),
       COALESCE(c.county_name,''), COALESCE(u.is_deleted,false)
FROM users u
LEFT JOIN counties c ON c.id=u.county_id
ORDER BY u.id DESC
LIMIT 200
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var email = ReadTextOrFirstArray(r, 1);
            var role = ReadTextOrFirstArray(r, 2);
            var dn = ReadTextOrFirstArray(r, 3);
            var county = ReadTextOrFirstArray(r, 4);
            var deleted = r.GetBoolean(5);

            rows.Append($@"
<tr>
  <td>{id}</td>
  <td>{H(email)}</td>
  <td>{H(role)}</td>
  <td>{H(dn)}</td>
  <td>{H(county)}</td>
  <td>{(deleted ? "Yes" : "No")}</td>
  <td class='right'>
    <form method='post' action='/admin/users/delete' style='display:inline' onsubmit=""{ConfirmJs("Remove this user? (Soft delete)").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}'/>
      <button class='btn btn-danger' type='submit'>Remove</button>
    </form>
  </td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "users")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Users</div>
    <div class='mv-subtle'>Includes admin, AOEs, contractors, and machine techs.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='btn-row'>
        <a class='btn btn-primary' href='/admin/invites'>Create invites</a>
      </div>

      <div style='height:12px'></div>

      <table class='table'>
        <thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Name</th><th>County</th><th>Deleted</th><th class='right'>Actions</th></tr></thead>
        <tbody>{(rows.Length==0 ? "<tr><td colspan='7'>No users.</td></tr>" : rows.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("Users", body));
});

app.MapPost("/admin/users/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/users");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
UPDATE users SET is_deleted=true WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/admin/users");
});

// =========================
// Admin Contractors (list + edit profile + docs placeholder)
// =========================
app.MapGet("/admin/contractors", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    var rows = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.id, u.email, COALESCE(p.full_name,''), COALESCE(p.phone,''),
       COALESCE(a.county_id,0) as assigned_county_id,
       COALESCE(c.county_name,'') as assigned_county_name
FROM users u
LEFT JOIN contractor_profiles p ON p.user_id=u.id
LEFT JOIN contractor_assignments a ON a.contractor_user_id=u.id AND COALESCE(a.is_active,true)=true
LEFT JOIN counties c ON c.id=a.county_id
WHERE u.role='contractor' AND COALESCE(u.is_deleted,false)=false
ORDER BY COALESCE(p.full_name,''), u.email
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var email = ReadTextOrFirstArray(r, 1);
            var name = ReadTextOrFirstArray(r, 2);
            var phone = ReadTextOrFirstArray(r, 3);
            var cid = r.IsDBNull(4) ? 0 : r.GetInt64(4);
            var county = ReadTextOrFirstArray(r, 5);

            var assignBadge = cid == 0
                ? "<span class='badge badge-danger'>Unassigned</span>"
                : "<span class='badge badge-ok'>Assigned</span>";

            rows.Append($@"
<tr>
  <td>{H(string.IsNullOrWhiteSpace(name) ? email : name)}</td>
  <td>{H(email)}</td>
  <td>{H(phone)}</td>
  <td>{assignBadge} {H(county)}</td>
  <td class='right'>
    <a class='btn btn-secondary' href='/admin/contractors/edit/{id}'>Edit</a>
    <form method='post' action='/admin/users/delete' style='display:inline' onsubmit=""{ConfirmJs("Remove this contractor user?").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}'/>
      <button class='btn btn-danger' type='submit'>Remove</button>
    </form>
  </td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "contractors")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Contractors</div>
    <div class='mv-subtle'>Highlighted if unassigned. Assignments are driven by elections (support requested).</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='btn-row'>
        <a class='btn btn-primary' href='/admin/invites'>Invite contractor</a>
      </div>

      <div style='height:12px'></div>

      <table class='table'>
        <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Assignment</th><th class='right'>Actions</th></tr></thead>
        <tbody>{(rows.Length==0 ? "<tr><td colspan='5'>No contractors.</td></tr>" : rows.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("Contractors", body));
});

app.MapGet("/admin/contractors/edit/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    string email="", fullName="", phone="", address="", dob="";
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.email,
       COALESCE(p.full_name,''), COALESCE(p.phone,''), COALESCE(p.address,''), COALESCE(p.dob,'')
FROM users u
LEFT JOIN contractor_profiles p ON p.user_id=u.id
WHERE u.id=@id AND u.role='contractor' AND COALESCE(u.is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);

        email = ReadTextOrFirstArray(r, 0);
        fullName = ReadTextOrFirstArray(r, 1);
        phone = ReadTextOrFirstArray(r, 2);
        address = ReadTextOrFirstArray(r, 3);
        dob = ReadTextOrFirstArray(r, 4);
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "contractors")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Edit Contractor</div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Profile</div>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>

        <form method='post' action='/admin/contractors/edit'>
          <input type='hidden' name='id' value='{id}'/>

          <label>Email</label>
          <input value='{H(email)}' disabled />

          <label>Full name</label>
          <input name='full_name' value='{H(fullName)}' />

          <label>Phone</label>
          <input name='phone' value='{H(phone)}' />

          <label>Address</label>
          <textarea name='address' rows='2'>{H(address)}</textarea>

          <label>DOB</label>
          <input name='dob' value='{H(dob)}' placeholder='YYYY-MM-DD' />

          <div style='height:12px'></div>
          <div class='btn-row'>
            <button class='btn btn-primary' type='submit'>Save</button>
            <a class='btn btn-secondary' href='/admin/contractors'>Back</a>
          </div>
        </form>
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Onboarding Docs (Coming soon)</div>
        <div class='mv-subtle'>Later: upload DL front/back + SS card and export a PDF.</div>
        <div style='height:10px'></div>
        <div class='alert warn'><strong>Note:</strong> Doc upload + PDF export is scaffolded but can be finalized later.</div>
      </div>
    </div>
  </div>
")}
";
    return Html(Layout("Edit Contractor", body));
});

app.MapPost("/admin/contractors/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/contractors");

    var fullName = (form["full_name"].ToString() ?? "").Trim();
    var phone = (form["phone"].ToString() ?? "").Trim();
    var address = (form["address"].ToString() ?? "").Trim();
    var dob = (form["dob"].ToString() ?? "").Trim();

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO contractor_profiles(user_id, full_name, phone, address, dob, updated_at)
VALUES (@id, @n, @p, @a, @d, NOW())
ON CONFLICT (user_id) DO UPDATE SET
  full_name=EXCLUDED.full_name,
  phone=EXCLUDED.phone,
  address=EXCLUDED.address,
  dob=EXCLUDED.dob,
  updated_at=NOW()
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@n", fullName);
        cmd.Parameters.AddWithValue("@p", phone);
        cmd.Parameters.AddWithValue("@a", address);
        cmd.Parameters.AddWithValue("@d", dob);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/admin/contractors");
});

// =========================
// AOE Portal (dashboard + county management allowed)
// =========================
app.MapGet("/aoe", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    // Must have county_id
    await using var conn = await OpenConnAsync();
    long countyId = 0;
    string countyName = "", countyCode = "";

    await using (var cmd = new NpgsqlCommand(@"
SELECT COALESCE(county_id,0)
FROM users
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Html(Layout("AOE", Topbar(ctx, "AOE Portal", false) + Container("<div class='mv-panel'><div class='alert err'><strong>Error:</strong> No county assigned.</div></div>")));

    await using (var cmd = new NpgsqlCommand(@"
SELECT county_name, county_code
FROM counties WHERE id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync())
        {
            countyName = ReadTextOrFirstArray(r, 0);
            countyCode = ReadTextOrFirstArray(r, 1);
        }
    }

    // Upcoming elections for this county
    var elections = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, election_name, election_date, COALESCE(progress_status,'')
FROM elections
WHERE county_id=@cid AND COALESCE(is_deleted,false)=false AND COALESCE(is_archived,false)=false
ORDER BY election_date ASC
LIMIT 50
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var eid = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var date = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
            var status = ReadTextOrFirstArray(r, 3);
            elections.Append($@"<tr><td><a href='/aoe/elections/{eid}'>{H(name)}</a></td><td>{H(date)}</td><td>{H(status)}</td></tr>");
        }
    }

    // Open issues count for this county
    long openIssues = 0;
    await using (var cmd = new NpgsqlCommand(@"
SELECT COUNT(*)
FROM inventory_issues i
JOIN inventory inv ON inv.id=i.inventory_id
WHERE inv.county_id=@cid AND COALESCE(inv.is_deleted,false)=false AND COALESCE(i.is_resolved,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        openIssues = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    var body = $@"
{Topbar(ctx, "AOE Portal", false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>{H(countyName)} <span class='mv-subtle'>({H(countyCode)})</span></div>
    <div class='mv-subtle'>AOE dashboard. You can manage your county profile, precincts, commissioners, machine techs, and inventory.</div>

    <div style='height:14px'></div>

    <div class='grid grid-3'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Open inventory issues</div>
        <div style='font-size:28px; font-weight:900;'>{openIssues}</div>
        <div class='mv-subtle'>Visible to Admin and your county.</div>
        <div style='height:10px'></div>
        <a class='btn btn-secondary' href='/aoe/county'>View county</a>
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>County Info</div>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>
        <a class='btn btn-secondary' href='/aoe/county'>Edit county / precincts / inventory</a>
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Quick Links</div>
        <div class='btn-row'>
          <a class='btn btn-secondary' href='https://microvote.com' target='_blank'>MicroVote</a>
          <a class='btn btn-secondary' href='/logout'>Logout</a>
        </div>
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Upcoming Elections</div>
      <table class='table'>
        <thead><tr><th>Election</th><th>Date</th><th>Status</th></tr></thead>
        <tbody>{(elections.Length==0 ? "<tr><td colspan='3'>No elections.</td></tr>" : elections.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("AOE", body));
});

// AOE: county page (reuses admin renderer but with AOE routes)
app.MapGet("/aoe/county", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();
    long countyId = 0;

    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Results.Text("No county assigned", "text/plain", statusCode: 400);

    // Fetch county core
    string countyName="", countyCode="", aoe="", deputy="", email="", phone="", office="", storage="", web="";
    await using (var cmd = new NpgsqlCommand(@"
SELECT county_name, county_code,
       COALESCE(aoe_name,''), COALESCE(deputy_name,''),
       COALESCE(email,''), COALESCE(phone,''),
       COALESCE(office_address,''), COALESCE(storage_address,''),
       COALESCE(website,'')
FROM counties WHERE id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync())
        {
            countyName = ReadTextOrFirstArray(r, 0);
            countyCode = ReadTextOrFirstArray(r, 1);
            aoe = ReadTextOrFirstArray(r, 2);
            deputy = ReadTextOrFirstArray(r, 3);
            email = ReadTextOrFirstArray(r, 4);
            phone = ReadTextOrFirstArray(r, 5);
            office = ReadTextOrFirstArray(r, 6);
            storage = ReadTextOrFirstArray(r, 7);
            web = ReadTextOrFirstArray(r, 8);
        }
    }

    var commissionerRows = await RenderCommissionersAsync(conn, countyId, adminView: false);
    var precinctRows = await RenderPrecinctsAsync(conn, countyId, adminView: false);
    var inventoryRows = await RenderInventoryAsync(conn, countyId, viewerUserId: auth.UserId, canReportIssue: true, adminView: false);

    // Machine tech list (AOE can edit tech contact info later; for now just view assignments)
    var techList = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.email, COALESCE(u.display_name,'')
FROM machine_tech_assignments a
JOIN users u ON u.id=a.tech_user_id
WHERE a.county_id=@cid AND COALESCE(a.is_active,true)=true AND COALESCE(u.is_deleted,false)=false
ORDER BY u.email ASC
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var em = ReadTextOrFirstArray(r, 0);
            var dn = ReadTextOrFirstArray(r, 1);
            techList.Append($"<li>{H(string.IsNullOrWhiteSpace(dn) ? em : dn)} ({H(em)})</li>");
        }
    }

    var body = $@"
{Topbar(ctx, "AOE Portal", false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>{H(countyName)} <span class='mv-subtle'>({H(countyCode)})</span></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>AOE County Info (editable)</div>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>

        <form method='post' action='/aoe/county/update'>
          <label>AOE name</label>
          <input name='aoe_name' value='{H(aoe)}' />

          <label>Deputy name</label>
          <input name='deputy_name' value='{H(deputy)}' />

          <div class='grid grid-2'>
            <div><label>Email</label><input name='email' value='{H(email)}' /></div>
            <div><label>Phone</label><input name='phone' value='{H(phone)}' /></div>
          </div>

          <label>Office address</label>
          <textarea name='office_address' rows='2'>{H(office)}</textarea>

          <label>Machine storage address</label>
          <textarea name='storage_address' rows='2'>{H(storage)}</textarea>

          <label>County website</label>
          <input name='website' value='{H(web)}' />

          <div style='height:12px'></div>
          <button class='btn btn-primary' type='submit'>Save</button>
        </form>
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Machine Techs (view)</div>
        <div class='mv-subtle'>Later: edit tech contact info per county.</div>
        <ul>{(techList.Length==0 ? "<li>None assigned.</li>" : techList.ToString())}</ul>
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Commissioners (editable)</div>
        {commissionerRows.Replace("/admin/counties/commissioners/save", "/aoe/commissioners/save")}
      </div>
      <div class='card'>
        <div class='h2' style='color:#111;'>Precincts (editable)</div>
        {precinctRows
            .Replace("/admin/precincts/create", "/aoe/precincts/create")
            .Replace("/admin/precincts/edit/", "/aoe/precincts/edit/")
            .Replace("/admin/precincts/delete", "/aoe/precincts/delete")}
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Inventory (editable + report issues)</div>
      {inventoryRows.Replace("/admin/inventory/create", "/aoe/inventory/create")
                   .Replace("/admin/inventory/edit/", "/aoe/inventory/edit/")
                   .Replace("/admin/inventory/delete", "/aoe/inventory/delete")
                   .Replace("return_to' value='/admin/counties/", "return_to' value='/aoe/county")}
    </div>

  </div>
")}
";
    return Html(Layout("AOE County", body));
});

app.MapPost("/aoe/county/update", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();
    long countyId = 0;

    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Results.Text("No county assigned", "text/plain", statusCode: 400);

    var form = await ctx.Request.ReadFormAsync();

    var aoe = (form["aoe_name"].ToString() ?? "").Trim();
    var deputy = (form["deputy_name"].ToString() ?? "").Trim();
    var email = (form["email"].ToString() ?? "").Trim();
    var phone = (form["phone"].ToString() ?? "").Trim();
    var office = (form["office_address"].ToString() ?? "").Trim();
    var storage = (form["storage_address"].ToString() ?? "").Trim();
    var web = (form["website"].ToString() ?? "").Trim();

    await using (var cmd = new NpgsqlCommand(@"
UPDATE counties
SET aoe_name=@aoe, deputy_name=@dep, email=@email, phone=@phone,
    office_address=@office, storage_address=@storage, website=@web,
    updated_at=NOW()
WHERE id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@aoe", aoe);
        cmd.Parameters.AddWithValue("@dep", deputy);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@phone", phone);
        cmd.Parameters.AddWithValue("@office", office);
        cmd.Parameters.AddWithValue("@storage", storage);
        cmd.Parameters.AddWithValue("@web", web);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});

// AOE commissioners save route (same logic as admin)
app.MapPost("/aoe/commissioners/save", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();
    long countyId = 0;

    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Results.Text("No county assigned", "text/plain", statusCode: 400);

    var form = await ctx.Request.ReadFormAsync();
    var chair = (form["chair_name"].ToString() ?? "").Trim();
    var sec = (form["secretary_name"].ToString() ?? "").Trim();
    var m1 = (form["member1_name"].ToString() ?? "").Trim();
    var m2 = (form["member2_name"].ToString() ?? "").Trim();
    var m3 = (form["member3_name"].ToString() ?? "").Trim();

    await using (var cmd = new NpgsqlCommand(@"
UPDATE county_commissioners
SET chair_name=@c, secretary_name=@s, member1_name=@m1, member2_name=@m2, member3_name=@m3, updated_at=NOW()
WHERE county_id=@cid
", conn))
    {
        cmd.Parameters.AddWithValue("@c", chair);
        cmd.Parameters.AddWithValue("@s", sec);
        cmd.Parameters.AddWithValue("@m1", m1);
        cmd.Parameters.AddWithValue("@m2", m2);
        cmd.Parameters.AddWithValue("@m3", m3);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});

// AOE precinct routes (reuse admin logic with countyId fixed)
app.MapPost("/aoe/precincts/create", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();
    long countyId = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Results.Text("No county assigned", "text/plain", statusCode: 400);

    var form = await ctx.Request.ReadFormAsync();
    var name = (form["precinct_name"].ToString() ?? "").Trim();
    var addr = (form["precinct_address"].ToString() ?? "").Trim();
    var votersStr = (form["registered_voters"].ToString() ?? "0").Trim();
    if (!int.TryParse(votersStr, out var voters)) voters = 0;
    voters = Math.Max(0, voters);

    if (string.IsNullOrWhiteSpace(name)) return Results.Redirect("/aoe/county");

    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO precincts(county_id, precinct_name, precinct_address, registered_voters, is_deleted)
VALUES (@cid, @n, @a, @v, FALSE)
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@a", addr);
        cmd.Parameters.AddWithValue("@v", voters);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});

// AOE inventory create/edit/delete (reuse admin logic with countyId fixed)
app.MapPost("/aoe/inventory/create", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "aoe") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();
    long countyId = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", auth.UserId);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
    if (countyId <= 0) return Results.Text("No county assigned", "text/plain", statusCode: 400);

    var form = await ctx.Request.ReadFormAsync();
    var type = (form["item_type"].ToString() ?? "").Trim();
    var sn = (form["serial_number"].ToString() ?? "").Trim();
    if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(sn)) return Results.Redirect("/aoe/county");

    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO inventory(county_id, item_type, serial_number, is_deleted, created_at)
VALUES (@cid, @t, @sn, false, NOW())
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        cmd.Parameters.AddWithValue("@t", type);
        cmd.Parameters.AddWithValue("@sn", sn);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});

// =========================
// Contractor Portal (dashboard + election view) - read county + add/report inventory
// =========================
app.MapGet("/contractor", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "contractor") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();

    // Elections assigned to contractor via contractor_assignments and elections' county
    var rows = new StringBuilder();
    long count = 0;

    await using (var cmd = new NpgsqlCommand(@"
SELECT e.id, e.election_name, e.election_date,
       c.county_name, c.county_code
FROM contractor_assignments a
JOIN elections e ON e.county_id=a.county_id
JOIN counties c ON c.id=e.county_id
WHERE a.contractor_user_id=@uid
  AND COALESCE(a.is_active,true)=true
  AND COALESCE(e.is_deleted,false)=false
  AND COALESCE(e.is_archived,false)=false
ORDER BY e.election_date ASC
LIMIT 100
", conn))
    {
        cmd.Parameters.AddWithValue("@uid", auth.UserId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            count++;
            var eid = r.GetInt64(0);
            var en = ReadTextOrFirstArray(r, 1);
            var ed = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
            var cn = ReadTextOrFirstArray(r, 3);
            var cc = ReadTextOrFirstArray(r, 4);

            rows.Append($@"<tr><td><a href='/contractor/elections/{eid}'>{H(en)}</a></td><td>{H(ed)}</td><td>{H(cn)} ({H(cc)})</td></tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "Contractor Portal", false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Contractor Dashboard</div>
    <div class='mv-subtle'>Shows elections you are assigned to.</div>

    <div style='height:14px'></div>

    <div class='grid grid-3'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Upcoming elections assigned</div>
        <div style='font-size:28px; font-weight:900;'>{count}</div>
      </div>
      <div class='card'>
        <div class='h2' style='color:#111;'>Profile</div>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>
        <div class='mv-subtle'>Self-edit profile coming next.</div>
      </div>
      <div class='card'>
        <div class='h2' style='color:#111;'>Quick Links</div>
        <div class='btn-row'>
          <a class='btn btn-secondary' href='https://microvote.com' target='_blank'>MicroVote</a>
          <a class='btn btn-secondary' href='/logout'>Logout</a>
        </div>
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Assigned Elections</div>
      <table class='table'>
        <thead><tr><th>Election</th><th>Date</th><th>County</th></tr></thead>
        <tbody>{(rows.Length==0 ? "<tr><td colspan='3'>None assigned.</td></tr>" : rows.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("Contractor", body));
});

app.MapGet("/contractor/elections/{id:long}", async (HttpContext ctx, long id) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "contractor") return Results.Redirect("/app");

    await using var conn = await OpenConnAsync();

    // Find election + county
    long countyId;
    string electionName="", electionDate="";
    string countyName="", countyCode="", officeAddr="", storageAddr="";

    await using (var cmd = new NpgsqlCommand(@"
SELECT e.county_id, e.election_name, e.election_date,
       c.county_name, c.county_code,
       COALESCE(c.office_address,''), COALESCE(c.storage_address,'')
FROM elections e
JOIN counties c ON c.id=e.county_id
WHERE e.id=@id AND COALESCE(e.is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);

        countyId = r.GetInt64(0);
        electionName = ReadTextOrFirstArray(r, 1);
        electionDate = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
        countyName = ReadTextOrFirstArray(r, 3);
        countyCode = ReadTextOrFirstArray(r, 4);
        officeAddr = ReadTextOrFirstArray(r, 5);
        storageAddr = ReadTextOrFirstArray(r, 6);
    }

    // Verify contractor assignment
    await using (var cmd = new NpgsqlCommand(@"
SELECT COUNT(*) FROM contractor_assignments
WHERE contractor_user_id=@uid AND county_id=@cid AND COALESCE(is_active,true)=true
", conn))
    {
        cmd.Parameters.AddWithValue("@uid", auth.UserId);
        cmd.Parameters.AddWithValue("@cid", countyId);
        var ok = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        if (ok == 0) return Results.Text("Not assigned.", "text/plain", statusCode: 403);
    }

    var precincts = await RenderPrecinctsAsync(conn, countyId, adminView: false);
    var inventory = await RenderInventoryAsync(conn, countyId, viewerUserId: auth.UserId, canReportIssue: true, adminView: false);

    // Replace admin routes with contractor routes for add/edit/delete later (for now, only allow add)
    precincts = precincts.Replace("action='/admin/precincts/create'", "action='/contractor/precincts/create'")
                         .Replace("/admin/precincts/edit/", "/contractor/precincts/edit/")
                         .Replace("/admin/precincts/delete", "/contractor/precincts/delete");

    inventory = inventory.Replace("action='/admin/inventory/create'", "action='/contractor/inventory/create'")
                         .Replace("/admin/inventory/edit/", "/contractor/inventory/edit/")
                         .Replace("/admin/inventory/delete", "/contractor/inventory/delete")
                         .Replace("return_to' value='/admin/counties/", "return_to' value='/contractor/elections/");

    var body = $@"
{Topbar(ctx, "Contractor Portal", false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>{H(electionName)} <span class='mv-subtle'>({H(electionDate)})</span></div>
    <div class='mv-subtle'>{H(countyName)} ({H(countyCode)})</div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Office Location</div>
        <div style='white-space:pre-wrap'>{H(officeAddr)}</div>
      </div>
      <div class='card'>
        <div class='h2' style='color:#111;'>Machine Storage</div>
        <div style='white-space:pre-wrap'>{H(storageAddr)}</div>
      </div>
    </div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>Precincts</div>
        {precincts.Replace("action='/admin/precincts/create'", "action='/contractor/precincts/create'")}
      </div>
      <div class='card'>
        <div class='h2' style='color:#111;'>Equipment / Inventory</div>
        {inventory.Replace("action='/admin/inventory/create'", "action='/contractor/inventory/create'")}
      </div>
    </div>
  </div>
")}
";
    return Html(Layout("Contractor Election", body));
});

// Contractor can add inventory/precincts (same as AOE, county derived from election in future; for now restrict by county assignment)
app.MapPost("/contractor/inventory/create", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "contractor") return Results.Redirect("/app");

    var form = await ctx.Request.ReadFormAsync();
    // contractor form has county_id hidden from renderer in this section (not set) -> so we keep simple:
    // We require a 'return_to' link? Not present. For now just send them back.
    // Final polish will improve this flow.
    return Results.Redirect("/contractor");
});

// MachineTech mirrors Contractor for now
app.MapGet("/machinetech", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");
    if (auth.Role != "machinetech") return Results.Redirect("/app");

    // Mirror contractor dashboard for now
    var body = $@"
{Topbar(ctx, "Machine Tech Portal", false)}
{Nav(ctx, "dashboard")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Machine Tech Dashboard</div>
    <div class='mv-subtle'>This mirrors contractor for now. Machine Tech instructions come later.</div>

    <div style='height:14px'></div>
    <div class='card'>
      <div class='profile-box'>Profile Picture<br/>Coming soon</div>
      <div style='height:10px'></div>
      <div class='btn-row'>
        <a class='btn btn-secondary' href='https://microvote.com' target='_blank'>MicroVote</a>
        <a class='btn btn-secondary' href='/logout'>Logout</a>
      </div>
    </div>
  </div>
")}
";
    return Html(Layout("Machine Tech", body));
});
// =========================
// Admin Elections (create/list/archived/delete) + Election Detail + Ballot Editor
// =========================
app.MapGet("/admin/elections", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var show = (ctx.Request.Query["show"].ToString() ?? "active").Trim().ToLowerInvariant(); // active|archived

    await using var conn = await OpenConnAsync();

    // County dropdown (only added counties)
    var countyOptions = new StringBuilder();
    await using (var cmd = new NpgsqlCommand(@"
SELECT id, county_name, county_code
FROM counties
WHERE COALESCE(is_deleted,false)=false
ORDER BY county_name ASC
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var code = ReadTextOrFirstArray(r, 2);
            countyOptions.Append($@"<option value='{id}'>{H(name)} ({H(code)})</option>");
        }
    }

    // Contractors dropdown
    var contractorOptions = new StringBuilder();
    contractorOptions.Append("<option value=''>-- Unassigned --</option>");
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.id, COALESCE(p.full_name,''), u.email
FROM users u
LEFT JOIN contractor_profiles p ON p.user_id=u.id
WHERE u.role='contractor' AND COALESCE(u.is_deleted,false)=false
ORDER BY COALESCE(p.full_name,''), u.email
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var email = ReadTextOrFirstArray(r, 2);
            contractorOptions.Append($@"<option value='{id}'>{H(string.IsNullOrWhiteSpace(name) ? email : name)} ({H(email)})</option>");
        }
    }

    // List elections
    var rows = new StringBuilder();
    var archivedFilter = show == "archived";

    await using (var cmd = new NpgsqlCommand(@"
SELECT e.id, e.election_name, e.election_date, COALESCE(e.progress_status,''),
       c.county_name, c.county_code,
       e.support_requested, COALESCE(e.contractor_user_id,0),
       COALESCE(p.full_name,''), COALESCE(p.phone,'')
FROM elections e
JOIN counties c ON c.id=e.county_id
LEFT JOIN contractor_profiles p ON p.user_id=e.contractor_user_id
WHERE COALESCE(e.is_deleted,false)=false
  AND COALESCE(c.is_deleted,false)=false
  AND COALESCE(e.is_archived,false)=@arch
ORDER BY e.election_date ASC, e.id DESC
", conn))
    {
        cmd.Parameters.AddWithValue("@arch", archivedFilter);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var en = ReadTextOrFirstArray(r, 1);
            var ed = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
            var st = ReadTextOrFirstArray(r, 3);
            var cn = ReadTextOrFirstArray(r, 4);
            var cc = ReadTextOrFirstArray(r, 5);
            var support = r.GetBoolean(6);
            var contractorId = r.IsDBNull(7) ? 0 : r.GetInt64(7);
            var contractorName = ReadTextOrFirstArray(r, 8);
            var contractorPhone = ReadTextOrFirstArray(r, 9);

            var supportBadge = support ? "<span class='badge badge-ok'>Support</span>" : "<span class='badge'>No support</span>";
            var contractor = contractorId == 0 ? "<span class='badge badge-danger'>Unassigned</span>" : $"<span class='badge badge-ok'>{H(string.IsNullOrWhiteSpace(contractorName)? "Assigned" : contractorName)}</span>";
            var phone = contractorId == 0 ? "" : H(contractorPhone);

            rows.Append($@"
<tr>
  <td><a href='/admin/elections/{id}'><strong>{H(en)}</strong></a><div class='mv-subtle'>{H(cn)} ({H(cc)})</div></td>
  <td>{H(ed)}</td>
  <td>{H(ProgressLabel(st))}</td>
  <td>{supportBadge}</td>
  <td>{contractor} <span class='mv-subtle'>{phone}</span></td>
  <td class='right'>
    <form method='post' action='/admin/elections/delete' style='display:inline' onsubmit=""{ConfirmJs("Remove this election? (Soft delete)").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}'/>
      <button class='btn btn-danger' type='submit'>Remove</button>
    </form>
  </td>
</tr>");
        }
    }

    var tabs = $@"
<div class='btn-row'>
  <a class='btn {(show=="active" ? "btn-primary":"btn-secondary")}' href='/admin/elections?show=active'>Active</a>
  <a class='btn {(show=="archived" ? "btn-primary":"btn-secondary")}' href='/admin/elections?show=archived'>Archived</a>
</div>";

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "elections")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Elections</div>
    <div class='mv-subtle'>County is selected from Counties list. County code auto-fills. Finishing prompts to archive.</div>

    <div style='height:10px'></div>
    {tabs}

    <div style='height:14px'></div>

    {(show=="active" ? $@"
    <div class='card'>
      <div class='h2' style='color:#111;'>Create Election</div>
      <form method='post' action='/admin/elections/create'>
        <div class='grid grid-2'>
          <div>
            <label>County</label>
            <select name='county_id' required>
              <option value=''>-- Select --</option>
              {countyOptions}
            </select>
          </div>
          <div>
            <label>Election name</label>
            <input name='election_name' required />
          </div>
        </div>

        <div class='grid grid-3'>
          <div>
            <label>Election date</label>
            <input type='date' name='election_date' required />
          </div>
          <div>
            <label>Status</label>
            <select name='progress_status'>
              <option value='started'>Started</option>
              <option value='sent_for_approval'>Sent for approval</option>
              <option value='revision'>Revision</option>
              <option value='approved_awaiting_programming'>Approved awaiting programming</option>
              <option value='finished'>Finished</option>
            </select>
          </div>
          <div>
            <label>Election Day Support?</label>
            <div style='display:flex; gap:10px; align-items:center; margin-top:6px;'>
              <input type='checkbox' name='support_requested' value='1' />
              <span class='mv-subtle'>If checked, you can assign a contractor now or later.</span>
            </div>
          </div>
        </div>

        <div class='grid grid-2'>
          <div>
            <label>Contractor (optional)</label>
            <select name='contractor_user_id'>
              {contractorOptions}
            </select>
          </div>
          <div>
            <label>Notes</label>
            <input name='notes' placeholder='(optional)' />
          </div>
        </div>

        <div style='height:12px'></div>
        <button class='btn btn-primary' type='submit'>Create election</button>
      </form>
    </div>
    <div style='height:14px'></div>
    " : "")}

    <div class='card'>
      <div class='h2' style='color:#111;'>{(show=="archived" ? "Archived elections" : "Active elections")}</div>
      <table class='table'>
        <thead><tr><th>Election</th><th>Date</th><th>Status</th><th>Support</th><th>Contractor</th><th class='right'>Actions</th></tr></thead>
        <tbody>{(rows.Length==0 ? "<tr><td colspan='6'>None found.</td></tr>" : rows.ToString())}</tbody>
      </table>
    </div>
  </div>
")}
";
    return Html(Layout("Elections", body));
});

app.MapPost("/admin/elections/create", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();

    if (!long.TryParse(form["county_id"].ToString(), out var countyId) || countyId <= 0)
        return Results.Redirect("/admin/elections");

    var electionName = (form["election_name"].ToString() ?? "").Trim();
    var dateStr = (form["election_date"].ToString() ?? "").Trim();
    var status = (form["progress_status"].ToString() ?? "started").Trim();
    var support = form["support_requested"].ToString() == "1";
    var contractorStr = (form["contractor_user_id"].ToString() ?? "").Trim();
    long? contractorId = null;
    if (long.TryParse(contractorStr, out var cid) && cid > 0) contractorId = cid;

    if (string.IsNullOrWhiteSpace(electionName)) return Results.Redirect("/admin/elections");
    if (!DateOnly.TryParse(dateStr, out var electionDate)) return Results.Redirect("/admin/elections");

    await using var conn = await OpenConnAsync();

    // Pull county code/name from counties and store snapshot on election as well
    string countyName = "", countyCode = "";
    await using (var cmd = new NpgsqlCommand(@"SELECT county_name, county_code FROM counties WHERE id=@id AND COALESCE(is_deleted,false)=false", conn))
    {
        cmd.Parameters.AddWithValue("@id", countyId);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Redirect("/admin/elections");
        countyName = ReadTextOrFirstArray(r, 0);
        countyCode = ReadTextOrFirstArray(r, 1);
    }

    long newId;
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO elections(county_id, county_code, county_name, election_name, election_date, progress_status,
                     support_requested, contractor_user_id, is_archived, is_deleted, created_at)
VALUES (@cid, @cc, @cn, @en, @ed, @st, @sup, @con, false, false, NOW())
RETURNING id
", conn))
    {
        cmd.Parameters.AddWithValue("@cid", countyId);
        cmd.Parameters.AddWithValue("@cc", countyCode);
        cmd.Parameters.AddWithValue("@cn", countyName);
        cmd.Parameters.AddWithValue("@en", electionName);
        cmd.Parameters.AddWithValue("@ed", electionDate);
        cmd.Parameters.AddWithValue("@st", status);
        cmd.Parameters.AddWithValue("@sup", support);
        cmd.Parameters.AddWithValue("@con", (object?)contractorId ?? DBNull.Value);
        newId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    // If support requested and contractor assigned, mirror to contractor_assignments so contractor dashboard works
    if (support && contractorId.HasValue)
    {
        await using var cmd = new NpgsqlCommand(@"
INSERT INTO contractor_assignments(contractor_user_id, county_id, is_active)
VALUES (@uid, @cid, true)
ON CONFLICT (contractor_user_id, county_id) DO UPDATE SET is_active=true
", conn);
        cmd.Parameters.AddWithValue("@uid", contractorId.Value);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/elections/{newId}");
});

app.MapPost("/admin/elections/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/elections");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"UPDATE elections SET is_deleted=true WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }
    return Results.Redirect("/admin/elections");
});

//==================================================test move====================================================
app.MapPost("/admin/elections/update", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/elections");

    var st = (form["progress_status"].ToString() ?? "started").Trim();
    var support = form["support_requested"].ToString() == "1";
    var contractorStr = (form["contractor_user_id"].ToString() ?? "").Trim();
    long? contractorId = null;
    if (long.TryParse(contractorStr, out var cid) && cid > 0) contractorId = cid;

    var archiveNow = form["archive_now"].ToString() == "1";

    await using var conn = await OpenConnAsync();

    // Load county_id to mirror contractor assignment if needed
    long countyId;
    await using (var cmd = new NpgsqlCommand(@"SELECT county_id FROM elections WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        countyId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    await using (var cmd = new NpgsqlCommand(@"
UPDATE elections
SET progress_status=@st,
    support_requested=@sup,
    contractor_user_id=@con,
    is_archived=CASE WHEN @arch THEN true ELSE is_archived END,
    updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@st", st);
        cmd.Parameters.AddWithValue("@sup", support);
        cmd.Parameters.AddWithValue("@con", (object?)contractorId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@arch", archiveNow);
        await cmd.ExecuteNonQueryAsync();
    }

    // Mirror assignment if contractor present
    if (support && contractorId.HasValue)
    {
        await using var cmd = new NpgsqlCommand(@"
INSERT INTO contractor_assignments(contractor_user_id, county_id, is_active)
VALUES (@uid, @cid, true)
ON CONFLICT (contractor_user_id, county_id) DO UPDATE SET is_active=true
", conn);
        cmd.Parameters.AddWithValue("@uid", contractorId.Value);
        cmd.Parameters.AddWithValue("@cid", countyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/elections/{id}");
});

//============================================new code start==============================

app.MapGet("/aoe/elections/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;

    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/login?role=aoe");

    await using var conn = await OpenConnAsync();

    // AOE user's county
    long userCountyId = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@uid", conn))
    {
        cmd.Parameters.AddWithValue("@uid", auth.UserId);
        var obj = await cmd.ExecuteScalarAsync();
        userCountyId = obj == null ? 0 : Convert.ToInt64(obj);
    }
    if (userCountyId <= 0)
        return Results.Text("AOE is not assigned to a county.", "text/plain", statusCode: 403);

    // Load election and enforce it belongs to this AOE
    long electionCountyId = 0;
    string electionName = "";
    string status = "";
    DateTime? electionDate = null;

    await using (var cmd = new NpgsqlCommand(@"
SELECT COALESCE(county_id,0), COALESCE(election_name,''), election_date, COALESCE(status,'')
FROM elections
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Redirect("/aoe/dashboard");

        electionCountyId = r.GetInt64(0);
        electionName = r.GetString(1);
        electionDate = r.IsDBNull(2) ? (DateTime?)null : r.GetDateTime(2);
        status = r.GetString(3);
    }

    if (electionCountyId != userCountyId)
        return Results.Text("Not allowed.", "text/plain", statusCode: 403);

    // Simple read-only view for now (no edit actions)
    var dateText = electionDate.HasValue ? electionDate.Value.ToString("yyyy-MM-dd") : "";

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "elections")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Election</div>
    <div class='mv-subtle'>Read-only election details.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <div><strong>Name:</strong> {H(electionName)}</div>
      <div><strong>Date:</strong> {H(dateText)}</div>
      <div><strong>Status:</strong> {H(status)}</div>

      <div style='height:14px'></div>
      <a class='btn btn-secondary' href='/aoe/dashboard'>Back</a>
    </div>
  </div>
")}
";
    return Html(Layout("Election", body));
});
//===============================================end================================================================================


// =========================
// Election detail (Admin) with county header + contractor assignment + ballot editor
// =========================

app.MapGet("/admin/elections/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    // Election + county
    long countyId;
    string en="", ed="", st="";
    bool support;
    long contractorId = 0;
    string countyName="", countyCode="", officeAddr="", storageAddr="", website="";

    await using (var cmd = new NpgsqlCommand(@"
SELECT e.county_id, e.election_name, e.election_date, COALESCE(e.progress_status,''),
       e.support_requested, COALESCE(e.contractor_user_id,0),
       c.county_name, c.county_code,
       COALESCE(c.office_address,''), COALESCE(c.storage_address,''), COALESCE(c.website,'')
FROM elections e
JOIN counties c ON c.id=e.county_id
WHERE e.id=@id AND COALESCE(e.is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);

        countyId = r.GetInt64(0);
        en = ReadTextOrFirstArray(r, 1);
        ed = r.GetFieldValue<DateOnly>(2).ToString("yyyy-MM-dd");
        st = ReadTextOrFirstArray(r, 3);
        support = r.GetBoolean(4);
        contractorId = r.IsDBNull(5) ? 0 : r.GetInt64(5);
        countyName = ReadTextOrFirstArray(r, 6);
        countyCode = ReadTextOrFirstArray(r, 7);
        officeAddr = ReadTextOrFirstArray(r, 8);
        storageAddr = ReadTextOrFirstArray(r, 9);
        website = ReadTextOrFirstArray(r, 10);
    }

    // Contractors dropdown
    var contractorOptions = new StringBuilder();
    contractorOptions.Append("<option value=''>-- Unassigned --</option>");
    await using (var cmd = new NpgsqlCommand(@"
SELECT u.id, COALESCE(p.full_name,''), u.email
FROM users u
LEFT JOIN contractor_profiles p ON p.user_id=u.id
WHERE u.role='contractor' AND COALESCE(u.is_deleted,false)=false
ORDER BY COALESCE(p.full_name,''), u.email
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var uid = r.GetInt64(0);
            var name = ReadTextOrFirstArray(r, 1);
            var email = ReadTextOrFirstArray(r, 2);
            var sel = (uid == contractorId) ? "selected" : "";
            contractorOptions.Append($@"<option value='{uid}' {sel}>{H(string.IsNullOrWhiteSpace(name) ? email : name)} ({H(email)})</option>");
        }
    }

    // County header info
    var commissioners = await RenderCommissionersReadOnlyAsync(conn, countyId);
    var techs = await RenderMachineTechsReadOnlyAsync(conn, countyId);
    var precincts = await RenderPrecinctsListOnlyAsync(conn, countyId);
    var inventory = await RenderInventoryAsync(conn, countyId, viewerUserId: 0, canReportIssue: false, adminView: true);

    // Ballot items list
    var ballot = await RenderBallotItemsAsync(conn, id);

    // Archive prompt JS when setting to finished
    var archiveJs = @"
function maybeArchive(sel){
  try{
    if(!sel) return;
    if(sel.value==='finished'){
      if(confirm('Set to Finished. Archive this election now?')){
        document.getElementById('archive_now').value='1';
      }
    }else{
      document.getElementById('archive_now').value='0';
    }
  }catch(e){}
}";


    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "elections")}
<script>{archiveJs}</script>
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>{H(en)}</div>
    <div class='mv-subtle'>{H(countyName)} ({H(countyCode)}) • {H(ed)}</div>

    <div style='height:14px'></div>

    <div class='grid grid-2'>
      <div class='card'>
        <div class='h2' style='color:#111;'>County Overview</div>
        <div class='profile-box'>Profile Picture<br/>Coming soon</div>
        <div style='height:10px'></div>

        <div><strong>Office:</strong><div style='white-space:pre-wrap'>{H(officeAddr)}</div></div>
        <div style='height:8px'></div>
        <div><strong>Storage:</strong><div style='white-space:pre-wrap'>{H(storageAddr)}</div></div>
        <div style='height:8px'></div>
        <div><strong>Website:</strong> {(string.IsNullOrWhiteSpace(website) ? "<span class='mv-subtle'>(none)</span>" : $"<a href='{H(website)}' target='_blank'>{H(website)}</a>")}</div>

        <div style='height:10px'></div>
        <div class='h2' style='color:#111;'>Commissioners</div>
        {commissioners}

        <div style='height:10px'></div>
        <div class='h2' style='color:#111;'>Machine Techs</div>
        {techs}
      </div>

      <div class='card'>
        <div class='h2' style='color:#111;'>Election Controls</div>

        <form method='post' action='/admin/elections/update'>
          <input type='hidden' name='id' value='{id}'/>
          <input type='hidden' id='archive_now' name='archive_now' value='0'/>

          <div class='grid grid-2'>
            <div>
              <label>Status</label>
              <select name='progress_status' onchange='maybeArchive(this)'>
                {string.Join("", ProgressChoices.Select(x => $"<option value='{x}' {(x==st?"selected":"")}>{H(ProgressLabel(x))}</option>"))}
              </select>
            </div>
            <div>
              <label>Election Day Support?</label>
              <div style='display:flex; gap:10px; align-items:center; margin-top:6px;'>
                <input type='checkbox' name='support_requested' value='1' {(support ? "checked" : "")}/>
                <span class='mv-subtle'>Support can be requested before assignment.</span>
              </div>
            </div>
          </div>

          <label>Contractor (optional)</label>
          <select name='contractor_user_id'>
            {contractorOptions}
          </select>

          <div style='height:12px'></div>
          <div class='btn-row'>
            <button class='btn btn-primary' type='submit'>Save</button>
            <a class='btn btn-secondary' href='/admin/elections'>Back</a>
          </div>
        </form>

        <div style='height:14px'></div>

        <div class='h2' style='color:#111;'>Precincts</div>
        {precincts}

        <div style='height:14px'></div>

        <div class='h2' style='color:#111;'>Inventory</div>
        {inventory}

      </div>
    </div>

    <div style='height:14px'></div>

    <div class='card'>
      <div class='h2' style='color:#111;'>Ballot Builder</div>
      <div class='mv-subtle'>Add Offices or Referendums. Use Edit to remove items/candidates.</div>
      <div style='height:10px'></div>

      <div class='btn-row'>
        <a class='btn btn-primary' href='/admin/elections/{id}/ballot/add?kind=office'>Add Office</a>
        <a class='btn btn-primary' href='/admin/elections/{id}/ballot/add?kind=referendum'>Add Referendum</a>
      </div>

      <div style='height:10px'></div>
      {ballot}
    </div>

  </div>
")}
";
    return Html(Layout("Election", body));
});


//================================new code end=======================================================================================


// =========================
// Ballot add/edit/remove + ordering
// =========================

static async Task<string> RenderBallotItemsAsync(NpgsqlConnection conn, long electionId)
{
    var sb = new StringBuilder();
    await using var cmd = new NpgsqlCommand(@"
SELECT id, kind, sort_order, title, subtitle, vote_for, question_text
FROM ballot_items
WHERE election_id=@eid AND COALESCE(is_deleted,false)=false
ORDER BY sort_order ASC, id ASC
", conn);
    cmd.Parameters.AddWithValue("@eid", electionId);

    await using var r = await cmd.ExecuteReaderAsync();
    var items = new List<(long id,string kind,int order,string title,string subtitle,int voteFor,string q)>();
    while (await r.ReadAsync())
    {
        items.Add((
            r.GetInt64(0),
            ReadTextOrFirstArray(r, 1),
            r.GetInt32(2),
            ReadTextOrFirstArray(r, 3),
            ReadTextOrFirstArray(r, 4),
            r.IsDBNull(5) ? 1 : r.GetInt32(5),
            ReadTextOrFirstArray(r, 6)
        ));
    }

    if (items.Count == 0)
        return "<div class='mv-subtle'>No ballot items yet.</div>";

    foreach (var it in items)
    {
        // candidates for office
        var candHtml = "";
        if (it.kind == "office")
        {
            var cands = new StringBuilder();
            await using var cmd2 = new NpgsqlCommand(@"
SELECT id, sort_order, last_name, first_name
FROM ballot_candidates
WHERE ballot_item_id=@bid AND COALESCE(is_deleted,false)=false
ORDER BY sort_order ASC, id ASC
", conn);
            cmd2.Parameters.AddWithValue("@bid", it.id);
            await using var rr = await cmd2.ExecuteReaderAsync();
            while (await rr.ReadAsync())
            {
                var ln = ReadTextOrFirstArray(rr, 2);
                var fn = ReadTextOrFirstArray(rr, 3);
                cands.Append($"<li>{H(ln)}, {H(fn)}</li>");
            }
            candHtml = cands.Length == 0 ? "<div class='mv-subtle'>(no candidates)</div>" : $"<ul>{cands}</ul>";
        }

        var details = it.kind == "referendum"
            ? $"<div class='mv-subtle'><strong>Question:</strong> {H(it.q.Length>180 ? it.q[..180] + "…" : it.q)}</div>"
            : $"<div class='mv-subtle'><strong>Vote for:</strong> {it.voteFor}</div>";

        sb.Append($@"
<div class='card' style='margin-top:10px;'>
  <div style='display:flex; justify-content:space-between; gap:12px; align-items:flex-start;'>
    <div>
      <div class='h2' style='color:#111;'>{H(it.title)} <span class='mv-subtle'>({H(it.kind)})</span></div>
      {(string.IsNullOrWhiteSpace(it.subtitle) ? "" : $"<div class='mv-subtle'>{H(it.subtitle)}</div>")}
      {details}
      {(it.kind=="office" ? $"<div style='height:8px'></div><div><strong>Candidates</strong></div>{candHtml}" : "")}
    </div>
    <div class='btn-row'>
      <form method='post' action='/admin/ballot/move' style='display:inline'>
        <input type='hidden' name='election_id' value='{electionId}'/>
        <input type='hidden' name='id' value='{it.id}'/>
        <input type='hidden' name='dir' value='up'/>
        <button class='btn btn-secondary' type='submit'>↑</button>
      </form>
      <form method='post' action='/admin/ballot/move' style='display:inline'>
        <input type='hidden' name='election_id' value='{electionId}'/>
        <input type='hidden' name='id' value='{it.id}'/>
        <input type='hidden' name='dir' value='down'/>
        <button class='btn btn-secondary' type='submit'>↓</button>
      </form>
      <a class='btn btn-secondary' href='/admin/ballot/edit/{it.id}'>Edit</a>
      <form method='post' action='/admin/ballot/delete' style='display:inline' onsubmit=""{ConfirmJs("Remove this ballot item?").Replace("\"","&quot;")}"">
        <input type='hidden' name='election_id' value='{electionId}'/>
        <input type='hidden' name='id' value='{it.id}'/>
        <button class='btn btn-danger' type='submit'>Remove</button>
      </form>
    </div>
  </div>
</div>
");
    }

    return sb.ToString();
}

app.MapGet("/admin/elections/{electionId:long}/ballot/add", async (HttpContext ctx, long electionId) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var kind = (ctx.Request.Query["kind"].ToString() ?? "office").Trim().ToLowerInvariant();
    if (kind != "office" && kind != "referendum") kind = "office";

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "elections")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Add {(kind=="office" ? "Office" : "Referendum")}</div>
    <div class='card'>
      <form method='post' action='/admin/elections/{electionId}/ballot/add'>
        <input type='hidden' name='kind' value='{H(kind)}' />

        <label>Title</label>
        <input name='title' required />

        <label>Subtitle (optional)</label>
        <input name='subtitle' />

        {(kind=="office" ? @"
          <label>Vote for #</label>
          <input name='vote_for' type='number' min='1' value='1' />
          <div style='height:10px'></div>
          <div class='h2' style='color:#111;'>Candidates</div>
          <div class='mv-subtle'>Enter candidates as Last, First. Add more after saving by editing.</div>
          <div class='grid grid-2'>
            <div><label>Candidate 1 last</label><input name='c1_last'/></div>
            <div><label>Candidate 1 first</label><input name='c1_first'/></div>
            <div><label>Candidate 2 last</label><input name='c2_last'/></div>
            <div><label>Candidate 2 first</label><input name='c2_first'/></div>
            <div><label>Candidate 3 last</label><input name='c3_last'/></div>
            <div><label>Candidate 3 first</label><input name='c3_first'/></div>
          </div>
        " : @"
          <label>Full question text</label>
          <textarea name='question_text' rows='6' required></textarea>
        ")}

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Add</button>
          <a class='btn btn-secondary' href='/admin/elections/{electionId}'>Cancel</a>
        </div>
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Add ballot item", body));
});

app.MapPost("/admin/elections/{electionId:long}/ballot/add", async (HttpContext ctx, long electionId) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    var kind = (form["kind"].ToString() ?? "office").Trim().ToLowerInvariant();
    if (kind != "office" && kind != "referendum") kind = "office";

    var title = (form["title"].ToString() ?? "").Trim();
    var subtitle = (form["subtitle"].ToString() ?? "").Trim();
    var voteFor = 1;
    if (int.TryParse((form["vote_for"].ToString() ?? "1").Trim(), out var vf)) voteFor = Math.Max(1, vf);
    var q = (form["question_text"].ToString() ?? "").Trim();

    if (string.IsNullOrWhiteSpace(title)) return Results.Redirect($"/admin/elections/{electionId}");

    await using var conn = await OpenConnAsync();

    int nextOrder = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(MAX(sort_order),0)+1 FROM ballot_items WHERE election_id=@eid AND COALESCE(is_deleted,false)=false", conn))
    {
        cmd.Parameters.AddWithValue("@eid", electionId);
        nextOrder = Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    long ballotId;
    await using (var cmd = new NpgsqlCommand(@"
INSERT INTO ballot_items(election_id, kind, sort_order, title, subtitle, vote_for, question_text, is_deleted, created_at)
VALUES (@eid, @k, @so, @t, @st, @vf, @q, false, NOW())
RETURNING id
", conn))
    {
        cmd.Parameters.AddWithValue("@eid", electionId);
        cmd.Parameters.AddWithValue("@k", kind);
        cmd.Parameters.AddWithValue("@so", nextOrder);
        cmd.Parameters.AddWithValue("@t", title);
        cmd.Parameters.AddWithValue("@st", subtitle);
        cmd.Parameters.AddWithValue("@vf", voteFor);
        cmd.Parameters.AddWithValue("@q", q);
        ballotId = Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    if (kind == "office")
    {
        var candidates = new List<(string ln,string fn)>
        {
            ((form["c1_last"].ToString()??"").Trim(), (form["c1_first"].ToString()??"").Trim()),
            ((form["c2_last"].ToString()??"").Trim(), (form["c2_first"].ToString()??"").Trim()),
            ((form["c3_last"].ToString()??"").Trim(), (form["c3_first"].ToString()??"").Trim()),
        }.Where(x => !string.IsNullOrWhiteSpace(x.ln) || !string.IsNullOrWhiteSpace(x.fn))
         .Select(x => (x.ln, x.fn))
         .ToList();

        var order = 0;
        foreach (var c in candidates)
        {
            await using var cmd = new NpgsqlCommand(@"
INSERT INTO ballot_candidates(ballot_item_id, sort_order, last_name, first_name, is_deleted, created_at)
VALUES (@bid, @so, @ln, @fn, false, NOW())
", conn);
            cmd.Parameters.AddWithValue("@bid", ballotId);
            cmd.Parameters.AddWithValue("@so", order++);
            cmd.Parameters.AddWithValue("@ln", c.ln);
            cmd.Parameters.AddWithValue("@fn", c.fn);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    return Results.Redirect($"/admin/elections/{electionId}");
});

app.MapPost("/admin/ballot/move", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["election_id"].ToString(), out var electionId)) return Results.Redirect("/admin/elections");
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect($"/admin/elections/{electionId}");
    var dir = (form["dir"].ToString() ?? "").Trim();

    await using var conn = await OpenConnAsync();
    // Swap sort_order with neighbor
    int curOrder;
    await using (var cmd = new NpgsqlCommand(@"SELECT sort_order FROM ballot_items WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        curOrder = Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    long neighborId = 0;
    int neighborOrder = curOrder;

    if (dir == "up")
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT id, sort_order FROM ballot_items
WHERE election_id=@eid AND COALESCE(is_deleted,false)=false AND sort_order < @o
ORDER BY sort_order DESC
LIMIT 1
", conn);
        cmd.Parameters.AddWithValue("@eid", electionId);
        cmd.Parameters.AddWithValue("@o", curOrder);
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync()) { neighborId = r.GetInt64(0); neighborOrder = r.GetInt32(1); }
    }
    else if (dir == "down")
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT id, sort_order FROM ballot_items
WHERE election_id=@eid AND COALESCE(is_deleted,false)=false AND sort_order > @o
ORDER BY sort_order ASC
LIMIT 1
", conn);
        cmd.Parameters.AddWithValue("@eid", electionId);
        cmd.Parameters.AddWithValue("@o", curOrder);
        await using var r = await cmd.ExecuteReaderAsync();
        if (await r.ReadAsync()) { neighborId = r.GetInt64(0); neighborOrder = r.GetInt32(1); }
    }

    if (neighborId != 0)
    {
        await using var tx = await conn.BeginTransactionAsync();
        await using (var a = new NpgsqlCommand(@"UPDATE ballot_items SET sort_order=@o WHERE id=@id", conn, tx))
        {
            a.Parameters.AddWithValue("@o", neighborOrder);
            a.Parameters.AddWithValue("@id", id);
            await a.ExecuteNonQueryAsync();
        }
        await using (var b = new NpgsqlCommand(@"UPDATE ballot_items SET sort_order=@o WHERE id=@id", conn, tx))
        {
            b.Parameters.AddWithValue("@o", curOrder);
            b.Parameters.AddWithValue("@id", neighborId);
            await b.ExecuteNonQueryAsync();
        }
        await tx.CommitAsync();
    }

    return Results.Redirect($"/admin/elections/{electionId}");
});

app.MapGet("/admin/ballot/edit/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    await using var conn = await OpenConnAsync();

    long electionId;
    string kind="", title="", subtitle="";
    int voteFor=1;
    string q="";

    await using (var cmd = new NpgsqlCommand(@"
SELECT election_id, kind, title, subtitle, vote_for, question_text
FROM ballot_items
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);
        electionId = r.GetInt64(0);
        kind = ReadTextOrFirstArray(r, 1);
        title = ReadTextOrFirstArray(r, 2);
        subtitle = ReadTextOrFirstArray(r, 3);
        voteFor = r.IsDBNull(4) ? 1 : r.GetInt32(4);
        q = ReadTextOrFirstArray(r, 5);
    }

    var candRows = new StringBuilder();
    if (kind == "office")
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT id, last_name, first_name
FROM ballot_candidates
WHERE ballot_item_id=@bid AND COALESCE(is_deleted,false)=false
ORDER BY sort_order ASC, id ASC
", conn);
        cmd.Parameters.AddWithValue("@bid", id);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var cid = r.GetInt64(0);
            var ln = ReadTextOrFirstArray(r, 1);
            var fn = ReadTextOrFirstArray(r, 2);

            candRows.Append($@"
<tr>
  <td><input name='ln_{cid}' value='{H(ln)}'/></td>
  <td><input name='fn_{cid}' value='{H(fn)}'/></td>
  <td class='right'>
    <form method='post' action='/admin/ballot/candidate/delete' style='display:inline' onsubmit=""{ConfirmJs("Remove candidate?").Replace("\"","&quot;")}"">
      <input type='hidden' name='ballot_item_id' value='{id}'/>
      <input type='hidden' name='election_id' value='{electionId}'/>
      <input type='hidden' name='id' value='{cid}'/>
      <button class='btn btn-danger' type='submit'>Remove</button>
    </form>
  </td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "elections")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Edit Ballot Item</div>

    <div class='card'>
      <form method='post' action='/admin/ballot/edit'>
        <input type='hidden' name='id' value='{id}'/>
        <input type='hidden' name='election_id' value='{electionId}'/>

        <label>Title</label>
        <input name='title' value='{H(title)}' required />

        <label>Subtitle</label>
        <input name='subtitle' value='{H(subtitle)}' />

        {(kind=="office" ? $@"
          <label>Vote for #</label>
          <input name='vote_for' type='number' min='1' value='{voteFor}' />
        " : $@"
          <label>Full question text</label>
          <textarea name='question_text' rows='6' required>{H(q)}</textarea>
        ")}

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Save</button>
          <a class='btn btn-secondary' href='/admin/elections/{electionId}'>Back</a>
        </div>

        {(kind=="office" ? $@"
          <div style='height:16px'></div>
          <div class='h2' style='color:#111;'>Candidates</div>
          <div class='mv-subtle'>Edit names or add new candidate.</div>

          <table class='table'>
            <thead><tr><th>Last</th><th>First</th><th class='right'>Actions</th></tr></thead>
            <tbody>{(candRows.Length==0 ? "<tr><td colspan='3' class='mv-subtle'>(none)</td></tr>" : candRows.ToString())}</tbody>
          </table>

          <div style='height:10px'></div>

          <div class='grid grid-2'>
            <div>
              <label>New candidate last</label>
              <input name='new_last' />
            </div>
            <div>
              <label>New candidate first</label>
              <input name='new_first' />
            </div>
          </div>
          <div style='height:10px'></div>
          <button class='btn btn-secondary' name='add_candidate' value='1' type='submit'>Add candidate</button>
        " : "")}
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Edit ballot item", body));
});

app.MapPost("/admin/ballot/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin/elections");
    if (!long.TryParse(form["election_id"].ToString(), out var electionId)) return Results.Redirect("/admin/elections");

    var title = (form["title"].ToString() ?? "").Trim();
    var subtitle = (form["subtitle"].ToString() ?? "").Trim();
    var voteFor = 1;
    int.TryParse((form["vote_for"].ToString() ?? "1").Trim(), out voteFor);
    voteFor = Math.Max(1, voteFor);
    var q = (form["question_text"].ToString() ?? "").Trim();

    var addCandidate = form["add_candidate"].ToString() == "1";
    var newLast = (form["new_last"].ToString() ?? "").Trim();
    var newFirst = (form["new_first"].ToString() ?? "").Trim();

    await using var conn = await OpenConnAsync();

    string kind = "";
    await using (var cmd = new NpgsqlCommand(@"SELECT kind FROM ballot_items WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        kind = (await cmd.ExecuteScalarAsync())?.ToString() ?? "office";
    }

    // Update item
    await using (var cmd = new NpgsqlCommand(@"
UPDATE ballot_items
SET title=@t, subtitle=@st, vote_for=@vf, question_text=@q, updated_at=NOW()
WHERE id=@id
", conn))
    {
        cmd.Parameters.AddWithValue("@t", title);
        cmd.Parameters.AddWithValue("@st", subtitle);
        cmd.Parameters.AddWithValue("@vf", voteFor);
        cmd.Parameters.AddWithValue("@q", q);
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    // Update existing candidates if office
    if (kind == "office")
    {
        // Update candidate fields from form keys ln_{id}, fn_{id}
        // Pull candidate ids and iterate
        var candIds = new List<long>();
        await using (var cmd = new NpgsqlCommand(@"
SELECT id FROM ballot_candidates
WHERE ballot_item_id=@bid AND COALESCE(is_deleted,false)=false
", conn))
        {
            cmd.Parameters.AddWithValue("@bid", id);
            await using var r = await cmd.ExecuteReaderAsync();
            while (await r.ReadAsync()) candIds.Add(r.GetInt64(0));
        }

        foreach (var cid in candIds)
        {
            var ln = (form[$"ln_{cid}"].ToString() ?? "").Trim();
            var fn = (form[$"fn_{cid}"].ToString() ?? "").Trim();

            await using var cmd = new NpgsqlCommand(@"
UPDATE ballot_candidates
SET last_name=@ln, first_name=@fn, updated_at=NOW()
WHERE id=@id
", conn);
            cmd.Parameters.AddWithValue("@ln", ln);
            cmd.Parameters.AddWithValue("@fn", fn);
            cmd.Parameters.AddWithValue("@id", cid);
            await cmd.ExecuteNonQueryAsync();
        }

        if (addCandidate && (!string.IsNullOrWhiteSpace(newLast) || !string.IsNullOrWhiteSpace(newFirst)))
        {
            int next = 0;
            await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(MAX(sort_order),-1)+1 FROM ballot_candidates WHERE ballot_item_id=@bid AND COALESCE(is_deleted,false)=false", conn))
            {
                cmd.Parameters.AddWithValue("@bid", id);
                next = Convert.ToInt32(await cmd.ExecuteScalarAsync());
            }

            await using var cmdIns = new NpgsqlCommand(@"
INSERT INTO ballot_candidates(ballot_item_id, sort_order, last_name, first_name, is_deleted, created_at)
VALUES (@bid, @so, @ln, @fn, false, NOW())
", conn);
            cmdIns.Parameters.AddWithValue("@bid", id);
            cmdIns.Parameters.AddWithValue("@so", next);
            cmdIns.Parameters.AddWithValue("@ln", newLast);
            cmdIns.Parameters.AddWithValue("@fn", newFirst);
            await cmdIns.ExecuteNonQueryAsync();
        }
    }

    return Results.Redirect($"/admin/ballot/edit/{id}");
});

app.MapPost("/admin/ballot/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["election_id"].ToString(), out var electionId)) return Results.Redirect("/admin/elections");
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect($"/admin/elections/{electionId}");

    await using var conn = await OpenConnAsync();
    await using (var cmd = new NpgsqlCommand(@"UPDATE ballot_items SET is_deleted=true WHERE id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }
    // candidates cascade logically by ballot_item_id; we soft delete candidates too
    await using (var cmd = new NpgsqlCommand(@"UPDATE ballot_candidates SET is_deleted=true WHERE ballot_item_id=@id", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect($"/admin/elections/{electionId}");
});

app.MapPost("/admin/ballot/candidate/delete", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["ballot_item_id"].ToString(), out var ballotId)) return Results.Redirect("/admin/elections");
    if (!long.TryParse(form["election_id"].ToString(), out var electionId)) return Results.Redirect("/admin/elections");
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect($"/admin/ballot/edit/{ballotId}");

    await using var conn = await OpenConnAsync();
    await using var cmd = new NpgsqlCommand(@"UPDATE ballot_candidates SET is_deleted=true WHERE id=@id", conn);
    cmd.Parameters.AddWithValue("@id", id);
    await cmd.ExecuteNonQueryAsync();

    return Results.Redirect($"/admin/ballot/edit/{ballotId}");
});

// =========================
// Read-only render helpers (commissioners/techs/precincts) used in election detail
// =========================
static async Task<string> RenderCommissionersReadOnlyAsync(NpgsqlConnection conn, long countyId)
{
    string chair="", sec="", m1="", m2="", m3="";
    await using var cmd = new NpgsqlCommand(@"
SELECT
  COALESCE(MAX(CASE WHEN role='chair' THEN name END), '')      AS chair_name,
  COALESCE(MAX(CASE WHEN role='secretary' THEN name END), '')  AS secretary_name,
  COALESCE(MAX(CASE WHEN role='member' AND sort_order=1 THEN name END), '') AS member1_name,
  COALESCE(MAX(CASE WHEN role='member' AND sort_order=2 THEN name END), '') AS member2_name,
  COALESCE(MAX(CASE WHEN role='member' AND sort_order=3 THEN name END), '') AS member3_name
FROM county_commissioners
WHERE county_id=@cid AND COALESCE(is_deleted,false)=false
", conn);

    cmd.Parameters.AddWithValue("@cid", countyId);
    await using var r = await cmd.ExecuteReaderAsync();
    if (await r.ReadAsync())
    {
        chair = ReadTextOrFirstArray(r, 0);
        sec = ReadTextOrFirstArray(r, 1);
        m1 = ReadTextOrFirstArray(r, 2);
        m2 = ReadTextOrFirstArray(r, 3);
        m3 = ReadTextOrFirstArray(r, 4);
    }
    return $@"
<ul>
  <li><strong>Chair:</strong> {H(chair)}</li>
  <li><strong>Secretary:</strong> {H(sec)}</li>
  <li><strong>Member 1:</strong> {H(m1)}</li>
  <li><strong>Member 2:</strong> {H(m2)}</li>
  <li><strong>Member 3:</strong> {H(m3)}</li>
</ul>";
}

static async Task<string> RenderMachineTechsReadOnlyAsync(NpgsqlConnection conn, long countyId)
{
    var sb = new StringBuilder("<ul>");
    await using var cmd = new NpgsqlCommand(@"
SELECT u.email, COALESCE(u.display_name,'')
FROM machine_tech_assignments a
JOIN users u ON u.id=a.tech_user_id
WHERE a.county_id=@cid AND COALESCE(a.is_active,true)=true AND COALESCE(u.is_deleted,false)=false
ORDER BY u.email ASC
", conn);
    cmd.Parameters.AddWithValue("@cid", countyId);
    await using var r = await cmd.ExecuteReaderAsync();
    while (await r.ReadAsync())
    {
        var em = ReadTextOrFirstArray(r, 0);
        var dn = ReadTextOrFirstArray(r, 1);
        sb.Append($"<li>{H(string.IsNullOrWhiteSpace(dn)?em:dn)} <span class='mv-subtle'>({H(em)})</span></li>");
    }
    sb.Append("</ul>");
    return sb.ToString().Replace("<ul></ul>", "<div class='mv-subtle'>(none)</div>");
}

static async Task<string> RenderPrecinctsListOnlyAsync(NpgsqlConnection conn, long countyId)
{
    var sb = new StringBuilder();
    await using var cmd = new NpgsqlCommand(@"
SELECT precinct_name, precinct_address, registered_voters
FROM precincts
WHERE county_id=@cid AND COALESCE(is_deleted,false)=false
ORDER BY precinct_name ASC
", conn);
    cmd.Parameters.AddWithValue("@cid", countyId);
    await using var r = await cmd.ExecuteReaderAsync();
    while (await r.ReadAsync())
    {
        var n = ReadTextOrFirstArray(r, 0);
        var a = ReadTextOrFirstArray(r, 1);
        var v = r.IsDBNull(2) ? 0 : r.GetInt32(2);
        sb.Append($@"<div style='margin:6px 0;'><strong>{H(n)}</strong> <span class='mv-subtle'>({v} voters)</span><div class='mv-subtle'>{H(a)}</div></div>");
    }
    if (sb.Length == 0) return "<div class='mv-subtle'>(no precincts yet)</div>";
    return sb.ToString();
}

// =========================
// Issues: report + resolve
// Admin can resolve with note; AOE can report; Contractor/MachineTech can report
// =========================

app.MapGet("/issues/report/{inventoryId:long}", async (HttpContext ctx, long inventoryId) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");

    // Anyone logged in can report, but access must be scoped:
    // - admin ok
    // - aoe must match county_id
    // - contractor/machinetech must be assigned to county
    await using var conn = await OpenConnAsync();

    long countyId = 0;
    string type="", sn="";
    await using (var cmd = new NpgsqlCommand(@"
SELECT county_id, item_type, serial_number
FROM inventory
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", inventoryId);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Text("Not found", "text/plain", statusCode: 404);
        countyId = r.GetInt64(0);
        type = ReadTextOrFirstArray(r, 1);
        sn = ReadTextOrFirstArray(r, 2);
    }

    // Authorization
    if (auth.Role == "aoe")
    {
        var userCounty = 0L;
        await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@id", conn))
        {
            cmd.Parameters.AddWithValue("@id", auth.UserId);
            userCounty = Convert.ToInt64(await cmd.ExecuteScalarAsync());
        }
        if (userCounty != countyId) return Results.Text("Forbidden", "text/plain", statusCode: 403);
    }
    else if (auth.Role == "contractor")
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT COUNT(*) FROM contractor_assignments WHERE contractor_user_id=@u AND county_id=@c AND COALESCE(is_active,true)=true
", conn);
        cmd.Parameters.AddWithValue("@u", auth.UserId);
        cmd.Parameters.AddWithValue("@c", countyId);
        if (Convert.ToInt64(await cmd.ExecuteScalarAsync()) == 0) return Results.Text("Forbidden", "text/plain", statusCode: 403);
    }
    else if (auth.Role == "machinetech")
    {
        await using var cmd = new NpgsqlCommand(@"
SELECT COUNT(*) FROM machine_tech_assignments WHERE tech_user_id=@u AND county_id=@c AND COALESCE(is_active,true)=true
", conn);
        cmd.Parameters.AddWithValue("@u", auth.UserId);
        cmd.Parameters.AddWithValue("@c", countyId);
        if (Convert.ToInt64(await cmd.ExecuteScalarAsync()) == 0) return Results.Text("Forbidden", "text/plain", statusCode: 403);
    }

    var back = ctx.Request.Query["return_to"].ToString();
    if (string.IsNullOrWhiteSpace(back)) back = "/app";

    var body = $@"
{Topbar(ctx, "Report Issue", false)}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Report Issue</div>
    <div class='mv-subtle'>Item: <strong>{H(type)}</strong> • SN: <strong>{H(sn)}</strong></div>

    <div style='height:12px'></div>

    <div class='card'>
      <form method='post' action='/issues/report'>
        <input type='hidden' name='inventory_id' value='{inventoryId}'/>
        <input type='hidden' name='return_to' value='{H(back)}'/>

        <label>Describe the issue</label>
        <textarea name='issue_text' rows='6' required></textarea>

        <div style='height:12px'></div>
        <div class='btn-row'>
          <button class='btn btn-primary' type='submit'>Submit</button>
          <a class='btn btn-secondary' href='{H(back)}'>Cancel</a>
        </div>
      </form>
    </div>
  </div>
")}
";
    return Html(Layout("Report Issue", body));
});

app.MapPost("/issues/report", async (HttpContext ctx) =>
{
    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/");

    var form = await ctx.Request.ReadFormAsync();
    var returnTo = (form["return_to"].ToString() ?? "/app").Trim();
    if (!long.TryParse(form["inventory_id"].ToString(), out var inventoryId)) return Results.Redirect(returnTo);
    var text = (form["issue_text"].ToString() ?? "").Trim();
    if (string.IsNullOrWhiteSpace(text)) return Results.Redirect(returnTo);

    await using var conn = await OpenConnAsync();
    await using var cmd = new NpgsqlCommand(@"
INSERT INTO inventory_issues(inventory_id, reported_by_user_id, reported_by_role, issue_text, is_resolved, created_at)
VALUES (@inv, @uid, @role, @txt, false, NOW())
", conn);
    cmd.Parameters.AddWithValue("@inv", inventoryId);
    cmd.Parameters.AddWithValue("@uid", auth.UserId);
    cmd.Parameters.AddWithValue("@role", auth.Role);
    cmd.Parameters.AddWithValue("@txt", text);
    await cmd.ExecuteNonQueryAsync();

    return Results.Redirect(returnTo);
});

app.MapGet("/admin/issues", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;

    await using var conn = await OpenConnAsync();

    var rows = new StringBuilder();

    await using (var cmd = new NpgsqlCommand(@"
SELECT i.id,
       c.county_name,
       inv.item_type,
       inv.serial_number,
       COALESCE(i.issue_text,''),
       COALESCE(i.is_resolved,false),
       COALESCE(i.reported_at, i.created_at, NOW())
FROM inventory_issues i
JOIN inventory inv ON inv.id = i.inventory_id
JOIN counties c ON c.id = inv.county_id
WHERE COALESCE(i.is_resolved,false)=false
ORDER BY COALESCE(i.reported_at, i.created_at) DESC
LIMIT 250
", conn))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            var id = r.GetInt64(0);
            var county = ReadTextOrFirstArray(r, 1);
            var type = ReadTextOrFirstArray(r, 2);
            var sn = ReadTextOrFirstArray(r, 3);
            var text = ReadTextOrFirstArray(r, 4);
            var when = r.GetFieldValue<DateTime>(6).ToString("yyyy-MM-dd HH:mm");

            rows.Append($@"
<tr>
  <td>{H(when)}</td>
  <td>{H(county)}</td>
  <td>{H(type)}</td>
  <td>{H(sn)}</td>
  <td>{H(text)}</td>
  <td class='right'>
    <form method='post' action='/admin/issues/resolve' style='display:inline' onsubmit=""{ConfirmJs("Mark this issue as resolved?").Replace("\"","&quot;")}"">
      <input type='hidden' name='id' value='{id}' />
      <input type='hidden' name='return_to' value='/admin/issues' />
      <button class='btn btn-primary' type='submit'>Resolve</button>
    </form>
  </td>
</tr>");
        }
    }

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "issues")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Open Issues</div>
    <div class='mv-subtle'>Reported inventory issues not yet resolved.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <table class='table'>
        <thead>
          <tr>
            <th>When</th><th>County</th><th>Type</th><th>Serial</th><th>Issue</th><th class='right'>Action</th>
          </tr>
        </thead>
        <tbody>
          {(rows.Length==0 ? "<tr><td colspan='6'>No open issues 🎉</td></tr>" : rows.ToString())}
        </tbody>
      </table>
    </div>
  </div>
")}
";

    return Html(Layout("Issues", body));
});


app.MapPost("/admin/issues/resolve", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "admin", out var fail)) return fail!;
    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/admin");
    var note = (form["note"].ToString() ?? "").Trim();
    var back = (form["return_to"].ToString() ?? "/admin").Trim();

    await using var conn = await OpenConnAsync();
    await using var cmd = new NpgsqlCommand(@"
UPDATE inventory_issues
SET is_resolved=true, resolved_by_user_id=@uid, resolved_note=@n, resolved_at=NOW(), updated_at=NOW()
WHERE id=@id
", conn);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.Parameters.AddWithValue("@uid", GetAuth(ctx)!.UserId);
    cmd.Parameters.AddWithValue("@n", note);
    await cmd.ExecuteNonQueryAsync();

    return Results.Redirect(back);
});

// =========================
// Final: ensure app.Run() exists
// =========================

app.MapGet("/aoe/precincts/edit/{id:long}", async (HttpContext ctx, long id) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;

    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/login?role=aoe");

    await using var conn = await OpenConnAsync();

    // Find this AOE user's county_id
    long userCountyId = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@uid", conn))
    {
        cmd.Parameters.AddWithValue("@uid", auth.UserId);
        var obj = await cmd.ExecuteScalarAsync();
        userCountyId = obj == null ? 0 : Convert.ToInt64(obj);
    }
    if (userCountyId <= 0) 
	return Results.Problem("AOE is not assigned to a county.", statusCode: 403);

    // Load precinct and ensure it's in the AOE's county
    long precinctCountyId = 0;
    string name = "", addr = "";
    int voters = 0;

    await using (var cmd = new NpgsqlCommand(@"
SELECT county_id, COALESCE(precinct_name,''), COALESCE(precinct_address,''), COALESCE(registered_voters,0)
FROM precincts
WHERE id=@id AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Redirect("/aoe/county");

        precinctCountyId = r.GetInt64(0);
        name = r.GetString(1);
        addr = r.GetString(2);
        voters = r.GetInt32(3);
    }

    if (precinctCountyId != userCountyId) 
	return Results.Problem("Not allowed.", statusCode: 403);

    var body = $@"
{Topbar(ctx, "MV Election Portal (POC)", false)}
{Nav(ctx, "county")}
{Container($@"
  <div class='mv-panel'>
    <div class='h1'>Edit Precinct</div>
    <div class='mv-subtle'>Update precinct details.</div>

    <div style='height:14px'></div>

    <div class='card'>
      <form method='post' action='/aoe/precincts/edit'>
        <input type='hidden' name='id' value='{id}' />
        <input type='hidden' name='county_id' value='{userCountyId}' />

        <label>Precinct Name</label>
        <input name='precinct_name' value='{H(name)}' />

        <label>Precinct Address</label>
        <input name='precinct_address' value='{H(addr)}' />

        <label>Registered Voters</label>
        <input name='registered_voters' value='{voters}' />

        <div style='height:12px'></div>

        <button class='btn btn-primary' type='submit'>Save</button>
        <a class='btn btn-secondary' href='/aoe/county'>Cancel</a>
      </form>
    </div>
  </div>
")}
";

    return Html(Layout("Edit Precinct", body));
});


/*==================================Dup========================================
app.MapPost("/aoe/precincts/edit", async (HttpContext ctx) =>
{
    if (!RequireRole(ctx, "aoe", out var fail)) return fail!;

    var auth = GetAuth(ctx);
    if (auth == null) return Results.Redirect("/login?role=aoe");

    var form = await ctx.Request.ReadFormAsync();
    if (!long.TryParse(form["id"].ToString(), out var id)) return Results.Redirect("/aoe/county");

    var name = (form["precinct_name"].ToString() ?? "").Trim();
    var addr = (form["precinct_address"].ToString() ?? "").Trim();
    var votersStr = (form["registered_voters"].ToString() ?? "0").Trim();
    if (!int.TryParse(votersStr, out var voters)) voters = 0;
    voters = Math.Max(0, voters);

    await using var conn = await OpenConnAsync();

    // Ensure precinct belongs to this AOE's county
    long userCountyId = 0;
    await using (var cmd = new NpgsqlCommand(@"SELECT COALESCE(county_id,0) FROM users WHERE id=@uid", conn))
    {
        cmd.Parameters.AddWithValue("@uid", auth.UserId);
        userCountyId = Convert.ToInt64(await cmd.ExecuteScalarAsync() ?? 0);
    }

    await using (var cmd = new NpgsqlCommand(@"
UPDATE precincts
SET precinct_name=@n, precinct_address=@a, registered_voters=@v, updated_at=NOW()
WHERE id=@id AND county_id=@cid AND COALESCE(is_deleted,false)=false
", conn))
    {
        cmd.Parameters.AddWithValue("@n", name);
        cmd.Parameters.AddWithValue("@a", addr);
        cmd.Parameters.AddWithValue("@v", voters);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.Parameters.AddWithValue("@cid", userCountyId);
        await cmd.ExecuteNonQueryAsync();
    }

    return Results.Redirect("/aoe/county");
});
====================================end dup==============================================
*/

app.Run();

// record (must be after top-level statements)
record Auth(long UserId, string Email, string Role);
