using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

string connStr = builder.Configuration.GetConnectionString("SageDatabase")
    ?? throw new InvalidOperationException(
        "Missing connection string. Set ConnectionStrings__SageDatabase in the environment.");

string jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException(
        "Missing JWT signing key. Set Jwt__Key in the environment.");

if (Encoding.UTF8.GetByteCount(jwtKey) < 32)
    throw new InvalidOperationException("JWT signing key must be at least 32 bytes long.");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title       = "ERP Integration API ",
        Version     = "v1",
        Description = "Demonstration API for ERP data integration, authentication, stock, receivables, alerts and synchronization"
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name         = "Authorization",
        Type         = SecuritySchemeType.Http,
        Scheme       = "Bearer",
        BearerFormat = "JWT",
        In           = ParameterLocation.Header,
        Description  = "Entrez: Bearer {votre_token}"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            new string[]{}
        }
    });
});

var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? Array.Empty<string>();

builder.Services.AddCors(options =>
    options.AddPolicy("ConfiguredOrigins", policy =>
    {
        if (allowedOrigins.Length > 0)
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
    }));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt =>
    {
        opt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = false,
            ValidateAudience         = false,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseCors("ConfiguredOrigins");

app.Use(async (context, next) =>
{
    var xtoken = context.Request.Headers["X-Sage-Token"].ToString();
    if (!string.IsNullOrEmpty(xtoken))
    {
        context.Request.Headers["Authorization"] = "Bearer " + xtoken;
    }
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Sage 100 API OK - ajouter /swagger pour tester");

// ── AUTHENTIFICATION ──────────────────────────────────────────────────────────

app.MapPost("/api/auth/login", (LoginRequest login) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var cmd = new SqlCommand(
        "SELECT Id, Login, Nom, Role, Password FROM API_USERS WHERE Login=@login AND Actif=1", cn);
    cmd.Parameters.AddWithValue("@login", login.Login);

    using var rd = cmd.ExecuteReader();
    if (!rd.Read()) return Results.Unauthorized();

    string hashEnBase = rd["Password"].ToString()!;
    if (!BCrypt.Net.BCrypt.Verify(login.Password, hashEnBase))
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.NameIdentifier, rd["Id"].ToString()!),
        new Claim(ClaimTypes.Name,           rd["Login"].ToString()!),
        new Claim("NomComplet",              rd["Nom"].ToString()!),
        new Claim(ClaimTypes.Role,           rd["Role"].ToString()!)
    };

    var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddHours(24),
        signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            SecurityAlgorithms.HmacSha256));

    return Results.Ok(new
    {
        access_token = new JwtSecurityTokenHandler().WriteToken(token),
        expiration   = DateTime.UtcNow.AddHours(24).ToString("dd/MM/yyyy HH:mm"),
        user         = new { Nom = rd["Nom"].ToString(), Role = rd["Role"].ToString() }
    });
})
.WithTags("Authentification")
.WithName("login")
.WithSummary("Login token JWT 24h mot de passe hache BCrypt");

app.MapPost("/api/auth/logout", [Authorize] () =>
    Results.Ok(new { Message = "Deconnexion reussie" }))
.WithTags("Authentification")
.WithName("logout")
.WithSummary("Logout deconnexion securisee");

app.MapGet("/api/auth/me", [Authorize] (ClaimsPrincipal user) =>
    Results.Ok(new
    {
        Login = user.FindFirst(ClaimTypes.Name)?.Value,
        Nom   = user.FindFirst("NomComplet")?.Value,
        Role  = user.FindFirst(ClaimTypes.Role)?.Value
    }))
.WithTags("Authentification")
.WithName("profiluser")
.WithSummary("Profil de lutilisateur connecte");

app.MapPost("/api/auth/change-password", [Authorize] (ChangePasswordRequest req, ClaimsPrincipal user) =>
{
    var login = user.FindFirst(ClaimTypes.Name)?.Value;
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var cmdGet = new SqlCommand("SELECT Password FROM API_USERS WHERE Login=@Login AND Actif=1", cn);
    cmdGet.Parameters.AddWithValue("@Login", login!);
    var hashActuel = cmdGet.ExecuteScalar()?.ToString();

    if (hashActuel == null || !BCrypt.Net.BCrypt.Verify(req.AncienMotDePasse, hashActuel))
        return Results.BadRequest(new { Message = "Ancien mot de passe incorrect" });

    string nouveauHash = BCrypt.Net.BCrypt.HashPassword(req.NouveauMotDePasse);

    var cmdUpd = new SqlCommand("UPDATE API_USERS SET Password=@NewPwd WHERE Login=@Login", cn);
    cmdUpd.Parameters.AddWithValue("@NewPwd", nouveauHash);
    cmdUpd.Parameters.AddWithValue("@Login",  login!);
    cmdUpd.ExecuteNonQuery();

    return Results.Ok(new { Message = "Mot de passe modifie - Reconnectez-vous." });
})
.WithTags("Authentification")
.WithName("changementmdp")
.WithSummary("Changer son propre mot de passe BCrypt");

// User provisioning is intentionally not exposed as a public API endpoint.

// ── GESTION UTILISATEURS ──────────────────────────────────────────────────────

app.MapGet("/api/users", [Authorize(Roles = "Admin")] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var list = new List<object>();
    var rd = new SqlCommand("SELECT Id, Login, Nom, Role, Actif FROM API_USERS", cn).ExecuteReader();
    while (rd.Read())
        list.Add(new
        {
            Id    = rd["Id"],
            Login = rd["Login"].ToString(),
            Nom   = rd["Nom"].ToString(),
            Role  = rd["Role"].ToString(),
            Actif = Convert.ToBoolean(rd["Actif"])
        });
    return Results.Ok(list);
})
.WithTags("Utilisateurs")
.WithName("listeutilisateurs")
.WithSummary("Liste des utilisateurs Admin uniquement");

app.MapPost("/api/users", [Authorize(Roles = "Admin")] (CreateUserRequest req) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    string hash = BCrypt.Net.BCrypt.HashPassword(req.Password);
    var cmd = new SqlCommand(
        "INSERT INTO API_USERS (Login,Password,Nom,Role,Actif) VALUES (@Login,@Pwd,@Nom,@Role,1)", cn);
    cmd.Parameters.AddWithValue("@Login", req.Login);
    cmd.Parameters.AddWithValue("@Pwd",   hash);
    cmd.Parameters.AddWithValue("@Nom",   req.Nom);
    cmd.Parameters.AddWithValue("@Role",  req.Role);
    cmd.ExecuteNonQuery();
    return Results.Ok(new { Message = $"Utilisateur {req.Login} cree avec mot de passe securise" });
})
.WithTags("Utilisateurs")
.WithName("creerutilisateur")
.WithSummary("Creer un utilisateur - Roles: Admin, Commercial, ResponsableEntrepot");

app.MapPost("/api/users/{id}/reset-password", [Authorize(Roles = "Admin")] (int id, ResetPasswordRequest req) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    string hash = BCrypt.Net.BCrypt.HashPassword(req.NouveauMotDePasse);
    var cmd = new SqlCommand("UPDATE API_USERS SET Password=@NewPwd WHERE Id=@Id", cn);
    cmd.Parameters.AddWithValue("@NewPwd", hash);
    cmd.Parameters.AddWithValue("@Id",     id);
    return cmd.ExecuteNonQuery() == 0
        ? Results.NotFound(new { Message = "Utilisateur introuvable" })
        : Results.Ok(new { Message = "Mot de passe reinitialise" });
})
.WithTags("Utilisateurs")
.WithName("resetmdp")
.WithSummary("Reinitialiser le mot de passe Admin");

app.MapPut("/api/users/{id}/actif", [Authorize(Roles = "Admin")] (int id, ToggleUserRequest req) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand("UPDATE API_USERS SET Actif=@Actif WHERE Id=@Id", cn);
    cmd.Parameters.AddWithValue("@Actif", req.Actif ? 1 : 0);
    cmd.Parameters.AddWithValue("@Id",    id);
    return cmd.ExecuteNonQuery() == 0
        ? Results.NotFound(new { Message = "Utilisateur introuvable" })
        : Results.Ok(new { Message = req.Actif ? "Utilisateur active" : "Utilisateur desactive" });
})
.WithTags("Utilisateurs")
.WithName("activerdesactivercompte")
.WithSummary("Activer ou desactiver un compte Admin");

// ── ARTICLES ET STOCK ─────────────────────────────────────────────────────────

app.MapGet("/api/articles", [Authorize] (string? search, string? famille, bool? disponible) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var sql = @"
        SELECT A.AR_Ref, A.AR_Design, A.FA_CodeFamille, A.AR_PrixVen,
               ISNULL((SELECT SUM(S.AS_QteSto) FROM F_ARTSTOCK S WHERE S.AR_Ref=A.AR_Ref),0) AS StockTotal
        FROM F_ARTICLE A
        WHERE A.AR_Sommeil=0";

    if (!string.IsNullOrEmpty(search))
        sql += " AND (A.AR_Ref LIKE @Search OR A.AR_Design LIKE @Search)";
    if (!string.IsNullOrEmpty(famille))
        sql += " AND A.FA_CodeFamille=@Famille";
    if (disponible == true)
        sql += " AND (SELECT SUM(S.AS_QteSto) FROM F_ARTSTOCK S WHERE S.AR_Ref=A.AR_Ref) > 0";

    var cmd = new SqlCommand(sql, cn);
    if (!string.IsNullOrEmpty(search))  cmd.Parameters.AddWithValue("@Search",  $"%{search}%");
    if (!string.IsNullOrEmpty(famille)) cmd.Parameters.AddWithValue("@Famille", famille);

    var list = new List<object>();
    var rd   = cmd.ExecuteReader();
    while (rd.Read())
        list.Add(new
        {
            Ref        = rd["AR_Ref"].ToString(),
            Design     = rd["AR_Design"].ToString(),
            Famille    = rd["FA_CodeFamille"].ToString(),
            Prix       = Convert.ToDecimal(rd["AR_PrixVen"]),
            StockTotal = Convert.ToDecimal(rd["StockTotal"]),
            Disponible = Convert.ToDecimal(rd["StockTotal"]) > 0
        });

    return Results.Ok(new { Total = list.Count, Articles = list });
})
.WithTags("Articles")
.WithName("listearticles")
.WithSummary("Liste articles avec filtres search famille disponible");

app.MapGet("/api/articles/familles", [Authorize] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var list = new List<object>();
    var rd   = new SqlCommand(
        "SELECT FA_CodeFamille, FA_Intitule FROM F_FAMILLE ORDER BY FA_CodeFamille", cn).ExecuteReader();
    while (rd.Read())
        list.Add(new { Code = rd["FA_CodeFamille"].ToString(), Intitule = rd["FA_Intitule"].ToString() });
    return Results.Ok(list);
})
.WithTags("Articles")
.WithName("famillearticle")
.WithSummary("Familles articles pour filtre categorie");

app.MapGet("/api/articles/{ref}", [Authorize] (string @ref) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var cmdA = new SqlCommand(@"
        SELECT A.AR_Ref, A.AR_Design, A.FA_CodeFamille, A.AR_PrixVen, A.AR_SuiviStock,
               ISNULL((SELECT SUM(S.AS_QteSto) FROM F_ARTSTOCK S WHERE S.AR_Ref=A.AR_Ref),0) AS StockTotal
        FROM F_ARTICLE A WHERE A.AR_Ref=@Ref", cn);
    cmdA.Parameters.AddWithValue("@Ref", @ref);
    var rd = cmdA.ExecuteReader();
    if (!rd.Read())
        return Results.NotFound(new { Message = "Article introuvable" });

    var article = new
    {
        Ref        = rd["AR_Ref"].ToString(),
        Design     = rd["AR_Design"].ToString(),
        Famille    = rd["FA_CodeFamille"].ToString(),
        Prix       = Convert.ToDecimal(rd["AR_PrixVen"]),
        StockTotal = Convert.ToDecimal(rd["StockTotal"]),
        Disponible = Convert.ToDecimal(rd["StockTotal"]) > 0,
        SuiviStock = Convert.ToInt32(rd["AR_SuiviStock"])
    };
    rd.Close();

    var cmdS = new SqlCommand(@"
        SELECT D.DE_No, D.DE_Intitule,
               ISNULL(S.AS_QteSto, 0) AS Stock,
               ISNULL(S.AS_QteRes, 0) AS StockReserve
        FROM F_ARTSTOCK S
        JOIN F_DEPOT D ON S.DE_No=D.DE_No
        WHERE S.AR_Ref=@Ref", cn);
    cmdS.Parameters.AddWithValue("@Ref", @ref);
    var rdS  = cmdS.ExecuteReader();
    var locs = new List<object>();
    while (rdS.Read())
        locs.Add(new
        {
            DepotId      = Convert.ToInt32(rdS["DE_No"]),
            Depot        = rdS["DE_Intitule"].ToString(),
            Stock        = Convert.ToDecimal(rdS["Stock"]),
            StockReserve = Convert.ToDecimal(rdS["StockReserve"]),
            StockDispo   = Convert.ToDecimal(rdS["Stock"]) - Convert.ToDecimal(rdS["StockReserve"])
        });

    return Results.Ok(new { Article = article, LocalisationParDepot = locs });
})
.WithTags("Articles")
.WithName("detailarticle")
.WithSummary("Detail complet et localisation par depot d un article");

app.MapGet("/api/articles/{ref}/stock-depots", [Authorize] (string @ref) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand(@"
        SELECT D.DE_No, D.DE_Intitule,
               ISNULL(S.AS_QteSto,0) AS Stock,
               ISNULL(S.AS_QteRes,0) AS StockReserve
        FROM F_ARTSTOCK S
        JOIN F_DEPOT D ON S.DE_No=D.DE_No
        WHERE S.AR_Ref=@ref", cn);
    cmd.Parameters.AddWithValue("@ref", @ref);
    var list = new List<object>();
    var rd   = cmd.ExecuteReader();
    while (rd.Read())
        list.Add(new
        {
            DepotId      = Convert.ToInt32(rd["DE_No"]),
            Depot        = rd["DE_Intitule"].ToString(),
            Stock        = Convert.ToDecimal(rd["Stock"]),
            StockReserve = Convert.ToDecimal(rd["StockReserve"]),
            StockDispo   = Convert.ToDecimal(rd["Stock"]) - Convert.ToDecimal(rd["StockReserve"])
        });
    return list.Count == 0
        ? Results.NotFound(new { Message = "Aucun stock trouve" })
        : Results.Ok(list);
})
.WithTags("Articles")
.WithName("niveaustockarticleentrepot")
.WithSummary("Niveaux de stock d un article par entrepot");

app.MapGet("/api/stock/depots", [Authorize] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var list = new List<object>();
    var rd = new SqlCommand(@"
        SELECT 
            S.AR_Ref, A.AR_Design, A.FA_CodeFamille,
            D.DE_No AS DepotId, D.DE_Intitule AS Depot,
            ISNULL(S.AS_QteSto, 0) AS Stock,
            ISNULL(S.AS_QteRes, 0) AS StockReserve,
            ISNULL(S.AS_QteSto,0) - ISNULL(S.AS_QteRes,0) AS StockDispo
        FROM F_ARTSTOCK S
        JOIN F_ARTICLE A ON A.AR_Ref = S.AR_Ref
        JOIN F_DEPOT D ON D.DE_No = S.DE_No
        WHERE A.AR_Sommeil = 0
        ORDER BY D.DE_No, A.AR_Design", cn).ExecuteReader();
    while (rd.Read())
        list.Add(new {
            Ref          = rd["AR_Ref"].ToString(),
            Depot        = rd["Depot"].ToString(),
            DepotId      = Convert.ToInt32(rd["DepotId"]),
            Design       = rd["AR_Design"].ToString(),
            Famille      = rd["FA_CodeFamille"].ToString(),
            Stock        = Convert.ToDecimal(rd["Stock"]),
            StockReserve = Convert.ToDecimal(rd["StockReserve"]),
            StockDispo   = Convert.ToDecimal(rd["StockDispo"])
        });
    return Results.Ok(new { Total = list.Count, Articles = list });
})
.WithTags("Articles")
.WithName("stockpardepot")
.WithSummary("Tous les articles avec stock par depot");

app.MapGet("/api/depots", [Authorize] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var list = new List<object>();
    var rd   = new SqlCommand("SELECT DE_No, DE_Intitule FROM F_DEPOT ORDER BY DE_No", cn).ExecuteReader();
    while (rd.Read())
        list.Add(new { Id = Convert.ToInt32(rd["DE_No"]), Nom = rd["DE_Intitule"].ToString() });
    return Results.Ok(list);
})
.WithTags("Articles")
.WithName("listedepot")
.WithSummary("Liste de tous les depots entrepots");

// ── ENCOURS CLIENTS ───────────────────────────────────────────────────────────

app.MapGet("/api/clients/encours", [Authorize] (string? search) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var sql = @"
        SELECT 
            C.CT_Num,
            C.CT_Intitule,
            C.CT_Telephone,
            C.CT_EMail,
            C.CT_Adresse,
            C.CT_Ville,
            C.CT_CodePostal,
            ISNULL(C.CT_Encours, 0) AS EncoursAutorise,
            ISNULL(SUM(CASE WHEN E.EC_Sens = 0 THEN E.EC_Montant 
                            ELSE -E.EC_Montant END), 0) AS EncoursActuel
        FROM F_COMPTET C
        LEFT JOIN F_ECRITUREC E ON E.CT_Num = C.CT_Num
        WHERE C.CT_Type    = 0
          AND C.CT_Sommeil = 0";

    if (!string.IsNullOrEmpty(search))
        sql += " AND (C.CT_Num LIKE @Search OR C.CT_Intitule LIKE @Search)";

    sql += @" GROUP BY C.CT_Num, C.CT_Intitule, C.CT_Telephone,
                       C.CT_EMail, C.CT_Adresse, C.CT_Ville,
                       C.CT_CodePostal, C.CT_Encours
              ORDER BY CT_Intitule ASC";

    var cmd = new SqlCommand(sql, cn);
    if (!string.IsNullOrEmpty(search))
        cmd.Parameters.AddWithValue("@Search", $"%{search}%");

    var list = new List<object>();
    var rd   = cmd.ExecuteReader();
    while (rd.Read())
    {
        var actuel   = Convert.ToDecimal(rd["EncoursActuel"]);
        var autorise = Convert.ToDecimal(rd["EncoursAutorise"]);
        var pct      = autorise > 0 ? Math.Round(actuel / autorise * 100, 1) : 0;

        list.Add(new
        {
            Code               = rd["CT_Num"].ToString(),
            Nom                = rd["CT_Intitule"].ToString(),
            Telephone          = rd["CT_Telephone"].ToString(),
            Email              = rd["CT_EMail"].ToString(),
            Adresse            = rd["CT_Adresse"].ToString(),
            Ville              = rd["CT_Ville"].ToString(),
            CodePostal         = rd["CT_CodePostal"].ToString(),
            EncoursAutorise    = autorise,
            EncoursActuel      = actuel,
            EncoursRestant     = autorise - actuel,
            PourcentageUtilise = autorise > 0 ? pct + "%" : "N/A",
            Statut             = actuel == 0                       ? "AUCUN ENCOURS"
                               : actuel > autorise && autorise > 0 ? "DEPASSE"
                               : pct >= 80                         ? "ATTENTION"
                               :                                     "OK"
        });
    }

    return Results.Ok(new { Total = list.Count, Clients = list });
})
.WithTags("Clients")
.WithName("listeclient")
.WithSummary("Liste complete des clients avec encours reels");

app.MapGet("/api/clients/{code}/paiements-attente", [Authorize] (string code) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand(@"
        SELECT 
            E.EC_Piece          AS Piece,
            E.EC_Date           AS Date,
            E.EC_Echeance       AS Echeance,
            E.EC_Intitule       AS Libelle,
            E.JO_Num            AS Journal,
            E.EC_Montant        AS Montant,
            ISNULL(E.EC_MontantRegle, 0) AS MontantRegle,
            E.EC_Montant - ISNULL(E.EC_MontantRegle, 0) AS Restant,
            E.EC_Lettre         AS Lettre,
            E.EC_Lettrage       AS Lettrage
        FROM F_ECRITUREC E
        WHERE E.CT_Num  = @Code
          AND E.EC_Sens = 0
          AND (E.EC_Lettre IS NULL OR E.EC_Lettre = '')
          AND E.EC_Montant - ISNULL(E.EC_MontantRegle, 0) > 0
        ORDER BY E.EC_Date ASC", cn);
    cmd.Parameters.AddWithValue("@Code", code);

    var list  = new List<object>();
    var total = 0m;
    var rd    = cmd.ExecuteReader();
    while (rd.Read())
    {
        var restant = Convert.ToDecimal(rd["Restant"]);
        total += restant;
        list.Add(new
        {
            Piece          = rd["Piece"].ToString(),
            Date           = Convert.ToDateTime(rd["Date"]).ToString("dd/MM/yyyy"),
            Echeance       = rd["Echeance"] == DBNull.Value
                                ? "Non definie"
                                : Convert.ToDateTime(rd["Echeance"]).ToString("dd/MM/yyyy"),
            Libelle        = rd["Libelle"].ToString(),
            Journal        = rd["Journal"].ToString(),
            Montant        = Convert.ToDecimal(rd["Montant"]),
            DejaRegle      = Convert.ToDecimal(rd["MontantRegle"]),
            RestantARegler = restant,
            Statut         = Convert.ToDecimal(rd["MontantRegle"]) == 0
                                ? "Non regle"
                                : "Partiellement regle"
        });
    }
    return Results.Ok(new { TotalDu = total, NombrePaiements = list.Count, Paiements = list });
})
.WithTags("Clients")
.WithName("paiementenattenteclient")
.WithSummary("Paiements en attente d un client ecritures non lettrees");

app.MapGet("/api/clients/{code}/factures", [Authorize] (string code) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand(@"
        SELECT 
            E.EC_Piece          AS Piece,
            E.EC_Date           AS Date,
            E.EC_Intitule       AS Libelle,
            E.JO_Num            AS Journal,
            E.EC_Sens           AS Sens,
            E.EC_Montant        AS Montant,
            ISNULL(E.EC_MontantRegle, 0) AS MontantRegle,
            E.EC_Montant - ISNULL(E.EC_MontantRegle, 0) AS Restant,
            E.EC_Lettre         AS Lettre,
            E.EC_Echeance       AS Echeance
        FROM F_ECRITUREC E
        WHERE E.CT_Num = @Code
        ORDER BY E.EC_Date DESC", cn);
    cmd.Parameters.AddWithValue("@Code", code);

    var list = new List<object>();
    var rd   = cmd.ExecuteReader();
    while (rd.Read())
    {
        var sens = Convert.ToInt32(rd["Sens"]);
        list.Add(new
        {
            Piece        = rd["Piece"].ToString(),
            Date         = Convert.ToDateTime(rd["Date"]).ToString("dd/MM/yyyy"),
            Libelle      = rd["Libelle"].ToString(),
            Journal      = rd["Journal"].ToString(),
            Debit        = sens == 0 ? Convert.ToDecimal(rd["Montant"]) : 0,
            Credit       = sens == 1 ? Convert.ToDecimal(rd["Montant"]) : 0,
            MontantRegle = Convert.ToDecimal(rd["MontantRegle"]),
            Restant      = Convert.ToDecimal(rd["Restant"]),
            Echeance     = rd["Echeance"] == DBNull.Value
                              ? "Non definie"
                              : Convert.ToDateTime(rd["Echeance"]).ToString("dd/MM/yyyy"),
            Lettre       = rd["Lettre"].ToString(),
            Statut       = rd["Lettre"].ToString() != ""
                              ? "Lettre"
                              : Convert.ToDecimal(rd["Restant"]) == 0
                                  ? "Solde"
                                  : Convert.ToDecimal(rd["MontantRegle"]) > 0
                                      ? "Partiellement regle"
                                      : "Non regle"
        });
    }
    return Results.Ok(new { Total = list.Count, Ecritures = list });
})
.WithTags("Clients")
.WithName("factureclient")
.WithSummary("Toutes les ecritures comptables d un client");

app.MapGet("/api/clients/{code}/historique", [Authorize] (string code, int? annee) =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var sql = @"
        SELECT 
            E.EC_Piece      AS Piece,
            E.EC_Date       AS Date,
            E.EC_Intitule   AS Libelle,
            E.JO_Num        AS Journal,
            E.EC_Sens       AS Sens,
            E.EC_Montant    AS Montant,
            E.EC_Lettre     AS Lettre
        FROM F_ECRITUREC E
        WHERE E.CT_Num = @Code";

    if (annee.HasValue)
        sql += " AND YEAR(E.EC_Date) = @Annee";

    sql += " ORDER BY E.EC_Date DESC";

    var cmd = new SqlCommand(sql, cn);
    cmd.Parameters.AddWithValue("@Code", code);
    if (annee.HasValue)
        cmd.Parameters.AddWithValue("@Annee", annee.Value);

    var list        = new List<object>();
    var totalDebit  = 0m;
    var totalCredit = 0m;
    var rd          = cmd.ExecuteReader();

    while (rd.Read())
    {
        var sens    = Convert.ToInt32(rd["Sens"]);
        var montant = Convert.ToDecimal(rd["Montant"]);
        if (sens == 0) totalDebit  += montant;
        else           totalCredit += montant;

        list.Add(new
        {
            Piece   = rd["Piece"].ToString(),
            Date    = Convert.ToDateTime(rd["Date"]).ToString("dd/MM/yyyy"),
            Libelle = rd["Libelle"].ToString(),
            Journal = rd["Journal"].ToString(),
            Debit   = sens == 0 ? montant : 0,
            Credit  = sens == 1 ? montant : 0,
            Lettre  = rd["Lettre"].ToString(),
            Statut  = rd["Lettre"].ToString() != "" ? "Lettre" : "Non lettre"
        });
    }

    return Results.Ok(new
    {
        TotalDebit  = totalDebit,
        TotalCredit = totalCredit,
        Solde       = totalDebit - totalCredit,
        Total       = list.Count,
        Historique  = list
    });
})
.WithTags("Clients")
.WithName("historique")
.WithSummary("Historique complet des ecritures comptables filtre annee disponible");

// ── ALERTES ───────────────────────────────────────────────────────────────────

app.MapGet("/api/alertes/stock", [Authorize] (int? seuil) =>
{
    int s = seuil ?? 5;
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand(@"
        SELECT A.AR_Ref, A.AR_Design, A.FA_CodeFamille,
               ISNULL(SUM(S.AS_QteSto),0) AS StockTotal
        FROM F_ARTICLE A
        LEFT JOIN F_ARTSTOCK S ON A.AR_Ref=S.AR_Ref
        WHERE A.AR_Sommeil=0
        GROUP BY A.AR_Ref, A.AR_Design, A.FA_CodeFamille
        HAVING ISNULL(SUM(S.AS_QteSto),0) < @Seuil
        ORDER BY StockTotal ASC", cn);
    cmd.Parameters.AddWithValue("@Seuil", s);

    var list = new List<object>();
    var rd   = cmd.ExecuteReader();
    while (rd.Read())
    {
        var stock = Convert.ToDecimal(rd["StockTotal"]);
        list.Add(new
        {
            Type      = stock == 0 ? "RUPTURE" : "STOCK_BAS",
            Ref       = rd["AR_Ref"].ToString(),
            Design    = rd["AR_Design"].ToString(),
            Famille   = rd["FA_CodeFamille"].ToString(),
            Stock     = stock,
            EnRupture = stock == 0,
            Message   = stock == 0
                ? $"RUPTURE : {rd["AR_Design"]}"
                : $"Stock bas ({stock}) : {rd["AR_Design"]}"
        });
    }
    return Results.Ok(new
    {
        SeuilUtilise  = s,
        NombreAlertes = list.Count,
        NbRuptures    = list.Count(x => (bool)((dynamic)x).EnRupture),
        Alertes       = list
    });
})
.WithTags("Alertes")
.WithName("rupturestockbas")
.WithSummary("Ruptures et stocks bas - parametre seuil defaut 5");

app.MapGet("/api/alertes/encours", [Authorize] (decimal? pourcentage) =>
{
    decimal pct = pourcentage ?? 80;
    using var cn = new SqlConnection(connStr);
    cn.Open();
    var cmd = new SqlCommand(@"
    SELECT 
        C.CT_Num, C.CT_Intitule, C.CT_Telephone,
        ISNULL(C.CT_Encours, 0) AS EncoursAutorise,
        ISNULL(SUM(CASE WHEN E.EC_Sens = 0 THEN E.EC_Montant 
                        ELSE -E.EC_Montant END), 0) AS EncoursActuel
    FROM F_COMPTET C
    LEFT JOIN F_ECRITUREC E ON E.CT_Num = C.CT_Num
    WHERE C.CT_Type = 0
      AND C.CT_Sommeil = 0
      AND ISNULL(C.CT_Encours, 0) > 0
    GROUP BY C.CT_Num, C.CT_Intitule, C.CT_Telephone, C.CT_Encours
    HAVING 
        ISNULL(SUM(CASE WHEN E.EC_Sens = 0 THEN E.EC_Montant 
                        ELSE -E.EC_Montant END), 0) > 0
        AND
        ISNULL(SUM(CASE WHEN E.EC_Sens = 0 THEN E.EC_Montant 
                        ELSE -E.EC_Montant END), 0) 
        >= (ISNULL(C.CT_Encours, 0) * @Pct / 100)
    ORDER BY EncoursActuel DESC", cn);
    cmd.Parameters.AddWithValue("@Pct", pct);

    var list = new List<object>();
    var rd = cmd.ExecuteReader();
    while (rd.Read())
    {
        var actuel   = Convert.ToDecimal(rd["EncoursActuel"]);
        var autorise = Convert.ToDecimal(rd["EncoursAutorise"]);
        var pctUtil  = autorise > 0 ? Math.Round(actuel / autorise * 100, 1) : 0m;
        list.Add(new
        {
            Code               = rd["CT_Num"].ToString(),
            Nom                = rd["CT_Intitule"].ToString(),
            Telephone          = rd["CT_Telephone"].ToString(),
            EncoursAutorise    = autorise,
            EncoursActuel      = actuel,
            PourcentageUtilise = pctUtil,
            Depassement        = actuel - autorise,
            Message            = pctUtil >= 100
                ? $"{rd["CT_Intitule"]} a DEPASSE son encours ({pctUtil}%)"
                : $"{rd["CT_Intitule"]} approche son encours ({pctUtil}%)"
        });
    }
    return Results.Ok(new {
        SeuilPourcentage = pct,
        NombreAlertes    = list.Count,
        Alertes          = list
    });
})
.WithTags("Alertes")
.WithName("pourcentageautorise")
.WithSummary("Alertes encours clients - parametre pourcentage defaut 80");

// ── DASHBOARD ─────────────────────────────────────────────────────────────────

app.MapGet("/api/dashboard", [Authorize] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    int nbArticles = (int)new SqlCommand(
        "SELECT COUNT(*) FROM F_ARTICLE WHERE AR_Sommeil=0", cn).ExecuteScalar()!;

    int nbRuptures = (int)new SqlCommand(@"
        SELECT COUNT(*) FROM F_ARTICLE A WHERE AR_Sommeil=0
        AND ISNULL((SELECT SUM(AS_QteSto) FROM F_ARTSTOCK WHERE AR_Ref=A.AR_Ref),0) = 0", cn).ExecuteScalar()!;

    int nbStockBas = (int)new SqlCommand(@"
        SELECT COUNT(*) FROM F_ARTICLE A WHERE AR_Sommeil=0
        AND ISNULL((SELECT SUM(AS_QteSto) FROM F_ARTSTOCK WHERE AR_Ref=A.AR_Ref),0) BETWEEN 1 AND 5", cn).ExecuteScalar()!;

    int nbClients = (int)new SqlCommand(
        "SELECT COUNT(*) FROM F_COMPTET WHERE CT_Type=0 AND CT_Sommeil=0", cn).ExecuteScalar()!;

    int nbEncoursDepasses = (int)new SqlCommand(@"
        SELECT COUNT(*) FROM F_COMPTET C WHERE CT_Type=0 AND CT_Sommeil=0
        AND ISNULL(C.CT_Encours,0) > 0
        AND ISNULL((SELECT SUM(CASE WHEN EC_Sens=0 THEN EC_Montant 
                                    ELSE -EC_Montant END)
                    FROM F_ECRITUREC WHERE CT_Num=C.CT_Num),0) 
        > ISNULL(C.CT_Encours,0)", cn).ExecuteScalar()!;

    var totalEncours = Convert.ToDecimal(new SqlCommand(@"
        SELECT ISNULL(SUM(CASE WHEN EC_Sens = 0 THEN EC_Montant 
                               ELSE -EC_Montant END), 0)
        FROM F_ECRITUREC E
        JOIN F_COMPTET C ON C.CT_Num = E.CT_Num
        WHERE C.CT_Type = 0
          AND C.CT_Sommeil = 0
          AND CASE WHEN EC_Sens = 0 THEN EC_Montant 
                   ELSE -EC_Montant END > 0", cn).ExecuteScalar());

    return Results.Ok(new
    {
        Articles      = new { Total = nbArticles, Ruptures = nbRuptures, StockBas = nbStockBas, OK = nbArticles - nbRuptures - nbStockBas },
        Clients       = new { Total = nbClients, EncoursDepasses = nbEncoursDepasses, TotalEncoursDu = totalEncours },
        DateMiseAJour = DateTime.Now.ToString("dd/MM/yyyy HH:mm")
    });
})
.WithTags("Dashboard")
.WithName("dashboard")
.WithSummary("KPIs globaux pour le tableau de bord Power Apps");

// ── SYNCHRONISATION ───────────────────────────────────────────────────────────

app.MapGet("/api/sync/timestamp", [Authorize] () =>
    Results.Ok(new
    {
        Timestamp   = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        DateServeur = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"),
        Message     = "Comparez ce timestamp avec votre dernier sync pour detecter les changements"
    }))
.WithTags("Synchronisation")
.WithName("majtempreel")
.WithSummary("Timestamp serveur pour detecter les mises a jour temps reel");

app.MapGet("/api/sync/full-data", [Authorize] () =>
{
    using var cn = new SqlConnection(connStr);
    cn.Open();

    var articles = new List<object>();
    var rdA = new SqlCommand(@"
        SELECT A.AR_Ref, A.AR_Design, A.FA_CodeFamille, A.AR_PrixVen,
               ISNULL((SELECT SUM(S.AS_QteSto) FROM F_ARTSTOCK S WHERE S.AR_Ref=A.AR_Ref),0) AS StockTotal
        FROM F_ARTICLE A WHERE A.AR_Sommeil=0", cn).ExecuteReader();
    while (rdA.Read())
        articles.Add(new
        {
            Ref        = rdA["AR_Ref"].ToString(),
            Design     = rdA["AR_Design"].ToString(),
            Famille    = rdA["FA_CodeFamille"].ToString(),
            Prix       = Convert.ToDecimal(rdA["AR_PrixVen"]),
            StockTotal = Convert.ToDecimal(rdA["StockTotal"]),
            Disponible = Convert.ToDecimal(rdA["StockTotal"]) > 0
        });
    rdA.Close();

    var clients = new List<object>();
    var rdC = new SqlCommand(@"
        SELECT C.CT_Num, C.CT_Intitule, C.CT_Telephone,
               ISNULL(C.CT_Encours,0) AS EncoursAutorise,
               ISNULL(SUM(CASE WHEN E.EC_Sens = 0 THEN E.EC_Montant 
                               ELSE -E.EC_Montant END), 0) AS EncoursActuel
        FROM F_COMPTET C
        LEFT JOIN F_ECRITUREC E ON E.CT_Num = C.CT_Num
        WHERE C.CT_Type=0 AND C.CT_Sommeil=0
        GROUP BY C.CT_Num, C.CT_Intitule, C.CT_Telephone, C.CT_Encours", cn).ExecuteReader();
    while (rdC.Read())
    {
        var actuel   = Convert.ToDecimal(rdC["EncoursActuel"]);
        var autorise = Convert.ToDecimal(rdC["EncoursAutorise"]);
        clients.Add(new
        {
            Code               = rdC["CT_Num"].ToString(),
            Nom                = rdC["CT_Intitule"].ToString(),
            Telephone          = rdC["CT_Telephone"].ToString(),
            EncoursAutorise    = autorise,
            EncoursActuel      = actuel,
            DepassementEncours = actuel > autorise
        });
    }
    rdC.Close();

    var depots = new List<object>();
    var rdD = new SqlCommand("SELECT DE_No, DE_Intitule FROM F_DEPOT", cn).ExecuteReader();
    while (rdD.Read())
        depots.Add(new { Id = Convert.ToInt32(rdD["DE_No"]), Nom = rdD["DE_Intitule"].ToString() });
    rdD.Close();

    var familles = new List<object>();
    var rdF = new SqlCommand("SELECT FA_CodeFamille, FA_Intitule FROM F_FAMILLE", cn).ExecuteReader();
    while (rdF.Read())
        familles.Add(new { Code = rdF["FA_CodeFamille"].ToString(), Intitule = rdF["FA_Intitule"].ToString() });
    rdF.Close();

    return Results.Ok(new
    {
        DateSynchronisation = DateTime.Now.ToString("dd/MM/yyyy HH:mm"),
        Timestamp           = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        Articles            = articles,
        Clients             = clients,
        Depots              = depots,
        Familles            = familles
    });
})
.WithTags("Synchronisation")
.WithName("horsligne")
.WithSummary("Telecharge TOUTES les donnees en une fois mode hors ligne Power Apps");

app.Run();

// ── MODELES ───────────────────────────────────────────────────────────────────

record LoginRequest(string Login, string Password);
record ChangePasswordRequest(string AncienMotDePasse, string NouveauMotDePasse);
record ResetPasswordRequest(string NouveauMotDePasse);
record CreateUserRequest(string Login, string Password, string Nom, string Role);
record ToggleUserRequest(bool Actif);