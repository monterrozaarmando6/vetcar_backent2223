package com.veterinaria;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;

/** Minimal dependency-free REST API for a veterinary practice. */
public final class ApiServer {
  private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
  private static final String SECRET = System.getenv().getOrDefault("APP_SECRET", "replace-this-secret-before-production");
  private static final String CORS_ORIGIN = System.getenv().getOrDefault("CORS_ORIGIN", "http://localhost:5173");
  private static final Set<String> RESOURCES = Set.of(
      "owners", "pets", "users", "appointments", "consultations", "vaccines", "treatments",
      "allergies", "medications", "inventory", "services", "payments", "invoices", "notifications", "hospitalizations");
  private static final Store STORE = new Store(Paths.get(System.getenv().getOrDefault("DATA_DIR", "data"), "veterinaria.bin"));

  public static void main(String[] args) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
    server.createContext("/api", ApiServer::handle);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    System.out.println("Veterinary API listening on http://localhost:" + PORT);
  }

  private static void handle(HttpExchange exchange) throws IOException {
    try {
      cors(exchange);
      if ("OPTIONS".equals(exchange.getRequestMethod())) { exchange.sendResponseHeaders(204, -1); return; }
      String method = exchange.getRequestMethod();
      String path = exchange.getRequestURI().getPath();
      if ("/api/health".equals(path)) { send(exchange, 200, Map.of("status", "ok")); return; }
      if (path.startsWith("/api/auth/")) { auth(exchange, method, path.substring(10)); return; }
      User user = authenticate(exchange);
      if (user == null) { send(exchange, 401, Map.of("error", "Authentication required")); return; }
      String[] parts = path.substring(5).split("/");
      if (parts.length >= 2 && "reports".equals(parts[0]) && "dashboard".equals(parts[1])) {
        if (!user.has("ADMIN", "VETERINARIAN", "RECEPTIONIST")) { forbidden(exchange); return; }
        dashboard(exchange); return;
      }
      if (parts.length == 0 || !RESOURCES.contains(parts[0])) { send(exchange, 404, Map.of("error", "Resource not found")); return; }
      resource(exchange, method, parts[0], parts.length > 1 ? parts[1] : null, user);
    } catch (IllegalArgumentException ex) {
      send(exchange, 400, Map.of("error", ex.getMessage()));
    } catch (Exception ex) {
      ex.printStackTrace();
      send(exchange, 500, Map.of("error", "Unexpected server error"));
    }
  }

  private static void auth(HttpExchange ex, String method, String action) throws IOException {
    if (!"POST".equals(method)) { send(ex, 405, Map.of("error", "Method not allowed")); return; }
    Map<String, String> body = Json.object(readBody(ex));
    switch (action) {
      case "register" -> {
        required(body, "name", "email", "password", "role");
        String email = body.get("email").toLowerCase(Locale.ROOT);
        if (STORE.findBy("users", "email", email) != null) throw new IllegalArgumentException("Email already registered");
        String role = body.get("role").toUpperCase(Locale.ROOT);
        if (!Set.of("ADMIN", "VETERINARIAN", "RECEPTIONIST", "OWNER").contains(role)) throw new IllegalArgumentException("Invalid role");
        Map<String, String> account = new LinkedHashMap<>(body);
        account.put("email", email); account.put("role", role);
        account.put("passwordHash", Password.hash(body.get("password")));
        account.remove("password");
        Map<String, String> saved = STORE.create("users", account);
        saved.remove("passwordHash");
        send(ex, 201, saved);
      }
      case "login" -> {
        required(body, "email", "password");
        Map<String, String> account = STORE.findBy("users", "email", body.get("email").toLowerCase(Locale.ROOT));
        if (account == null || !Password.matches(body.get("password"), account.get("passwordHash"))) {
          send(ex, 401, Map.of("error", "Invalid credentials")); return;
        }
        send(ex, 200, Map.of("token", Token.create(account.get("id"), account.get("role")), "role", account.get("role"), "userId", account.get("id")));
      }
      case "recover" -> {
        required(body, "email");
        // Do not reveal whether an account exists.
        send(ex, 202, Map.of("message", "If the account exists, a recovery notification was queued"));
      }
      default -> send(ex, 404, Map.of("error", "Authentication action not found"));
    }
  }

  private static void resource(HttpExchange ex, String method, String resource, String id, User user) throws IOException {
    if (!allowed(user, resource, method)) { forbidden(ex); return; }
    if ("GET".equals(method) && id == null) { send(ex, 200, STORE.list(resource)); return; }
    if ("GET".equals(method)) {
      Map<String, String> record = STORE.get(resource, id);
      if (record == null) { send(ex, 404, Map.of("error", "Record not found")); return; }
      if ("OWNER".equals(user.role()) && !belongsToOwner(record, user.id())) { forbidden(ex); return; }
      send(ex, 200, record); return;
    }
    if ("POST".equals(method) && id == null) {
      Map<String, String> body = Json.object(readBody(ex));
      validate(resource, body);
      if ("OWNER".equals(user.role())) body.put("ownerUserId", user.id());
      Map<String, String> saved = STORE.create(resource, body);
      if ("payments".equals(resource) && saved.containsKey("amount")) {
        STORE.create("invoices", new LinkedHashMap<>(Map.of("paymentId", saved.get("id"), "amount", saved.get("amount"), "status", "ISSUED")));
      }
      inventoryAlert(saved, resource);
      send(ex, 201, saved); return;
    }
    if ("PUT".equals(method) && id != null) {
      Map<String, String> current = STORE.get(resource, id);
      if (current == null) { send(ex, 404, Map.of("error", "Record not found")); return; }
      if ("OWNER".equals(user.role()) && !belongsToOwner(current, user.id())) { forbidden(ex); return; }
      Map<String, String> saved = STORE.update(resource, id, Json.object(readBody(ex)));
      inventoryAlert(saved, resource);
      send(ex, 200, saved); return;
    }
    if ("DELETE".equals(method) && id != null) {
      if (!"ADMIN".equals(user.role())) { forbidden(ex); return; }
      if (!STORE.delete(resource, id)) { send(ex, 404, Map.of("error", "Record not found")); return; }
      send(ex, 204, null); return;
    }
    send(ex, 405, Map.of("error", "Method not allowed"));
  }

  private static boolean allowed(User user, String resource, String method) {
    if ("ADMIN".equals(user.role())) return true;
    if ("OWNER".equals(user.role())) return Set.of("pets", "appointments", "consultations", "vaccines", "treatments", "notifications", "invoices").contains(resource) && "GET".equals(method);
    if ("VETERINARIAN".equals(user.role())) return !Set.of("payments", "invoices", "users").contains(resource);
    return !Set.of("consultations", "vaccines", "treatments", "allergies", "hospitalizations", "users").contains(resource);
  }

  private static boolean belongsToOwner(Map<String, String> record, String userId) {
    return userId.equals(record.get("ownerUserId")) || userId.equals(record.get("ownerId"));
  }

  private static void validate(String resource, Map<String, String> body) {
    if ("pets".equals(resource)) required(body, "name", "species", "ownerId");
    if ("appointments".equals(resource)) required(body, "petId", "date", "time");
    if ("consultations".equals(resource)) required(body, "petId", "diagnosis");
    if ("payments".equals(resource)) required(body, "amount", "method");
  }

  private static void inventoryAlert(Map<String, String> record, String resource) {
    if (!"inventory".equals(resource)) return;
    try {
      int quantity = Integer.parseInt(record.getOrDefault("quantity", "0"));
      int minimum = Integer.parseInt(record.getOrDefault("minimumStock", "0"));
      if (quantity <= minimum) STORE.create("notifications", new LinkedHashMap<>(Map.of("type", "LOW_STOCK", "message", "Low stock: " + record.getOrDefault("name", record.get("id")), "inventoryId", record.get("id"))));
    } catch (NumberFormatException ignored) { }
  }

  private static void dashboard(HttpExchange ex) throws IOException {
    Map<String, Object> report = new LinkedHashMap<>();
    for (String resource : RESOURCES) report.put(resource, STORE.list(resource).size());
    report.put("generatedAt", Instant.now().toString());
    send(ex, 200, report);
  }

  private static User authenticate(HttpExchange ex) {
    String header = ex.getRequestHeaders().getFirst("Authorization");
    if (header == null || !header.startsWith("Bearer ")) return null;
    return Token.verify(header.substring(7));
  }
  private static void required(Map<String, String> map, String... keys) { for (String key : keys) if (map.get(key) == null || map.get(key).isBlank()) throw new IllegalArgumentException("Missing required field: " + key); }
  private static void forbidden(HttpExchange ex) throws IOException { send(ex, 403, Map.of("error", "Insufficient permissions")); }
  private static String readBody(HttpExchange ex) throws IOException { return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8); }
  private static void send(HttpExchange ex, int status, Object body) throws IOException {
    if (status == 204) { ex.sendResponseHeaders(204, -1); return; }
    byte[] bytes = Json.value(body).getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    ex.sendResponseHeaders(status, bytes.length);
    try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
  }
  private static void cors(HttpExchange ex) {
    ex.getResponseHeaders().set("Access-Control-Allow-Origin", CORS_ORIGIN);
    ex.getResponseHeaders().set("Vary", "Origin");
    ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
    ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  }

  private record User(String id, String role) { boolean has(String... roles) { return Set.of(roles).contains(role); } }

  private static final class Store {
    private final Path file; private Map<String, List<Map<String, String>>> data;
    Store(Path file) { this.file = file; this.data = load(); }
    @SuppressWarnings("unchecked") private Map<String, List<Map<String, String>>> load() {
      if (!Files.exists(file)) return new HashMap<>();
      try (ObjectInputStream in = new ObjectInputStream(Files.newInputStream(file))) { return (Map<String, List<Map<String, String>>>) in.readObject(); }
      catch (Exception ignored) { return new HashMap<>(); }
    }
    synchronized List<Map<String, String>> list(String resource) {
      return data.getOrDefault(resource, List.of()).stream()
          .<Map<String, String>>map(LinkedHashMap::new).toList();
    }
    synchronized Map<String, String> get(String resource, String id) { return list(resource).stream().filter(r -> id.equals(r.get("id"))).findFirst().orElse(null); }
    synchronized Map<String, String> findBy(String resource, String key, String value) { return list(resource).stream().filter(r -> value.equals(r.get(key))).findFirst().orElse(null); }
    synchronized Map<String, String> create(String resource, Map<String, String> fields) { Map<String, String> item = new LinkedHashMap<>(fields); item.put("id", UUID.randomUUID().toString()); item.put("createdAt", Instant.now().toString()); data.computeIfAbsent(resource, r -> new ArrayList<>()).add(item); save(); return new LinkedHashMap<>(item); }
    synchronized Map<String, String> update(String resource, String id, Map<String, String> fields) { for (Map<String, String> item : data.getOrDefault(resource, List.of())) if (id.equals(item.get("id"))) { fields.remove("id"); fields.remove("createdAt"); item.putAll(fields); item.put("updatedAt", Instant.now().toString()); save(); return new LinkedHashMap<>(item); } return null; }
    synchronized boolean delete(String resource, String id) { boolean removed = data.getOrDefault(resource, List.of()).removeIf(r -> id.equals(r.get("id"))); if (removed) save(); return removed; }
    private void save() { try { Files.createDirectories(file.getParent()); try (ObjectOutputStream out = new ObjectOutputStream(Files.newOutputStream(file))) { out.writeObject(data); } } catch (IOException e) { throw new IllegalStateException("Could not persist data", e); } }
  }

  private static final class Password {
    private static final SecureRandom RANDOM = new SecureRandom();
    static String hash(String password) { byte[] salt = new byte[16]; RANDOM.nextBytes(salt); return Base64.getEncoder().encodeToString(salt) + ":" + hex(hmac(salt, password)); }
    static boolean matches(String password, String stored) { String[] p = stored.split(":", 2); return p.length == 2 && hex(hmac(Base64.getDecoder().decode(p[0]), password)).equals(p[1]); }
  }
  private static final class Token {
    static String create(String id, String role) { String payload = id + ":" + role + ":" + (Instant.now().getEpochSecond() + 28800); String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8)); return encoded + "." + hex(hmac(SECRET.getBytes(StandardCharsets.UTF_8), encoded)); }
    static User verify(String token) { try { String[] p = token.split("\\.", 2); if (p.length != 2 || !hex(hmac(SECRET.getBytes(StandardCharsets.UTF_8), p[0])).equals(p[1])) return null; String[] body = new String(Base64.getUrlDecoder().decode(p[0]), StandardCharsets.UTF_8).split(":", 3); return body.length == 3 && Long.parseLong(body[2]) >= Instant.now().getEpochSecond() ? new User(body[0], body[1]) : null; } catch (Exception e) { return null; } }
  }
  private static byte[] hmac(byte[] key, String text) { try { Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256")); return mac.doFinal(text.getBytes(StandardCharsets.UTF_8)); } catch (Exception e) { throw new IllegalStateException(e); } }
  private static String hex(byte[] bytes) { StringBuilder b = new StringBuilder(); for (byte v : bytes) b.append(String.format("%02x", v)); return b.toString(); }

  /** Small JSON codec for flat request objects and API responses. */
  private static final class Json {
    static Map<String, String> object(String json) {
      if (json == null || json.isBlank()) return new LinkedHashMap<>();
      String s = json.trim(); if (!s.startsWith("{") || !s.endsWith("}")) throw new IllegalArgumentException("A JSON object is required");
      Map<String, String> out = new LinkedHashMap<>(); int i = 1;
      while (i < s.length() - 1) { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; if (i < s.length() && s.charAt(i) == ',') { i++; continue; } if (i >= s.length()-1) break; String[] key = quoted(s, i); i = Integer.parseInt(key[1]); while (Character.isWhitespace(s.charAt(i)) || s.charAt(i)==':') i++; String value; if (s.charAt(i)=='\"') { String[] v=quoted(s,i); value=v[0]; i=Integer.parseInt(v[1]); } else { int end=i; while(end<s.length()-1 && s.charAt(end)!=',') end++; value=s.substring(i,end).trim(); i=end; } out.put(key[0], value); }
      return out;
    }
    static String[] quoted(String s, int start) { if (s.charAt(start) != '\"') throw new IllegalArgumentException("JSON keys must be strings"); StringBuilder b=new StringBuilder(); int i=start+1; while(i<s.length()) { char c=s.charAt(i++); if(c=='\"') return new String[]{b.toString(), String.valueOf(i)}; if(c=='\\' && i<s.length()) c=s.charAt(i++); b.append(c); } throw new IllegalArgumentException("Unclosed JSON string"); }
    static String value(Object o) { if (o == null) return ""; if (o instanceof Map<?,?> m) { StringJoiner j=new StringJoiner(",","{","}"); for(var e:m.entrySet()) j.add(string(e.getKey().toString())+":"+value(e.getValue())); return j.toString(); } if(o instanceof Collection<?> c) { StringJoiner j=new StringJoiner(",","[","]"); for(Object x:c) j.add(value(x)); return j.toString(); } if(o instanceof Number || o instanceof Boolean) return o.toString(); return string(o.toString()); }
    static String string(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""; }
  }
}
