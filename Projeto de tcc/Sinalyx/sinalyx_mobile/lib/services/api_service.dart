import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../models/user_model.dart';

class ApiService {
  // localhost: Windows desktop, Web, iOS Simulator
  // 10.0.2.2: emulador Android
  // IP do PC (ex: 192.168.x.x): dispositivo físico Android/iOS
  static const String _baseUrl = 'http://192.168.1.6:8000';

  static Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('auth_token');
  }

  static Future<void> setToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('auth_token', token);
  }

  static Future<void> clearToken() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('auth_token');
  }

  static Future<Map<String, String>> _authHeaders() async {
    final token = await getToken();
    return {
      'Content-Type': 'application/json',
      if (token != null) 'Authorization': 'Bearer $token',
    };
  }

  // ─── AUTH ────────────────────────────────────────────────────────────────

  static Future<Map<String, dynamic>> login(
      String email, String password) async {
    final response = await http.post(
      Uri.parse('$_baseUrl/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (response.statusCode == 200) {
      final token = data['data']['access_token'] as String;
      await setToken(token);
      return data['data']['user'] as Map<String, dynamic>;
    }
    throw Exception(data['detail']?['message'] ?? 'Credenciais inválidas.');
  }

  // ─── USERS CRUD ──────────────────────────────────────────────────────────

  /// [READ] Lista todos os usuários
  static Future<List<UserModel>> listUsers() async {
    final headers = await _authHeaders();
    final response = await http.get(
      Uri.parse('$_baseUrl/admin/users?limit=100'),
      headers: headers,
    );
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final users = data['data']['users'] as List<dynamic>;
      return users
          .map((u) => UserModel.fromJson(u as Map<String, dynamic>))
          .toList();
    }
    throw Exception('Erro ao listar usuários: ${response.statusCode}');
  }

  /// [CREATE] Cria um novo usuário
  static Future<UserModel> createUser({
    required String name,
    required String email,
    required String password,
    String role = 'user',
  }) async {
    final headers = await _authHeaders();
    final response = await http.post(
      Uri.parse('$_baseUrl/admin/users'),
      headers: headers,
      body: jsonEncode({
        'name': name,
        'email': email,
        'password': password,
        'role': role,
        'is_active': true,
      }),
    );
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (response.statusCode == 200 || response.statusCode == 201) {
      return UserModel.fromJson(data['data']['user'] as Map<String, dynamic>);
    }
    throw Exception(data['detail']?['message'] ?? 'Erro ao criar usuário.');
  }

  /// [UPDATE] Atualiza dados de um usuário
  static Future<UserModel> updateUser({
    required int userId,
    required String name,
    required String email,
    required String role,
  }) async {
    final headers = await _authHeaders();
    final response = await http.put(
      Uri.parse('$_baseUrl/admin/users/$userId'),
      headers: headers,
      body: jsonEncode({'name': name, 'email': email, 'role': role}),
    );
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (response.statusCode == 200) {
      return UserModel.fromJson(data['data']['user'] as Map<String, dynamic>);
    }
    throw Exception(data['detail']?['message'] ?? 'Erro ao atualizar usuário.');
  }

  /// [DELETE] Remove um usuário
  static Future<void> deleteUser(int userId) async {
    final headers = await _authHeaders();
    final response = await http.delete(
      Uri.parse('$_baseUrl/admin/users/$userId'),
      headers: headers,
    );
    if (response.statusCode != 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      throw Exception(data['detail']?['message'] ?? 'Erro ao deletar usuário.');
    }
  }

  // ─── DASHBOARD ───────────────────────────────────────────────────────────

  static Future<Map<String, dynamic>> getDashboardSummary() async {
    final headers = await _authHeaders();
    final response = await http.get(
      Uri.parse('$_baseUrl/dashboard/summary'),
      headers: headers,
    );
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      return data['data'] as Map<String, dynamic>? ?? {};
    }
    return {};
  }
}
