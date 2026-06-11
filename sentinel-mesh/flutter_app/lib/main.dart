// main.dart — Sentinel Mesh Mobil Dashboard
//
// Raspberry Pi HIDS'ten gelen canlı saldırı tespitlerini gösterir.
// Bulut relay sunucusuna WebSocket ile bağlanır.
//
// Kurulum:
//   flutter create sentinel_app
//   pubspec.yaml'a ekle: web_socket_channel, fl_chart, intl
//   bu dosyayı lib/main.dart yerine koy
//   SERVER_URL'i kendi sunucu IP'nle değiştir
//   flutter run

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:fl_chart/fl_chart.dart';

// ⚠️ Kendi bulut sunucu IP'nle değiştir
const String SERVER_URL = "ws://10.0.2.2:9000/stream"; // emülatör için 10.0.2.2

void main() => runApp(const SentinelApp());

class SentinelApp extends StatelessWidget {
  const SentinelApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Sentinel Mesh',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark().copyWith(
        scaffoldBackgroundColor: const Color(0xFF0A0E14),
        primaryColor: const Color(0xFF00E5FF),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00E5FF),
          secondary: Color(0xFF40E56C),
          error: Color(0xFFFF5252),
        ),
      ),
      home: const DashboardScreen(),
    );
  }
}

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  WebSocketChannel? _channel;
  bool _connected = false;

  int _totalEvents = 0;
  int _anomalyCount = 0;
  int _criticalCount = 0;
  int _normalCount = 0;
  int _sensorsOnline = 0;

  final List<Map<String, dynamic>> _logs = [];
  Map<String, int> _attackDist = {};
  final List<String> _alerts = [];

  @override
  void initState() {
    super.initState();
    _connect();
  }

  void _connect() {
    try {
      _channel = WebSocketChannel.connect(Uri.parse(SERVER_URL));
      setState(() => _connected = true);
      _channel!.stream.listen(
        _onMessage,
        onDone: _onDisconnect,
        onError: (_) => _onDisconnect(),
      );
    } catch (e) {
      _onDisconnect();
    }
  }

  void _onDisconnect() {
    setState(() => _connected = false);
    Future.delayed(const Duration(seconds: 3), _connect);
  }

  void _onMessage(dynamic raw) {
    final msg = jsonDecode(raw as String);
    final type = msg['type'];

    setState(() {
      if (type == 'init') {
        final stats = msg['stats'] ?? {};
        _totalEvents = stats['total_events'] ?? 0;
        _anomalyCount = stats['anomaly_count'] ?? 0;
        _criticalCount = stats['critical_count'] ?? 0;
        _normalCount = stats['normal_count'] ?? 0;
        _sensorsOnline = stats['sensors_online'] ?? 0;
        _attackDist = Map<String, int>.from(msg['attack_distribution'] ?? {});
        final recent = msg['recent_logs'] as List? ?? [];
        _logs.clear();
        for (var e in recent) {
          _logs.add(Map<String, dynamic>.from(e));
        }
      } else if (type == 'event') {
        final e = Map<String, dynamic>.from(msg['data']);
        _logs.insert(0, e);
        if (_logs.length > 100) _logs.removeLast();
        _totalEvents++;
        if (e['label'] == 'ANOMALY') {
          _anomalyCount++;
          final at = e['attack_type'] ?? 'Unknown';
          _attackDist[at] = (_attackDist[at] ?? 0) + 1;
          if ((e['threat_score'] ?? 0) >= 70) _criticalCount++;
        } else {
          _normalCount++;
        }
      } else if (type == 'sensor_status') {
        _sensorsOnline = msg['online'] ?? 0;
      } else if (type == 'alert') {
        _alerts.insert(0, "${msg['title']}\n${msg['body']}");
        if (_alerts.length > 20) _alerts.removeLast();
        _showAlert(msg['title'] ?? 'Uyarı', msg['body'] ?? '');
      }
    });
  }

  void _showAlert(String title, String body) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('$title\n$body'),
      backgroundColor: const Color(0xFFFF5252),
      duration: const Duration(seconds: 4),
    ));
  }

  @override
  void dispose() {
    _channel?.sink.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF111722),
        title: Row(
          children: [
            const Icon(Icons.shield, color: Color(0xFF00E5FF), size: 22),
            const SizedBox(width: 8),
            const Text('SENTINEL MESH',
                style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 2)),
            const Spacer(),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: _connected
                    ? const Color(0xFF40E56C).withOpacity(0.15)
                    : const Color(0xFFFF5252).withOpacity(0.15),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Row(children: [
                Icon(Icons.circle,
                    size: 8,
                    color: _connected
                        ? const Color(0xFF40E56C)
                        : const Color(0xFFFF5252)),
                const SizedBox(width: 6),
                Text(_connected ? 'ONLINE' : 'OFFLINE',
                    style: const TextStyle(fontSize: 11)),
              ]),
            ),
          ],
        ),
      ),
      body: RefreshIndicator(
        onRefresh: () async => _connect(),
        child: ListView(
          padding: const EdgeInsets.all(12),
          children: [
            _buildSensorBanner(),
            const SizedBox(height: 12),
            _buildKpiGrid(),
            const SizedBox(height: 16),
            _buildAttackChart(),
            const SizedBox(height: 16),
            _buildLogList(),
          ],
        ),
      ),
    );
  }

  Widget _buildSensorBanner() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        gradient: LinearGradient(colors: [
          const Color(0xFF00E5FF).withOpacity(0.12),
          const Color(0xFF111722),
        ]),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF00E5FF).withOpacity(0.3)),
      ),
      child: Row(children: [
        const Icon(Icons.router, color: Color(0xFF00E5FF)),
        const SizedBox(width: 12),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('$_sensorsOnline Sensör Aktif',
              style: const TextStyle(
                  fontSize: 16, fontWeight: FontWeight.bold)),
          const Text('Raspberry Pi HIDS',
              style: TextStyle(fontSize: 11, color: Colors.white54)),
        ]),
        const Spacer(),
        Icon(Icons.circle,
            size: 10,
            color: _sensorsOnline > 0
                ? const Color(0xFF40E56C)
                : const Color(0xFFFF5252)),
      ]),
    );
  }

  Widget _buildKpiGrid() {
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 1.6,
      crossAxisSpacing: 10,
      mainAxisSpacing: 10,
      children: [
        _kpiCard('Toplam Olay', '$_totalEvents', Icons.analytics,
            const Color(0xFF00E5FF)),
        _kpiCard('Anomali', '$_anomalyCount', Icons.warning_amber,
            const Color(0xFFFFB74D)),
        _kpiCard('Kritik', '$_criticalCount', Icons.dangerous,
            const Color(0xFFFF5252)),
        _kpiCard('Normal', '$_normalCount', Icons.check_circle,
            const Color(0xFF40E56C)),
      ],
    );
  }

  Widget _kpiCard(String title, String value, IconData icon, Color color) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF111722),
        borderRadius: BorderRadius.circular(12),
        border: Border(left: BorderSide(color: color, width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            Text(title,
                style: const TextStyle(fontSize: 11, color: Colors.white54)),
            Icon(icon, color: color, size: 18),
          ]),
          Text(value,
              style: TextStyle(
                  fontSize: 28, fontWeight: FontWeight.bold, color: color)),
        ],
      ),
    );
  }

  Widget _buildAttackChart() {
    if (_attackDist.isEmpty) {
      return _panel('Saldırı Dağılımı',
          const Center(child: Padding(
            padding: EdgeInsets.all(20),
            child: Text('Henüz saldırı tespit edilmedi',
                style: TextStyle(color: Colors.white38)),
          )));
    }
    final entries = _attackDist.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    final maxVal = entries.first.value.toDouble();
    return _panel(
      'Saldırı Dağılımı',
      Column(
        children: entries.take(6).map((e) {
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Row(children: [
              SizedBox(
                  width: 90,
                  child: Text(e.key,
                      style: const TextStyle(fontSize: 11),
                      overflow: TextOverflow.ellipsis)),
              Expanded(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: e.value / maxVal,
                    minHeight: 14,
                    backgroundColor: const Color(0xFF1C2230),
                    valueColor: const AlwaysStoppedAnimation(
                        Color(0xFF00E5FF)),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Text('${e.value}',
                  style: const TextStyle(
                      fontSize: 12, fontWeight: FontWeight.bold)),
            ]),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildLogList() {
    return _panel(
      'Canlı Tespit Akışı',
      Column(
        children: _logs.take(30).map((log) {
          final score = log['threat_score'] ?? 0;
          final isAnomaly = log['label'] == 'ANOMALY';
          final color = score >= 70
              ? const Color(0xFFFF5252)
              : score >= 35
                  ? const Color(0xFFFFB74D)
                  : const Color(0xFF40E56C);
          return Container(
            margin: const EdgeInsets.symmetric(vertical: 3),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFF0A0E14),
              borderRadius: BorderRadius.circular(8),
              border: Border(left: BorderSide(color: color, width: 3)),
            ),
            child: Row(children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${log['source_ip'] ?? '?'} → ${log['destination_ip'] ?? '?'}',
                      style: const TextStyle(
                          fontSize: 12, fontFamily: 'monospace'),
                    ),
                    const SizedBox(height: 2),
                    Row(children: [
                      Text(log['attack_type'] ?? 'BENIGN',
                          style: TextStyle(
                              fontSize: 11,
                              color: color,
                              fontWeight: FontWeight.bold)),
                      const SizedBox(width: 8),
                      Text('[${log['method'] ?? '?'}]',
                          style: const TextStyle(
                              fontSize: 10, color: Colors.white38)),
                    ]),
                  ],
                ),
              ),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text('$score',
                    style: TextStyle(
                        color: color,
                        fontWeight: FontWeight.bold,
                        fontSize: 13)),
              ),
            ]),
          );
        }).toList(),
      ),
    );
  }

  Widget _panel(String title, Widget child) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF111722),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title.toUpperCase(),
              style: const TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1,
                  color: Color(0xFF00E5FF))),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}
