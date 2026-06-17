"""
sysmetrics.py — Raspberry Pi sistem metriklerini toplar (CPU, RAM, sıcaklık...).

Yalnızca Python standart kütüphanesi + Linux /proc & /sys kullanır; ek pip
paketi (psutil vb.) GEREKMEZ — Pi'de yeni kurulum yapmadan çalışır. Bu, projenin
"hafif / Pi-dostu" ilkesiyle (bkz. R-02 donanım kısıtı) uyumludur.

Linux dışı ortamda (örn. Windows geliştirme makinesi) bozulmadan çalışır;
okunamayan alanlar için None döner.

Kullanım:
    from sysmetrics import SysMetrics
    sm = SysMetrics()
    data = sm.read()   # {"cpu_percent": 23.4, "temp_c": 51.2, ...}
"""

import os
import socket
import time
import shutil


class SysMetrics:
    """Periyodik çağrılır; CPU% iki çağrı arasındaki /proc/stat farkından hesaplanır."""

    def __init__(self):
        self._prev_cpu = self._read_cpu_times()
        self._hostname = socket.gethostname()

    # ── CPU ──
    @staticmethod
    def _read_cpu_times():
        """(toplam, boşta) jiffy sayaçları — /proc/stat ilk satırı."""
        try:
            with open("/proc/stat") as f:
                fields = f.readline().split()[1:]
            vals = [float(x) for x in fields]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0.0)  # idle + iowait
            return sum(vals), idle
        except Exception:
            return None

    def _cpu_percent(self):
        cur, prev = self._read_cpu_times(), self._prev_cpu
        self._prev_cpu = cur
        if not cur or not prev:
            return None
        dt, di = cur[0] - prev[0], cur[1] - prev[1]
        if dt <= 0:
            return None
        return round(max(0.0, min(100.0, 100.0 * (dt - di) / dt)), 1)

    @staticmethod
    def _cpu_freq_mhz():
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
                return round(int(f.read().strip()) / 1000.0)  # kHz -> MHz
        except Exception:
            return None

    # ── Bellek ──
    @staticmethod
    def _mem():
        """(yüzde, kullanılan_MB, toplam_MB)."""
        try:
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        info[parts[0]] = int(parts[1].strip().split()[0])  # kB
            total = info.get("MemTotal", 0)
            avail = info.get("MemAvailable", info.get("MemFree", 0))
            used = max(total - avail, 0)
            pct = round(100.0 * used / total, 1) if total else None
            return pct, round(used / 1024.0), round(total / 1024.0)
        except Exception:
            return None, None, None

    # ── Sıcaklık ──
    @staticmethod
    def _temp_c():
        try:
            with open("/sys/class/thermal/thermal_zone0/temp") as f:
                return round(int(f.read().strip()) / 1000.0, 1)
        except Exception:
            return None

    # ── Yük / disk / uptime ──
    @staticmethod
    def _loadavg():
        try:
            return [round(x, 2) for x in os.getloadavg()]
        except Exception:
            return [None, None, None]

    @staticmethod
    def _disk():
        """(yüzde, kullanılan_GB, toplam_GB) — kök bölüm."""
        try:
            u = shutil.disk_usage("/")
            pct = round(100.0 * u.used / u.total, 1) if u.total else None
            return pct, round(u.used / 1e9, 1), round(u.total / 1e9, 1)
        except Exception:
            return None, None, None

    @staticmethod
    def _uptime_s():
        try:
            with open("/proc/uptime") as f:
                return int(float(f.read().split()[0]))
        except Exception:
            return None

    def read(self) -> dict:
        """Tüm metrikleri tek sözlükte döndür."""
        mem_pct, mem_used, mem_total = self._mem()
        disk_pct, disk_used, disk_total = self._disk()
        load = self._loadavg()
        return {
            "hostname": self._hostname,
            "cpu_percent": self._cpu_percent(),
            "cpu_count": os.cpu_count(),
            "cpu_freq_mhz": self._cpu_freq_mhz(),
            "load1": load[0], "load5": load[1], "load15": load[2],
            "mem_percent": mem_pct, "mem_used_mb": mem_used, "mem_total_mb": mem_total,
            "temp_c": self._temp_c(),
            "disk_percent": disk_pct, "disk_used_gb": disk_used, "disk_total_gb": disk_total,
            "uptime_s": self._uptime_s(),
            "ts_epoch": time.time(),
        }


if __name__ == "__main__":
    import json
    sm = SysMetrics()
    time.sleep(1)  # CPU% için ilk fark
    print(json.dumps(sm.read(), indent=2))
