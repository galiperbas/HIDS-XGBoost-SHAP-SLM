# Uç Cihazlarda Çalışan, SHAP Açıklanabilirlik ve Chatbot Entegreli Saldırı Tespit Sistemi

![Sistem Mimarisi: VMware üzerinde çalışan iki sanal sunucu (simülsayon ortamı), çevrimiçi gösterge paneli/monitörü (relay sunucu) ve uç cihaz/Raspberry Pi 4 bağlantısı](image-and-videos/image.jpg)

Bu proje, uç (edge) veya sis (fog) bilişim ağlarındaki (Örn: IoT ortamları, Raspberry Pi istasyonları vb.) tehditleri anlık olarak algılayabilmek amacıyla geliştirilen bir Siber Saldırı Tespit Sistemi (IDS) prototipidir. **Saldırı tespiti (XGBoost) uç cihaz üzerinde lokal çalışır**; teknik bilgisi olmayan kullanıcıya yönelik doğal dilde açıklama katmanı ise bulut tabanlı bir dil modeli (Google Gemini API) ile sağlanır.

Sistem temel mimarisi: Siber saldırı sınıflandırmada yüksek başarıya sahip **XGBoost** algoritmasından, modelin karar gerekçelerini incelemek için oyun teorisine dayanan **SHAP (SHapley Additive exPlanations)** analizinden ve son kullanıcının ağ olaylarını sade dille sorgulayabildiği bir **chatbot** (bulut Gemini API) katmanından oluşmaktadır.

> **Not (akademik dürüstlük):** Cihaz-üstü çalışan kısım yalnızca tespit motorudur (XGBoost + kural tabanlı). Chatbot ve doğal dil açıklamaları bulut servisine (Gemini) istek atar — yani sistem tümüyle "buluttan bağımsız" değildir. Cihaz-içi bir Küçük Dil Modeli (SLM) bu sürümde **yoktur**; gelecek çalışma olarak konumlandırılmıştır.

---

## 🏗️ Sistem Mimarisi (Turkish)

Geliştirilen siber saldırı tespit sisteminin canlı test (Proof of Concept) süreçlerinin doğrulanması amacıyla sanal ve fiziksel bileşenlerin entegre edildiği hibrit bir test yatağı (testbed) ortamı kurulmuştur. Sistem bileşenlerinin topolojik dağılımı şu şekildedir:

* **Simülasyon ve Konak Donanım Altyapısı:** Ana konak (Host) bilgisayar olarak Windows 11 (16 GB RAM, NVIDIA GTX 1650) donanımı kullanılmış ve tip hypervisor olarak **VMware Workstation Pro 26H1** sanallaştırma katmanı konumlandırılmıştır.
* **Sanal Düğümler (Sanal Sunucular):** İzole simülasyon ortamında iki adet **Ubuntu Server 26.04 LTS** işletim sistemi ayağa kaldırılmıştır:
  * `SimVM-Normal`: Ağ üzerinde olağan trafik üretimi sağlamak amacıyla bünyesinde HTTP ve FTP gibi temel ağ servislerini barındıran kurban/hedef makine.
  * `SimVM-Attacker`: Hedef makineye siber saldırı vektörleri fırlatmakla görevli saldırgan makine.
* **Ağ Konfigürasyonu:** Sanal makinelerin ağ adaptörleri fiziksel ağ durumunu kopyalayacak şekilde **"Bridged Mode (with replicated physical network connection state)"** olarak yapılandırılmıştır. Düğümler dinamik olarak `192.168.137.X` DHCP alt ağ aralığından IP adresi almaktadır.
* **Donanım Entegrasyonu ve Canlı Çıkarım (Inference):** Saldırgan (`SimVM-Attacker`) ile hedef (`SimVM-Normal`) makineler arasındaki ağ hattına RJ45 Ethernet arayüzü üzerinden satır içi (**inline**) olarak fiziksel bir **Raspberry Pi 4 (8GB)** donanımı entegre edilmiştir. Bu uç cihaz üzerinde, Google Colab (T4 GPU) ortamında **CICIoT2023** veri setiyle eğitilmiş ve optimize edilmiş hafifletilmiş makine öğrenmesi modeli canlı ağ paketlerini dinleyerek anlık anomali tespiti gerçekleştirmektedir.
* **Merkezi Bildirim ve Bulut Dağıtımı:** Raspberry Pi 4 donanımı hat üzerinde herhangi bir anomali veya saldırı izi yakaladığı anda, yerel kaynakları yormamak adına veriyi harici bir **HTTP POST** webhook isteği (JSON payload) ile bulut tabanlı **Render** platformunda barındırılan web backend sunucusuna iletir ve geliştirilen gösterge panelinde (UI) gerçek zamanlı olarak görselleştirir.

---

## 🏗️ System Architecture (English)

To validate the real-time detection capabilities of the proposed intrusion detection system, a hybrid testbed combining virtual and physical network components has been implemented. The architectural layout consists of the following components:

* **Simulation & Host Infrastructure:** The core framework is deployed on a Windows 11 host (16 GB RAM, NVIDIA GTX 1650) utilizing **VMware Workstation Pro 26H1** as the primary type-2 hypervisor layer.
* **Virtual Nodes (Target & Attacker):** Two distinct **Ubuntu Server 26.04 LTS** virtual instances are configured within the isolated sandbox environment:
  * `SimVM-Normal`: The victim/target node running essential network services such as HTTP and FTP to generate baseline operational traffic.
  * `SimVM-Attacker`: The dedicated malicious node utilized to execute simulated cyber attack vectors against the target server.
* **Networking Environment:** The virtual network adapters are configured in **"Bridged Mode (with replicated physical network connection state)"** to seamlessly map onto the physical layer. The servers dynamically lease IP addresses within the `192.168.137.X` DHCP subnet range.
* **Hardware Integration & Inline Inference:** A physical **Raspberry Pi 4 (8GB)** hardware appliance is integrated **inline** between the attacker and target network streams via an RJ45 Ethernet interface. This edge device runs the lightweight anomaly detection model—previously trained on Google Colab (T4 GPU) using the **CICIoT2023** dataset—to perform real-time packet sniffing and zero-latency stream classification.
* **Central Alerting & Cloud Deployment:** Upon detecting an anomaly or exploit pattern, the Raspberry Pi 4 issues an asynchronous **HTTP POST** webhook request containing the transaction payload to a centralized web backend deployed on the **Render** cloud platform, reflecting the threat mitigation metrics onto a web user interface.

---

## 🏗️ Proje İş Paketleri (Project Work Packages)

Önerilen projenin yöntem mimarisi; “Veri Ön İşleme”, “XGBoost Model Eğitimi”, “SHAP Entegrasyonu ve Testleri”, “Yerel SLM Entegrasyonu” ve “Canlı Sistem Testleri ve Final Sürecine Hazırlık” olmak üzere beş iş paketinden oluşmaktadır. İlk 4 iş paketi, Şekil 1’de diyagrama karşılık gelmektedir. 5. iş paketi ise, bu mimarinin gerçek donanım kaynaklarına taşınması ve ürünleşmesi sürecini kapsamaktadır.

![Şekil 1: Proje Mimarisi Diyagramı](2242.jpg)

## 🌟 Temel Özellikler (Features)

* **Edge Cihaz Optimizasyonu:** Eğitilen XGBoost modeli ağaç sayısı ve derinliği sınırlanarak hafif tutulmuş (sıkıştırılmış joblib ~birkaç MB) ve Raspberry Pi 4 üzerinde çalışacak şekilde hedeflenmiştir. *(Pi üzerindeki gerçek çıkarım gecikmesi ölçülüp rapora eklenecektir.)*
* **Benchmark Model Başarımı:** CICIoT2023 veri setinin **test kümesinde** **~%99.6 Doğruluk (Accuracy)** ve **%99+ F1** elde edilmiştir (bkz. `models/model_meta.json`). *Bu değerler veri setinin test kümesine aittir; canlı testbed üzerindeki sistem başarımı ayrıca ölçülmektedir.*
* **Açıklanabilirlik (SHAP):** Eğitim aşamasında SHAP analizi ile modelin hangi özniteliklere ağırlık verdiği (küresel öznitelik önemi) beeswarm/bar grafikleriyle raporlanır. *(Her tespit için canlı, olay-bazlı SHAP açıklaması gelecek çalışmadır.)*
* **Hibrit Tespit:** Anlık kural tabanlı katman (port tarama, SYN flood, DoS, brute-force) + akış-bazlı XGBoost katmanı birlikte çalışır.
* **Sade Dilde Chatbot:** Dashboard üzerindeki chatbot, ağ olaylarını teknik olmayan kullanıcıya sade Türkçe ile açıklar (bulut Gemini API).

## 🚀 Öne Çıkan Başarımlar (Key Highlights)

* **Lokal Tespit:** Saldırı tespiti (XGBoost + kurallar) uç cihaz üzerinde çalışır; ham ağ trafiği buluta gönderilmez. *(Yalnızca tespit edilen olay özetleri relay sunucuya iletilir; chatbot kullanılırsa bu özetler Gemini'ye gider.)*
* **Veri Sızıntısı Önleyici Eğitim:** Ön işlemede train/test ayrımı ölçekleme ve SMOTE'tan **önce** yapılarak veri sızıntısı (data leakage) engellenir.
* **Kural Katmanı:** Port tarama, SYN flood, genel flood ve SSH/FTP brute-force gibi gürültülü saldırı örüntülerini anlık yakalar.

## ⚙️ Nasıl Çalıştırılır? (How to Run)

Projenin defter yapısı bir Google Colab (Jupyter) ortamında anında baştan aşağı koşacak şekilde tasarlanmıştır:

1. Bir **Google Colab** oturumu başlatın. 
2. `hids.ipynb` defterini (script'ini) çalışma diskinize bağlayın/aktarın.
3. Çalışma süresince gerekli veri setlerini indirme işlemi Kaggle Hub vasıtasıyla kendi kendine yapılacaktır.
4. Menü sekmelerinden `Runtime -> Run all` (Çalışma Zamanı -> Tümünü Çalıştır) butonuna basın. (İlk çalıştırmada ortalama döngü 2-3 dakika sürebilir).
5. Eğitim çıktıları (`xgboost_ciciot2023.joblib`, `scaler.joblib`, `feature_names.json`, `model_meta.json`) `models/` klasörüne kopyalanır ve canlı sensör (`hids-sensor/`) bu modeli yükler.