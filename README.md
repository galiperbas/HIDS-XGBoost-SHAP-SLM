# Uç Cihazlarda Çalışan, SHAP Açıklanabilirlik ve SLM Entegreli Saldırı Tespit Sistemi


Bu proje, uç (edge) veya sis (fog) bilişim ağlarındaki (Örn: IoT ortamları, Raspberry Pi istasyonları vb.) tehditleri anlık olarak algılayabilmek amacıyla, bulut bağımlılığı olmayan on-device (cihaz-üstü) bir Siber Saldırı Tespit Sistemi (IDS) prototipidir. 

Sistem temel mimarisi: Siber saldırı sınıflandırmada yüksek başarıya sahip **XGBoost** algoritmasından, kararların şeffaf izlenebilirliği için oyun teorisine dayanan **SHAP (SHapley Additive exPlanations)** mimarisinden ve analiste teknik verileri doğal dilde açıklayabilen Küçük Dil Modeli (**SLM**, Phi-3-mini) entegrasyonundan oluşmaktadır.

## 🏗️ Proje Mimarisi (Project Architecture)

Önerilen projenin yöntem mimarisi; “Veri Ön İşleme”, “XGBoost Model Eğitimi”, “SHAP Entegrasyonu ve Testleri”, “Yerel SLM Entegrasyonu” ve “Canlı Sistem Testleri ve Final Sürecine Hazırlık” olmak üzere beş iş paketinden oluşmaktadır. İlk 4 iş paketi, Şekil 1’de diyagrama karşılık gelmektedir. 5. iş paketi ise, bu mimarinin gerçek donanım kaynaklarına taşınması ve ürünleşmesi sürecini kapsamaktadır.

![Şekil 1: Proje Mimarisi Diyagramı](2242.jpg)

## 🌟 Temel Özellikler (Features)

* **Edge Cihaz Optimizasyonu:** Kurulan ML iterasyonu <5 MB seviyesinde sıkıştırılmıştır ve gelen sistem/ağ telemetrilerini cihaz üzerinde cihaz başı 10 ms (milisaniye) hızlarda derecelendirir.
* **Yüksek Doğruluk Oranı:** Modern IoT tehditlerini barındıran ToN_IoT Network veri tabanında, zafiyet/alarm kaçırma senaryolarını önlemek amacıyla **%98+ Doğruluk (Accuracy)** ve **%99+ Duyarlılık (Recall)** gibi oldukça başarılı oranlara imza atmıştır.
* **Şeffaf Tehdit Teşhisi (Kara Kutu Çözümü):** Ağ saldırı uyarılarını "var" ya da "yok" şeklinde vermez. İçerdiği SHAP Katmanı ile birlikte tahmini tetikleyen "Nedenleri" bulur ve "Örneğin: Bu saldırı, Port 4444 tabanlı bir ters bağlantıdır" şeklinde nedensel ağırlıkları ekrana basar.
* **Dil Modeli Destekli Uyarı Sistemi (Natural Language Alerts):** Modülden dönen yoğun matematiksel SHAP sayılarını; Olay Müdahale Uzmanlarının (SOC/Incident Response) anlayıp anında aksiyon komutları (Playbook) yazabileceği özet doğal insan diline çevirir.

## 🚀 Öne Çıkan Başarımlar (Key Highlights)

* **Veri Egemenliği/Gizliliği:** Güvenlik tespitleri esnasında buluta bağımlı kalınmaz, lokal çalışır. Veri sızıntısının önüne geçer.
* **Alarm Yorgunluğu Çözümlemesi:** Yanlış alarmların (False Positive) sayısını minimize edecek stabil eğrilere (PR, ROC-AUC) sahiptir.
* **Kesintisiz Veri Akışı (Data Pipeline):** IP tabanlı "ezbercilikleri" ve hedef bağımlılıklarını önleyen baştan aşağı izole edilmiş Veri Sızıntısı (Data Leakage) önleyici bir veri ön işleme filtresine sahiptir.
* Model port-bazlı bilindik Metasploit tarzı zararlı davranış modellerini tanır ve yakalar.

## ⚙️ Nasıl Çalıştırılır? (How to Run)

Projenin defter yapısı bir Google Colab (Jupyter) ortamında anında baştan aşağı koşacak şekilde tasarlanmıştır:

1. Bir **Google Colab** oturumu başlatın. 
2. `hids.ipynb` defterini (script'ini) çalışma diskinize bağlayın/aktarın.
3. Çalışma süresince gerekli ToN_IoT tabanlı veriyi indirme işlemi Kaggle Hub vasıtasıyla kendi kendine yapılacaktır.
4. Menü sekmelerinden `Runtime -> Run all` (Çalışma Zamanı -> Tümünü Çalıştır) butonuna basın. (İlk çalıştırmada ortalama döngü 2-3 dakika sürebilir).
5. *(İsteğe Bağlı)* Defterin sonundaki doğal dil modelinin (Phi-3-mini) mock testten gerçeğine (canlı inference) geçişini sağlamak için **Colab T4 GPU** desteği sekmesini aktif edin ve hücre başındaki yorum satırlarını (slash-out) kaldırın.
