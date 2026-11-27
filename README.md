# NET KALKAN v2 — başlangıç sürümü

## Özellikler
- Koyu, mobil uyumlu panel (iPhone/Android/bilgisayar tarayıcıları).
- Elle tek adres kontrolü.
- İzleme listesine adres ekleme ve listedekileri elle toplu kontrol.
- SQLite kayıt geçmişi.

## Bilinçli sınırlar
- Otomatik zamanlayıcı bu sürümde henüz etkin değildir; kalıcı arka plan görevi barındırma ortamında ayrıca yapılandırılmalıdır.
- İnternetin tamamını taramaz. Kaynak/alan adı keşfi, güvenilir ve izinli açık kaynak listeleri seçildikten sonra ayrı modül olarak eklenmelidir.
- Yalnızca herkese açık ana sayfaya tek istek gönderir; yönlendirmeleri takip etmez, giriş yapmaz, form göndermez, CAPTCHA aşmaz, özel panellere erişmez.
- Kelime eşleşmesi hukuki karar değildir.
- Otomatik resmî ihbar gönderimi yoktur.

## Yerelde çalıştırma
Python 3.11+
```bash
pip install -r requirements.txt
python app.py
```
Geliştirme sunucusunu internete açık şekilde kullanmayın.

## Yayına almadan önce zorunlu işler
1. `SECRET_KEY` değerini güçlü rastgele gizli değerle ayarlayın.
2. Kimlik doğrulama ve yönetici erişim kontrolü ekleyin.
3. HTTPS, hız sınırı, istek kotası ve güvenlik başlıkları ekleyin.
4. DNS yeniden bağlama/SSRF korumasını üretim seviyesinde güçlendirin; güvenli egress proxy kullanın.
5. Tarama görevlerini ayrı zamanlanmış worker üzerinden çalıştırın.
6. Sadece yasal ve herkese açık kaynakları kullanın; kaynak listesi ve veri saklama süresini belgeleyin.
