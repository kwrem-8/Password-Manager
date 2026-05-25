# password-manager

AES-256-GCM şifreleme ile yerel şifre yöneticisi. Ana şifren olmadan hiçbir veri okunamaz.

## Güvenlik

- AES-256-GCM — endüstri standardı simetrik şifreleme
- PBKDF2-HMAC-SHA256 — 600.000 iterasyon ile anahtar türetme
- Her kayıt rastgele nonce ile şifrelenir
- Tüm veri tek şifreli dosyada saklanır (`~/.pwvault`)
- 5 dakika hareketsizlikte otomatik kilitlenir
- Şifre kopyalandıktan 15 saniye sonra panodan temizlenir
- İnternete bağlantı yok, her şey cihazda kalır

## Özellikler

- Ana şifre ile kasa oluştur ve aç
- Site, kullanıcı adı, şifre, not alanları
- Güçlü rastgele şifre üretici
- Şifreyi tek tıkla panoya kopyala
- İsim veya kullanıcı adı ile arama
- Kayıt ekle, düzenle, sil

## Çalıştırma

```bash
pip install cryptography
python password_manager.py
```

## .exe olarak derleme

```bash
build.bat
```

`dist/password-manager.exe` oluşur.

## Lisans

MIT
