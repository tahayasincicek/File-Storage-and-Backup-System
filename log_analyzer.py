import json
import os

# JSON dosyasından kullanıcı verilerini yükleme
def load_user_data():
    data_file = "user_data.json"  # JSON dosyasının yolu
    if os.path.exists(data_file):
        with open(data_file, "r") as f:
            return json.load(f)
    return {}

# Kullanıcı verilerini kaydetme
def save_user_data(user_data):
    data_file = "user_data.json"
    with open(data_file, "w") as f:
        json.dump(user_data, f, indent=4)

# Tüm log dosyalarının listesini al
def get_log_files(log_directory="logs"):
    if not os.path.exists(log_directory):
        return []
    return [os.path.join(log_directory, f) for f in os.listdir(log_directory) if f.endswith(".txt")]

# Bir log dosyasını analiz et
def analyze_log_file(file_path, keywords):
    keyword_count_per_user = {}  # Kullanıcı bazında anahtar kelime sayımı
    anomalies = []
    username = "Unknown"  # Varsayılan kullanıcı adı
    shared_files = {}  # Kullanıcı başına paylaşılan dosya bilgisi

    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                # Kullanıcı adını doğrudan kontrol et
                if "Username:" in line:
                    parts = line.split("Username:")
                    if len(parts) > 1:
                        username = parts[1].strip()  # Kullanıcı adını temizle

                # Anahtar kelimeleri kontrol et
                for keyword in keywords:
                    if keyword in line:
                        # Kullanıcı bazında anahtar kelime sayımını artır
                        if username not in keyword_count_per_user:
                            keyword_count_per_user[username] = {}
                        if keyword not in keyword_count_per_user[username]:
                            keyword_count_per_user[username][keyword] = 1
                        keyword_count_per_user[username][keyword] += 1

                # Dosya paylaşımını kontrol et
                if "SHARE_FILE" in file_path and "FAILED: Duplicate share attempt" in line:
                    parts = line.split("FAILED: Duplicate share attempt")
                    if len(parts) > 1:
                        file_info = parts[1].strip()
                        if username not in shared_files:
                            shared_files[username] = set()
                        # Aynı dosya farklı kullanıcılarla mı paylaşılmış kontrol et
                        if file_info in shared_files[username]:
                            anomalies.append((file_path, username, file_info))
                        shared_files[username].add(file_info)

                # Yedekleme veya senkronizasyon işlemleri sırasında kesilme kontrolü
                if "AUTO_SYNC" in file_path:
                    if "ERROR" in line or "FAILED" in line:
                        anomalies.append((file_path, "Unexpected interruption during AUTO_SYNC"))

    except FileNotFoundError:
        print(f"Log file not found: {file_path}")

    # 3'ten fazla bulunan anahtar kelimeleri anomali olarak kaydet
    for user, counts in keyword_count_per_user.items():
        for keyword, count in counts.items():
            if count > 3:
                anomalies.append((file_path, count, keyword, user))

    return anomalies


# Log dosyalarını analiz etmek için anahtar kelimeler
log_keywords = {
    "AUTO_SYNC": ["ERROR", "FAILED"],
    "LOGIN": ["FAILED login", "unauthorized access"],
    "REGISTER": ["FAILED", "username already taken", "password too short", "invalid role"],
    "BACKUP": ["ERROR", "FAILED"],
    "FILE_MODIFIED": ["ERROR", "FAILED"],
    "UPLOAD_FILE": ["SUCCESS"],
    "SHARE_FILE": ["FAILED: Duplicate share attempt"],
    "REQUEST_PASSWORD_CHANGE": ["SUCCES"],
}

# Tüm log dosyalarını analiz et
def analyze_all_logs():
    anomalies_detected = []
    log_files = get_log_files()
    for log_file in log_files:
        operation_code = os.path.splitext(os.path.basename(log_file))[0]
        keywords = log_keywords.get(operation_code, [])
        if keywords:
            anomalies = analyze_log_file(log_file, keywords)
            anomalies_detected.extend(anomalies)  # Anomalileri listeye ekle
    return anomalies_detected

# Kullanıcıları anormallik konusunda bilgilendiren fonksiyon
def notify_anomaly(user_data, anomalies):
    for anomaly in anomalies:
        if len(anomaly) == 4:  # Anahtar kelime anormallikleri
            log_file, count, keyword, username = anomaly
            if username in user_data:
                notification = f"Anomaly detected in {log_file}: {count} instances of '{keyword}' found."
                user_data[username]["notifications"].append(notification)

        elif len(anomaly) == 3:  # Yetkisiz paylaşım anormallikleri
            log_file, username, file_info = anomaly
            if username in user_data:
                notification = f"Anomaly detected in {log_file}: Duplicate share attempt for file '{file_info}'."
                user_data[username]["notifications"].append(notification)

        elif len(anomaly) == 2:  # AUTO_SYNC anormallikleri
            log_file, detail = anomaly
            for user in user_data:
                notification = f"Anomaly detected in {log_file}: {detail}."
                user_data[user]["notifications"].append(notification)

    # Güncellenen kullanıcı verilerini kaydedelim
    save_user_data(user_data)




# Log dosyasına rapor yazma
def log_to_file(anomalies, log_filename="anomaly_report.txt"):
    with open(log_filename, "a") as log_file:
        if not anomalies:
            log_file.write("No anomalies detected.\n")
            return

        log_file.write("\n### Anomaly Report ###\n")
        for anomaly in anomalies:
            if len(anomaly) == 4:  # Anahtar kelime anormallikleri
                log_file.write(f"Anomaly detected in {anomaly[0]}:\n")
                log_file.write(f"Detail: {anomaly[1]} instances of '{anomaly[2]}'\n")
                log_file.write(f"Username: {anomaly[3]}\n\n")
            elif len(anomaly) == 3:  # Yetkisiz paylaşım anormallikleri
                log_file.write(f"Anomaly detected in {anomaly[0]}:\n")
                log_file.write(f"Detail: Duplicate share attempt\n")
                log_file.write(f"Username: {anomaly[1]}\n\n") 
            elif len(anomaly) == 2:  # AUTO_SYNC ile ilgili anomaliler
                log_file.write(f"Anomaly detected in {anomaly[0]}:\n")
                log_file.write(f"Detail: {anomaly[1]}\n\n")

def report_anomalies(anomalies, user_data):
    if not anomalies:
        print("No anomalies detected.")
        return

    print("\n### Anomaly Report ###\n")
    for anomaly in anomalies:
        if len(anomaly) == 4:  # Anahtar kelime anormallikleri
            print(f"Anomaly detected in {anomaly[0]}:")
            print(f"Detail: {anomaly[1]} instances of '{anomaly[2]}'")
            print(f"Username: {anomaly[3]}\n")
        elif len(anomaly) == 3:  # Yetkisiz paylaşım anormallikleri
            print(f"Anomaly detected in {anomaly[0]}:")
            print(f"Detail: Duplicate share attempt")
            print(f"Username: {anomaly[1]}\n")
        elif len(anomaly) == 2 and "AUTO_SYNC" in anomaly[0]:  # Sadece AUTO_SYNC ile ilgili anomaliler burada işlenir
            print(f"Anomaly detected in {anomaly[0]}:")
            print(f"Detail: {anomaly[1]}\n")

    # Log dosyasına raporu yaz
    log_to_file(anomalies)

# Fonksiyonun çalıştırılacağı yer
def analyze_logs_in_project():
    # Veriyi yükle
    user_data = load_user_data()

    # Logları analiz et
    anomalies = analyze_all_logs()

    # Anormallikleri raporla ve kullanıcıları bilgilendir
    report_anomalies(anomalies, user_data)