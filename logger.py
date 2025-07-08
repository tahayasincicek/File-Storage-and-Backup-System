from datetime import datetime
import os

# Log dosyalarını saklamak için dizin
log_directory = "logs"

# Log dosyasını kaydetme
def log_event(category, operation_code, status_code, username=None, source_dir=None, backup_size=None):
    # Her işlem için ayrı bir log dosyası oluşturulacak
    log_file = os.path.join(log_directory, f"{operation_code}.txt")
    
    # Log dosyasının bulunduğu dizin yoksa oluştur
    os.makedirs(log_directory, exist_ok=True)
    
    with open(log_file, "a") as log:
        start_time = datetime.now()
        log.write(f"Category: {category}\n")
        log.write(f"Start Time: {start_time}\n")
        log.write(f"Operation Code: {operation_code}\n")
        log.write(f"Status Code: {status_code}\n")
        if username:
            log.write(f"Username: {username}\n")
        if source_dir:
            log.write(f"Source Directory: {source_dir}\n")
        if backup_size is not None:
            log.write(f"Backup Size: {backup_size} bytes\n")
        log.write(f"End Time: {datetime.now()}\n")
        log.write("\n" + "-" * 50 + "\n")
