#!/data/data/com.termux/files/usr/bin/bash

# تحديث وتثبيت Python
pkg update -y && pkg upgrade -y
pkg install -y python python-pip

# إنشاء هيكل المشروع
mkdir -p utils

# إنشاء ملف logger.py
cat > utils/logger.py << 'EOF'
import logging

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)
EOF

# إنشاء requirements.txt صحيح
cat > requirements.txt << 'EOF'
requests
colorama
pyfiglet
termcolor
EOF

# تثبيت المتطلبات
pip install -r requirements.txt

echo "تم التثبيت بنجاح!"
echo "لتشغيل البرنامج: python3 src/main.py"
