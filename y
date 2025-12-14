# إنشاء ملف .gitignore
cat > .gitignore << EOF
# ملفات النظام
.DS_Store
*.swp
*.swo
*~
\#*\#

# بايثون
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Termux
storage/
termux-backup/

# Reports
reports/*.txt
reports/*.json
!reports/.gitkeep

# Logs
*.log
logs/

# Configs
config/secrets.ini
config/api_keys.json

# IDE
.vscode/
.idea/
*.iml

# بيانات مؤقتة
temp/
tmp/
EOF
