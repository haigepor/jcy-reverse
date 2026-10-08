#!/usr/bin/env bash
# 在临时目录生成一份「标准 Capacitor 7 安卓工程」，用于提取我们手工骨架缺失的模板文件。
set -euo pipefail

# 用 mktemp 而不是硬编码用户目录（Git Bash 的 /tmp 已映射到系统临时目录，npm 可正常处理）
GEN="$(mktemp -d -t jcy_capgen.XXXXXX)"
rm -rf "$GEN"
mkdir -p "$GEN/www"
cd "$GEN"

echo "=== 1. package.json ==="
npm init -y >/dev/null
node -e "const f='package.json',p=require('./'+f);p.name='jcy-capgen';delete p.scripts;require('fs').writeFileSync(f,JSON.stringify(p,null,2))"

echo "=== 2. capacitor.config.json ==="
cat > capacitor.config.json <<'JSON'
{
  "appId": "app.video.guoguo",
  "appName": "囧次元",
  "webDir": "www"
}
JSON

echo "=== 3. www/index.html ==="
printf '<!doctype html><html><body>placeholder</body></html>' > www/index.html

echo "=== 4. npm install @capacitor ==="
npm i --no-audit --no-fund @capacitor/core@7 @capacitor/android@7
npm i --no-audit --no-fund -D @capacitor/cli@7

echo "=== 5. npx cap add android ==="
npx cap add android

echo "=== 6. 结果清单 ==="
find android -maxdepth 3 -not -path "*/build/*" | sort | head -60
echo "=== 模板文件到位检查 ==="
for f in android/gradlew android/gradlew.bat android/gradle/wrapper/gradle-wrapper.jar android/gradle/wrapper/gradle-wrapper.properties android/app/capacitor.build.gradle android/capacitor-cordova-android-plugins/build.gradle android/app/src/main/res/values/colors.xml android/app/src/main/res/values/strings.xml; do
  [ -e "$f" ] && echo "OK   $f" || echo "MISS $f"
done
echo "=== mipmap ==="
ls android/app/src/main/res/ 2>/dev/null
echo "=== wrapper properties ==="
cat android/gradle/wrapper/gradle-wrapper.properties 2>/dev/null
echo "=== 完成 ==="
