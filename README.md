# HelloBBK 激活工具（Activation Code Generator）

一个 Android 小工具，用于**离线生成 HelloBBK / SystemToolbox 宿主认可的激活码**。
界面与图标沿用 HelloBBK 原版（`HELLO bbk`），支持**自定义 RSA 私钥**与**自定义到期时间**。

> **产物为未签名 APK**（按要求「编译完之后不用签名」）。未签名 APK 不能直接安装到普通设备；如需安装，请自行用 `apksigner` 签名，或在需要加载补丁的场景下配合宿主使用。

> 这是补丁的「签发端」。宿主（`com.system.toolbox`）里的 `Activation.kt` 是「验签端」，两者格式严格对齐。

## 功能

- 自定义 **RSA 私钥**：粘贴 PEM，或从文件选择。同时兼容
  `-----BEGIN PRIVATE KEY-----`（PKCS#8）与 `-----BEGIN RSA PRIVATE KEY-----`（PKCS#1）。
- 自定义 **到期时间**：日期时间选择器 + 快捷 `+30 天 / +90 天 / +1 年 / 长期(2100)`。
- 输入**设备序列号 SN**（激活码与 SN 绑定）。
- 一键生成激活码（Base64URL），可复制；自动记住 SN / 私钥 / 上次到期时间。
- **本地自检**：从私钥推导公钥，按宿主 `verify()` 的等价逻辑回验，确保生成的码能被验签通过。
- RSA-2048 / RSA-4096 自适应（签名长度按模长动态计算，4096 → 512 字节）。
- 纯离线运算：不联网、不申请任何权限、不上传密钥。

## 激活码格式（与宿主严格一致）

```
payload = [2B 大端 SN长度][SN 的 UTF-8 字节][8B 大端过期时间戳(Unix 秒)][RSA 签名]
签名内容 = SN 的 UTF-8 字节 + 过期时间戳的 8 字节大端表示
签名算法 = SHA256withRSA
激活码   = Base64(URL_SAFE, NO_WRAP, NO_PADDING)(payload)
校验条件 = SN 与本机一致 && 签名有效 && 当前秒 <= 过期秒
```

宿主 `verify()` 里签名长度按公钥模长推导（2048→256B、4096→512B），并要求
`payload.size == 2 + snLen + 8 + sigSize`、`snLen ∈ [1,128]`，本工具完全遵守。

## 关键前提：私钥必须与宿主在线公钥配对

宿主当前是**在线验签**：点击激活时从 `https://share.weiyun.com/YtHW1ZPF` 拉取
**RSA-4096 公钥**。因此：

- 若要让生成的激活码直接被现有宿主接受，请填入**与该公钥成对的那把私钥**；
- 若填入自己的私钥，需同步把对应公钥（PEM `BEGIN PUBLIC KEY`）更新到该分享页后，
  在宿主里重新点击激活（强制刷新公钥）；旧私钥签发的激活码随即失效。

工具本身不关心公钥，只负责用私钥正确签名。

## 编译

需要 JDK 17、Android SDK 34（platform-34 / build-tools 34.0.0），`local.properties` 指向 SDK：

```bash
echo "sdk.dir=/path/to/android-sdk" > local.properties
./gradlew :app:assembleRelease
# 产物：app/build/outputs/apk/release/app-release-unsigned.apk（未签名）
```

工程不含任何 `signingConfig`，因此 `assembleRelease` 直接产出未签名 APK。
本仓库**只放源码**，不配置 CI 编译、不上传 APK 制品、不发布 Release；APK 由维护者本地编译后另行分发。
如需自行签名，可用：
```bash
apksigner sign --ks your.keystore --out app-signed.apk app/build/outputs/apk/release/app-release-unsigned.apk
```

工程为 **Kotlin + Android framework**，除 Kotlin 标准库外零 AndroidX / Compose / 第三方依赖，
保证在干净环境也能稳定编译。

## 代码结构

| 文件 | 作用 |
|---|---|
| `app/.../ActivationGenerator.kt` | 激活码拼装 / 签名 / Base64URL / 宿主等价 verify 自检（纯 JDK，object 单例） |
| `app/.../PemUtil.kt` | PEM 私钥解析，PKCS#8 与 PKCS#1 兼容（纯 JDK，object 单例） |
| `app/.../MainActivity.kt` | UI 与交互（原生 View，无 AndroidX） |
| `app/src/main/res/mipmap-*` | HelloBBK 原版 `HELLO bbk` 图标 |

## 回环验证

`ActivationGenerator.kt` / `PemUtil.kt` 只用 JDK 标准库，可脱离 Android 在 JVM 里跑
「工具生成 → 宿主等价验签」回环测试。已覆盖 RSA-2048 / 4096、PKCS#8 / PKCS#1、
过期、SN 不符、签名篡改、openssl 独立公钥交叉验证，共 41 项全部通过。

## 免责说明

本工具仅用于**你自己拥有合法授权**的设备/应用的激活码签发与调试。请妥善保管私钥，
不要分发含私钥的 APK 或把私钥提交到公开仓库。
