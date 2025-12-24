# flutter_sm

Flutter/Dart 实现的国密SM2、SM3、SM4算法库。

## 功能特性

- **SM2**: 椭圆曲线公钥密码算法
  - 密钥对生成
  - 数字签名/验签 (支持DER格式)
  - 加密/解密 (支持C1C2C3和C1C3C2格式)

- **SM3**: 密码杂凑算法
  - 256位哈希值
  - 支持字符串和字节数组输入

- **SM4**: 分组密码算法
  - 128位对称加密
  - 支持ECB和CBC模式

## 安装

在 `pubspec.yaml` 中添加:

```yaml
dependencies:
   gm_crypto: ^1.0.0
```

然后运行:

```bash
flutter pub get
```

## 使用示例

### SM2 - 非对称加密

```dart
import 'package:flutter_sm/flutter_sm.dart';

// 生成密钥对
final keyPair = SM2.generateKeyPair();
print('私钥: ${keyPair.privateKey}');
print('公钥: ${keyPair.publicKey}');

// 签名和验签
const msg = 'Hello SM2!';
final signature = SM2.signature(msg, keyPair.privateKey);
final isValid = SM2.verifySignature(msg, signature, keyPair.publicKey);
print('签名验证: $isValid');

// 加密和解密
final cipher = SM2.encrypt(msg, keyPair.publicKey);
final decrypted = SM2.decrypt(cipher, keyPair.privateKey);
print('解密结果: $decrypted');

// 使用DER格式签名
final derSignature = SM2.signature(msg, keyPair.privateKey, der: true);
final isDerValid = SM2.verifySignature(msg, derSignature, keyPair.publicKey, der: true);
```

### SM3 - 哈希算法

```dart
import 'package:flutter_sm/flutter_sm.dart';

// 字符串哈希
const msg = 'Hello SM3!';
final hash = SM3.hash(msg);
print('哈希: $hash');

// 字节数组哈希
final bytes = [0x01, 0x02, 0x03];
final bytesHash = SM3.hashBytes(bytes);
print('字节哈希: $bytesHash');
```

### SM4 - 对称加密

```dart
import 'package:flutter_sm/flutter_sm.dart';

const plainText = 'Hello SM4!';
const key = '0123456789abcdef0123456789abcdef'; // 32位16进制字符串
const iv = 'fedcba9876543210fedcba9876543210';  // CBC模式需要IV

// ECB模式
final ecbCipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.ECB);
final ecbDecrypted = SM4.decrypt(ecbCipher, key: key, mode: SM4CryptoMode.ECB);

// CBC模式
final cbcCipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.CBC, iv: iv);
final cbcDecrypted = SM4.decrypt(cbcCipher, key: key, mode: SM4CryptoMode.CBC, iv: iv);
```

## API 参考

### SM2

| 方法 | 说明 |
|------|------|
| `generateKeyPair()` | 生成SM2密钥对 |
| `signature(msg, privateKey, {der, userId})` | 签名 |
| `verifySignature(msg, signHex, publicKey, {der, userId})` | 验签 |
| `encrypt(msg, publicKey, {cipherMode})` | 加密 |
| `decrypt(cipher, privateKey, {cipherMode})` | 解密 |

### SM3

| 方法 | 说明 |
|------|------|
| `hash(msg)` | 对字符串计算SM3哈希 |
| `hashBytes(input)` | 对字节数组计算SM3哈希 |
| `hashBytesToBytes(input)` | 返回字节数组格式的哈希值 |

### SM4

| 方法 | 说明 |
|------|------|
| `encrypt(plainText, key, mode, [iv])` | SM4加密 |
| `decrypt(cipherText, key, mode, [iv])` | SM4解密 |

## 在线验证工具

以下网站可用于验证SM算法结果：

- [SM2在线工具 - the-x.cn](https://the-x.cn/cryptography/Sm2.aspx)
- [SM2签名验签 - hiofd.com](https://tool.hiofd.com/sm2-sign-verify/)
- [SM2加解密 - bkssl.com](https://bkssl.com/ssl/sm2)
- [SM4在线工具 - lzltool.com](https://www.lzltool.com/SM4)

## 致谢

感谢以下开源项目的贡献：

- [sm_crypto](https://pub.dev/packages/sm_crypto)
- [smx_encrypt](https://pub.dev/packages/smx_encrypt)
- [dart_sm](https://pub.dev/packages/dart_sm)

## License

MIT License
