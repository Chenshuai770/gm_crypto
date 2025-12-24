
import 'package:flutter/material.dart';
import 'package:gm_crypto/gm_crypto.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter SM Demo',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const SMDemoPage(),
    );
  }
}

class SMDemoPage extends StatefulWidget {
  const SMDemoPage({super.key});

  @override
  State<SMDemoPage> createState() => _SMDemoPageState();
}

class _SMDemoPageState extends State<SMDemoPage> {
  String _result = '';

  void _testSM2() {
    final buffer = StringBuffer();
    buffer.writeln('=== SM2 测试 ===');

    // 生成密钥对
    final keyPair = SM2.generateKeyPair();
    buffer.writeln('私钥: ${keyPair.privateKey}');
    buffer.writeln('公钥: ${keyPair.publicKey}');
    debugPrint('私钥: ${keyPair.privateKey}');
    debugPrint('公钥: ${keyPair.publicKey}');

    // 签名和验签
    const msg = 'Hello SM2!';
    var hashMsg=SM3.hash(msg);
    buffer.writeln('');
    buffer.writeln('--- 签名/验签 ---');
    buffer.writeln('原数据: $msg');
    buffer.writeln('待签名数据(sm3加密后 utf-8): $hashMsg');
    debugPrint('待签名数据(sm3加密后 utf-8): $hashMsg');

    final signature = SM2.signature(hashMsg, keyPair.privateKey, der: true);
    buffer.writeln('签名值: $signature');
    debugPrint('签名值: $signature');

    final isValid = SM2.verifySignature(hashMsg, signature, keyPair.publicKey,der: true);
    buffer.writeln('验签结果: ${isValid ? "验签成功" : "验签失败"}');
    debugPrint('验签结果: ${isValid ? "验签成功" : "验签失败"}');


    // 加密和解密
    buffer.writeln('');
    buffer.writeln('--- 加密/解密 ---');
    buffer.writeln('待加密数据: $msg');
    debugPrint('待加密数据: $msg');

    final cipher = SM2.encrypt(msg, keyPair.publicKey);
    buffer.writeln('密文: $cipher');
    debugPrint('密文: $cipher');

    final decrypted = SM2.decrypt(cipher, keyPair.privateKey);
    buffer.writeln('解密结果: $decrypted');
    debugPrint('解密结果: $decrypted');


    setState(() => _result = buffer.toString());
  }


  void _testSM3() {
    final buffer = StringBuffer();
    buffer.writeln('=== SM3 测试 ===');

    const msg = 'Hello SM3!';
    final hash = SM3.hash(msg);
    buffer.writeln('原文: $msg');
    buffer.writeln('哈希: $hash');
    debugPrint('原文: $msg');
    debugPrint('哈希: $hash');

    setState(() => _result = buffer.toString());
  }

  void _testSM4() {
    final buffer = StringBuffer();
    buffer.writeln('=== SM4 测试 ===');

    const plainText = 'Hello SM4!';
    const key = '0123456789abcdef0123456789abcdef';
    const iv = 'fedcba9876543210fedcba9876543210';

    // ECB模式
    final ecbCipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.ECB);
    final ecbDecrypted = SM4.decrypt(ecbCipher, key: key, mode: SM4CryptoMode.ECB);
    buffer.writeln('ECB加密: $ecbCipher');
    buffer.writeln('ECB解密: $ecbDecrypted');
    debugPrint('ECB加密: $ecbCipher');
    debugPrint('ECB解密: $ecbDecrypted');


    // CBC模式
    final cbcCipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.CBC, iv: iv);
    final cbcDecrypted = SM4.decrypt(cbcCipher, key: key, mode: SM4CryptoMode.CBC, iv: iv);
    buffer.writeln('CBC加密: $cbcCipher');
    buffer.writeln('CBC解密: $cbcDecrypted');
    debugPrint('CBC加密: $cbcCipher');
    debugPrint('CBC解密: $cbcDecrypted');


    setState(() => _result = buffer.toString());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Flutter SM Demo')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Wrap(
              spacing: 8,
              children: [
                ElevatedButton(onPressed: _testSM2, child: const Text('SM2')),
                ElevatedButton(onPressed: _testSM3, child: const Text('SM3')),
                ElevatedButton(onPressed: _testSM4, child: const Text('SM4')),
              ],
            ),
            const SizedBox(height: 16),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.grey[100],
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    _result.isEmpty ? '点击按钮测试SM算法' : _result,
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
